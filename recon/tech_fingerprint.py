"""
Lightweight technology fingerprinting from a single benign GET request to
the homepage: response headers, cookie names, and a handful of well-known
HTML/meta markers. This is the same signal an outsider gets just by
visiting the site in a browser and viewing source - no active probing.

Also extracts (product, version) pairs where the site discloses them
(Server/X-Powered-By header tokens, <meta name="generator">, script tag
?ver= query strings) - this feeds vulnscan/cve_lookup.py, which checks
those versions against known public CVEs. Nothing here does more than
parse text already served to any visitor.
"""
from __future__ import annotations

import re
from typing import Any

import aiohttp

# (regex over headers/body, label) - deliberately small and well-known,
# not an exhaustive fingerprint DB.
HEADER_SIGNATURES = {
    "Server": "server_banner",
    "X-Powered-By": "x_powered_by",
    "X-AspNet-Version": "aspnet_version",
    "X-Generator": "generator",
    "Via": "via_proxy",
}

BODY_SIGNATURES = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"Drupal\.settings|/sites/default/files", re.I), "Drupal"),
    (re.compile(r"cdn\.shopify\.com", re.I), "Shopify"),
    (re.compile(r"data-reactroot|__NEXT_DATA__", re.I), "React/Next.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django"),
    (re.compile(r"laravel_session", re.I), "Laravel"),
]

# name/version tokens inside a header value, e.g. "Apache/2.4.49 (Unix)
# OpenSSL/1.0.2k-fips PHP/7.3.29" -> [("Apache","2.4.49"), ("OpenSSL","1.0.2k-fips"), ("PHP","7.3.29")]
_HEADER_VERSION_RE = re.compile(r"([A-Za-z][\w\-]*)/([0-9][\w.\-]*)")

# <meta name="generator" content="WordPress 5.8.1"> and similar
_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
_GENERATOR_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z !]*?)\s+([0-9]+(?:\.[0-9]+){0,3})")

# <script src=".../jquery.min.js?ver=1.12.4">
_SCRIPT_VER_RE = re.compile(r'<script[^>]+src=["\']([^"\'?]+?)(?:\.min)?\.js\?[^"\']*\bver=([\w.\-]+)["\']', re.I)


def _extract_header_versions(headers_of_interest: dict[str, str]) -> list[dict[str, str]]:
    found = []
    for label, value in headers_of_interest.items():
        for product, version in _HEADER_VERSION_RE.findall(value):
            found.append({"product": product, "version": version, "source": f"header:{label}"})
    return found


def _extract_generator_version(body: str) -> list[dict[str, str]]:
    m = _META_GENERATOR_RE.search(body)
    if not m:
        return []
    content = m.group(1)
    vm = _GENERATOR_VERSION_RE.search(content)
    if vm:
        return [{"product": vm.group(1).strip(), "version": vm.group(2), "source": "meta:generator"}]
    return [{"product": content.strip(), "version": None, "source": "meta:generator"}]


def _extract_script_versions(body: str) -> list[dict[str, str]]:
    found = []
    for path, version in _SCRIPT_VER_RE.findall(body):
        product = path.rsplit("/", 1)[-1] or path
        found.append({"product": product, "version": version, "source": "script:ver"})
    return found


async def fingerprint(base_url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    result: dict[str, Any] = {
        "headers_of_interest": {},
        "detected": [],
        "cookies": [],
        "software_versions": [],
        "error": None,
    }
    try:
        async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
            for header, label in HEADER_SIGNATURES.items():
                if header in resp.headers:
                    result["headers_of_interest"][label] = resp.headers[header]

            result["cookies"] = sorted({c.key for c in resp.cookies.values()})

            body = await resp.text(errors="ignore")
            for pattern, label in BODY_SIGNATURES:
                if pattern.search(body):
                    result["detected"].append(label)

            versions = []
            versions += _extract_header_versions(result["headers_of_interest"])
            versions += _extract_generator_version(body)
            versions += _extract_script_versions(body)
            # De-dupe identical (product, version) pairs from overlapping sources.
            seen = set()
            deduped = []
            for v in versions:
                key = (v["product"].lower(), v["version"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(v)
            result["software_versions"] = deduped

            result["final_url"] = str(resp.url)
            result["status"] = resp.status
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)

    return result
