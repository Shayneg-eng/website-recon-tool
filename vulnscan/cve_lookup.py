"""
Known-CVE matching: takes the (product, version) signatures collected
during recon (Server/X-Powered-By headers, <meta name="generator">, script
?ver= tags, WordPress readme.html) and checks each against the public
NVD (National Vulnerability Database) CVE API - a read-only government
database, not the target site. This is "does your software have a known,
publicly-documented hole" - matching against a public list, not probing
the target or guessing at anything. It's how most real-world breaches
actually happen (unpatched known vulnerabilities), so it's high-value
despite being simple.

Important caveats, surfaced in the output rather than hidden:
- This uses NVD's keywordSearch, not precise CPE version-range matching
  (which would need a full CPE dictionary and version-range parser - a
  much bigger undertaking). A keyword match means "this CVE's text
  mentions this product and version", not a confirmed, authoritative
  match - always worth a manual look at the linked CVE before acting.
- Version strings scraped from headers/HTML are sometimes wrong, stale
  (cached/CDN-served), or deliberately obscured - treat this as a lead,
  not a certainty.
- NVD's public API is rate-limited (5 requests/30s without an API key,
  50/30s with a free one from nvd.nist.gov/developers/request-an-api-key).
  This module paces itself to stay under the unauthenticated limit by
  default and skips products with no usable version rather than wasting
  a rate-limited call.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

import aiohttp

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Product names too generic/short to search usefully, or common
# false-positive extraction artifacts (e.g. "Via" from the Via header).
SKIP_PRODUCTS = {"via", "self", "none", "unknown", "generator", "js"}


def _severity_from_cve(cve: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return score, severity
    return None, None


def _description(cve: dict[str, Any]) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


async def _query_nvd(
    product: str, version: str, session: aiohttp.ClientSession, api_key: Optional[str], max_results: int
) -> dict[str, Any]:
    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": str(max_results * 3)}
    headers = {"apiKey": api_key} if api_key else {}
    result: dict[str, Any] = {"query": params["keywordSearch"], "total_results": 0, "matches": [], "error": None}
    try:
        async with session.get(
            NVD_API_URL, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            if resp.status == 403 or resp.status == 429:
                result["error"] = f"HTTP {resp.status} - likely rate-limited by NVD"
                return result
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    result["total_results"] = data.get("totalResults", 0)
    matches = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        score, severity = _severity_from_cve(cve)
        matches.append(
            {
                "id": cve.get("id"),
                "description": _description(cve)[:300],
                "cvss_score": score,
                "cvss_severity": severity,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}" if cve.get("id") else None,
            }
        )
    matches.sort(key=lambda m: (m["cvss_score"] is not None, m["cvss_score"]), reverse=True)
    result["matches"] = matches[:max_results]
    return result


async def check_known_cves(software_versions: list[dict[str, Any]], session: aiohttp.ClientSession, cfg: dict) -> dict[str, Any]:
    api_key = cfg.get("api_key")
    max_products = int(cfg.get("max_products", 8))
    max_results_per_product = int(cfg.get("max_results_per_product", 5))
    # NVD's public rate limit is 5 requests/30s without a key (~1 per 6s);
    # with a key it's 50/30s (~1 per 0.6s). Pad slightly for safety margin.
    delay_seconds = float(cfg.get("delay_seconds", 0.7 if api_key else 6.5))

    # Dedupe by (product, version); skip entries with no version or a
    # generic/junk product name - nothing useful to search for either way.
    seen = set()
    to_query: list[tuple[str, str]] = []
    for sv in software_versions:
        product = (sv.get("product") or "").strip()
        version = sv.get("version")
        if not product or not version:
            continue
        key = (product.lower(), version)
        if key in seen or product.lower() in SKIP_PRODUCTS:
            continue
        seen.add(key)
        to_query.append((product, version))

    to_query = to_query[:max_products]

    results: dict[str, Any] = {}
    for i, (product, version) in enumerate(to_query):
        if i > 0:
            await asyncio.sleep(delay_seconds)
        query_result = await _query_nvd(product, version, session, api_key, max_results_per_product)
        results[f"{product} {version}"] = query_result

    return {
        "queried_count": len(to_query),
        "skipped_count": len(software_versions) - len(to_query),
        "results": results,
    }
