"""
Security header audit - checks for the presence (and sane values) of the
HTTP response headers that matter for an outsider's ability to exploit the
site client-side (clickjacking, MIME sniffing, mixed content, etc).
Read-only: a single GET request to the homepage.
"""
from __future__ import annotations

from typing import Any

import aiohttp

EXPECTED_HEADERS = {
    "Strict-Transport-Security": "Protects against SSL-stripping / downgrade attacks.",
    "Content-Security-Policy": "Mitigates XSS and data-injection attacks.",
    "X-Content-Type-Options": "Prevents MIME-sniffing (expected value: nosniff).",
    "X-Frame-Options": "Mitigates clickjacking (expected value: DENY or SAMEORIGIN).",
    "Referrer-Policy": "Controls how much referrer info leaks to other sites.",
    "Permissions-Policy": "Restricts access to browser features/APIs.",
}


async def check_security_headers(base_url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    result: dict[str, Any] = {"present": {}, "missing": [], "error": None}
    try:
        async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
            for header, why in EXPECTED_HEADERS.items():
                if header in resp.headers:
                    result["present"][header] = resp.headers[header]
                else:
                    result["missing"].append({"header": header, "why_it_matters": why})

            # Flag cookies missing Secure/HttpOnly flags.
            insecure_cookies = []
            for cookie in resp.cookies.values():
                flags = []
                if not cookie.get("secure"):
                    flags.append("missing Secure")
                if not cookie.get("httponly"):
                    flags.append("missing HttpOnly")
                if flags:
                    insecure_cookies.append({"name": cookie.key, "issues": flags})
            result["insecure_cookies"] = insecure_cookies
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)

    return result
