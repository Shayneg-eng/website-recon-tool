"""
HTTP method / WebDAV misconfiguration check - standard, well-established
auditing (this is essentially OWASP's "Test HTTP Methods" check, the same
thing Nikto flags as "WebDAV enabled" / "TRACE enabled"). Three things it
looks for:

1. Dangerous methods advertised via OPTIONS (PUT/DELETE would let someone
   upload or remove files if actually honored - worth flagging even just
   as an advertised capability).
2. WebDAV's PROPFIND method returning a real multi-status listing on a
   path that blocks normal GET-based browsing - i.e. an access control
   that only covers one HTTP verb, not the resource itself.
3. Whether TRACE, if advertised, actually implements the classic
   request-echo behavior that Cross-Site Tracing (XST) depends on. XST
   needs TWO things together: an XSS bug somewhere on the origin (this
   tool does not search for XSS - that's a separate, much larger class of
   testing) AND the server echoing the raw request - including any
   cookies attached to it - back in the TRACE response body. A server can
   advertise TRACE in its Allow header without actually implementing that
   echo (some proxies strip it, some server configs don't reflect the
   body), so "TRACE is allowed" and "TRACE is exploitable via XST" are
   different claims - this confirms the second one specifically, by
   sending a real TRACE request with a unique marker header and checking
   whether it comes back in the response body. A positive result means
   the mechanical precondition is there, not that a working exploit
   exists - that still requires an actual XSS bug, which this tool
   doesn't hunt for.

This only tests methods the server itself advertises/responds to - it does
not attempt to use PUT/DELETE, does not send crafted paths, and does not
try to defeat any 403 through encoding or verb-tampering tricks. It answers
"what does this server say it allows", not "how do I get around what it
disallows".
"""
from __future__ import annotations

import secrets
from typing import Any

import aiohttp

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}

PROPFIND_BODY = """<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>"""

TRACE_MARKER_HEADER = "X-Xst-Probe-Marker"


async def _check_options(url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    result: dict[str, Any] = {"url": url, "allowed_methods": [], "dangerous_methods": [], "error": None}
    try:
        async with session.options(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            allow = resp.headers.get("Allow") or resp.headers.get("Public") or ""
            methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
            result["allowed_methods"] = methods
            result["dangerous_methods"] = [m for m in methods if m in DANGEROUS_METHODS]
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    return result


async def _check_propfind(url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    result: dict[str, Any] = {"url": url, "webdav_listing_status": None, "webdav_enabled": False, "error": None}
    try:
        async with session.request(
            "PROPFIND",
            url,
            data=PROPFIND_BODY,
            headers={"Content-Type": "application/xml", "Depth": "1"},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            result["webdav_listing_status"] = resp.status
            # 207 Multi-Status is WebDAV's real success response.
            result["webdav_enabled"] = resp.status == 207
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    return result


async def _check_trace_echo(url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    result: dict[str, Any] = {
        "tested": True,
        "status": None,
        "echoed_marker": False,
        "error": None,
    }
    marker = f"xst-probe-{secrets.token_hex(8)}"
    try:
        async with session.request(
            "TRACE",
            url,
            headers={TRACE_MARKER_HEADER: marker},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            result["status"] = resp.status
            body = await resp.text(errors="ignore")
            result["echoed_marker"] = marker in body
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    return result


async def check_http_methods(
    base_url: str, directories: list[str], session: aiohttp.ClientSession
) -> dict[str, Any]:
    targets = [base_url] + [base_url.rstrip("/") + d for d in directories]
    results = []
    for target in targets:
        options_result = await _check_options(target, session)
        propfind_result = await _check_propfind(target, session)

        trace_echo = None
        if "TRACE" in options_result["dangerous_methods"]:
            trace_echo = await _check_trace_echo(target, session)

        results.append(
            {
                "target": target,
                "allowed_methods": options_result["allowed_methods"],
                "dangerous_methods": options_result["dangerous_methods"],
                "options_error": options_result["error"],
                "webdav_listing_status": propfind_result["webdav_listing_status"],
                "webdav_enabled": propfind_result["webdav_enabled"],
                "propfind_error": propfind_result["error"],
                "trace_echo": trace_echo,
            }
        )
    return {"checked": results}
