"""
Best-effort detection (NOT exploitation) of the classic IIS 8.3
short-filename disclosure quirk (aka the "tilde vulnerability", first
published by Soroush Dalili). Older/misconfigured IIS + ASP.NET handler
mappings will respond differently to a wildcard short-name pattern
(`*~1*`) depending on whether any file/folder with a matching legacy 8.3
name exists - which can leak partial real filenames without needing any
wordlist at all, including inside directories that block normal browsing.

This module only answers "does this server show the signature that makes
this vulnerability class exploitable" (info-level finding, needs manual
confirmation) - it deliberately does NOT implement the character-by-character
short-name reconstruction that a real exploitation of this issue requires.
That's a much larger, purpose-built enumeration technique and is out of
scope for this tool; if this comes back positive, a dedicated tool (e.g.
"IIS Shortname Scanner") and manual follow-up is the appropriate next step.
"""
from __future__ import annotations

from typing import Any

import aiohttp

# A wildcard short-name pattern. Handler extension varies by what's mapped
# on the target (.aspx is the most commonly present on IIS/ASP.NET); if
# this comes back inconclusive that doesn't mean the server is safe, just
# that this one extension mapping didn't trigger the signature.
VULNERABLE_PATTERN = "/*~1*/.aspx"
CONTROL_PATTERN = "/a*~1*.aspx"


async def check_iis_shortname(base_url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    result: dict[str, Any] = {
        "tested": True,
        "vulnerable_pattern_status": None,
        "control_pattern_status": None,
        "signature_observed": False,
        "error": None,
        "note": "Heuristic only - a positive signal needs manual confirmation with a dedicated IIS "
        "shortname tool. This module does not reconstruct actual filenames.",
    }
    try:
        vuln_url = base_url.rstrip("/") + VULNERABLE_PATTERN
        control_url = base_url.rstrip("/") + CONTROL_PATTERN

        async with session.get(vuln_url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as resp:
            result["vulnerable_pattern_status"] = resp.status

        async with session.get(control_url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as resp:
            result["control_pattern_status"] = resp.status

        # Published signature: vulnerable servers return 404 for the
        # wildcard short-name pattern but 400 for a pattern that can't
        # match any legacy short name. Identical statuses = inconclusive.
        result["signature_observed"] = (
            result["vulnerable_pattern_status"] == 404 and result["control_pattern_status"] == 400
        )
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)

    return result
