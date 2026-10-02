"""
WordPress ships a readme.html at its webroot by default that discloses its
exact version ("Version X.Y.Z") - one of the most common real-world version
disclosure sources, and the reason security-conscious WordPress admins
delete or block it. This is a single GET to a file WordPress itself puts
at a well-known public path; it's only fetched when tech_fingerprint.py
has already detected WordPress from normal page content.
"""
from __future__ import annotations

import re
from typing import Any, Optional

import aiohttp

VERSION_RE = re.compile(r"Version\s+([0-9]+(?:\.[0-9]+){1,3})", re.I)


async def check_wordpress_version(base_url: str, session: aiohttp.ClientSession) -> Optional[dict[str, Any]]:
    url = base_url.rstrip("/") + "/readme.html"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as resp:
            if resp.status != 200:
                return None
            body = await resp.text(errors="ignore")
            m = VERSION_RE.search(body)
            if not m:
                return None
            return {"product": "WordPress", "version": m.group(1), "source": "readme.html", "url": url}
    except Exception:  # noqa: BLE001
        return None
