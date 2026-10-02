"""
Passive subdomain enumeration via certificate transparency logs (crt.sh).

This is a purely passive OSINT technique: it queries a public CT-log search
index, not the target infrastructure at all, so it carries no load/DoS risk
for the target. This mirrors the "certificate transparency" recon tactic
catalogued across awesome-osint style lists.
"""
from __future__ import annotations

import json
import aiohttp
from typing import Any


async def find_subdomains_crtsh(domain: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: set[str] = set()
    error = None
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 200:
                text = await resp.text()
                # crt.sh sometimes returns concatenated JSON objects; be lenient.
                try:
                    rows = json.loads(text)
                except json.JSONDecodeError:
                    rows = []
                for row in rows:
                    name_value = row.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and not name.startswith("*."):
                            subdomains.add(name)
                        elif name.startswith("*."):
                            subdomains.add(name[2:])
            else:
                error = f"crt.sh returned HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001
        error = str(exc)

    return {
        "source": "crt.sh (certificate transparency)",
        "count": len(subdomains),
        "subdomains": sorted(subdomains),
        "error": error,
    }
