"""
Fetch and parse robots.txt and sitemap.xml. These are files a site
publishes specifically to be read by outside crawlers, so this is the
lowest-impact recon step possible - but they often reveal paths the site
owner didn't intend to advertise (staging areas, admin paths disallowed
from indexing, etc).
"""
from __future__ import annotations

import re
from typing import Any

import aiohttp


async def fetch_robots_and_sitemap(base_url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    result: dict[str, Any] = {
        "robots_txt": {"found": False, "disallowed_paths": [], "sitemaps": []},
        "sitemap_xml": {"found": False, "url_count": 0, "sample_urls": []},
    }

    robots_url = base_url.rstrip("/") + "/robots.txt"
    try:
        async with session.get(robots_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="ignore")
                result["robots_txt"]["found"] = True
                result["robots_txt"]["disallowed_paths"] = re.findall(
                    r"^Disallow:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE
                )
                result["robots_txt"]["sitemaps"] = re.findall(
                    r"^Sitemap:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE
                )
    except Exception as exc:  # noqa: BLE001
        result["robots_txt"]["error"] = str(exc)

    sitemap_url = base_url.rstrip("/") + "/sitemap.xml"
    try:
        async with session.get(sitemap_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="ignore")
                urls = re.findall(r"<loc>(.*?)</loc>", text)
                result["sitemap_xml"]["found"] = True
                result["sitemap_xml"]["url_count"] = len(urls)
                result["sitemap_xml"]["sample_urls"] = urls[:25]
    except Exception as exc:  # noqa: BLE001
        result["sitemap_xml"]["error"] = str(exc)

    return result
