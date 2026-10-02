"""Runs all enabled recon submodules and returns one aggregated dict."""
from __future__ import annotations

import time
from typing import Any

import aiohttp
from rich.console import Console

from .dns_recon import get_dns_records
from .subdomains import find_subdomains_crtsh
from .whois_lookup import get_whois_info
from .tech_fingerprint import fingerprint
from .robots_sitemap import fetch_robots_and_sitemap
from .wordpress_version import check_wordpress_version

console = Console()

STEPS = [
    ("dns_records", "DNS records"),
    ("whois_lookup", "WHOIS lookup"),
    ("crtsh_subdomains", "Subdomains (certificate transparency)"),
    ("tech_fingerprint", "Tech fingerprinting"),
    ("robots_sitemap", "robots.txt / sitemap.xml"),
]


async def run_recon(domain: str, base_url: str, cfg: dict, session: aiohttp.ClientSession) -> dict[str, Any]:
    results: dict[str, Any] = {}

    for key, label in STEPS:
        if not cfg.get(key, True):
            continue
        started = time.monotonic()
        with console.status(f"[bold cyan]Recon:[/bold cyan] {label}...", spinner="dots"):
            if key == "dns_records":
                results["dns"] = get_dns_records(domain)
            elif key == "whois_lookup":
                results["whois"] = get_whois_info(domain)
            elif key == "crtsh_subdomains":
                results["subdomains"] = await find_subdomains_crtsh(domain, session)
            elif key == "tech_fingerprint":
                results["tech_fingerprint"] = await fingerprint(base_url, session)
                if "WordPress" in results["tech_fingerprint"].get("detected", []):
                    wp = await check_wordpress_version(base_url, session)
                    if wp:
                        results["tech_fingerprint"]["software_versions"].append(wp)
            elif key == "robots_sitemap":
                results["robots_sitemap"] = await fetch_robots_and_sitemap(base_url, session)
        elapsed = time.monotonic() - started
        console.print(f"  [green]done[/green] {label} ({elapsed:.1f}s)")

    return results
