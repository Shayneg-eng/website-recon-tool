"""Runs all enabled vulnscan submodules and returns one aggregated dict."""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import aiohttp
from rich.console import Console

from .headers_check import check_security_headers
from .tls_check import check_tls
from .sensitive_files import check_sensitive_files
from .http_methods_check import check_http_methods
from .iis_shortname_check import check_iis_shortname
from .cve_lookup import check_known_cves

console = Console()


async def run_vulnscan(
    domain: str,
    base_url: str,
    cfg: dict,
    session: aiohttp.ClientSession,
    discovery_dirs: list[str] | None = None,
    software_versions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    discovery_dirs = discovery_dirs or []
    software_versions = software_versions or []

    if cfg.get("check_security_headers", True):
        started = time.monotonic()
        with console.status("[bold cyan]Vulnscan:[/bold cyan] security headers...", spinner="dots"):
            results["security_headers"] = await check_security_headers(base_url, session)
        console.print(f"  [green]done[/green] security headers ({time.monotonic() - started:.1f}s)")

    if cfg.get("check_tls", True):
        started = time.monotonic()
        hostname = urlparse(base_url).hostname or domain
        with console.status("[bold cyan]Vulnscan:[/bold cyan] TLS/certificate...", spinner="dots"):
            results["tls"] = check_tls(hostname)
        console.print(f"  [green]done[/green] TLS/certificate ({time.monotonic() - started:.1f}s)")

    if cfg.get("check_http_methods", True):
        started = time.monotonic()
        label = f"HTTP methods / WebDAV ({len(discovery_dirs) + 1} target(s))"
        with console.status(f"[bold cyan]Vulnscan:[/bold cyan] {label}...", spinner="dots"):
            results["http_methods"] = await check_http_methods(base_url, discovery_dirs, session)
        console.print(f"  [green]done[/green] {label} ({time.monotonic() - started:.1f}s)")

    if cfg.get("check_iis_shortname", True):
        started = time.monotonic()
        with console.status("[bold cyan]Vulnscan:[/bold cyan] IIS short-filename signature...", spinner="dots"):
            results["iis_shortname"] = await check_iis_shortname(base_url, session)
        console.print(f"  [green]done[/green] IIS short-filename signature ({time.monotonic() - started:.1f}s)")

    if cfg.get("check_sensitive_files", True):
        # This one prints its own progress bar (see sensitive_files.py).
        results["sensitive_files"] = await check_sensitive_files(base_url, cfg, session)

    if cfg.get("check_known_cves", True) and software_versions:
        started = time.monotonic()
        cve_cfg = cfg.get("cve_lookup", {})
        with console.status(
            f"[bold cyan]Vulnscan:[/bold cyan] known-CVE lookup ({len(software_versions)} software "
            f"signature(s) found)...",
            spinner="dots",
        ):
            results["cve_lookup"] = await check_known_cves(software_versions, session, cve_cfg)
        console.print(
            f"  [green]done[/green] known-CVE lookup "
            f"({results['cve_lookup']['queried_count']} queried, "
            f"{time.monotonic() - started:.1f}s)"
        )
    elif cfg.get("check_known_cves", True):
        console.print("  [dim]skipped known-CVE lookup - no software versions were identified[/dim]")

    return results
