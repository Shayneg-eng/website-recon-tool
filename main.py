#!/usr/bin/env python3
"""
External Exposure Assessment Tool
==================================

Runs an "outsider's view" assessment against a single web target: passive
OSINT recon (DNS, WHOIS, certificate-transparency subdomains, robots/
sitemap, tech fingerprinting), active content discovery (SecLists-style
wordlist fuzzing) with an automatic targeted deep-dive into any directory
found to be distinctly restricted (guessable backup filenames), and a
vulnerability/misconfiguration scan (security headers, TLS, exposed
sensitive files, HTTP-method/WebDAV auditing, IIS short-filename signature).

AUTHORIZED USE ONLY.
Only run this against a domain you own or have explicit written
authorization to test. Active scanning against systems you don't control
is illegal in most jurisdictions (e.g. the US Computer Fraud and Abuse
Act) even when well-intentioned. See README.md.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from urllib.parse import urlparse

import aiohttp
import yaml
from rich.console import Console

from recon.runner import run_recon
from discovery.content_discovery import run_content_discovery, load_wordlist
from discovery.directory_deepdive import run_directory_deep_dive, _find_candidate_directories
from vulnscan.runner import run_vulnscan
from report.report_generator import generate_reports

console = Console()


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def confirm_authorization(domain: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    console.print(f"\nYou are about to run active scans (content discovery, sensitive-file")
    console.print(f"checks) against: [bold]{domain}[/bold]")
    console.print("This tool must only be used against domains you own or are explicitly")
    console.print("authorized to test.\n")
    answer = input("Type 'yes' to confirm you are authorized to test this target: ").strip().lower()
    return answer == "yes"


def estimate_discovery_requests(cfg: dict) -> int:
    try:
        words = load_wordlist(cfg["discovery"]["wordlist"])
        extensions = cfg["discovery"].get("extensions", [""])
        return len(words) * len(extensions)
    except FileNotFoundError:
        return -1


async def run_pipeline(cfg: dict) -> dict:
    domain = cfg["target"]["domain"]
    base_url = cfg["target"]["base_url"]
    results: dict = {"target": {"domain": domain, "base_url": base_url}}

    connector = aiohttp.TCPConnector(limit=50, ssl=False)
    default_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    user_agent = cfg.get("http", {}).get("user_agent", default_ua)
    headers = {"User-Agent": user_agent}
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        if cfg["recon"].get("enabled", True):
            console.rule("[bold cyan]1/3 OSINT Recon")
            results["recon"] = await run_recon(domain, base_url, cfg["recon"], session)

        discovery_dirs: list[str] = []
        if cfg["discovery"].get("enabled", True):
            console.rule("[bold cyan]2/4 Content Discovery")
            n = estimate_discovery_requests(cfg)
            rps = cfg["discovery"].get("requests_per_second", 40)
            if n > 0:
                console.print(f"  testing {n} paths at ~{rps} req/s (~{n / rps:.0f}s estimated)\n")
            results["discovery"] = await run_content_discovery(base_url, cfg["discovery"], session)
            console.print(
                f"  tested {results['discovery']['total_paths_tested']} paths, "
                f"{results['discovery']['findings_count']} findings in "
                f"{results['discovery']['elapsed_seconds']}s.\n"
            )

            discovery_dirs = _find_candidate_directories(results["discovery"]["findings"])
            deep_dive_cfg = cfg["discovery"].get("deep_dive", {})
            if deep_dive_cfg.get("enabled", True) and discovery_dirs:
                console.rule("[bold cyan]3/4 Directory Deep-Dive")
                console.print(
                    f"  {len(discovery_dirs)} restricted director{'y' if len(discovery_dirs) == 1 else 'ies'} "
                    f"found ({', '.join(discovery_dirs)}) - probing known backup-filename patterns inside "
                    f"each. This does not try to bypass the 403 itself, just checks whether specific files "
                    f"are directly reachable.\n"
                )
                results["directory_deep_dive"] = await run_directory_deep_dive(
                    base_url, results["discovery"]["findings"], deep_dive_cfg, session
                )

        if cfg["vulnscan"].get("enabled", True):
            console.rule("[bold cyan]4/4 Vulnerability / Misconfiguration Scan")
            software_versions = results.get("recon", {}).get("tech_fingerprint", {}).get("software_versions", [])
            results["vulnscan"] = await run_vulnscan(
                domain, base_url, cfg["vulnscan"], session, discovery_dirs, software_versions
            )

    return results


def main():
    parser = argparse.ArgumentParser(description="External exposure assessment tool (authorized use only)")
    parser.add_argument("--config", default="config.yaml", help="Path to config YAML")
    parser.add_argument("--target", help="Override target base URL (e.g. https://example.com)")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive authorization confirmation")
    parser.add_argument("--skip-discovery", action="store_true", help="Skip active content discovery")
    parser.add_argument("--skip-vulnscan", action="store_true", help="Skip vulnerability/misconfig scan")
    parser.add_argument("--wordlist", help="Override discovery.wordlist (e.g. wordlists/content_discovery.txt)")
    parser.add_argument("--extensions", help="Comma-separated extension list, e.g. ',.php,.bak' (empty = no ext)")
    parser.add_argument("--rps", type=float, help="Override discovery.requests_per_second")
    parser.add_argument("--concurrency", type=int, help="Override discovery.concurrency")
    args = parser.parse_args()

    cfg = load_config(args.config)

    if args.target:
        parsed = urlparse(args.target)
        cfg["target"]["base_url"] = args.target
        cfg["target"]["domain"] = parsed.hostname or args.target

    if args.skip_discovery:
        cfg["discovery"]["enabled"] = False
    if args.skip_vulnscan:
        cfg["vulnscan"]["enabled"] = False
    if args.wordlist:
        cfg["discovery"]["wordlist"] = args.wordlist
    if args.extensions is not None:
        cfg["discovery"]["extensions"] = args.extensions.split(",")
    if args.rps:
        cfg["discovery"]["requests_per_second"] = args.rps
    if args.concurrency:
        cfg["discovery"]["concurrency"] = args.concurrency

    domain = cfg["target"]["domain"]

    if not confirm_authorization(domain, args.yes):
        console.print("[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(1)

    started = time.monotonic()
    results = asyncio.run(run_pipeline(cfg))
    total_elapsed = time.monotonic() - started

    console.rule("[bold cyan]Report")
    out = generate_reports(results, cfg["output"]["directory"], domain)
    console.print(f"\n[bold]Done in {total_elapsed:.1f}s.[/bold] {out['findings_count']} findings.")
    console.print(f"  JSON: {out['json']}")
    console.print(f"  HTML: {out['html']}")


if __name__ == "__main__":
    main()
