"""
Targeted follow-up scan: when content discovery finds a directory that the
server actively distinguishes from its normal "not found" response (401/403
rather than the site's baseline signature), a plain 403 on the directory
listing very often does NOT mean the files inside are protected too - many
servers block `Options -Indexes`-style browsing while still serving any
file whose exact name you already know. This module guesses filenames
inside a specific discovered directory instead of across the whole site,
using patterns real backup tooling actually produces (dated archives,
common tool defaults).

This is the same GET-and-compare technique as content_discovery.py, just
re-scoped to a directory the server has already flagged as "something is
here." It does NOT attempt to defeat/bypass the 403 itself (no encoding
tricks, no verb tampering, no path-normalization quirks) - see
vulnscan/http_methods_check.py for the one legitimate alternate-avenue
check (WebDAV) this tool includes, and the README for why more aggressive
bypass techniques aren't built in here.
"""
from __future__ import annotations

import asyncio
import re
import secrets
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Optional

import aiohttp
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .content_discovery import RateLimiter, load_wordlist


async def _get_directory_baseline(
    session: aiohttp.ClientSession, base_url: str, directory: str, timeout_seconds: int
) -> tuple[Optional[int], Optional[int]]:
    """Same wildcard-noise detection as content_discovery.py's baseline,
    but scoped to THIS directory rather than the site root - a SPA
    catch-all rewrite rule, or the directory's own IIS/Apache 404 handler,
    may behave differently here than at the root, so root-level baseline
    data can't be assumed to apply. Without this, every guessed filename
    that doesn't exist would show up as a false "found" hit, exactly like
    the bug that was in vulnscan/sensitive_files.py."""
    samples = []
    for _ in range(2):
        token = secrets.token_hex(16)
        url = base_url.rstrip("/") + directory + f"__probe_{token}_does_not_exist__"
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout_seconds), allow_redirects=False
            ) as resp:
                length = resp.headers.get("Content-Length")
                samples.append((resp.status, int(length) if length and length.isdigit() else None))
        except Exception:  # noqa: BLE001
            return None, None

    if len(samples) == 2 and samples[0] == samples[1]:
        return samples[0]
    return None, None

# Every knob here is config-overridable (see config.yaml) - these are just
# the defaults. Widening any of them is a straightforward tradeoff: more
# coverage for proportionally longer run time (candidates = all_names x
# extensions), not a fundamentally different or riskier technique.
DATE_FORMATS = ["%Y%m%d", "%Y-%m-%d"]
MONTH_FORMATS = ["%Y-%m", "%Y%m"]
DEFAULT_EXTENSIONS = [".zip", ".sql", ".sql.gz", ".tar.gz", ".bak", ".7z", ".old"]
DEFAULT_DAYS_BACK = 21
DEFAULT_MONTHS_BACK = 6


def _generate_dated_names(basenames: list[str], days_back: int) -> list[str]:
    """basename + date-in-various-formats, for the last `days_back` days -
    mirrors how backup jobs are actually named (nightly cron dumps, etc)."""
    names: list[str] = []
    today = date.today()
    for offset in range(days_back + 1):
        d = today - timedelta(days=offset)
        for fmt in DATE_FORMATS:
            stamp = d.strftime(fmt)
            for base in basenames:
                names.append(f"{base}_{stamp}")
                names.append(f"{base}-{stamp}")
            names.append(stamp)  # bare date, no basename - also common
    return names


def _generate_monthly_names(basenames: list[str], months_back: int) -> list[str]:
    """basename + year-month, for the last `months_back` months - covers
    weekly/monthly backup schedules a daily-only date range would miss."""
    names: list[str] = []
    today = date.today()
    year, month = today.year, today.month
    for offset in range(months_back + 1):
        m = month - offset
        y = year
        while m <= 0:
            m += 12
            y -= 1
        d = date(y, m, 1)
        for fmt in MONTH_FORMATS:
            stamp = d.strftime(fmt)
            for base in basenames:
                names.append(f"{base}_{stamp}")
                names.append(f"{base}-{stamp}")
            names.append(stamp)
    return names


def _find_candidate_directories(discovery_findings: list[dict[str, Any]]) -> list[str]:
    """Pull out directory-shaped hits with a status that means 'this exists
    and is distinct from the site's default response' - 401/403 - from a
    completed content-discovery pass. Dedupes case variants to one entry."""
    seen: set[str] = set()
    dirs: list[str] = []
    for f in discovery_findings:
        if f.get("status") not in (401, 403):
            continue
        url = f["url"]
        path = re.sub(r"^https?://[^/]+", "", url)
        path = path if path.endswith("/") else path + "/"
        key = path.lower()
        if key not in seen:
            seen.add(key)
            dirs.append(path)
    return dirs


async def _probe(session, base_url, path, semaphore, limiter, timeout_seconds, results, on_done, is_noise):
    url = base_url.rstrip("/") + path
    hit: Optional[dict[str, Any]] = None
    async with semaphore:
        await limiter.wait()
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout_seconds), allow_redirects=False
            ) as resp:
                if resp.status == 200:
                    length = resp.headers.get("Content-Length")
                    content_length = int(length) if length and length.isdigit() else None
                    if not is_noise(resp.status, content_length):
                        hit = {
                            "url": url,
                            "status": resp.status,
                            "content_type": resp.headers.get("Content-Type"),
                            "content_length": content_length,
                        }
        except Exception:  # noqa: BLE001
            pass
    if hit:
        results.append(hit)
    on_done(hit)


async def run_directory_deep_dive(
    base_url: str, discovery_findings: list[dict[str, Any]], cfg: dict, session: aiohttp.ClientSession
) -> dict[str, Any]:
    directories = _find_candidate_directories(discovery_findings)
    if not directories:
        return {"enabled": True, "directories_checked": [], "findings": []}

    basenames_path = cfg.get("basenames_wordlist", "wordlists/backup_basenames.txt")
    basenames = load_wordlist(basenames_path)
    days_back = int(cfg.get("date_days_back", DEFAULT_DAYS_BACK))
    months_back = int(cfg.get("months_back", DEFAULT_MONTHS_BACK))
    extensions = cfg.get("extensions", DEFAULT_EXTENSIONS)
    concurrency = int(cfg.get("concurrency", 15))
    rate = float(cfg.get("requests_per_second", 25))
    timeout_seconds = int(cfg.get("timeout_seconds", 8))

    dated_names = _generate_dated_names(basenames, days_back)
    monthly_names = _generate_monthly_names(basenames, months_back)
    all_names = sorted(set(basenames + dated_names + monthly_names))
    candidate_files = [name + ext for name in all_names for ext in extensions]

    semaphore = asyncio.Semaphore(concurrency)
    limiter = RateLimiter(rate)
    all_results: dict[str, list[dict[str, Any]]] = {}

    total_requests = len(candidate_files) * len(directories)
    print(
        f"  [i] Deep-dive: {len(all_names)} filename variants x {len(extensions)} extensions = "
        f"{len(candidate_files)} candidates per directory, {len(directories)} director"
        f"{'y' if len(directories) == 1 else 'ies'} -> {total_requests} requests total "
        f"(~{total_requests / rate:.0f}s estimated at {rate:.0f} req/s).\n"
    )

    baselines: dict[str, tuple] = {}

    for directory in directories:
        results: list[dict[str, Any]] = []
        paths = [directory + fname for fname in candidate_files]

        baseline_status, baseline_length = await _get_directory_baseline(session, base_url, directory, timeout_seconds)
        baselines[directory] = (baseline_status, baseline_length)
        if baseline_status == 200:
            print(
                f"  [!] {directory} returns HTTP 200 for filenames that don't exist "
                f"(content-length {baseline_length}) - likely the same catch-all as the rest of the site. "
                f"Filtering exact matches to that signature out of deep-dive results."
            )

        def is_noise(status: int, content_length: Optional[int], _bstatus=baseline_status, _blength=baseline_length) -> bool:
            return _bstatus is not None and status == _bstatus and content_length == _blength

        progress = Progress(
            SpinnerColumn(),
            TextColumn(f"[bold yellow]Deep-dive: {directory}[/bold yellow]"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("• [red]{task.fields[found]}[/red] found"),
            TimeElapsedColumn(),
        )
        with progress:
            task_id = progress.add_task("deepdive", total=len(paths), found=0)

            def on_done(hit: Optional[dict[str, Any]]):
                progress.update(task_id, advance=1, found=len(results))
                if hit:
                    progress.console.print(f"  [bold red]FOUND[/bold red] {hit['url']}")

            tasks = [
                _probe(session, base_url, p, semaphore, limiter, timeout_seconds, results, on_done, is_noise)
                for p in paths
            ]
            await asyncio.gather(*tasks)

        all_results[directory] = sorted(results, key=lambda r: r["url"])

    return {
        "enabled": True,
        "directories_checked": directories,
        "candidates_per_directory": len(candidate_files),
        "baselines": {d: {"status": s, "content_length": l} for d, (s, l) in baselines.items()},
        "findings": all_results,
    }
