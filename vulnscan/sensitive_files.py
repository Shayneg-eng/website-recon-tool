"""
Checks a curated list of commonly-exposed sensitive paths (.env, .git/HEAD,
backup archives, etc). Same GET-based technique as content discovery, just
scoped to a short, high-signal list so it's cheap to run every time.

Uses the same wildcard-baseline filtering as content_discovery.py: a site
that returns 200 (or any other single status) for every unmatched path -
a single-page app serving index.html for every route, a catch-all error
page, a WAF block page - will otherwise make EVERY path in this wordlist
look "exposed", including things like .env and id_rsa. That's a false
positive, not a finding, and reporting it as one is worse than finding
nothing: someone could reasonably panic over a fake credentials leak.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

import aiohttp
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from discovery.content_discovery import load_wordlist, RateLimiter, _get_baseline

INTERESTING_STATUSES = {200, 401, 403}


async def _check_one(session, base_url, path, semaphore, limiter, timeout_seconds, results, on_done, is_noise):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    hit: Optional[dict[str, Any]] = None
    async with semaphore:
        await limiter.wait()
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout_seconds), allow_redirects=False
            ) as resp:
                if resp.status in INTERESTING_STATUSES:
                    length_header = resp.headers.get("Content-Length")
                    content_length = int(length_header) if length_header and length_header.isdigit() else None
                    if not is_noise(resp.status, content_length):
                        # Read a small snippet to avoid pulling down huge files
                        # (e.g. someone's entire database backup).
                        chunk = await resp.content.read(256)
                        hit = {
                            "url": url,
                            "status": resp.status,
                            "content_length": content_length,
                            "content_type": resp.headers.get("Content-Type"),
                            "snippet_preview": chunk[:120].decode(errors="replace"),
                        }
        except Exception:  # noqa: BLE001
            pass

    if hit:
        results.append(hit)
    on_done(hit)


async def check_sensitive_files(base_url: str, cfg: dict, session: aiohttp.ClientSession) -> dict[str, Any]:
    wordlist_path = cfg.get("sensitive_files_wordlist", "wordlists/sensitive_files.txt")
    paths = load_wordlist(wordlist_path)

    semaphore = asyncio.Semaphore(8)
    limiter = RateLimiter(10)
    timeout_seconds = 8
    results: list[dict[str, Any]] = []

    baseline_status, baseline_length = None, None
    if cfg.get("filter_wildcard_responses", True):
        baseline_status, baseline_length = await _get_baseline(session, base_url, timeout_seconds)
        if baseline_status in INTERESTING_STATUSES:
            print(
                f"  [!] Server returns HTTP {baseline_status} for paths that don't exist "
                f"(content-length {baseline_length}). Filtering exact matches to that "
                f"signature out of sensitive-file results too."
            )

    def is_noise(status: int, content_length: Optional[int]) -> bool:
        return baseline_status is not None and status == baseline_status and content_length == baseline_length

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold magenta]Sensitive file checks[/bold magenta]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("• [red]{task.fields[found]}[/red] exposed"),
        TimeElapsedColumn(),
    )

    with progress:
        task_id = progress.add_task("sensitive", total=len(paths), found=0)

        def on_done(hit: Optional[dict[str, Any]]):
            progress.update(task_id, advance=1, found=len(results))
            if hit:
                progress.console.print(f"  [bold red]EXPOSED[/bold red] {hit['status']}  {hit['url']}")

        tasks = [
            _check_one(session, base_url, p, semaphore, limiter, timeout_seconds, results, on_done, is_noise)
            for p in paths
        ]
        await asyncio.gather(*tasks)

    return {
        "wordlist_used": wordlist_path,
        "total_paths_tested": len(paths),
        "wildcard_baseline": {"status": baseline_status, "content_length": baseline_length},
        "exposed_count": len(results),
        "exposed_files": sorted(results, key=lambda r: r["url"]),
    }
