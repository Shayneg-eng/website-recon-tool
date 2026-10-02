"""
Content/directory discovery: probes the target for paths from a wordlist,
using the same technique as ffuf/gobuster/dirb but implemented directly so
the whole pipeline stays in one Python codebase.

Safety notes (read before changing concurrency/rate settings):
- This is an ACTIVE technique - it sends real requests to the live site.
  Keep concurrency and requests_per_second modest so this behaves like a
  normal crawler, not a load test. This tool is for finding exposed
  content, not for measuring how much traffic your site can take.
- A client-side rate limiter (asyncio.Semaphore + a sleep-based token
  pacer) caps outbound request rate regardless of how fast responses come
  back, so a fast/cached target can't cause this to open the throttle.
- Total requests sent = len(wordlist) x len(extensions). If a run feels
  slow, the fix is usually a smaller wordlist or fewer extensions, not a
  higher rate limit - see config.yaml comments.
"""
from __future__ import annotations

import asyncio
import secrets
import time
from pathlib import Path
from typing import Any, Optional

import aiohttp
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)


def load_wordlist(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    with p.open("r", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


async def _get_baseline(
    session: aiohttp.ClientSession, base_url: str, timeout_seconds: int
) -> tuple[Optional[int], Optional[int]]:
    """Requests two random, near-certainly-nonexistent paths and returns
    (status, content_length) if the server answered both identically. Some
    servers return 200/403 (instead of 404) for anything unrecognized -
    e.g. a catch-all error page, a WAF block page, or an SPA that serves
    index.html for every route. Without this check every one of those
    paths would show up as a false-positive "finding"."""
    samples = []
    for _ in range(2):
        token = secrets.token_hex(16)
        url = base_url.rstrip("/") + f"/__probe_{token}_does_not_exist__"
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


class RateLimiter:
    """Simple client-side pacer: blocks callers so the aggregate call rate
    never exceeds `rate_per_second`, independent of concurrency."""

    def __init__(self, rate_per_second: float):
        self._interval = 1.0 / max(rate_per_second, 0.1)
        self._lock = asyncio.Lock()
        self._next_time = 0.0

    async def wait(self):
        async with self._lock:
            now = time.monotonic()
            wait_for = max(0.0, self._next_time - now)
            self._next_time = max(now, self._next_time) + self._interval
        if wait_for:
            await asyncio.sleep(wait_for)


async def _probe(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    semaphore: asyncio.Semaphore,
    limiter: RateLimiter,
    timeout_seconds: int,
    status_codes_of_interest: set[int],
    results: list[dict[str, Any]],
    on_done,
) -> None:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    hit: Optional[dict[str, Any]] = None
    async with semaphore:
        await limiter.wait()
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                allow_redirects=False,
            ) as resp:
                if resp.status in status_codes_of_interest:
                    length = resp.headers.get("Content-Length")
                    hit = {
                        "url": url,
                        "status": resp.status,
                        "content_length": int(length) if length and length.isdigit() else None,
                        "redirect_to": resp.headers.get("Location") if resp.status in (301, 302, 307) else None,
                    }
        except asyncio.TimeoutError:
            pass
        except Exception:  # noqa: BLE001 - a single bad path shouldn't abort the scan
            pass

    if hit:
        results.append(hit)
    on_done(hit)


async def run_content_discovery(base_url: str, cfg: dict, session: aiohttp.ClientSession) -> dict[str, Any]:
    wordlist_path = cfg.get("wordlist", "wordlists/quickhits.txt")
    words = load_wordlist(wordlist_path)
    extensions = cfg.get("extensions", [""])
    concurrency = int(cfg.get("concurrency", 25))
    rate = float(cfg.get("requests_per_second", 40))
    timeout_seconds = int(cfg.get("timeout_seconds", 8))
    status_codes = set(cfg.get("status_codes_of_interest", [200, 301, 302, 401, 403]))

    paths = [w + ext for w in words for ext in extensions]
    total = len(paths)

    semaphore = asyncio.Semaphore(concurrency)
    limiter = RateLimiter(rate)
    results: list[dict[str, Any]] = []

    baseline_status, baseline_length = None, None
    if cfg.get("filter_wildcard_responses", True):
        baseline_status, baseline_length = await _get_baseline(session, base_url, timeout_seconds)
        if baseline_status in status_codes:
            print(
                f"  [!] Server returns HTTP {baseline_status} for paths that don't exist "
                f"(content-length {baseline_length}). Filtering exact matches to that "
                f"signature out of findings - see 'wildcard_baseline' in the JSON output."
            )

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Content discovery"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("• {task.fields[rate]:>5.1f} req/s"),
        TextColumn("• [green]{task.fields[found]}[/green] found"),
        TimeElapsedColumn(),
        TextColumn("eta"),
        TimeRemainingColumn(),
    )

    started = time.monotonic()

    with progress:
        task_id = progress.add_task("discovery", total=total, rate=0.0, found=0)

        genuine_so_far = 0

        def is_wildcard_noise(hit: dict[str, Any]) -> bool:
            return baseline_status is not None and hit["status"] == baseline_status and hit["content_length"] == baseline_length

        def on_done(hit: Optional[dict[str, Any]]):
            nonlocal genuine_so_far
            elapsed = max(time.monotonic() - started, 0.001)
            completed = progress.tasks[0].completed + 1
            if hit and not is_wildcard_noise(hit):
                genuine_so_far += 1
            progress.update(task_id, advance=1, rate=completed / elapsed, found=genuine_so_far)
            if hit and not is_wildcard_noise(hit):
                progress.console.print(f"  [green]HIT[/green] {hit['status']}  {hit['url']}")

        tasks = [
            _probe(session, base_url, path, semaphore, limiter, timeout_seconds, status_codes, results, on_done)
            for path in paths
        ]
        await asyncio.gather(*tasks)

    elapsed = time.monotonic() - started

    if baseline_status is not None:
        genuine = [
            r for r in results if not (r["status"] == baseline_status and r["content_length"] == baseline_length)
        ]
        filtered_as_noise = len(results) - len(genuine)
    else:
        genuine = results
        filtered_as_noise = 0

    genuine.sort(key=lambda r: r["url"])
    return {
        "wordlist_used": wordlist_path,
        "total_paths_tested": total,
        "elapsed_seconds": round(elapsed, 1),
        "wildcard_baseline": {"status": baseline_status, "content_length": baseline_length},
        "filtered_as_wildcard_noise": filtered_as_noise,
        "findings_count": len(genuine),
        "findings": genuine,
    }
