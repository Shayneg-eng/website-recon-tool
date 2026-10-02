# External Exposure Assessment Tool

A small Python pipeline that assesses a website the way an outsider
(researcher, opportunistic attacker, or bug bounty hunter) would: what can
they learn about it passively, and what does light active probing turn up.

Built on tactics catalogued in [SecLists](https://github.com/danielmiessler/SecLists)
(content-discovery wordlists) and OSINT reconnaissance techniques catalogued
in lists like [awesome-osint](https://github.com/jivoi/awesome-osint) and
[Awesome-OSINT-List](https://github.com/Astrosp/Awesome-OSINT-List)
(certificate transparency, DNS/WHOIS, tech fingerprinting).

## ⚠️ Authorized use only

Only run this against a domain **you own** or have **explicit written
authorization** to test. The content-discovery and sensitive-file modules
send real requests to the live target — running them against a system you
don't control or don't have permission to test is illegal in most
jurisdictions (e.g. the U.S. Computer Fraud and Abuse Act), regardless of
intent. `main.py` will ask you to confirm authorization interactively
before running; `--yes` skips that prompt for scripted/CI use — only use
it once you've already confirmed authorization out of band.

This is a reconnaissance and misconfiguration-discovery tool, not an
exploit framework. It does not attempt SQL injection, XSS injection,
credential brute-forcing, or anything that could corrupt data or take the
target offline. It also isn't a load/stress tool in the performance-testing
sense — it deliberately rate-limits itself so it behaves like a crawler,
not a DoS test.

## What it checks

**Recon (passive)** — `recon/`
- DNS records (A/AAAA/MX/NS/TXT/SOA/CAA), SPF/DMARC presence
- WHOIS (registrar, dates, exposed contact info)
- Subdomains via certificate transparency logs (crt.sh) — no direct queries to your infra
- `robots.txt` / `sitemap.xml` parsing
- Tech stack fingerprinting from response headers + page markers

**Content discovery (active)** — `discovery/`
- Wordlist-based path fuzzing (SecLists `common.txt` by default) to find
  unlinked directories/files, rate-limited and concurrency-capped

**Vulnerability / misconfiguration scan (active)** — `vulnscan/`
- Security header audit (HSTS, CSP, X-Frame-Options, etc.) + cookie flags
- TLS/certificate check (protocol version, expiry)
- Exposed sensitive-file check (`.env`, `.git/HEAD`, backups, etc.)

**Report** — `report/`
- One JSON file with full raw results
- One self-contained HTML report with a severity-sorted findings summary

## Setup

```bash
pip install -r requirements.txt
```

> **Note:** this was built and tested in a network-sandboxed cloud
> environment that blocks outbound requests to arbitrary internet hosts, so
> live scans against a real domain couldn't be exercised end-to-end there.
> Each module was verified logically (a local fixture server for the HTTP-based
> checks, real DNS resolution for the recon module) and every module fails
> gracefully — one blocked/failed request never crashes the run. Run it for
> real from your own machine or a server with normal internet access.

## Usage

1. Edit `config.yaml` — set `target.domain` and `target.base_url` to your site.
2. Run:

```bash
python main.py
```

You'll be asked to confirm authorization, then it runs recon → content
discovery → vuln scan → report, and prints the output file paths.

Useful flags:

```bash
python main.py --target https://yoursite.com   # override target without editing config.yaml
python main.py --skip-discovery                 # recon + vulnscan only (fully passive)
python main.py --skip-vulnscan
python main.py --yes                             # skip the interactive confirmation
```

## Tuning

`config.yaml` controls concurrency (`discovery.concurrency`), client-side
rate limit (`discovery.requests_per_second`), timeouts, and which wordlist
to use. Two extra wordlists are included in `wordlists/` if you want more
coverage than the default `common.txt`:

- `raft_small_directories.txt` — larger, more thorough (~20k entries)
- `quickhits.txt` — smaller, high-signal common paths

Swap `discovery.wordlist` in `config.yaml` to point at either. Bigger
wordlists mean longer scans — keep `requests_per_second` reasonable so you
don't put unnecessary load on your own production site.

## Extending

Each module returns a plain dict, so it's straightforward to add checks:
drop a new file in `recon/`, `discovery/`, or `vulnscan/`, wire it into
that folder's `runner.py`, and it'll show up in the JSON/HTML output
automatically. Natural next additions: subdomain takeover checks, a
Nuclei template wrapper (`subprocess` call out to the `nuclei` CLI if
installed), or Shodan/Censys lookups (both need API keys).
