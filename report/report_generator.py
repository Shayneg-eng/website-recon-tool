"""
Aggregates recon / discovery / vulnscan output into a summary + JSON file +
a single self-contained HTML report.
"""
from __future__ import annotations

import json
import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _detect_waf_block(data: dict[str, Any]) -> dict[str, Any] | None:
    """Heuristic check for 'the active-scan modules didn't actually see
    the real site' - i.e. a WAF/bot-management layer (Cloudflare, etc.)
    blanket-blocked the scanner before it reached the application. This
    matters because it silently turns a 'nothing found' result into 'we
    don't actually know', which is a very different thing to report."""
    recon = data.get("recon", {})
    disc = data.get("discovery", {})
    tech = recon.get("tech_fingerprint", {})

    cookies = [c.lower() for c in tech.get("cookies", [])]
    server = (tech.get("headers_of_interest", {}) or {}).get("server_banner", "") or ""
    homepage_blocked = tech.get("status") in (403, 503) and (
        any("cf_bm" in c or "cf_clearance" in c for c in cookies) or "cloudflare" in server.lower()
    )

    total = disc.get("total_paths_tested", 0) or 0
    noise = disc.get("filtered_as_wildcard_noise", 0) or 0
    baseline_status = (disc.get("wildcard_baseline") or {}).get("status")
    mostly_filtered = total > 0 and (noise / total) > 0.9 and baseline_status in (403, 429, 503)

    if homepage_blocked or mostly_filtered:
        return {
            "server": server or "a WAF/bot-management layer",
            "status": tech.get("status") or baseline_status,
        }
    return None


def _build_findings_summary(data: dict[str, Any]) -> list[dict[str, str]]:
    """Turn raw module output into a flat list of human-readable findings
    with a rough severity, for the top-of-report summary table."""
    findings: list[dict[str, str]] = []

    waf = _detect_waf_block(data)
    if waf:
        findings.append(
            {
                "severity": "notice",
                "area": "Scan Reliability",
                "finding": f"Active-scan requests were likely blocked by {waf['server']} (HTTP {waf['status']} on "
                f"most/all requests)",
                "detail": "Content-discovery and sensitive-file results below should be read as inconclusive, not "
                "clean - the scanner may never have reached your real application. This is often a sign your bot "
                "protection is working, but it means this run didn't verify what it set out to. See the README for "
                "how to get a real pass (temporarily allowlisting the scanning machine's IP is the legitimate option).",
            }
        )

    vs = data.get("vulnscan", {})

    headers = vs.get("security_headers", {})
    for m in headers.get("missing", []):
        findings.append(
            {
                "severity": "medium",
                "area": "Security Headers",
                "finding": f"Missing {m['header']}",
                "detail": m["why_it_matters"],
            }
        )
    for c in headers.get("insecure_cookies", []):
        findings.append(
            {
                "severity": "medium",
                "area": "Cookies",
                "finding": f"Cookie '{c['name']}' {', '.join(c['issues'])}",
                "detail": "Cookies without Secure/HttpOnly can be stolen via network sniffing or XSS.",
            }
        )

    tls = vs.get("tls", {})
    if tls.get("weak_protocol"):
        findings.append(
            {
                "severity": "high",
                "area": "TLS",
                "finding": f"Weak TLS protocol negotiated: {tls.get('protocol')}",
                "detail": "Upgrade server TLS config to require TLS 1.2+.",
            }
        )
    if tls.get("expiry_warning"):
        findings.append(
            {
                "severity": "high",
                "area": "TLS",
                "finding": f"Certificate expires in {tls.get('days_until_expiry')} days",
                "detail": "Renew the certificate before it lapses.",
            }
        )
    if tls.get("error"):
        findings.append(
            {
                "severity": "info",
                "area": "TLS",
                "finding": f"TLS check failed: {tls['error']}",
                "detail": "Could not establish/verify a TLS connection.",
            }
        )

    sens = vs.get("sensitive_files", {})
    for f in sens.get("exposed_files", []):
        if f["status"] == 200:
            findings.append(
                {
                    "severity": "critical",
                    "area": "Exposed File",
                    "finding": f"Publicly accessible: {f['url']}",
                    "detail": f"HTTP 200, content-type {f.get('content_type')}. This path serves real content to "
                    "anyone, not the site's normal catch-all response.",
                }
            )
        else:
            findings.append(
                {
                    "severity": "low",
                    "area": "Exposed File",
                    "finding": f"Path exists but is access-restricted: {f['url']}",
                    "detail": f"HTTP {f['status']} - distinct from the site's normal catch-all response, so this "
                    "path is real (unlike a 200 that just happens to match every URL), but its contents aren't "
                    "directly readable. Worth confirming what's actually blocking it and whether any specific "
                    "filenames underneath are reachable.",
                }
            )

    disc = data.get("discovery", {})
    for f in disc.get("findings", []):
        if f["status"] in (200, 401, 403):
            findings.append(
                {
                    "severity": "low",
                    "area": "Content Discovery",
                    "finding": f"{f['status']} {f['url']}",
                    "detail": "Discovered path not linked from the site's normal navigation.",
                }
            )

    deep_dive = data.get("directory_deep_dive", {})
    for directory, hits in deep_dive.get("findings", {}).items():
        for f in hits:
            findings.append(
                {
                    "severity": "critical",
                    "area": "Directory Deep-Dive",
                    "finding": f"Guessable backup file is directly reachable: {f['url']}",
                    "detail": f"HTTP 200, content-type {f.get('content_type')}. The directory blocks browsing but "
                    "this specific filename is served anyway - treat as an active data exposure, not a theoretical "
                    "one.",
                }
            )

    methods = vs.get("http_methods", {})
    for check in methods.get("checked", []):
        non_trace_dangerous = [m for m in check.get("dangerous_methods", []) if m != "TRACE"]
        if non_trace_dangerous:
            findings.append(
                {
                    "severity": "high",
                    "area": "HTTP Methods",
                    "finding": f"{check['target']} advertises {', '.join(non_trace_dangerous)}",
                    "detail": "These methods, if actually honored by the server, could allow uploading or deleting "
                    "content. Confirm whether they're truly enabled (vs just advertised) and disable if unused.",
                }
            )

        if "TRACE" in check.get("dangerous_methods", []):
            trace_echo = check.get("trace_echo") or {}
            if trace_echo.get("echoed_marker"):
                findings.append(
                    {
                        "severity": "high",
                        "area": "HTTP Methods",
                        "finding": f"TRACE on {check['target']} echoes requests back - Cross-Site Tracing "
                        "precondition confirmed",
                        "detail": "Confirmed (not just advertised): this server reflects the raw request - "
                        "including any cookies attached to it - back in the TRACE response body. Combined with an "
                        "XSS bug anywhere on this origin (this tool doesn't search for XSS - that's separate "
                        "testing), this lets an attacker's injected script read cookies that HttpOnly would "
                        "normally hide from JavaScript, including session cookies. Disable TRACE at the server "
                        "level regardless of whether an XSS bug is currently known - there's no legitimate reason "
                        "to leave it enabled in production.",
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "medium",
                        "area": "HTTP Methods",
                        "finding": f"{check['target']} advertises TRACE (echo behavior not confirmed)",
                        "detail": "TRACE is listed in the server's Allow header, but a probe request's marker "
                        "wasn't reflected back, so the classic Cross-Site Tracing precondition isn't confirmed "
                        "here (a proxy may be stripping the echo, or the handler may not reflect the body the way "
                        "older TRACE implementations do). Still worth disabling as defense in depth.",
                    }
                )

        if check.get("webdav_enabled"):
            findings.append(
                {
                    "severity": "high",
                    "area": "HTTP Methods",
                    "finding": f"WebDAV PROPFIND succeeds on {check['target']}",
                    "detail": "This can return a directory listing via WebDAV even where normal GET-based browsing "
                    "is blocked - the same content, reachable through a different door.",
                }
            )

    shortname = vs.get("iis_shortname", {})
    if shortname.get("signature_observed"):
        findings.append(
            {
                "severity": "medium",
                "area": "IIS Configuration",
                "finding": "Server shows the IIS short-filename (8.3/tilde) disclosure signature",
                "detail": "Needs manual confirmation with a dedicated tool, but this class of issue can leak "
                "partial real filenames - including inside directories that block normal browsing - without any "
                "wordlist. Mitigate by disabling 8.3 name generation on the IIS server (fsutil behavior set "
                "disable8dot3 1) and rebuilding the NTFS volume's short names.",
            }
        )

    cve = vs.get("cve_lookup", {})
    for product_version, query_result in cve.get("results", {}).items():
        if query_result.get("error"):
            findings.append(
                {
                    "severity": "info",
                    "area": "Known CVEs",
                    "finding": f"CVE lookup for {product_version} failed: {query_result['error']}",
                    "detail": "Couldn't reach or parse the NVD API for this query - not a finding about the "
                    "software itself, just a lookup failure. Safe to retry later.",
                }
            )
            continue
        for match in query_result.get("matches", []):
            score = match.get("cvss_score")
            if score is not None and score >= 9:
                severity = "critical"
            elif score is not None and score >= 7:
                severity = "high"
            elif score is not None and score >= 4:
                severity = "medium"
            else:
                severity = "low"
            findings.append(
                {
                    "severity": severity,
                    "area": "Known CVEs",
                    "finding": f"{match.get('id')} may affect {product_version}"
                    + (f" (CVSS {score})" if score is not None else ""),
                    "detail": f"{match.get('description', '')} Keyword match against NVD, not a confirmed "
                    f"CPE-range match - verify applicability at {match.get('url')} before acting. Version was "
                    f"read from what the site discloses (headers/HTML), which can be stale or wrong.",
                }
            )

    recon = data.get("recon", {})
    dns = recon.get("dns", {})
    if dns and not dns.get("_spf_present"):
        findings.append(
            {
                "severity": "medium",
                "area": "Email/DNS",
                "finding": "No SPF record found",
                "detail": "Without SPF, attackers can more easily spoof email from your domain.",
            }
        )
    if dns and not dns.get("DMARC"):
        findings.append(
            {
                "severity": "medium",
                "area": "Email/DNS",
                "finding": "No DMARC record found",
                "detail": "DMARC tells receiving mail servers what to do with spoofed mail from your domain.",
            }
        )
    elif dns:
        # A DMARC record existing doesn't mean much by itself - p=none is
        # monitor-only and won't stop a single spoofed email.
        policy = dns.get("_dmarc_policy")
        if policy == "none":
            findings.append(
                {
                    "severity": "medium",
                    "area": "Email/DNS",
                    "finding": "DMARC policy is p=none (monitor-only)",
                    "detail": "Spoofed email from your domain won't be quarantined or rejected under this policy - "
                    "it's collecting visibility (if rua= is set) but not enforcing anything. Move to p=quarantine, "
                    "then p=reject, once you've confirmed all your legitimate senders are covered.",
                }
            )
        elif policy == "quarantine":
            findings.append(
                {
                    "severity": "low",
                    "area": "Email/DNS",
                    "finding": "DMARC policy is p=quarantine",
                    "detail": "Reasonable middle ground. Consider moving to p=reject for full enforcement once "
                    "you're confident all legitimate senders are covered.",
                }
            )
        elif policy is None:
            findings.append(
                {
                    "severity": "info",
                    "area": "Email/DNS",
                    "finding": "DMARC record present but no p= policy could be parsed",
                    "detail": "Double check the record's syntax - a malformed record may be ignored by mail "
                    "providers.",
                }
            )

        if not dns.get("_dmarc_has_rua"):
            findings.append(
                {
                    "severity": "info",
                    "area": "Email/DNS",
                    "finding": "DMARC record has no aggregate reporting address (rua=)",
                    "detail": "Without rua=, you get no visibility into spoofing attempts or your own senders' "
                    "delivery/alignment issues.",
                }
            )

    subs = recon.get("subdomains", {})
    if subs.get("count", 0) > 0:
        findings.append(
            {
                "severity": "info",
                "area": "Attack Surface",
                "finding": f"{subs['count']} subdomains discovered via certificate transparency",
                "detail": "Review each for stale/forgotten deployments (a common outsider entry point).",
            }
        )

    severity_order = {"notice": -1, "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))
    return findings


def generate_reports(data: dict[str, Any], output_dir: str, domain: str) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    json_path = out / f"{domain}_{timestamp}.json"
    with json_path.open("w") as f:
        json.dump(data, f, indent=2, default=str)

    findings = _build_findings_summary(data)
    html_path = out / f"{domain}_{timestamp}.html"
    html_path.write_text(_render_html(domain, timestamp, data, findings))

    return {"json": str(json_path), "html": str(html_path), "findings_count": len(findings)}


SEVERITY_COLORS = {
    "notice": "#7c3aed",
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#1d4ed8",
    "info": "#4b5563",
}
SEVERITY_ORDER_LIST = ["notice", "critical", "high", "medium", "low", "info"]


def _deep_dive_summary_html(data: dict[str, Any]) -> str:
    dd = data.get("directory_deep_dive")
    if not dd or not dd.get("directories_checked"):
        return ""
    total_hits = sum(len(v) for v in dd.get("findings", {}).values())
    dirs = ", ".join(f"<code>{html.escape(d)}</code>" for d in dd["directories_checked"])
    return (
        f"<p style='margin-top:0.75rem'>Directory deep-dive: checked {dd.get('candidates_per_directory', '?')} "
        f"guessable backup filenames in each of {dirs} &rarr; <strong>{total_hits}</strong> directly reachable.</p>"
    )


def _render_html(domain: str, timestamp: str, data: dict[str, Any], findings: list[dict[str, str]]) -> str:
    rows = "\n".join(
        f"""<tr>
            <td><span class="badge" style="background:{SEVERITY_COLORS.get(f['severity'], '#4b5563')}">{html.escape(f['severity'].upper())}</span></td>
            <td>{html.escape(f['area'])}</td>
            <td>{html.escape(f['finding'])}</td>
            <td>{html.escape(f['detail'])}</td>
        </tr>"""
        for f in findings
    )

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    count_badges = " ".join(
        f'<span class="badge" style="background:{SEVERITY_COLORS.get(sev, "#4b5563")}">{sev}: {n}</span>'
        for sev, n in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER_LIST.index(kv[0]))
    )

    disc = data.get("discovery", {})
    recon = data.get("recon", {})
    subs = recon.get("subdomains", {}).get("subdomains", [])
    subs_html = "".join(f"<li>{html.escape(s)}</li>" for s in subs[:100]) or "<li><em>none found</em></li>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>External Exposure Report - {html.escape(domain)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem; background: #f8fafc; color: #0f172a; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #64748b; margin-bottom: 1.5rem; }}
  .card {{ background: white; border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  th {{ color: #475569; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; }}
  .badge {{ display: inline-block; color: white; padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }}
  .summary-bar {{ margin: 0.75rem 0 0; }}
  code {{ background: #f1f5f9; padding: 0.1rem 0.35rem; border-radius: 4px; }}
  .disclaimer {{ font-size: 0.85rem; color: #64748b; border-left: 3px solid #cbd5e1; padding-left: 0.75rem; }}
</style>
</head>
<body>
  <h1>External Exposure Report</h1>
  <div class="meta">Target: <code>{html.escape(domain)}</code> &middot; Generated: {html.escape(timestamp)} UTC</div>

  <div class="card">
    <p class="disclaimer">This report reflects what a passive/light-touch outside observer could see about
    this domain at the time of the scan. It is not exhaustive and is not a substitute for a professional
    penetration test. Run only against domains you own or are authorized to test.</p>
  </div>

  <div class="card">
    <h2>Findings Summary ({len(findings)})</h2>
    <div class="summary-bar">{count_badges or '<em>No findings</em>'}</div>
    <table>
      <thead><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Detail</th></tr></thead>
      <tbody>{rows or '<tr><td colspan="4"><em>No findings</em></td></tr>'}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Subdomains Discovered ({len(subs)})</h2>
    <ul>{subs_html}</ul>
  </div>

  <div class="card">
    <h2>Content Discovery</h2>
    <p>{disc.get('findings_count', 0)} interesting paths found out of {disc.get('total_paths_tested', 0)} tested
    in {disc.get('elapsed_seconds', '?')}s.</p>
    {_deep_dive_summary_html(data)}
  </div>

  <div class="card">
    <h2>Raw Data</h2>
    <p>Full machine-readable results are in the accompanying JSON file.</p>
  </div>
</body>
</html>
"""
