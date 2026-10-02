"""
DNS reconnaissance: pulls the record types an outside attacker would query
for free, with zero interaction with the target host itself (all queries
go to public DNS resolvers, not to the target's web server).
"""
from __future__ import annotations

import re
import dns.resolver
from typing import Any


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]


def get_dns_records(domain: str) -> dict[str, Any]:
    """Query common DNS record types for a domain. Returns a dict keyed by
    record type; missing/failed lookups are recorded as empty lists rather
    than raising, so one bad record type doesn't abort the whole scan."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    results: dict[str, Any] = {}
    for rtype in RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, rtype)
            results[rtype] = sorted(str(r).strip('"') for r in answer)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except Exception as exc:  # noqa: BLE001 - log and continue
            results[rtype] = [f"lookup_error: {exc}"]

    # Flag anything in TXT records that looks like an SPF/DMARC policy gap,
    # since these are a common outsider-visible weakness (email spoofing).
    txt_records = results.get("TXT", [])
    has_spf = any(t.lower().startswith("v=spf1") for t in txt_records)
    results["_spf_present"] = has_spf

    try:
        dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
        results["DMARC"] = sorted(str(r).strip('"') for r in dmarc)
    except Exception:
        results["DMARC"] = []

    # A DMARC record existing doesn't mean much on its own - the policy
    # (p=) is what actually determines whether spoofed mail gets rejected,
    # quarantined, or just monitored (or nothing, if there's no policy at
    # all in the record). Parse it out so the report can flag a weak
    # policy instead of just "DMARC: present".
    dmarc_policy = None
    dmarc_has_rua = False
    for rec in results["DMARC"]:
        if not rec.lower().startswith("v=dmarc1"):
            continue
        m = re.search(r"p\s*=\s*(\w+)", rec, re.IGNORECASE)
        if m:
            dmarc_policy = m.group(1).lower()
        dmarc_has_rua = bool(re.search(r"rua\s*=", rec, re.IGNORECASE))
        break
    results["_dmarc_policy"] = dmarc_policy
    results["_dmarc_has_rua"] = dmarc_has_rua

    return results
