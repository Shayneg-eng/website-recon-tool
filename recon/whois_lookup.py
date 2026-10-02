"""WHOIS lookup - registrar, creation/expiry dates, and (if not privacy
redacted) registrant contact info. All info here is what any outsider can
pull from a public WHOIS server."""
from __future__ import annotations

from typing import Any

import whois  # python-whois


def get_whois_info(domain: str) -> dict[str, Any]:
    try:
        w = whois.whois(domain)
        # python-whois returns lists for some fields inconsistently; normalize.
        def norm(v):
            if isinstance(v, list):
                return [str(x) for x in v]
            if v is None:
                return None
            return str(v)

        return {
            "registrar": norm(w.get("registrar")),
            "creation_date": norm(w.get("creation_date")),
            "expiration_date": norm(w.get("expiration_date")),
            "updated_date": norm(w.get("updated_date")),
            "name_servers": norm(w.get("name_servers")),
            "status": norm(w.get("status")),
            "emails": norm(w.get("emails")),
            "org": norm(w.get("org")),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
