"""
TLS/certificate check: connects on port 443, inspects the certificate
chain's validity window and the negotiated protocol version. This is what
any browser (or outsider) sees on connection - no vulnerability probing.
"""
from __future__ import annotations

import ssl
import socket
import datetime
from typing import Any


def check_tls(hostname: str, port: int = 443) -> dict[str, Any]:
    result: dict[str, Any] = {"error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None

                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.utcnow()).days
                    result["expires"] = expiry.isoformat()
                    result["days_until_expiry"] = days_left
                    result["expiry_warning"] = days_left < 30

                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")

                subject_alt_names = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                result["subject_alt_names"] = subject_alt_names

                # Flag old/weak protocol versions.
                result["weak_protocol"] = ssock.version() in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)

    return result
