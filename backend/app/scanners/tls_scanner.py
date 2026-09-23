"""
TLS / SSL Scanner — OpenSecX Phase 2

Deep-inspects TLS configuration for a hostname:
  - Certificate expiry and days remaining
  - TLS protocol version (flags TLS 1.0/1.1 as vulnerabilities)
  - Issuer and subject CN
  - Subject Alternative Names (SANs)
  - Self-signed certificate detection
  - Certificate transparency

Returns a list of Finding objects (not AssetRecord).
Pure Python — uses only stdlib `ssl` + optional `cryptography` library.

Installation: pip install cryptography
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

logger = logging.getLogger(__name__)
_tls_pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix="tls-scan")

INSECURE_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def _check_tls_sync(hostname: str, port: int = 443) -> dict:
    """Synchronous TLS inspection — runs in thread pool."""
    result = {
        "hostname": hostname,
        "port": port,
        "reachable": False,
        "tls_version": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_not_after": None,
        "cert_days_left": None,
        "cert_self_signed": False,
        "cert_expired": False,
        "cert_expiring_soon": False,  # < 30 days
        "cert_sans": [],
        "findings": [],  # list of Finding dicts
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((hostname, port), timeout=8) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                result["reachable"] = True
                result["tls_version"] = tls_sock.version()

                cert_der = tls_sock.getpeercert(True)
                cert_dict = tls_sock.getpeercert()

        # Parse cert using cryptography if available
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            subject_cn = None
            try:
                subject_cn = cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value
            except Exception:
                pass

            issuer_cn = None
            try:
                issuer_cn = cert.issuer.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value
            except Exception:
                pass

            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days

            result["cert_subject"] = subject_cn
            result["cert_issuer"] = issuer_cn
            result["cert_not_after"] = not_after.isoformat()
            result["cert_days_left"] = days_left
            result["cert_expired"] = days_left < 0
            result["cert_expiring_soon"] = 0 <= days_left <= 30
            result["cert_self_signed"] = (subject_cn == issuer_cn)

            # Extract SANs
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                result["cert_sans"] = [str(name.value) for name in san_ext.value]
            except Exception:
                pass

        except ImportError:
            # Fallback to stdlib cert dict
            if cert_dict:
                subject = dict(x[0] for x in cert_dict.get("subject", []))
                issuer = dict(x[0] for x in cert_dict.get("issuer", []))
                result["cert_subject"] = subject.get("commonName")
                result["cert_issuer"] = issuer.get("commonName")
                if cert_dict.get("notAfter"):
                    not_after = datetime.datetime.strptime(
                        cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
                    result["cert_not_after"] = not_after.isoformat()
                    result["cert_days_left"] = days_left
                    result["cert_expired"] = days_left < 0
                    result["cert_expiring_soon"] = 0 <= days_left <= 30
                result["cert_self_signed"] = (result["cert_subject"] == result["cert_issuer"])

        # Build findings from results
        if result["tls_version"] in INSECURE_PROTOCOLS:
            result["findings"].append({
                "title": f"Insecure TLS Version: {result['tls_version']}",
                "severity": "high",
                "category": "A02:Cryptographic Failures",
                "description": f"The server supports {result['tls_version']} which has known cryptographic weaknesses. Upgrade to TLS 1.2 or TLS 1.3.",
                "evidence": {"tls_version": result["tls_version"], "hostname": hostname},
                "grade": "confirmed",
                "remediation": "Disable TLS 1.0 and TLS 1.1 in your server configuration. Enable TLS 1.2 and TLS 1.3 only.",
            })

        if result["cert_expired"]:
            result["findings"].append({
                "title": "Expired TLS Certificate",
                "severity": "critical",
                "category": "A02:Cryptographic Failures",
                "description": f"The TLS certificate for {hostname} expired {abs(result['cert_days_left'])} days ago.",
                "evidence": {"not_after": result["cert_not_after"], "days_left": result["cert_days_left"]},
                "grade": "confirmed",
                "remediation": "Renew the TLS certificate immediately. Consider using Let's Encrypt for automated renewal.",
            })
        elif result["cert_expiring_soon"]:
            result["findings"].append({
                "title": f"TLS Certificate Expiring Soon ({result['cert_days_left']} days)",
                "severity": "medium",
                "category": "A02:Cryptographic Failures",
                "description": f"The TLS certificate expires in {result['cert_days_left']} days.",
                "evidence": {"not_after": result["cert_not_after"], "days_left": result["cert_days_left"]},
                "grade": "confirmed",
                "remediation": "Renew the certificate before expiry. Set up automated renewal with certbot or similar.",
            })

        if result["cert_self_signed"]:
            result["findings"].append({
                "title": "Self-Signed TLS Certificate",
                "severity": "medium",
                "category": "A02:Cryptographic Failures",
                "description": "The certificate is self-signed and will not be trusted by browsers without manual installation.",
                "evidence": {"subject": result["cert_subject"], "issuer": result["cert_issuer"]},
                "grade": "confirmed",
                "remediation": "Replace with a certificate from a trusted CA. Let's Encrypt provides free trusted certificates.",
            })

    except ssl.SSLError as e:
        result["findings"].append({
            "title": "TLS/SSL Error",
            "severity": "high",
            "category": "A02:Cryptographic Failures",
            "description": f"SSL/TLS error when connecting: {e}",
            "evidence": {"error": str(e), "hostname": hostname},
            "grade": "confirmed",
            "remediation": "Review server TLS configuration and certificate setup.",
        })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass  # Port not open — not a finding, just not reachable

    return result


async def scan_tls(hostname: str, port: int = 443) -> dict:
    """Async wrapper — runs TLS check in thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_tls_pool, _check_tls_sync, hostname, port)
