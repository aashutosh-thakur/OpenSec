"""
Security Headers Scanner — OpenSecX Phase 2

Checks HTTP responses for the presence and correct configuration of
7 critical security headers as recommended by OWASP and Mozilla.

Checks:
  1. Strict-Transport-Security (HSTS)
  2. Content-Security-Policy (CSP)
  3. X-Frame-Options
  4. X-Content-Type-Options
  5. Referrer-Policy
  6. Permissions-Policy
  7. Cross-Origin-Opener-Policy (COOP)

Additionally checks:
  - Server header information disclosure
  - X-Powered-By header information disclosure

Pure Python — uses stdlib urllib. No external binary.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# Header definitions: name → (severity_if_missing, owasp_category, description, remediation)
SECURITY_HEADERS: Dict[str, Dict] = {
    "strict-transport-security": {
        "severity": "high",
        "category": "A02:Cryptographic Failures",
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "description": "The Strict-Transport-Security header is missing. Without HSTS, browsers may connect over HTTP, enabling downgrade attacks and cleartext interception.",
        "remediation": 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        "good_value_check": lambda v: "max-age" in v.lower(),
    },
    "content-security-policy": {
        "severity": "high",
        "category": "A03:Injection",
        "title": "Missing Content-Security-Policy (CSP) Header",
        "description": "No Content-Security-Policy header found. CSP prevents XSS and other injection attacks by controlling which resources can be loaded.",
        "remediation": "Add a CSP header. Start with Content-Security-Policy: default-src 'self' and gradually expand.",
        "good_value_check": lambda v: "default-src" in v or "script-src" in v,
    },
    "x-frame-options": {
        "severity": "medium",
        "category": "A05:Security Misconfiguration",
        "title": "Missing X-Frame-Options Header",
        "description": "The X-Frame-Options header is missing. The page may be embeddable in iframes, enabling clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed)",
        "good_value_check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
    },
    "x-content-type-options": {
        "severity": "low",
        "category": "A05:Security Misconfiguration",
        "title": "Missing X-Content-Type-Options Header",
        "description": "Without this header, browsers may MIME-sniff responses and execute unexpected content types.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "good_value_check": lambda v: "nosniff" in v.lower(),
    },
    "referrer-policy": {
        "severity": "low",
        "category": "A05:Security Misconfiguration",
        "title": "Missing Referrer-Policy Header",
        "description": "Without a Referrer-Policy, browsers may send the full URL in the Referer header to third parties, leaking sensitive path information.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "good_value_check": lambda v: len(v) > 0,
    },
    "permissions-policy": {
        "severity": "low",
        "category": "A05:Security Misconfiguration",
        "title": "Missing Permissions-Policy Header",
        "description": "No Permissions-Policy (formerly Feature-Policy) header. This header controls access to browser APIs like camera, microphone, geolocation.",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "good_value_check": lambda v: len(v) > 0,
    },
    "cross-origin-opener-policy": {
        "severity": "medium",
        "category": "A05:Security Misconfiguration",
        "title": "Missing Cross-Origin-Opener-Policy (COOP) Header",
        "description": "Without COOP, the page may be susceptible to cross-origin attacks via window.opener references.",
        "remediation": "Add: Cross-Origin-Opener-Policy: same-origin",
        "good_value_check": lambda v: "same-origin" in v.lower(),
    },
}

# Headers that SHOULD NOT be present (information disclosure)
LEAKY_HEADERS = {
    "server": "Server header reveals web server software version, aiding fingerprinting.",
    "x-powered-by": "X-Powered-By header reveals backend technology (e.g. PHP version), aiding targeted attacks.",
    "x-aspnet-version": "X-AspNet-Version discloses the ASP.NET version in use.",
    "x-aspnetmvc-version": "X-AspNetMvc-Version discloses the ASP.NET MVC version.",
}


def check_security_headers(headers: Dict[str, str], url: str) -> List[dict]:
    """
    Check response headers for security issues.

    Args:
        headers: Response headers dict (lowercase keys)
        url: The URL that was checked (for evidence)

    Returns:
        List of finding dicts
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check for missing or misconfigured security headers
    for header_name, config in SECURITY_HEADERS.items():
        value = headers_lower.get(header_name)

        if value is None:
            findings.append({
                "title": config["title"],
                "severity": config["severity"],
                "category": config["category"],
                "description": config["description"],
                "evidence": {"header": header_name, "url": url, "present": False},
                "grade": "confirmed",
                "remediation": config["remediation"],
            })
        else:
            # Check if the value is misconfigured
            good_check = config.get("good_value_check")
            if good_check and not good_check(value):
                findings.append({
                    "title": f"Misconfigured {header_name.title()} Header",
                    "severity": "low",
                    "category": config["category"],
                    "description": f"The {header_name} header is present but may be misconfigured: '{value}'",
                    "evidence": {"header": header_name, "value": value, "url": url},
                    "grade": "supported",
                    "remediation": config["remediation"],
                })

    # Check for information-disclosing headers
    for header_name, description in LEAKY_HEADERS.items():
        value = headers_lower.get(header_name)
        if value:
            # Only flag if it reveals version info
            has_version = any(char.isdigit() for char in value)
            if has_version or header_name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
                findings.append({
                    "title": f"Information Disclosure via {header_name.title()} Header",
                    "severity": "low",
                    "category": "A05:Security Misconfiguration",
                    "description": description + f" Detected value: '{value}'",
                    "evidence": {"header": header_name, "value": value, "url": url},
                    "grade": "confirmed",
                    "remediation": f"Remove or obscure the {header_name} response header.",
                })

    return findings
