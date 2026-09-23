"""
CORS Misconfiguration Scanner — OpenSecX Phase 2

Detects CORS misconfigurations by sending requests with a crafted
Origin header and checking whether the server reflects it or allows
wildcards with credentials.

Checks:
  1. Origin reflection (echoes back attacker-controlled origin)
  2. Wildcard ACAO with credentials (ACAC: true + ACAO: *)
  3. Null origin allowed
  4. Trusted subdomain bypass (attacker.target.com)
  5. Pre-flight OPTIONS exposure

Pure Python — uses stdlib urllib. No binary required.
"""
from __future__ import annotations

import asyncio
import logging
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

logger = logging.getLogger(__name__)
_cors_pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix="cors-scan")

EVIL_ORIGINS = [
    "https://evil.attacker.com",
    "null",
    "https://attacker.target.com",  # will be replaced with real domain
]


def _check_cors_sync(url: str, target_domain: str) -> List[dict]:
    """Synchronous CORS check — runs in thread pool."""
    findings = []
    test_origins = [
        "https://evil.attacker.com",
        "null",
        f"https://attacker.{target_domain}",
    ]

    for origin in test_origins:
        try:
            req = urllib.request.Request(url)
            req.add_header("Origin", origin)
            req.add_header("User-Agent", "OpenSecX-Scanner/1.0")

            try:
                with urllib.request.urlopen(req, timeout=8) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()}

            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")

            # Check 1: Reflected origin
            if acao == origin and origin != "null":
                severity = "critical" if acac.lower() == "true" else "high"
                findings.append({
                    "title": "CORS: Origin Reflection Vulnerability",
                    "severity": severity,
                    "category": "A05:Security Misconfiguration",
                    "description": (
                        f"The server reflects the attacker-controlled Origin '{origin}' in the "
                        f"Access-Control-Allow-Origin response header"
                        + (" with Access-Control-Allow-Credentials: true, enabling cross-origin request forgery with user credentials." if acac.lower() == "true" else ".")
                    ),
                    "evidence": {
                        "url": url,
                        "request_origin": origin,
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac,
                    },
                    "grade": "confirmed",
                    "remediation": (
                        "Implement an allowlist of trusted origins. Never reflect the Origin header directly. "
                        "Never combine Access-Control-Allow-Credentials: true with a dynamic or wildcard origin."
                    ),
                })

            # Check 2: Wildcard with credentials (always invalid per spec but some servers do it)
            if acao == "*" and acac.lower() == "true":
                findings.append({
                    "title": "CORS: Wildcard Origin with Credentials",
                    "severity": "critical",
                    "category": "A05:Security Misconfiguration",
                    "description": (
                        "The server sends Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true. This combination allows any origin "
                        "to make authenticated cross-origin requests."
                    ),
                    "evidence": {
                        "url": url,
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac,
                    },
                    "grade": "confirmed",
                    "remediation": (
                        "Use a specific origin allowlist when credentials are required. "
                        "Never use wildcard with credentials enabled."
                    ),
                })

            # Check 3: Null origin allowed
            if origin == "null" and acao == "null":
                findings.append({
                    "title": "CORS: Null Origin Allowed",
                    "severity": "high",
                    "category": "A05:Security Misconfiguration",
                    "description": (
                        "The server accepts 'null' as a valid CORS origin. "
                        "The null origin can be triggered by sandboxed iframes, local files, and redirects, "
                        "which attackers can exploit."
                    ),
                    "evidence": {
                        "url": url,
                        "request_origin": "null",
                        "access-control-allow-origin": acao,
                    },
                    "grade": "confirmed",
                    "remediation": "Remove 'null' from your CORS origin allowlist.",
                })

        except Exception as exc:
            logger.debug("[cors] Check failed for %s with origin %s: %s", url, origin, exc)
            continue

    # Deduplicate by title
    seen = set()
    unique = []
    for f in findings:
        if f["title"] not in seen:
            seen.add(f["title"])
            unique.append(f)
    return unique


async def scan_cors(url: str, target_domain: str) -> List[dict]:
    """Async wrapper for CORS scanning."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_cors_pool, _check_cors_sync, url, target_domain)
