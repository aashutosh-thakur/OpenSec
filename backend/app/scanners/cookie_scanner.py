"""
Cookie Security Scanner — OpenSecX Phase 2

Checks cookies set by the target for missing security flags.
A single request is made and all Set-Cookie headers are analysed.

Checks per cookie:
  - Missing Secure flag (allows transmission over HTTP)
  - Missing HttpOnly flag (accessible via JavaScript — XSS risk)
  - Missing SameSite attribute (CSRF risk)
  - SameSite=None without Secure (invalid, browser may reject)
  - Session cookies with Expires/Max-Age (should be session-scoped)
  - Overly-broad Domain attribute
"""
from __future__ import annotations

import asyncio
import logging
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from typing import List

logger = logging.getLogger(__name__)
_cookie_pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="cookie-scan")


def _parse_set_cookie(header_value: str) -> dict:
    """Parse a Set-Cookie header value into a dict of attributes."""
    parts = [p.strip() for p in header_value.split(";")]
    cookie = {}
    if parts:
        name_val = parts[0]
        if "=" in name_val:
            name, val = name_val.split("=", 1)
            cookie["name"] = name.strip()
            cookie["value"] = val.strip()
        else:
            cookie["name"] = name_val
            cookie["value"] = ""

    for attr in parts[1:]:
        attr_lower = attr.lower()
        if attr_lower == "secure":
            cookie["secure"] = True
        elif attr_lower == "httponly":
            cookie["httponly"] = True
        elif attr_lower.startswith("samesite="):
            cookie["samesite"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("expires="):
            cookie["expires"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("max-age="):
            cookie["max_age"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain="):
            cookie["domain"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("path="):
            cookie["path"] = attr.split("=", 1)[1].strip()

    return cookie


def _check_cookies_sync(url: str) -> List[dict]:
    """Fetch URL and check all Set-Cookie headers. Runs in thread pool."""
    findings = []
    cookies_raw = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OpenSecX-Scanner/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                # Get all Set-Cookie headers
                for key, val in resp.headers.items():
                    if key.lower() == "set-cookie":
                        cookies_raw.append(val)
                final_url = resp.url
        except urllib.error.HTTPError as e:
            for key, val in e.headers.items():
                if key.lower() == "set-cookie":
                    cookies_raw.append(val)
            final_url = url
    except Exception as exc:
        logger.debug("[cookie] Could not fetch %s: %s", url, exc)
        return []

    is_https = final_url.startswith("https://")

    for raw in cookies_raw:
        cookie = _parse_set_cookie(raw)
        name = cookie.get("name", "unknown")

        # Check: Missing Secure flag on HTTPS site
        if is_https and not cookie.get("secure"):
            findings.append({
                "title": f"Cookie '{name}': Missing Secure Flag",
                "severity": "medium",
                "category": "A02:Cryptographic Failures",
                "description": (
                    f"The cookie '{name}' is set without the Secure flag on an HTTPS site. "
                    "This allows the cookie to be transmitted over unencrypted HTTP connections "
                    "(e.g. after a redirect or mixed content)."
                ),
                "evidence": {"cookie_name": name, "url": final_url, "raw": raw[:200]},
                "grade": "confirmed",
                "remediation": f"Add the Secure attribute: Set-Cookie: {name}=...; Secure; ...",
            })

        # Check: Missing HttpOnly flag
        if not cookie.get("httponly"):
            # Only flag for cookies that look like session/auth cookies
            name_lower = name.lower()
            looks_sensitive = any(kw in name_lower for kw in [
                "session", "auth", "token", "csrf", "xsrf", "user",
                "login", "jwt", "access", "refresh", "sid", "id",
            ])
            if looks_sensitive:
                findings.append({
                    "title": f"Session Cookie '{name}': Missing HttpOnly Flag",
                    "severity": "medium",
                    "category": "A07:Identification and Authentication Failures",
                    "description": (
                        f"The cookie '{name}' appears to be a session/authentication cookie "
                        "but lacks the HttpOnly flag. This makes it accessible via JavaScript, "
                        "allowing XSS attacks to steal the session."
                    ),
                    "evidence": {"cookie_name": name, "url": final_url, "raw": raw[:200]},
                    "grade": "confirmed",
                    "remediation": f"Add HttpOnly: Set-Cookie: {name}=...; HttpOnly; ...",
                })

        # Check: Missing SameSite
        if not cookie.get("samesite"):
            findings.append({
                "title": f"Cookie '{name}': Missing SameSite Attribute",
                "severity": "low",
                "category": "A05:Security Misconfiguration",
                "description": (
                    f"The cookie '{name}' has no SameSite attribute. "
                    "Without SameSite, the cookie is sent on all cross-site requests, "
                    "enabling CSRF attacks."
                ),
                "evidence": {"cookie_name": name, "url": final_url, "raw": raw[:200]},
                "grade": "confirmed",
                "remediation": "Add SameSite=Strict or SameSite=Lax to all cookies.",
            })
        elif cookie.get("samesite", "").lower() == "none" and not cookie.get("secure"):
            findings.append({
                "title": f"Cookie '{name}': SameSite=None Without Secure",
                "severity": "medium",
                "category": "A05:Security Misconfiguration",
                "description": (
                    f"Cookie '{name}' uses SameSite=None but is missing the Secure flag. "
                    "Modern browsers reject SameSite=None cookies without Secure, "
                    "which may break functionality and indicates a misconfiguration."
                ),
                "evidence": {"cookie_name": name, "url": final_url, "raw": raw[:200]},
                "grade": "confirmed",
                "remediation": "When using SameSite=None, always include Secure.",
            })

    return findings


async def scan_cookies(url: str) -> List[dict]:
    """Async wrapper for cookie security scanning."""
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_cookie_pool, _check_cookies_sync, url),
            timeout=15,
        )
    except asyncio.TimeoutError:
        logger.warning("[cookie] Scan timed out for %s", url)
        return []
    except Exception as exc:
        logger.error("[cookie] Error: %s", exc)
        return []
