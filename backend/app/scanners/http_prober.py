"""
Pure-Python HTTP Prober — OpenSecX Phase 1

Probes a list of hostnames for live HTTP/HTTPS services using the `httpx`
Python library. This replaces the ProjectDiscovery `httpx` binary for
environments where Go tools are not available.

Discovers:
- HTTP/HTTPS status codes
- Page titles
- Server headers
- Content-Type and security headers
- Redirect chains

Installation: pip install httpx
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple

from app.scanners.base import (
    AdapterStatus,
    AssetRecord,
    BaseScannerAdapter,
    ScannerResult,
)

logger = logging.getLogger(__name__)

# Concurrency limit — don't hammer all hosts at once
CONCURRENT_PROBES = 10


class HttpProber(BaseScannerAdapter):
    """
    HTTP/HTTPS prober using the httpx Python library.
    No binary required. Probes each hostname on port 80 and 443.
    """

    @property
    def name(self) -> str:
        return "http_prober"

    @property
    def binary(self) -> None:
        return None  # Python library

    def is_available(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    async def run(self, target: str, timeout: int = 60) -> ScannerResult:
        """Probe a single target."""
        return await self.probe_list([target], timeout=timeout)

    async def probe_list(self, hostnames: List[str], timeout: int = 60) -> ScannerResult:
        """
        Probe a list of hostnames for live HTTP/HTTPS services.
        Used by the DiscoveryOrchestrator.
        """
        if not self.is_available():
            return ScannerResult(
                status=AdapterStatus.UNAVAILABLE,
                error="httpx Python library not installed. Run: pip install httpx",
            )

        if not hostnames:
            return ScannerResult(status=AdapterStatus.OK, assets=[])

        logger.info("[http_prober] Probing %d hostnames", len(hostnames))

        # Use semaphore to limit concurrency
        semaphore = asyncio.Semaphore(CONCURRENT_PROBES)
        tasks = [self._probe_host(host, semaphore, timeout) for host in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        assets: List[AssetRecord] = []
        live_count = 0

        for result in results:
            if isinstance(result, Exception):
                continue
            if result is not None:
                assets.append(result)
                live_count += 1

        logger.info("[http_prober] Found %d live services from %d probed", live_count, len(hostnames))
        return ScannerResult(
            status=AdapterStatus.OK,
            assets=assets,
        )

    async def _probe_host(
        self,
        hostname: str,
        semaphore: asyncio.Semaphore,
        timeout: int,
    ) -> Optional[AssetRecord]:
        """Probe a single hostname on HTTPS first, then HTTP."""
        async with semaphore:
            for scheme in ("https", "http"):
                result = await self._try_probe(hostname, scheme, timeout)
                if result is not None:
                    return result
        return None

    async def _try_probe(
        self,
        hostname: str,
        scheme: str,
        timeout: int,
    ) -> Optional[AssetRecord]:
        """Try to probe hostname with a specific scheme."""
        try:
            import httpx

            url = f"{scheme}://{hostname}"
            port = 443 if scheme == "https" else 80

            # Use sync client in thread pool to avoid anyio/asyncio backend issues on Windows
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None, self._sync_probe, url, scheme, hostname, port
            )
            return result
        except Exception as exc:
            logger.debug("[http_prober] %s://%s failed: %s", scheme, hostname, exc)
            return None

    @staticmethod
    def _sync_probe(url: str, scheme: str, hostname: str, port: int) -> Optional[AssetRecord]:
        """Synchronous HTTP probe — safe to run in thread pool."""
        try:
            import httpx
            with httpx.Client(
                verify=False,
                timeout=httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0),
                follow_redirects=True,
            ) as client:
                resp = client.get(url, headers={
                    "User-Agent": "Mozilla/5.0 (compatible; OpenSecX-Scanner/1.0)"
                })

            title = HttpProber._extract_title(resp.text)
            technologies = HttpProber._detect_technologies(dict(resp.headers), resp.text)
            server = resp.headers.get("server", "")

            notes_parts = []
            if title:
                notes_parts.append(f"Title: {title[:100]}")
            if server:
                notes_parts.append(f"Server: {server}")

            status = (
                "Active" if resp.status_code < 400
                else "Warning" if resp.status_code < 500
                else "Critical"
            )

            return AssetRecord(
                domain=hostname,
                hostname=hostname,
                protocol=scheme,
                service=f"{scheme.upper()} {resp.status_code}",
                ports=[port],
                technologies=technologies if technologies else None,
                source="http_prober",
                status=status,
                notes=" | ".join(notes_parts) if notes_parts else None,
            )
        except Exception:
            return None

    @staticmethod
    def _extract_title(html: str) -> Optional[str]:
        """Extract <title> from HTML content."""
        if not html:
            return None
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:150]
        return None

    @staticmethod
    def _detect_technologies(headers: Dict, body: str) -> List[str]:
        """Detect technologies from HTTP response headers and body."""
        techs = []

        server = headers.get("server", "").lower()
        x_powered = headers.get("x-powered-by", "").lower()
        via = headers.get("via", "").lower()

        # Server header
        if "nginx" in server:
            techs.append("Nginx")
        if "apache" in server:
            techs.append("Apache")
        if "iis" in server or "microsoft" in server:
            techs.append("IIS")
        if "cloudflare" in server:
            techs.append("Cloudflare")
        if "lighttpd" in server:
            techs.append("Lighttpd")
        if "caddy" in server:
            techs.append("Caddy")

        # X-Powered-By
        if "php" in x_powered:
            techs.append("PHP")
        if "asp.net" in x_powered:
            techs.append("ASP.NET")
        if "express" in x_powered:
            techs.append("Express.js")

        # Security headers
        if "strict-transport-security" in headers:
            techs.append("HSTS")
        if "content-security-policy" in headers:
            techs.append("CSP")

        # Body detection
        if isinstance(body, str):
            body_lower = body.lower()
            if "wp-content" in body_lower or "wordpress" in body_lower:
                techs.append("WordPress")
            if "joomla" in body_lower:
                techs.append("Joomla")
            if "drupal" in body_lower:
                techs.append("Drupal")
            if "react" in body_lower:
                techs.append("React")
            if "angular" in body_lower:
                techs.append("Angular")
            if "vue" in body_lower:
                techs.append("Vue.js")
            if "jquery" in body_lower:
                techs.append("jQuery")
            if "bootstrap" in body_lower:
                techs.append("Bootstrap")

        return list(dict.fromkeys(techs))  # Deduplicate preserving order
