"""
Wayback Machine Scanner — OpenSecX Phase 1

Discovers subdomains by querying the Wayback Machine CDX API for
historical crawl data. This source often finds subdomains that have
since been decommissioned but may still resolve or expose old config.

API: https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey

No API key required. Free, no rate limit for reasonable use.
"""
from __future__ import annotations

import asyncio
import logging
import re
import urllib.request
import json
from typing import List, Set
from concurrent.futures import ThreadPoolExecutor

from app.scanners.base import (
    AdapterStatus,
    AssetRecord,
    BaseScannerAdapter,
    ScannerResult,
)

logger = logging.getLogger(__name__)
_wayback_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="wayback")


class WaybackScanner(BaseScannerAdapter):
    """
    Queries the Wayback Machine CDX API to discover subdomains from
    historical web crawl data. Finds domains that may have been active
    years ago and are missed by certificate transparency logs.
    """

    @property
    def name(self) -> str:
        return "wayback"

    @property
    def binary(self) -> None:
        return None

    def is_available(self) -> bool:
        return True  # Pure HTTP, always available

    async def run(self, target: str, timeout: int = 30) -> ScannerResult:
        logger.info("[wayback] Querying Wayback Machine CDX API for *.%s", target)
        loop = asyncio.get_running_loop()
        try:
            subdomains = await asyncio.wait_for(
                loop.run_in_executor(_wayback_pool, self._fetch_cdx, target),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return ScannerResult(
                status=AdapterStatus.TIMEOUT,
                error=f"Wayback CDX API timed out after {timeout}s",
            )
        except Exception as exc:
            logger.warning("[wayback] CDX API failed: %s", exc)
            return ScannerResult(status=AdapterStatus.ERROR, error=str(exc))

        assets = [
            AssetRecord(
                domain=sub,
                hostname=sub,
                source="wayback",
                status="Active",
                notes="Discovered via Wayback Machine CDX historical crawl",
            )
            for sub in subdomains
        ]

        logger.info("[wayback] Found %d unique subdomains", len(assets))
        return ScannerResult(status=AdapterStatus.OK, assets=assets)

    @staticmethod
    def _fetch_cdx(target: str) -> Set[str]:
        """Synchronous CDX fetch — runs in thread pool."""
        subdomains: Set[str] = set()
        # Query wildcard subdomains
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{target}&output=json&fl=original&collapse=urlkey&limit=5000"
        )
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "OpenSecX-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
            # data is list of [original_url] rows; first row is header
            domain_pattern = re.compile(
                r"https?://([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\." + re.escape(target) + r")",
                re.IGNORECASE,
            )
            for row in data[1:]:  # skip header row
                if not row:
                    continue
                original = row[0] if isinstance(row, list) else str(row)
                match = domain_pattern.match(original)
                if match:
                    sub = match.group(1).lower().lstrip("www.") if match.group(1).lower().startswith("www.") else match.group(1).lower()
                    subdomains.add(sub)
        except Exception as exc:
            logger.debug("[wayback] CDX fetch error: %s", exc)

        return subdomains
