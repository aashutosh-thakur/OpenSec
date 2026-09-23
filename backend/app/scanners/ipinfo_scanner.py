"""
IPInfo Scanner — OpenSecX Phase 1

Enriches IP addresses with ASN, organization, city, country and
hosting attribution data from ipinfo.io.

Free tier: 50,000 requests/month with no API key.
With API key (IPINFO_TOKEN env var): 150,000 requests/month.

Installation: None required — uses urllib (stdlib)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Set

from app.scanners.base import (
    AdapterStatus,
    AssetRecord,
    BaseScannerAdapter,
    ScannerResult,
)

logger = logging.getLogger(__name__)
_ipinfo_pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix="ipinfo")


class IPInfoScanner(BaseScannerAdapter):
    """
    Enriches resolved IP addresses with ASN, org, city, and country data
    via the ipinfo.io API. Run AFTER DNS resolution to add context to IPs.
    """

    @property
    def name(self) -> str:
        return "ipinfo"

    @property
    def binary(self) -> None:
        return None

    def is_available(self) -> bool:
        return True

    async def run(self, target: str, timeout: int = 30) -> ScannerResult:
        """Enrich a single IP or domain. Used for direct calls."""
        return await self.enrich_ips([target], timeout=timeout)

    async def enrich_ips(
        self, ip_list: List[str], timeout: int = 30
    ) -> ScannerResult:
        """
        Enrich a list of IP addresses with ipinfo data.
        Returns AssetRecord per IP with org, asn, country, city.
        """
        if not ip_list:
            return ScannerResult(status=AdapterStatus.OK, assets=[])

        # Deduplicate and filter — only real IPs, not domains
        import ipaddress
        unique_ips: Set[str] = set()
        for item in ip_list:
            try:
                ipaddress.ip_address(item)
                # Skip private/loopback ranges
                addr = ipaddress.ip_address(item)
                if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                    unique_ips.add(item)
            except ValueError:
                pass  # Not an IP address, skip

        if not unique_ips:
            return ScannerResult(status=AdapterStatus.OK, assets=[])

        logger.info("[ipinfo] Enriching %d IPs", len(unique_ips))
        loop = asyncio.get_running_loop()

        token = os.getenv("IPINFO_TOKEN", "")
        tasks = [
            loop.run_in_executor(_ipinfo_pool, self._query_ip, ip, token)
            for ip in unique_ips
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        assets: List[AssetRecord] = []
        for r in results:
            if isinstance(r, AssetRecord):
                assets.append(r)

        logger.info("[ipinfo] Enriched %d/%d IPs", len(assets), len(unique_ips))
        return ScannerResult(status=AdapterStatus.OK, assets=assets)

    @staticmethod
    def _query_ip(ip: str, token: str = "") -> Optional[AssetRecord]:
        """Synchronous ipinfo.io query — safe for thread pool."""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            if token:
                url += f"?token={token}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "OpenSecX-Scanner/1.0", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())

            org_raw = data.get("org", "")  # e.g. "AS13335 Cloudflare, Inc."
            asn = ""
            org = org_raw
            if org_raw.startswith("AS"):
                parts = org_raw.split(" ", 1)
                asn = parts[0]
                org = parts[1] if len(parts) > 1 else org_raw

            hostname = data.get("hostname", "")
            city = data.get("city", "")
            region = data.get("region", "")
            country = data.get("country", "")

            notes_parts = []
            if city and region:
                notes_parts.append(f"Location: {city}, {region}, {country}")
            if hostname:
                notes_parts.append(f"Hostname: {hostname}")

            return AssetRecord(
                domain=hostname or ip,
                hostname=hostname or None,
                ip_address=ip,
                source="ipinfo",
                asn=asn or None,
                org=org or None,
                country=country or None,
                status="Active",
                notes=" | ".join(notes_parts) if notes_parts else None,
            )
        except Exception as exc:
            logger.debug("[ipinfo] Failed for %s: %s", ip, exc)
            return None
