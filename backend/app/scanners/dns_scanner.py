"""
Pure-Python DNS Scanner — OpenSecX Phase 1

Resolves full DNS records for a list of hostnames using the `dnspython`
library. This replaces the `dnsx` binary for environments where Go tools
are not installed (Windows, CI, Docker without Go).

Retrieves: A, AAAA, CNAME, MX, NS, TXT, SOA records.

Installation: pip install dnspython
"""
from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set

from app.scanners.base import (
    AdapterStatus,
    AssetRecord,
    BaseScannerAdapter,
    ScannerResult,
)

logger = logging.getLogger(__name__)

# Module-level thread pool for blocking DNS calls
_dns_executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="dns-resolve")


class PythonDnsScanner(BaseScannerAdapter):
    """
    DNS resolution using dnspython — no external binary required.

    Resolves A, AAAA, CNAME, MX, NS, TXT, SOA records for each hostname.
    Falls back gracefully if dnspython is not installed.
    """

    @property
    def name(self) -> str:
        return "dns_python"

    @property
    def binary(self) -> None:
        return None  # Python library, no binary needed

    def is_available(self) -> bool:
        try:
            import dns.resolver  # noqa: F401
            return True
        except ImportError:
            return False

    async def run(self, target: str, timeout: int = 60) -> ScannerResult:
        """Resolve DNS records for a single target domain."""
        if not self.is_available():
            return ScannerResult(
                status=AdapterStatus.UNAVAILABLE,
                error="dnspython not installed. Run: pip install dnspython",
            )
        result = await self.resolve_list([target], timeout=timeout)
        return result

    async def resolve_list(self, hostnames: List[str], timeout: int = 60) -> ScannerResult:
        """
        Resolve DNS records for a list of hostnames concurrently.
        This is the main entry point used by the DiscoveryOrchestrator.
        """
        if not self.is_available():
            return ScannerResult(
                status=AdapterStatus.UNAVAILABLE,
                error="dnspython not installed. Run: pip install dnspython",
            )

        if not hostnames:
            return ScannerResult(status=AdapterStatus.OK, assets=[])

        logger.info("[dns_python] Resolving %d hostnames", len(hostnames))

        loop = asyncio.get_running_loop()

        # Resolve all hostnames concurrently using thread pool
        tasks = [
            loop.run_in_executor(_dns_executor, self._resolve_one, hostname)
            for hostname in hostnames
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        assets: List[AssetRecord] = []
        resolved_count = 0

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.debug("[dns_python] Error resolving %s: %s", hostnames[i], result)
                continue
            if result is not None:
                assets.append(result)
                resolved_count += 1

        logger.info(
            "[dns_python] Resolved %d/%d hostnames successfully",
            resolved_count, len(hostnames)
        )
        return ScannerResult(
            status=AdapterStatus.OK,
            assets=assets,
        )

    @staticmethod
    def _resolve_one(hostname: str) -> Optional[AssetRecord]:
        """
        Synchronous DNS resolution for a single hostname.
        Called inside a thread pool executor.

        Returns AssetRecord with all DNS records, or None if resolution fails.
        """
        try:
            import dns.resolver
            import dns.exception

            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8

            dns_records: Dict[str, List[str]] = {}
            primary_ip: Optional[str] = None

            # ── A records (IPv4) ──────────────────────────────────────────────
            try:
                answers = resolver.resolve(hostname, "A")
                a_records = [str(rdata) for rdata in answers]
                if a_records:
                    dns_records["A"] = a_records
                    primary_ip = a_records[0]
            except Exception:
                pass

            # ── AAAA records (IPv6) ───────────────────────────────────────────
            try:
                answers = resolver.resolve(hostname, "AAAA")
                aaaa = [str(rdata) for rdata in answers]
                if aaaa:
                    dns_records["AAAA"] = aaaa
            except Exception:
                pass

            # ── CNAME records ─────────────────────────────────────────────────
            try:
                answers = resolver.resolve(hostname, "CNAME")
                cnames = [str(rdata) for rdata in answers]
                if cnames:
                    dns_records["CNAME"] = cnames
            except Exception:
                pass

            # ── MX records ───────────────────────────────────────────────────
            try:
                answers = resolver.resolve(hostname, "MX")
                mx_records = [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
                if mx_records:
                    dns_records["MX"] = mx_records
            except Exception:
                pass

            # ── NS records ───────────────────────────────────────────────────
            try:
                answers = resolver.resolve(hostname, "NS")
                ns_records = [str(rdata) for rdata in answers]
                if ns_records:
                    dns_records["NS"] = ns_records
            except Exception:
                pass

            # ── TXT records ───────────────────────────────────────────────────
            try:
                answers = resolver.resolve(hostname, "TXT")
                txt_records = []
                for rdata in answers:
                    # Each TXT record may have multiple strings
                    txt_records.append(" ".join(s.decode("utf-8", errors="replace") for s in rdata.strings))
                if txt_records:
                    dns_records["TXT"] = txt_records
            except Exception:
                pass

            # ── SOA records ───────────────────────────────────────────────────
            try:
                answers = resolver.resolve(hostname, "SOA")
                soa_records = [str(rdata) for rdata in answers]
                if soa_records:
                    dns_records["SOA"] = soa_records
            except Exception:
                pass

            # If we got no records at all, the hostname is likely dead
            if not dns_records:
                return None

            return AssetRecord(
                domain=hostname,
                hostname=hostname,
                ip_address=primary_ip,
                source="dns_python",
                dns_records=dns_records,
                status="Active",
            )

        except Exception as exc:
            logger.debug("[dns_python] Resolution failed for %s: %s", hostname, exc)
            return None
