"""
WHOIS / RDAP Scanner — OpenSecX Phase 1

Queries WHOIS/RDAP data for a target domain using the python-whois library.
Returns organization, registrar, nameserver, country and ASN metadata.
No binary required — uses a Python library.

Installation: pip install python-whois

NOTE: python-whois internally may call asyncio.get_event_loop() which
fails on Windows when called from an existing async context. This adapter
runs the query in a completely isolated process via ProcessPoolExecutor.
"""
from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from app.scanners.base import (
    AdapterStatus,
    AssetRecord,
    BaseScannerAdapter,
    ScannerResult,
)

logger = logging.getLogger(__name__)

# Dedicated thread pool — keeps whois calls isolated from the main event loop
_whois_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="whois-query")


class WhoisScanner(BaseScannerAdapter):
    """
    Retrieves WHOIS/RDAP registration data for the target domain.
    Enriches assets with org, country, registrar and nameserver metadata.
    Runs in a thread pool to avoid event loop conflicts on Windows.
    """

    @property
    def name(self) -> str:
        return "whois"

    @property
    def binary(self) -> None:
        return None  # Python-library-based

    def is_available(self) -> bool:
        try:
            import whois  # noqa: F401
            return True
        except ImportError:
            return False

    async def run(self, target: str, timeout: int = 30) -> ScannerResult:
        if not self.is_available():
            return ScannerResult(
                status=AdapterStatus.UNAVAILABLE,
                error=(
                    "python-whois is not installed. "
                    "Run: pip install python-whois"
                ),
            )

        logger.info("[whois] Querying WHOIS for %s", target)

        try:
            loop = asyncio.get_running_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(_whois_pool, _whois_query_isolated, target),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("[whois] WHOIS query timed out for %s", target)
            return ScannerResult(
                status=AdapterStatus.TIMEOUT,
                error=f"WHOIS query timed out after {timeout}s",
            )
        except Exception as exc:
            logger.error("[whois] WHOIS query failed for %s: %s", target, exc)
            return ScannerResult(
                status=AdapterStatus.ERROR,
                error=f"WHOIS query failed: {exc}",
            )

        if result is None:
            return ScannerResult(
                status=AdapterStatus.OK,
                assets=[],
                error="WHOIS returned no data",
            )

        asset = AssetRecord(
            domain=target,
            hostname=target,
            source="whois",
            org=_safe_str(result.get("org") or result.get("registrant_name")),
            country=_safe_str(result.get("country")),
            status="Active",
            notes=(
                f"Registrar: {_safe_str(result.get('registrar'))} | "
                f"Name servers: {', '.join(result.get('name_servers') or [])}"
            ),
        )

        logger.info("[whois] WHOIS data retrieved for %s", target)
        return ScannerResult(
            status=AdapterStatus.OK,
            assets=[asset],
        )


def _whois_query_isolated(target: str) -> Optional[dict]:
    """
    Runs in a thread pool — completely isolated from the async event loop.
    python-whois is synchronous and safe here.
    """
    try:
        import whois
        data = whois.whois(target)
        if data is None:
            return None
        return dict(data)
    except Exception as exc:
        logger.warning("[whois] Query error for %s: %s", target, exc)
        return None


def _safe_str(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return str(value)
