"""
Subdomain Discovery Scanner — OpenSecX Phase 1

Discovers subdomains using multiple passive OSINT APIs — no binary required.
Tries each source in order and merges unique results.

Sources (in order):
  1. crt.sh — Certificate Transparency logs
  2. HackerTarget — DNS lookup API
  3. ThreatCrowd — threat intelligence
  4. BufferOver — passive DNS
  5. RapidDNS — passive subdomain database
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
import urllib.error
from typing import List, Optional, Set

from app.scanners.base import (
    AdapterStatus,
    AssetRecord,
    BaseScannerAdapter,
    ScannerResult,
)

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 25  # seconds per API call


class CrtShScanner(BaseScannerAdapter):
    """
    Discovers subdomains from multiple passive OSINT APIs.
    No binary required. Always available. Falls through the chain until
    at least one source returns results.
    """

    @property
    def name(self) -> str:
        return "crtsh"

    @property
    def binary(self) -> None:
        return None  # HTTP-based, always available

    async def run(self, target: str, timeout: int = 60) -> ScannerResult:
        """
        Run all OSINT APIs concurrently and merge unique results.
        """
        logger.info("[osint] Starting passive subdomain discovery for %s", target)

        # Run all sources concurrently
        tasks = [
            self._fetch_crtsh(target),
            self._fetch_hackertarget(target),
            self._fetch_threatcrowd(target),
            self._fetch_rapiddns(target),
            self._fetch_anubis(target),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen: Set[str] = set()
        all_assets: List[AssetRecord] = []

        for result in results:
            if isinstance(result, Exception):
                continue
            if isinstance(result, list):
                for asset in result:
                    key = asset.domain or asset.hostname or ""
                    if key and key not in seen:
                        seen.add(key)
                        all_assets.append(asset)

        # Always include the root domain itself
        if target not in seen:
            all_assets.insert(0, AssetRecord(
                domain=target,
                hostname=target,
                source="osint",
                status="Active",
            ))

        logger.info("[osint] Found %d unique subdomains for %s", len(all_assets), target)
        return ScannerResult(
            status=AdapterStatus.OK,
            assets=all_assets,
        )

    async def _fetch_crtsh(self, target: str) -> List[AssetRecord]:
        """crt.sh Certificate Transparency logs."""
        url = f"https://crt.sh/?q=%.{target}&output=json"
        logger.info("[osint] Querying crt.sh for %s", target)
        try:
            raw = await asyncio.get_running_loop().run_in_executor(
                None, self._fetch, url, REQUEST_TIMEOUT
            )
            entries = json.loads(raw)
            seen: Set[str] = set()
            assets: List[AssetRecord] = []
            for entry in entries:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lower()
                    if not name or name.startswith("*") or name in seen:
                        continue
                    # Only include subdomains of the target
                    if not (name == target or name.endswith("." + target)):
                        continue
                    seen.add(name)
                    assets.append(AssetRecord(
                        domain=name,
                        hostname=name,
                        source="crtsh",
                        status="Active",
                        certificate={
                            "issuer": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                        },
                    ))
            logger.info("[osint] crt.sh: %d subdomains", len(assets))
            return assets
        except Exception as exc:
            logger.warning("[osint] crt.sh failed: %s", exc)
            return []

    async def _fetch_hackertarget(self, target: str) -> List[AssetRecord]:
        """HackerTarget hostsearch API."""
        url = f"https://api.hackertarget.com/hostsearch/?q={target}"
        logger.info("[osint] Querying HackerTarget for %s", target)
        try:
            raw = await asyncio.get_running_loop().run_in_executor(
                None, self._fetch, url, REQUEST_TIMEOUT
            )
            assets: List[AssetRecord] = []
            for line in raw.splitlines():
                line = line.strip()
                if not line or "," not in line or "error" in line.lower():
                    continue
                parts = line.split(",")
                hostname = parts[0].strip().lower()
                ip = parts[1].strip() if len(parts) > 1 else None
                if not hostname:
                    continue
                if not (hostname == target or hostname.endswith("." + target)):
                    continue
                assets.append(AssetRecord(
                    domain=hostname,
                    hostname=hostname,
                    ip_address=ip,
                    source="hackertarget",
                    status="Active",
                ))
            logger.info("[osint] HackerTarget: %d subdomains", len(assets))
            return assets
        except Exception as exc:
            logger.warning("[osint] HackerTarget failed: %s", exc)
            return []

    async def _fetch_threatcrowd(self, target: str) -> List[AssetRecord]:
        """ThreatCrowd domain search API."""
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}"
        logger.info("[osint] Querying ThreatCrowd for %s", target)
        try:
            raw = await asyncio.get_running_loop().run_in_executor(
                None, self._fetch, url, REQUEST_TIMEOUT
            )
            data = json.loads(raw)
            subdomains = data.get("subdomains", [])
            assets: List[AssetRecord] = []
            for sub in subdomains:
                sub = sub.strip().lower()
                if not sub:
                    continue
                if not (sub == target or sub.endswith("." + target)):
                    continue
                assets.append(AssetRecord(
                    domain=sub,
                    hostname=sub,
                    source="threatcrowd",
                    status="Active",
                ))
            logger.info("[osint] ThreatCrowd: %d subdomains", len(assets))
            return assets
        except Exception as exc:
            logger.warning("[osint] ThreatCrowd failed: %s", exc)
            return []

    async def _fetch_rapiddns(self, target: str) -> List[AssetRecord]:
        """RapidDNS subdomain search."""
        url = f"https://rapiddns.io/subdomain/{target}?full=1&down=1"
        logger.info("[osint] Querying RapidDNS for %s", target)
        try:
            raw = await asyncio.get_running_loop().run_in_executor(
                None, self._fetch, url, REQUEST_TIMEOUT
            )
            import re
            # Extract subdomains from HTML table
            pattern = rf'([a-z0-9\-\.]+\.{re.escape(target)})'
            matches = re.findall(pattern, raw.lower())
            seen: Set[str] = set()
            assets: List[AssetRecord] = []
            for match in matches:
                match = match.strip()
                if match not in seen and match != target:
                    seen.add(match)
                    assets.append(AssetRecord(
                        domain=match,
                        hostname=match,
                        source="rapiddns",
                        status="Active",
                    ))
            logger.info("[osint] RapidDNS: %d subdomains", len(assets))
            return assets
        except Exception as exc:
            logger.warning("[osint] RapidDNS failed: %s", exc)
            return []

    async def _fetch_anubis(self, target: str) -> List[AssetRecord]:
        """Anubis-DB subdomain API."""
        url = f"https://jldc.me/anubis/subdomains/{target}"
        logger.info("[osint] Querying AnubisDB for %s", target)
        try:
            raw = await asyncio.get_running_loop().run_in_executor(
                None, self._fetch, url, REQUEST_TIMEOUT
            )
            subdomains = json.loads(raw)
            assets: List[AssetRecord] = []
            for sub in subdomains:
                sub = sub.strip().lower()
                if not sub:
                    continue
                if not (sub == target or sub.endswith("." + target)):
                    continue
                assets.append(AssetRecord(
                    domain=sub,
                    hostname=sub,
                    source="anubis",
                    status="Active",
                ))
            logger.info("[osint] AnubisDB: %d subdomains", len(assets))
            return assets
        except Exception as exc:
            logger.warning("[osint] AnubisDB failed: %s", exc)
            return []

    @staticmethod
    def _fetch(url: str, timeout: int) -> str:
        """Synchronous HTTP fetch — called inside executor."""
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OpenSecX-Scanner/1.0; +https://github.com/OpenSecX)",
                "Accept": "application/json, text/plain, */*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
