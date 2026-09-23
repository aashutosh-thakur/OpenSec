"""
Asset Discovery Orchestrator — OpenSecX Phase 1 + Enhancements

Bulletproof pipeline: every step is wrapped in try/except so one failing
tool NEVER crashes the whole scan.

Pipeline:
  1. OSINT      — crt.sh + HackerTarget + ThreatCrowd + RapidDNS + AnubisDB
  2. Wayback    — historical subdomain discovery via Wayback Machine CDX API
  3. DNS        — dnspython: full A/AAAA/MX/NS/TXT/CNAME/SOA resolution
  4. IPInfo     — IP enrichment: ASN, org, city, country via ipinfo.io
  5. HTTP Probe — live host detection, title, tech stack, WAF detection
  6. WHOIS      — registrar, dates, nameservers via python-whois
"""
from __future__ import annotations

import logging
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.asset import Asset
from app.models.scan import ScanJob, ScanStatus
from app.scanners.base import AdapterStatus, AssetRecord

logger = logging.getLogger(__name__)


class DiscoveryOrchestrator:
    """Coordinates Phase 1 asset discovery. Each step is fully isolated."""

    async def run(
        self,
        scan_id: int,
        target: str,
        tools: List[str],
        db: AsyncSession,
    ) -> Tuple[Dict[str, str], int]:
        """
        Execute the discovery pipeline. Returns (tool_statuses, assets_saved).
        Every step is wrapped in try/except — a single failure is logged
        and skipped, never propagated.
        """
        from app.scanners.crtsh import CrtShScanner
        from app.scanners.dns_scanner import PythonDnsScanner
        from app.scanners.http_prober import HttpProber
        from app.scanners.whois_scanner import WhoisScanner
        from app.scanners.wayback_scanner import WaybackScanner
        from app.scanners.ipinfo_scanner import IPInfoScanner

        tool_statuses: Dict[str, str] = {}
        all_assets: List[AssetRecord] = []

        logger.info("[orchestrator] Starting scan #%d for target: %s", scan_id, target)

        # ── Step 1: Multi-API OSINT ──────────────────────────────────────────
        try:
            scanner = CrtShScanner()
            result = await scanner.run(target, timeout=45)
            tool_statuses["crtsh"] = result.status.value
            all_assets.extend(result.assets)
            logger.info("[step1/osint] %d subdomains", len(result.assets))
        except Exception:
            logger.error("[step1/osint] CRASHED:\n%s", traceback.format_exc())
            tool_statuses["crtsh"] = "error"

        # ── Step 2: Wayback Machine CDX ──────────────────────────────────────
        try:
            scanner = WaybackScanner()
            result = await scanner.run(target, timeout=30)
            tool_statuses["wayback"] = result.status.value
            all_assets.extend(result.assets)
            logger.info("[step2/wayback] %d subdomains from Wayback", len(result.assets))
        except Exception:
            logger.error("[step2/wayback] CRASHED:\n%s", traceback.format_exc())
            tool_statuses["wayback"] = "error"

        # ── Collect unique domains ────────────────────────────────────────────
        unique_domains = list({a.domain for a in all_assets if a.domain})
        if target not in unique_domains:
            unique_domains.insert(0, target)
        logger.info("[orchestrator] %d unique domains to resolve/probe", len(unique_domains))

        # ── Step 3: Python DNS resolution ────────────────────────────────────
        try:
            scanner = PythonDnsScanner()
            if scanner.is_available():
                result = await scanner.resolve_list(unique_domains, timeout=60)
                tool_statuses["dns"] = result.status.value
                all_assets.extend(result.assets)
                logger.info("[step3/dns] %d records resolved", len(result.assets))
            else:
                tool_statuses["dns"] = AdapterStatus.UNAVAILABLE.value
                logger.warning("[step3/dns] dnspython not installed")
        except Exception:
            logger.error("[step3/dns] CRASHED:\n%s", traceback.format_exc())
            tool_statuses["dns"] = "error"

        # ── Step 4: IPInfo IP enrichment ─────────────────────────────────────
        try:
            resolved_ips = list({a.ip_address for a in all_assets if a.ip_address})
            if resolved_ips:
                ipinfo = IPInfoScanner()
                result = await ipinfo.enrich_ips(resolved_ips, timeout=30)
                tool_statuses["ipinfo"] = result.status.value
                all_assets.extend(result.assets)
                logger.info("[step4/ipinfo] Enriched %d IPs", len(result.assets))
            else:
                tool_statuses["ipinfo"] = "ok"
        except Exception:
            logger.error("[step4/ipinfo] CRASHED:\n%s", traceback.format_exc())
            tool_statuses["ipinfo"] = "error"

        # ── Step 5: HTTP Probing ──────────────────────────────────────────────
        try:
            scanner = HttpProber()
            if scanner.is_available() and unique_domains:
                result = await scanner.probe_list(unique_domains[:20], timeout=60)
                tool_statuses["http"] = result.status.value
                all_assets.extend(result.assets)
                logger.info("[step5/http] %d live services", len(result.assets))
            else:
                tool_statuses["http"] = AdapterStatus.UNAVAILABLE.value
        except Exception:
            logger.error("[step5/http] CRASHED:\n%s", traceback.format_exc())
            tool_statuses["http"] = "error"

        # ── Step 5b: Port Scanning (pure Python, no binary) ─────────────────
        try:
            from app.scanners.port_scanner import PortScanner
            scanner = PortScanner()
            # Scan root target + up to 5 resolved IPs
            resolved_ips = list({a.ip_address for a in all_assets if a.ip_address})[:5]
            port_targets = [target] + resolved_ips
            result = await scanner.scan_multiple(port_targets[:6], timeout=60)
            tool_statuses["ports"] = result.status.value
            all_assets.extend(result.assets)
            logger.info("[step5b/ports] %d port records", len(result.assets))
        except Exception:
            logger.error("[step5b/ports] CRASHED:\n%s", traceback.format_exc())
            tool_statuses["ports"] = "error"

        # ── Step 6: WHOIS metadata ────────────────────────────────────────────
        try:
            scanner = WhoisScanner()
            if scanner.is_available():
                result = await scanner.run(target, timeout=20)
                tool_statuses["whois"] = result.status.value
                all_assets.extend(result.assets)
                logger.info("[step6/whois] %d records", len(result.assets))
            else:
                tool_statuses["whois"] = AdapterStatus.UNAVAILABLE.value
        except Exception:
            logger.error("[step6/whois] CRASHED:\n%s", traceback.format_exc())
            tool_statuses["whois"] = "error"

        # ── Persist ───────────────────────────────────────────────────────────
        try:
            assets_saved = await self._save_assets(all_assets, db)
        except Exception:
            logger.error("[orchestrator] _save_assets CRASHED:\n%s", traceback.format_exc())
            assets_saved = 0

        logger.info(
            "[orchestrator] Scan #%d DONE: %d raw records → %d saved. Tools: %s",
            scan_id, len(all_assets), assets_saved, tool_statuses,
        )
        return tool_statuses, assets_saved


    async def _save_assets(self, records: List[AssetRecord], db: AsyncSession) -> int:
        """Deduplicate and persist asset records to the database."""
        # Build dedup map: domain → best merged AssetRecord
        dedup: Dict[str, AssetRecord] = {}
        for rec in records:
            key = rec.domain or rec.hostname or rec.ip_address or ""
            if not key:
                continue
            if key not in dedup:
                dedup[key] = rec
            else:
                existing = dedup[key]
                if rec.ip_address and not existing.ip_address:
                    existing.ip_address = rec.ip_address
                if rec.ports:
                    existing.ports = sorted(set((existing.ports or []) + rec.ports))
                if rec.technologies:
                    existing.technologies = list(dict.fromkeys(
                        (existing.technologies or []) + rec.technologies
                    ))
                if rec.dns_records:
                    if not existing.dns_records:
                        existing.dns_records = rec.dns_records
                    else:
                        merged = dict(existing.dns_records)
                        merged.update(rec.dns_records)
                        existing.dns_records = merged
                if rec.certificate and not existing.certificate:
                    existing.certificate = rec.certificate
                if rec.org and not existing.org:
                    existing.org = rec.org
                if rec.country and not existing.country:
                    existing.country = rec.country
                if rec.protocol and not existing.protocol:
                    existing.protocol = rec.protocol
                if rec.service and not existing.service:
                    existing.service = rec.service
                if rec.notes and not existing.notes:
                    existing.notes = rec.notes

        saved = 0
        for key, rec in dedup.items():
            try:
                query = select(Asset).where(Asset.domain == rec.domain)
                result = await db.execute(query)
                existing_asset = result.scalar_one_or_none()

                if existing_asset:
                    if rec.ip_address and not existing_asset.ip_address:
                        existing_asset.ip_address = rec.ip_address
                    if rec.ports:
                        existing_asset.ports = sorted(
                            set((existing_asset.ports or []) + rec.ports)
                        )
                    if rec.technologies:
                        existing_asset.technologies = list(dict.fromkeys(
                            (existing_asset.technologies or []) + rec.technologies
                        ))
                    if rec.dns_records:
                        if not existing_asset.dns_records:
                            existing_asset.dns_records = rec.dns_records
                        else:
                            merged = dict(existing_asset.dns_records)
                            merged.update(rec.dns_records)
                            existing_asset.dns_records = merged
                    if rec.certificate and not existing_asset.certificate:
                        existing_asset.certificate = rec.certificate
                    if rec.protocol and not existing_asset.protocol:
                        existing_asset.protocol = rec.protocol
                    if rec.service and not existing_asset.service:
                        existing_asset.service = rec.service
                    if rec.notes and not existing_asset.notes:
                        existing_asset.notes = rec.notes
                    existing_asset.last_seen = datetime.utcnow()
                else:
                    asset = Asset(
                        domain=rec.domain,
                        hostname=rec.hostname,
                        ip_address=rec.ip_address,
                        ports=rec.ports,
                        protocol=rec.protocol,
                        service=rec.service,
                        technologies=rec.technologies,
                        dns_records=rec.dns_records,
                        certificate=rec.certificate,
                        source=rec.source,
                        asn=rec.asn,
                        org=rec.org,
                        country=rec.country,
                        status=rec.status,
                        notes=rec.notes,
                    )
                    db.add(asset)
                    saved += 1
            except Exception:
                logger.error("[save] Failed to save asset %s:\n%s", key, traceback.format_exc())
                continue

        await db.commit()
        return saved
