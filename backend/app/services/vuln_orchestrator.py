"""
Vulnerability Orchestrator — OpenSecX Phase 2

Runs all Phase 2 vulnerability scanners against discovered assets
from a completed Phase 1 scan. Stores results as Finding records.

Scanner pipeline:
  1. TLS Scanner      — cert expiry, protocol version
  2. Security Headers — 7 critical headers
  3. CORS Scanner     — CORS misconfiguration
  4. CVE Scanner      — NVD + CISA KEV + EPSS

Each scanner is individually wrapped in try/except so a failure
in one never blocks the others (fail-soft principle).
"""
from __future__ import annotations

import asyncio
import logging
import urllib.request
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.finding import Finding
from app.scanners.tls_scanner import scan_tls
from app.scanners.security_headers_scanner import check_security_headers
from app.scanners.cors_scanner import scan_cors
from app.scanners.cve_scanner import scan_cves

logger = logging.getLogger(__name__)


async def run_vuln_scan(
    scan_id: int,
    target: str,
    db: AsyncSession,
) -> int:
    """
    Run all Phase 2 vulnerability scanners against assets from scan_id.

    Returns:
        Number of findings created.
    """
    logger.info("[vuln] Starting vulnerability scan for scan_id=%d target=%s", scan_id, target)

    # Load assets from this scan (or recent scans for target)
    result = await db.execute(
        select(Asset).where(Asset.domain.like(f"%.{target}") | (Asset.domain == target))
    )
    assets: List[Asset] = result.scalars().all()

    if not assets:
        logger.info("[vuln] No assets found for %s — skipping vuln scan", target)
        return 0

    findings_created = 0
    all_finding_dicts: List[dict] = []

    # ── 1. TLS scanning for live HTTPS assets ────────────────────────────────
    try:
        https_assets = [a for a in assets if a.protocol in ("https", "http") or a.domain]
        # Limit to max 20 assets to avoid excessive scanning
        scan_targets = list({a.domain for a in https_assets if a.domain})[:20]

        logger.info("[vuln] TLS scanning %d domains", len(scan_targets))
        tls_tasks = [scan_tls(domain, 443) for domain in scan_targets]
        tls_results = await asyncio.gather(*tls_tasks, return_exceptions=True)

        for i, tls_result in enumerate(tls_results):
            if isinstance(tls_result, Exception):
                continue
            domain = scan_targets[i]
            # Find matching asset
            matching_asset = next((a for a in assets if a.domain == domain), None)
            asset_id = matching_asset.id if matching_asset else None

            for finding_dict in tls_result.get("findings", []):
                finding_dict["_asset_id"] = asset_id
                all_finding_dicts.append(finding_dict)

            # Update asset certificate info from TLS result
            if matching_asset and tls_result.get("reachable"):
                matching_asset.certificate = {
                    "subject": tls_result.get("cert_subject"),
                    "issuer": tls_result.get("cert_issuer"),
                    "not_after": tls_result.get("cert_not_after"),
                    "days_left": tls_result.get("cert_days_left"),
                    "tls_version": tls_result.get("tls_version"),
                    "sans": tls_result.get("cert_sans", [])[:10],
                }
                await db.flush()

    except Exception as exc:
        logger.error("[vuln] TLS scanning failed: %s", exc)

    # ── 2. Security Headers ──────────────────────────────────────────────────
    try:
        # Get the main target URL
        target_url = f"https://{target}"
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "OpenSecX-Scanner/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_headers = dict(resp.headers)
                effective_url = resp.url
        except Exception:
            try:
                target_url = f"http://{target}"
                req = urllib.request.Request(
                    target_url,
                    headers={"User-Agent": "OpenSecX-Scanner/1.0"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp_headers = dict(resp.headers)
                    effective_url = resp.url
            except Exception as he:
                resp_headers = {}
                effective_url = target_url
                logger.debug("[vuln] Could not fetch headers for %s: %s", target, he)

        if resp_headers:
            header_findings = check_security_headers(resp_headers, effective_url)
            # Link to main target asset
            main_asset = next((a for a in assets if a.domain == target), None)
            asset_id = main_asset.id if main_asset else None
            for f in header_findings:
                f["_asset_id"] = asset_id
            all_finding_dicts.extend(header_findings)

    except Exception as exc:
        logger.error("[vuln] Security headers scan failed: %s", exc)

    # ── 2b. Cookie Security ────────────────────────────────────────────
    try:
        from app.scanners.cookie_scanner import scan_cookies
        cookie_url = f"https://{target}"
        cookie_findings = await scan_cookies(cookie_url)
        main_asset = next((a for a in assets if a.domain == target), None)
        asset_id = main_asset.id if main_asset else None
        for f in cookie_findings:
            f["_asset_id"] = asset_id
        all_finding_dicts.extend(cookie_findings)
        logger.info("[vuln] Cookie scan: %d findings", len(cookie_findings))
    except Exception as exc:
        logger.error("[vuln] Cookie scan failed: %s", exc)

    # ── 3. CORS ──────────────────────────────────────────────────────────────
    try:
        target_url = f"https://{target}"
        cors_findings = await scan_cors(target_url, target)
        main_asset = next((a for a in assets if a.domain == target), None)
        asset_id = main_asset.id if main_asset else None
        for f in cors_findings:
            f["_asset_id"] = asset_id
        all_finding_dicts.extend(cors_findings)
    except Exception as exc:
        logger.error("[vuln] CORS scan failed: %s", exc)

    # ── 4. CVE scanning ──────────────────────────────────────────────────────
    try:
        # Collect all unique technologies from all assets
        all_techs: List[str] = []
        for asset in assets:
            if asset.technologies:
                all_techs.extend(asset.technologies)

        # Deduplicate
        unique_techs = list(set(all_techs))
        logger.info("[vuln] CVE scanning for %d unique technologies", len(unique_techs))

        if unique_techs:
            cve_findings = await scan_cves(unique_techs, target)
            # Link to main asset
            main_asset = next((a for a in assets if a.domain == target), None)
            asset_id = main_asset.id if main_asset else None
            for f in cve_findings:
                f["_asset_id"] = asset_id
            all_finding_dicts.extend(cve_findings)

    except Exception as exc:
        logger.error("[vuln] CVE scan failed: %s", exc)

    # ── Persist all findings ─────────────────────────────────────────────────
    for fd in all_finding_dicts:
        try:
            asset_id = fd.pop("_asset_id", None)
            finding = Finding(
                scan_id=scan_id,
                asset_id=asset_id,
                title=fd.get("title", "Unknown Finding"),
                description=fd.get("description"),
                severity=fd.get("severity", "medium"),
                category=fd.get("category"),
                evidence=fd.get("evidence"),
                grade=fd.get("grade", "supported"),
                remediation=fd.get("remediation"),
                cve_id=fd.get("cve_id"),
                cvss=fd.get("cvss"),
                epss=fd.get("epss"),
                in_kev=fd.get("in_kev", False),
                priority=fd.get("priority"),
                triage_status="open",
            )
            db.add(finding)
            findings_created += 1
        except Exception as exc:
            logger.error("[vuln] Failed to store finding '%s': %s", fd.get("title"), exc)

    try:
        await db.commit()
    except Exception as exc:
        logger.error("[vuln] Failed to commit findings: %s", exc)
        await db.rollback()

    logger.info(
        "[vuln] Vulnerability scan complete for %s: %d findings stored",
        target, findings_created,
    )
    return findings_created
