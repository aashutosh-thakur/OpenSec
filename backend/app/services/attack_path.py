"""
Attack Path Service — OpenSecX Phase 3

Correlates discovered assets + findings into structured attack chains.
Each chain follows the pattern:
  Entry Point → Open Service → Technology → CVE → Technique → Impact

Evidence grades are preserved from source findings.
No extra probes are made — purely correlates existing DB data.
"""
from __future__ import annotations

import logging
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.asset import Asset
from app.models.finding import Finding

logger = logging.getLogger(__name__)

OWASP_TECHNIQUES = {
    "A01:Broken Access Control":             "Privilege Escalation / Unauthorized Access",
    "A02:Cryptographic Failures":            "Data Interception / Credential Theft",
    "A03:Injection":                         "Code/Command Injection",
    "A05:Security Misconfiguration":         "Reconnaissance / Lateral Movement",
    "A06:Vulnerable and Outdated Components": "Exploit Known CVE → RCE / Privilege Escalation",
    "A07:Identification and Authentication Failures": "Session Hijacking / Credential Theft",
}

IMPACT_MAP = {
    "critical": "Remote Code Execution / Full System Compromise",
    "high":     "Significant Data Breach / Service Disruption",
    "medium":   "Partial Data Exposure / Privilege Escalation",
    "low":      "Information Disclosure / Minor Misconfiguration",
    "info":     "Reconnaissance Data",
}


async def build_attack_paths(scan_id: int, target: str, db: AsyncSession) -> List[dict]:
    """
    Build attack path chains for a completed scan.
    Returns list of attack path dicts for API/UI consumption.
    """
    # Load assets and findings
    assets_res = await db.execute(
        select(Asset).where(
            Asset.domain.like(f"%.{target}") | (Asset.domain == target)
        )
    )
    assets: List[Asset] = assets_res.scalars().all()

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
        .order_by(Finding.in_kev.desc(), Finding.created_at.desc())
    )
    findings: List[Finding] = findings_res.scalars().all()

    paths = []

    # Group findings by asset
    findings_by_asset: dict = {}
    unlinked_findings = []
    for f in findings:
        if f.asset_id:
            findings_by_asset.setdefault(f.asset_id, []).append(f)
        else:
            unlinked_findings.append(f)

    # Build paths from asset-linked findings
    for asset in assets:
        asset_findings = findings_by_asset.get(asset.id, [])
        if not asset_findings:
            continue

        # Entry point step
        entry_label = asset.domain or asset.ip_address or "Unknown"
        entry_step = {
            "label": entry_label,
            "type": "entry",
            "grade": "confirmed",
            "detail": f"Public-facing asset: {entry_label}",
        }

        # Service step — from ports/protocol
        service_steps = []
        if asset.ports:
            for port in asset.ports[:3]:
                service_steps.append({
                    "label": f"Port {port}/{asset.service or 'unknown'}",
                    "type": "service",
                    "grade": "confirmed",
                    "detail": f"Open port {port} detected via port scan",
                })
        elif asset.protocol:
            service_steps.append({
                "label": f"{asset.protocol.upper()}",
                "type": "service",
                "grade": "confirmed",
                "detail": f"Protocol: {asset.protocol}",
            })

        # Tech step — from technologies
        tech_steps = []
        if asset.technologies:
            for tech in asset.technologies[:3]:
                tech_steps.append({
                    "label": tech,
                    "type": "technology",
                    "grade": "supported",
                    "detail": f"Detected via HTTP response analysis",
                })

        # Finding steps
        for finding in asset_findings[:5]:
            technique = OWASP_TECHNIQUES.get(finding.category or "", "Exploit Finding")
            impact = IMPACT_MAP.get(finding.severity or "info", "Unknown Impact")

            path = {
                "id": f"path-{asset.id}-{finding.id}",
                "target": target,
                "asset": entry_label,
                "severity": finding.severity,
                "in_kev": finding.in_kev,
                "priority": finding.priority,
                "steps": [
                    entry_step,
                    *service_steps[:1],
                    *tech_steps[:1],
                    {
                        "label": finding.cve_id or finding.category or finding.title[:40],
                        "type": "vulnerability",
                        "grade": finding.grade,
                        "detail": finding.title,
                        "finding_id": finding.id,
                        "severity": finding.severity,
                        "cvss": finding.cvss,
                        "epss": finding.epss,
                        "in_kev": finding.in_kev,
                    },
                    {
                        "label": technique,
                        "type": "technique",
                        "grade": "possible",
                        "detail": f"OWASP: {finding.category}",
                    },
                    {
                        "label": impact,
                        "type": "impact",
                        "grade": "possible",
                        "detail": f"If exploited: {impact}",
                    },
                ],
            }
            paths.append(path)

    # Build paths from unlinked (domain-level) findings
    for finding in unlinked_findings[:10]:
        technique = OWASP_TECHNIQUES.get(finding.category or "", "Exploit Finding")
        impact = IMPACT_MAP.get(finding.severity or "info", "Unknown Impact")

        path = {
            "id": f"path-domain-{finding.id}",
            "target": target,
            "asset": target,
            "severity": finding.severity,
            "in_kev": finding.in_kev,
            "priority": finding.priority,
            "steps": [
                {"label": target, "type": "entry", "grade": "confirmed", "detail": "Target domain"},
                {
                    "label": finding.cve_id or finding.category or finding.title[:40],
                    "type": "vulnerability",
                    "grade": finding.grade,
                    "detail": finding.title,
                    "finding_id": finding.id,
                    "severity": finding.severity,
                    "cvss": finding.cvss,
                    "epss": finding.epss,
                    "in_kev": finding.in_kev,
                },
                {"label": technique, "type": "technique", "grade": "possible", "detail": f"OWASP: {finding.category}"},
                {"label": impact, "type": "impact", "grade": "possible", "detail": f"If exploited: {impact}"},
            ],
        }
        paths.append(path)

    # Sort: KEV first, then by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    paths.sort(key=lambda p: (not p.get("in_kev", False), sev_order.get(p.get("severity", "info"), 5)))

    logger.info("[attack_paths] Built %d attack paths for scan %d", len(paths), scan_id)
    return paths
