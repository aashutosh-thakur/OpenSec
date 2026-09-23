"""
Risk Scorer — OpenSecX Phase 4

Calculates a 0–100 risk score from scan findings and assets.
Higher score = higher risk.

Score Components (weighted):
  - Vuln score   (50%): severity-weighted finding count + EPSS
  - KEV penalty  (20%): each KEV finding adds a penalty
  - Exposure     (15%): open high-risk ports, internet-facing services
  - Hygiene      (15%): missing security headers, weak TLS, cookie issues

Letter Grades:
  0–19  → A  (Excellent)
  20–39 → B  (Good)
  40–59 → C  (Fair)
  60–74 → D  (Poor)
  75+   → F  (Critical)
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.risk import RiskScore

logger = logging.getLogger(__name__)

# Severity weights for vuln scoring
SEV_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

# High-risk ports that increase exposure score
HIGH_RISK_PORTS = {
    3306, 5432, 27017, 6379, 9200, 11211, 5984,
    1433, 1521, 2181, 5900, 23, 3389, 61616, 8161,
}

# OWASP Top 10 2021 categories
OWASP_CATEGORIES = [
    "A01:Broken Access Control",
    "A02:Cryptographic Failures",
    "A03:Injection",
    "A04:Insecure Design",
    "A05:Security Misconfiguration",
    "A06:Vulnerable and Outdated Components",
    "A07:Identification and Authentication Failures",
    "A08:Software and Data Integrity Failures",
    "A09:Security Logging and Monitoring Failures",
    "A10:Server-Side Request Forgery",
]

# CIS Controls mapping from OWASP categories
CIS_MAPPING: Dict[str, List[str]] = {
    "A01:Broken Access Control":               ["CIS-06: Access Control Management"],
    "A02:Cryptographic Failures":              ["CIS-03: Data Protection", "CIS-12: Network Infrastructure Management"],
    "A03:Injection":                           ["CIS-16: Application Software Security"],
    "A04:Insecure Design":                     ["CIS-16: Application Software Security"],
    "A05:Security Misconfiguration":           ["CIS-04: Secure Configuration", "CIS-12: Network Infrastructure Management"],
    "A06:Vulnerable and Outdated Components":  ["CIS-02: Inventory and Control of Software Assets", "CIS-07: Continuous Vulnerability Management"],
    "A07:Identification and Authentication Failures": ["CIS-05: Account Management", "CIS-06: Access Control Management"],
    "A08:Software and Data Integrity Failures": ["CIS-16: Application Software Security"],
    "A09:Security Logging and Monitoring Failures": ["CIS-08: Audit Log Management"],
    "A10:Server-Side Request Forgery":         ["CIS-16: Application Software Security", "CIS-12: Network Infrastructure Management"],
}

# NIST CSF mapping from OWASP categories
NIST_MAPPING: Dict[str, str] = {
    "A01:Broken Access Control":               "PR.AC: Identity Management and Access Control",
    "A02:Cryptographic Failures":              "PR.DS: Data Security",
    "A03:Injection":                           "PR.IP: Information Protection Processes",
    "A04:Insecure Design":                     "PR.IP: Information Protection Processes",
    "A05:Security Misconfiguration":           "PR.IP: Information Protection Processes",
    "A06:Vulnerable and Outdated Components":  "ID.RA: Risk Assessment",
    "A07:Identification and Authentication Failures": "PR.AC: Identity Management and Access Control",
    "A08:Software and Data Integrity Failures": "PR.DS: Data Security",
    "A09:Security Logging and Monitoring Failures": "DE.CM: Security Continuous Monitoring",
    "A10:Server-Side Request Forgery":         "PR.IP: Information Protection Processes",
}


def _score_to_grade(score: float) -> str:
    if score < 20: return "A"
    if score < 40: return "B"
    if score < 60: return "C"
    if score < 75: return "D"
    return "F"


async def calculate_risk(scan_id: int, target: str, db: AsyncSession) -> RiskScore:
    """Calculate and persist risk score for a completed scan."""

    # Load findings
    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings: List[Finding] = findings_res.scalars().all()

    # Load assets
    assets_res = await db.execute(
        select(Asset).where(
            Asset.domain.like(f"%.{target}") | (Asset.domain == target)
        )
    )
    assets: List[Asset] = assets_res.scalars().all()

    # ── 1. Vulnerability Score (0–50) ─────────────────────────────────────────
    raw_vuln = 0.0
    for f in findings:
        w = SEV_WEIGHTS.get(f.severity or "info", 0)
        epss_boost = (f.epss or 0) * 5  # Max +5 per finding
        raw_vuln += w + epss_boost

    # Normalize to 0–50 (cap at 200 raw points = 50 score)
    vuln_score = min(50.0, raw_vuln / 4.0)

    # ── 2. KEV Penalty (0–20) ─────────────────────────────────────────────────
    kev_count = sum(1 for f in findings if f.in_kev)
    kev_score = min(20.0, kev_count * 7.0)

    # ── 3. Exposure Score (0–15) ──────────────────────────────────────────────
    exposure_raw = 0.0
    all_ports: set = set()
    for a in assets:
        for p in (a.ports or []):
            all_ports.add(p)

    for p in all_ports:
        if p in HIGH_RISK_PORTS:
            exposure_raw += 4.0
        elif p not in (80, 443, 22):
            exposure_raw += 0.5

    exposure_score = min(15.0, exposure_raw)

    # ── 4. Hygiene Score (0–15) ───────────────────────────────────────────────
    hygiene_categories = {
        "A02:Cryptographic Failures",
        "A05:Security Misconfiguration",
    }
    hygiene_count = sum(1 for f in findings if (f.category or "") in hygiene_categories)
    hygiene_score = min(15.0, hygiene_count * 2.0)

    # ── Composite score ───────────────────────────────────────────────────────
    total_score = vuln_score + kev_score + exposure_score + hygiene_score

    # ── OWASP coverage ────────────────────────────────────────────────────────
    found_categories = set(f.category for f in findings if f.category)
    owasp_coverage = {}
    for cat in OWASP_CATEGORIES:
        matched = [f for f in findings if f.category == cat]
        owasp_coverage[cat] = {
            "findings": len(matched),
            "critical": sum(1 for f in matched if f.severity == "critical"),
            "high": sum(1 for f in matched if f.severity == "high"),
            "status": "vulnerable" if matched else "not_tested",
        }

    # ── CIS Controls coverage ─────────────────────────────────────────────────
    cis_issues: Dict[str, int] = {}
    for cat in found_categories:
        for ctrl in CIS_MAPPING.get(cat, []):
            cis_issues[ctrl] = cis_issues.get(ctrl, 0) + 1

    cis_coverage = {
        ctrl: {"findings": count, "status": "gap_identified"}
        for ctrl, count in cis_issues.items()
    }

    # ── NIST CSF coverage ─────────────────────────────────────────────────────
    nist_issues: Dict[str, int] = {}
    for cat in found_categories:
        nist_fn = NIST_MAPPING.get(cat)
        if nist_fn:
            nist_issues[nist_fn] = nist_issues.get(nist_fn, 0) + 1

    nist_coverage = {
        fn: {"findings": count, "status": "needs_attention"}
        for fn, count in nist_issues.items()
    }

    # Breakdown for UI
    breakdown = {
        "vuln_score": round(vuln_score, 1),
        "kev_score": round(kev_score, 1),
        "exposure_score": round(exposure_score, 1),
        "hygiene_score": round(hygiene_score, 1),
        "findings_total": len(findings),
        "findings_critical": sum(1 for f in findings if f.severity == "critical"),
        "findings_high": sum(1 for f in findings if f.severity == "high"),
        "findings_medium": sum(1 for f in findings if f.severity == "medium"),
        "findings_kev": kev_count,
        "assets_total": len(assets),
        "open_ports": sorted(list(all_ports))[:20],
        "high_risk_ports_open": sorted([p for p in all_ports if p in HIGH_RISK_PORTS]),
        "owasp_categories_affected": len(found_categories),
    }

    grade = _score_to_grade(total_score)

    # Upsert risk score
    existing_res = await db.execute(
        select(RiskScore).where(RiskScore.scan_id == scan_id)
    )
    risk = existing_res.scalar_one_or_none()

    if risk:
        risk.score = round(total_score, 1)
        risk.grade = grade
        risk.vuln_score = round(vuln_score, 1)
        risk.kev_score = round(kev_score, 1)
        risk.exposure_score = round(exposure_score, 1)
        risk.hygiene_score = round(hygiene_score, 1)
        risk.owasp_coverage = owasp_coverage
        risk.cis_coverage = cis_coverage
        risk.nist_coverage = nist_coverage
        risk.breakdown = breakdown
    else:
        risk = RiskScore(
            scan_id=scan_id,
            target=target,
            score=round(total_score, 1),
            grade=grade,
            vuln_score=round(vuln_score, 1),
            kev_score=round(kev_score, 1),
            exposure_score=round(exposure_score, 1),
            hygiene_score=round(hygiene_score, 1),
            owasp_coverage=owasp_coverage,
            cis_coverage=cis_coverage,
            nist_coverage=nist_coverage,
            breakdown=breakdown,
        )
        db.add(risk)

    await db.commit()
    await db.refresh(risk)

    logger.info(
        "[risk] Scan %d | %s | Score: %.1f | Grade: %s | KEV: %d",
        scan_id, target, total_score, grade, kev_count,
    )
    return risk
