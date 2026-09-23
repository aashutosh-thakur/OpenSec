"""
Risk & Compliance API — OpenSecX Phase 4

IMPORTANT: Static routes (/summary) MUST be declared before parameterised
routes (/{scan_id}) so FastAPI doesn't try to parse "summary" as an integer.

Endpoints:
  GET /risk/summary            → Aggregate risk across all scans  [static - must be first]
  GET /risk/{scan_id}          → Risk score + breakdown + compliance
  POST /risk/{scan_id}/recalculate → Force recalculation
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.risk import RiskScore
from app.models.scan import ScanJob, ScanStatus

router = APIRouter()


# ── STATIC ROUTES FIRST ───────────────────────────────────────────────────────

@router.get("/summary")
async def risk_summary(db: AsyncSession = Depends(get_db)):
    """Aggregate risk across all completed scans."""
    res = await db.execute(select(RiskScore))
    scores = res.scalars().all()

    if not scores:
        return {
            "total_scans_scored": 0,
            "average_score": None,
            "worst_score": None,
            "best_score": None,
            "grade_distribution": {},
            "latest_scores": [],
        }

    avg = sum(r.score for r in scores) / len(scores)
    worst = max(scores, key=lambda r: r.score)
    best = min(scores, key=lambda r: r.score)

    grade_dist: dict = {}
    for r in scores:
        grade_dist[r.grade] = grade_dist.get(r.grade, 0) + 1

    latest = sorted(scores, key=lambda r: r.id, reverse=True)[:5]

    return {
        "total_scans_scored": len(scores),
        "average_score": round(avg, 1),
        "worst_score": {
            "scan_id": worst.scan_id,
            "target": worst.target,
            "score": worst.score,
            "grade": worst.grade,
        },
        "best_score": {
            "scan_id": best.scan_id,
            "target": best.target,
            "score": best.score,
            "grade": best.grade,
        },
        "grade_distribution": grade_dist,
        "latest_scores": [
            {"scan_id": r.scan_id, "target": r.target, "score": r.score, "grade": r.grade}
            for r in latest
        ],
    }


@router.post("/backfill")
async def backfill_risk_scores(db: AsyncSession = Depends(get_db)):
    """
    Calculate risk scores for all completed scans that don't have one yet.
    Call this once after upgrading to Phase 4 to score historical scans.
    """
    from app.services.risk_scorer import calculate_risk

    # Find all done scans
    done_res = await db.execute(
        select(ScanJob).where(ScanJob.status == ScanStatus.DONE)
    )
    done_scans = done_res.scalars().all()

    # Find which already have scores
    scored_res = await db.execute(select(RiskScore.scan_id))
    already_scored = {row for row in scored_res.scalars().all()}

    results = []
    for scan in done_scans:
        if scan.id in already_scored:
            results.append({"scan_id": scan.id, "target": scan.target, "status": "already_scored"})
            continue
        try:
            risk = await calculate_risk(scan.id, scan.target, db)
            results.append({"scan_id": scan.id, "target": scan.target, "status": "scored", "score": risk.score, "grade": risk.grade})
        except Exception as e:
            results.append({"scan_id": scan.id, "target": scan.target, "status": "error", "error": str(e)})

    return {"processed": len(done_scans), "results": results}


# ── PARAMETERISED ROUTES AFTER ────────────────────────────────────────────────

@router.get("/{scan_id}")
async def get_risk_score(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Full risk score + compliance breakdown for a scan."""
    res = await db.execute(select(RiskScore).where(RiskScore.scan_id == scan_id))
    risk = res.scalar_one_or_none()

    if not risk:
        # Calculate on demand if scan is done
        scan_res = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
        scan = scan_res.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status != ScanStatus.DONE:
            return {
                "scan_id": scan_id,
                "status": "scan_not_complete",
                "score": None,
                "grade": None,
                "components": {},
                "owasp_coverage": {},
                "cis_coverage": {},
                "nist_coverage": {},
                "breakdown": {},
                "calculated_at": None,
            }
        from app.services.risk_scorer import calculate_risk
        risk = await calculate_risk(scan_id, scan.target, db)

    return {
        "scan_id": risk.scan_id,
        "target": risk.target,
        "score": risk.score,
        "grade": risk.grade,
        "components": {
            "vulnerability": risk.vuln_score,
            "kev_penalty": risk.kev_score,
            "exposure": risk.exposure_score,
            "hygiene": risk.hygiene_score,
        },
        "owasp_coverage": risk.owasp_coverage or {},
        "cis_coverage": risk.cis_coverage or {},
        "nist_coverage": risk.nist_coverage or {},
        "breakdown": risk.breakdown or {},
        "calculated_at": risk.created_at.isoformat() if risk.created_at else None,
    }


@router.post("/{scan_id}/recalculate")
async def recalculate_risk(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Force risk recalculation for a scan."""
    scan_res = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.DONE:
        raise HTTPException(status_code=400, detail="Scan is not complete yet")

    from app.services.risk_scorer import calculate_risk
    risk = await calculate_risk(scan_id, scan.target, db)
    return {"scan_id": scan_id, "score": risk.score, "grade": risk.grade}
