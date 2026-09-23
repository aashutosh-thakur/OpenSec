"""
Findings API endpoints — OpenSecX Phase 2

GET  /findings/          — list findings with filters
GET  /findings/{id}      — get single finding
PATCH /findings/{id}/triage — update triage status
GET  /findings/scan/{scan_id} — all findings for a scan
DELETE /findings/{id}    — delete finding
"""
from __future__ import annotations

import datetime
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.finding import Finding

router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: int
    scan_id: int
    asset_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    severity: str
    category: Optional[str] = None
    evidence: Optional[dict] = None
    grade: str
    remediation: Optional[str] = None
    cve_id: Optional[str] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    in_kev: bool = False
    priority: Optional[str] = None
    triage_status: str
    triage_note: Optional[str] = None
    triaged_at: Optional[datetime.datetime] = None
    created_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True


class TriageUpdate(BaseModel):
    status: Literal["open", "confirmed_real", "false_positive", "accepted_risk"]
    note: Optional[str] = None


class FindingSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    open: int
    triaged: int
    in_kev: int


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[FindingOut])
async def list_findings(
    scan_id: Optional[int] = Query(None, description="Filter by scan ID"),
    asset_id: Optional[int] = Query(None, description="Filter by asset ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    triage_status: Optional[str] = Query(None, description="Filter by triage status"),
    category: Optional[str] = Query(None, description="Filter by OWASP category"),
    in_kev: Optional[bool] = Query(None, description="Only show KEV findings"),
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List findings with optional filters."""
    q = select(Finding)
    if scan_id is not None:
        q = q.where(Finding.scan_id == scan_id)
    if asset_id is not None:
        q = q.where(Finding.asset_id == asset_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if triage_status:
        q = q.where(Finding.triage_status == triage_status)
    if category:
        q = q.where(Finding.category.ilike(f"%{category}%"))
    if in_kev is not None:
        q = q.where(Finding.in_kev == in_kev)

    # Order: critical first, then by created_at desc
    q = q.order_by(
        Finding.in_kev.desc(),
        Finding.created_at.desc(),
    ).offset(skip).limit(limit)

    result = await db.execute(q)
    return result.scalars().all()


@router.get("/summary", response_model=FindingSummary)
async def findings_summary(
    scan_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated counts for dashboard widgets."""
    q = select(Finding)
    if scan_id is not None:
        q = q.where(Finding.scan_id == scan_id)
    result = await db.execute(q)
    findings = result.scalars().all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_count = 0
    triaged_count = 0
    kev_count = 0

    for f in findings:
        sev = f.severity.lower() if f.severity else "info"
        if sev in severity_counts:
            severity_counts[sev] += 1
        if f.triage_status == "open":
            open_count += 1
        else:
            triaged_count += 1
        if f.in_kev:
            kev_count += 1

    return FindingSummary(
        total=len(findings),
        **severity_counts,
        open=open_count,
        triaged=triaged_count,
        in_kev=kev_count,
    )


@router.get("/scan/{scan_id}", response_model=List[FindingOut])
async def findings_for_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """All findings for a specific scan, ordered by severity."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
        .order_by(Finding.in_kev.desc(), Finding.created_at.desc())
    )
    findings = result.scalars().all()
    return sorted(findings, key=lambda f: severity_order.get(f.severity or "info", 5))


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: int, db: AsyncSession = Depends(get_db)):
    """Get a single finding by ID."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/triage", response_model=FindingOut)
async def triage_finding(
    finding_id: int,
    body: TriageUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update the triage status of a finding with a required reason note."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.triage_status = body.status
    finding.triage_note = body.note
    finding.triaged_at = datetime.datetime.utcnow()
    await db.commit()
    await db.refresh(finding)
    return finding


@router.delete("/{finding_id}", status_code=204)
async def delete_finding(finding_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    await db.delete(finding)
    await db.commit()
