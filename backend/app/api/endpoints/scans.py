"""
Scan endpoint — Phase 1
POST /api/v1/scans/start  - Start a real asset discovery scan for an authorized target
GET  /api/v1/scans/       - List recent scan jobs
GET  /api/v1/scans/{id}   - Get status of a specific scan

AUTHORIZED USE ONLY — only scan systems you own or are explicitly authorized to assess.
All scan targets are recorded for audit purposes.
"""
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel, field_validator
from typing import Optional, List
from datetime import datetime
import re
import logging

from app.db.session import get_db
from app.models.scan import ScanJob, ScanStatus

logger = logging.getLogger(__name__)
router = APIRouter()


# ─── Schemas ─────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    tools: Optional[List[str]] = None
    profile: Optional[str] = "full"  # "recon" = discovery only, "full" = discovery + vuln
    notes: Optional[str] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip().lower()
        domain_pattern = r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        cidr_pattern = r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$"
        if not (
            re.match(domain_pattern, v)
            or re.match(ip_pattern, v)
            or re.match(cidr_pattern, v)
        ):
            raise ValueError(
                f"'{v}' is not a valid domain name or IP address. "
                "Please provide a fully-qualified domain (e.g. example.com) or an IP."
            )
        return v


class ScanResponse(BaseModel):
    id: int
    target: str
    status: str
    tools: Optional[List[str]]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    assets_found: int
    findings_count: Optional[int] = 0
    error: Optional[str]

    class Config:
        from_attributes = True


# ─── Background discovery task ───────────────────────────────────────────────

async def run_discovery(scan_id: int, target: str, tools: List[str], profile: str = "full"):
    """
    Run the full scan pipeline:
      Phase 1: Asset discovery (always runs)
      Phase 2: Vulnerability assessment (runs if profile == 'full')
    """
    from app.db.session import AsyncSessionLocal
    from app.services.discovery import DiscoveryOrchestrator

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return
        scan.status = ScanStatus.RUNNING
        await db.commit()

        try:
            # ── Phase 1: Asset Discovery ─────────────────────────────────────
            orchestrator = DiscoveryOrchestrator()
            tool_statuses, assets_found = await orchestrator.run(
                scan_id=scan_id,
                target=target,
                tools=tools,
                db=db,
            )

            # ── Phase 2: Vulnerability Scan (full profile only) ───────────
            findings_count = 0
            if profile == "full":
                try:
                    from app.services.vuln_orchestrator import run_vuln_scan
                    findings_count = await run_vuln_scan(
                        scan_id=scan_id,
                        target=target,
                        db=db,
                    )
                    tool_statuses["vuln_scan"] = "ok"
                    logger.info("[scan %d] Vuln scan: %d findings", scan_id, findings_count)
                except Exception as ve:
                    logger.error("[scan %d] Vuln scan error: %s", scan_id, ve)
                    tool_statuses["vuln_scan"] = "error"

                # ── Phase 3: Risk Scoring ─────────────────────────────────────
                try:
                    from app.services.risk_scorer import calculate_risk
                    risk = await calculate_risk(scan_id, target, db)
                    tool_statuses["risk_score"] = "ok"
                    logger.info("[scan %d] Risk score: %.1f (%s)", scan_id, risk.score, risk.grade)
                except Exception as re:
                    logger.error("[scan %d] Risk scoring error: %s", scan_id, re)
                    tool_statuses["risk_score"] = "error"

            # Update scan job
            result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.DONE
                scan.completed_at = datetime.utcnow()
                scan.assets_found = assets_found
                scan.findings_count = findings_count
                scan.tools = [
                    f"{tool}:{status}" for tool, status in tool_statuses.items()
                ]
                await db.commit()

            logger.info(
                "[scan %d] Completed: %d assets, %d findings for %s",
                scan_id, assets_found, findings_count, target,
            )

        except Exception as exc:
            logger.exception("[scan %d] Scan failed for %s: %s", scan_id, target, exc)
            result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.ERROR
                scan.error = str(exc)[:1024]
                scan.completed_at = datetime.utcnow()
                await db.commit()


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/start", response_model=ScanResponse, status_code=202)
async def start_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Start an asset discovery scan for an authorized target domain or IP.

    The scan runs all available tools in the background:
    - crt.sh (always available — HTTP only)
    - Subfinder (requires binary on PATH)
    - dnsx (requires binary on PATH)
    - httpx (requires ProjectDiscovery httpx binary on PATH)
    - Nmap (requires nmap binary on PATH)
    - WHOIS (requires python-whois: pip install python-whois)

    Poll GET /api/v1/scans/{id} for real-time status updates.

    IMPORTANT: Only scan systems you own or are explicitly authorized to assess.
    This endpoint logs all scan targets for audit purposes.
    """
    scan = ScanJob(
        target=payload.target,
        tools=payload.tools or [],
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    logger.info(
        "[scan %d] Queued discovery for target=%s tools=%s",
        scan.id, payload.target, payload.tools,
    )

    background_tasks.add_task(
        run_discovery,
        scan.id,
        payload.target,
        payload.tools or [],
        payload.profile or "full",
    )
    return scan


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """List recent scan jobs ordered by most recent first."""
    result = await db.execute(
        select(ScanJob).order_by(ScanJob.id.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get the current status and details of a specific scan job."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ─── Phase 3: Report & Attack Path Endpoints ─────────────────────────────────

@router.get("/{scan_id}/report")
async def get_scan_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Full JSON report: assets + findings + attack paths + summary."""
    from app.services.report_export import build_report_data
    data = await build_report_data(scan_id, db)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data


@router.get("/{scan_id}/report.html")
async def export_html_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Download self-contained HTML report."""
    from fastapi.responses import HTMLResponse
    from app.services.report_export import build_report_data, render_html_report
    data = await build_report_data(scan_id, db)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    html = render_html_report(data)
    target = data.get("meta", {}).get("target", "report")
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="opensecx-{target}-scan{scan_id}.html"'},
    )


@router.get("/{scan_id}/attack-paths")
async def get_attack_paths(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get structured attack paths for a completed scan."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    from app.services.attack_path import build_attack_paths
    paths = await build_attack_paths(scan_id, scan.target, db)
    return {"scan_id": scan_id, "target": scan.target, "count": len(paths), "paths": paths}
