"""
Stats endpoint — Phase 1
GET /api/v1/stats/   - Live platform statistics computed from real database records

Returns real counts — no hardcoded or simulated values.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, distinct
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta

from app.db.session import get_db
from app.models.asset import Asset
from app.models.scan import ScanJob, ScanStatus

router = APIRouter()


class PlatformStats(BaseModel):
    """
    Live platform statistics derived entirely from the database.
    All values are real counts — none are hardcoded or estimated.
    """
    total_assets: int
    active_assets: int
    warning_assets: int
    critical_assets: int
    inactive_assets: int
    internet_facing_assets: int   # Assets with ports 80/443
    unique_domains: int
    unique_ips: int
    unique_ports: int
    total_scans: int
    running_scans: int
    completed_scans: int
    failed_scans: int
    last_scan_at: Optional[datetime]
    assets_added_today: int
    assets_added_last_7_days: int


@router.get("/", response_model=PlatformStats)
async def get_stats(db: AsyncSession = Depends(get_db)):
    """
    Return live platform statistics computed from real database records.

    All values reflect the actual state of the database.
    No mock or simulated values are ever returned.
    """
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = now - timedelta(days=7)

    # ── Asset counts ──────────────────────────────────────────────────────────
    total_result = await db.execute(select(func.count(Asset.id)))
    total_assets = total_result.scalar() or 0

    active_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.status == "Active")
    )
    active_assets = active_result.scalar() or 0

    warning_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.status == "Warning")
    )
    warning_assets = warning_result.scalar() or 0

    critical_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.status == "Critical")
    )
    critical_assets = critical_result.scalar() or 0

    inactive_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.status == "Inactive")
    )
    inactive_assets = inactive_result.scalar() or 0

    # ── Unique identifiers ────────────────────────────────────────────────────
    domains_result = await db.execute(
        select(func.count(distinct(Asset.domain))).where(Asset.domain.isnot(None))
    )
    unique_domains = domains_result.scalar() or 0

    ips_result = await db.execute(
        select(func.count(distinct(Asset.ip_address))).where(Asset.ip_address.isnot(None))
    )
    unique_ips = ips_result.scalar() or 0

    # ── Port data — compute unique port count from JSON arrays ────────────────
    # Fetch all port arrays and flatten in Python (SQLite doesn't have JSON_TABLE)
    ports_result = await db.execute(
        select(Asset.ports).where(Asset.ports.isnot(None))
    )
    all_port_lists = ports_result.scalars().all()
    unique_port_set: set[int] = set()
    for port_list in all_port_lists:
        if isinstance(port_list, list):
            unique_port_set.update(port_list)
    unique_ports = len(unique_port_set)

    # ── Internet-facing: assets with port 80 or 443 in their ports list ───────
    internet_facing_result = await db.execute(
        select(Asset.ports).where(Asset.ports.isnot(None))
    )
    internet_facing = 0
    for port_list in internet_facing_result.scalars().all():
        if isinstance(port_list, list) and (80 in port_list or 443 in port_list):
            internet_facing += 1

    # ── Scan job stats ────────────────────────────────────────────────────────
    total_scans_result = await db.execute(select(func.count(ScanJob.id)))
    total_scans = total_scans_result.scalar() or 0

    running_result = await db.execute(
        select(func.count(ScanJob.id)).where(ScanJob.status == ScanStatus.RUNNING)
    )
    running_scans = running_result.scalar() or 0

    done_result = await db.execute(
        select(func.count(ScanJob.id)).where(ScanJob.status == ScanStatus.DONE)
    )
    completed_scans = done_result.scalar() or 0

    failed_result = await db.execute(
        select(func.count(ScanJob.id)).where(ScanJob.status == ScanStatus.ERROR)
    )
    failed_scans = failed_result.scalar() or 0

    # Last scan timestamp
    last_scan_result = await db.execute(
        select(ScanJob.started_at).order_by(ScanJob.id.desc()).limit(1)
    )
    last_scan_at = last_scan_result.scalar_one_or_none()

    # ── Recent asset additions ────────────────────────────────────────────────
    today_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.first_seen >= today_start)
    )
    assets_added_today = today_result.scalar() or 0

    week_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.first_seen >= week_ago)
    )
    assets_added_last_7_days = week_result.scalar() or 0

    return PlatformStats(
        total_assets=total_assets,
        active_assets=active_assets,
        warning_assets=warning_assets,
        critical_assets=critical_assets,
        inactive_assets=inactive_assets,
        internet_facing_assets=internet_facing,
        unique_domains=unique_domains,
        unique_ips=unique_ips,
        unique_ports=unique_ports,
        total_scans=total_scans,
        running_scans=running_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        last_scan_at=last_scan_at,
        assets_added_today=assets_added_today,
        assets_added_last_7_days=assets_added_last_7_days,
    )
