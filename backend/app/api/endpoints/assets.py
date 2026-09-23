"""
Assets API endpoints — Phase 1
GET  /api/v1/assets/          - List all assets (with optional search + status filter)
GET  /api/v1/assets/{id}      - Get single asset
POST /api/v1/assets/          - Create an asset manually
PUT  /api/v1/assets/{id}      - Update an asset
DELETE /api/v1/assets/{id}    - Delete an asset
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import or_
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from app.db.session import get_db
from app.models.asset import Asset

router = APIRouter()


# ─── Pydantic Schemas ────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    domain:       Optional[str] = None
    hostname:     Optional[str] = None
    ip_address:   Optional[str] = None
    ports:        Optional[List[int]] = None
    protocol:     Optional[str] = None
    service:      Optional[str] = None
    technologies: Optional[List[str]] = None
    dns_records:  Optional[dict] = None
    certificate:  Optional[dict] = None
    source:       Optional[str] = None
    asn:          Optional[str] = None
    org:          Optional[str] = None
    country:      Optional[str] = None
    status:       Optional[str] = "Active"
    notes:        Optional[str] = None


class AssetUpdate(BaseModel):
    domain:       Optional[str] = None
    hostname:     Optional[str] = None
    ip_address:   Optional[str] = None
    ports:        Optional[List[int]] = None
    protocol:     Optional[str] = None
    service:      Optional[str] = None
    technologies: Optional[List[str]] = None
    dns_records:  Optional[dict] = None
    certificate:  Optional[dict] = None
    source:       Optional[str] = None
    asn:          Optional[str] = None
    org:          Optional[str] = None
    country:      Optional[str] = None
    status:       Optional[str] = None
    notes:        Optional[str] = None


class AssetResponse(BaseModel):
    id:           int
    domain:       Optional[str]
    hostname:     Optional[str]
    ip_address:   Optional[str]
    ports:        Optional[List[int]]
    protocol:     Optional[str]
    service:      Optional[str]
    technologies: Optional[List[str]]
    dns_records:  Optional[dict]
    certificate:  Optional[dict]
    source:       Optional[str]
    asn:          Optional[str]
    org:          Optional[str]
    country:      Optional[str]
    status:       str
    notes:        Optional[str]
    first_seen:   Optional[datetime]
    last_seen:    Optional[datetime]

    class Config:
        from_attributes = True


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.get("/", response_model=List[AssetResponse])
async def list_assets(
    search: Optional[str] = Query(None, description="Search by domain, IP, or technology"),
    status: Optional[str] = Query(None, description="Filter by status: Active, Warning, Critical, Inactive"),
    skip: int = 0,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
):
    """List all discovered assets with optional search and status filter."""
    query = select(Asset)

    if search:
        query = query.where(
            or_(
                Asset.domain.ilike(f"%{search}%"),
                Asset.ip_address.ilike(f"%{search}%"),
                Asset.hostname.ilike(f"%{search}%"),
            )
        )

    if status:
        query = query.where(Asset.status == status)

    query = query.offset(skip).limit(limit).order_by(Asset.id.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: int, db: AsyncSession = Depends(get_db)):
    """Get a single asset by ID."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.post("/", response_model=AssetResponse, status_code=201)
async def create_asset(payload: AssetCreate, db: AsyncSession = Depends(get_db)):
    """Manually create an asset record."""
    asset = Asset(**payload.model_dump())
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: int, payload: AssetUpdate, db: AsyncSession = Depends(get_db)):
    """Update an existing asset."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)

    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: int, db: AsyncSession = Depends(get_db)):
    """Delete an asset record."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    await db.delete(asset)
    await db.commit()
