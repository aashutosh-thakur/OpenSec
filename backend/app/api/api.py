from fastapi import APIRouter
from app.api.endpoints import assets, scans, stats, findings, risk

api_router = APIRouter()
api_router.include_router(assets.router,   prefix="/assets",   tags=["assets"])
api_router.include_router(scans.router,    prefix="/scans",    tags=["scans"])
api_router.include_router(stats.router,    prefix="/stats",    tags=["stats"])
api_router.include_router(findings.router, prefix="/findings", tags=["findings"])
api_router.include_router(risk.router,     prefix="/risk",     tags=["risk"])
