from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.api.api import api_router
from app.db.session import engine, Base
# Import models so SQLAlchemy registers them before create_all
import app.models.asset    # noqa: F401
import app.models.scan     # noqa: F401
import app.models.finding  # noqa: F401
import app.models.risk     # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create all database tables on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title="OpenSecX API",
    description="Open-source Cybersecurity Exposure Management Platform — Phase 1 & 2",
    version="2.0.0",
    lifespan=lifespan,
)

# Allow all origins for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/health", tags=["system"])
async def health_check():
    return {"status": "ok", "service": "opensecx-api", "phase": 1}
