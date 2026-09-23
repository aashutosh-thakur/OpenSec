"""
ScanJob SQLAlchemy model — tracks asset discovery scan jobs
"""
import enum
from sqlalchemy import Column, Integer, String, JSON, DateTime, Enum
from sqlalchemy.sql import func
from app.db.session import Base


class ScanStatus(str, enum.Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    DONE     = "done"
    ERROR    = "error"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id           = Column(Integer, primary_key=True, index=True)
    target       = Column(String(255), nullable=False, index=True)
    status       = Column(String(32), default=ScanStatus.PENDING)
    tools        = Column(JSON, nullable=True)          # List[str] of tool names used
    assets_found = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    error        = Column(String(1024), nullable=True)

    started_at   = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
