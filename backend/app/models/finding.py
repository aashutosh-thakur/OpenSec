"""
Finding SQLAlchemy model — OpenSecX Phase 2

Represents a security finding produced by vulnerability scanners.
Each finding is linked to a scan job and optionally to a specific asset.

Evidence grades (from ReconTitan methodology):
  confirmed — directly observed on this target
  supported — multiple observations agree / authoritative source
  possible  — plausible inference, never executed

Triage status:
  open           — not yet reviewed
  confirmed_real — reviewed and confirmed as a real issue
  false_positive — reviewed and dismissed
  accepted_risk  — reviewed, understood, and accepted
"""
import datetime
import enum
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.db.session import Base


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class FindingGrade(str, enum.Enum):
    CONFIRMED = "confirmed"
    SUPPORTED = "supported"
    POSSIBLE  = "possible"


class TriageStatus(str, enum.Enum):
    OPEN           = "open"
    CONFIRMED_REAL = "confirmed_real"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK  = "accepted_risk"


class Finding(Base):
    __tablename__ = "findings"

    id          = Column(Integer, primary_key=True, index=True)
    scan_id     = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id    = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)

    # Core fields
    title       = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity    = Column(String(32), default="medium")      # critical/high/medium/low/info
    category    = Column(String(128), nullable=True)        # OWASP category e.g. "A02:Cryptographic Failures"
    evidence    = Column(JSON, nullable=True)               # structured evidence dict
    grade       = Column(String(32), default="supported")   # confirmed/supported/possible
    remediation = Column(Text, nullable=True)

    # CVE-specific fields
    cve_id      = Column(String(32), nullable=True, index=True)
    cvss        = Column(Float, nullable=True)
    epss        = Column(Float, nullable=True)
    in_kev      = Column(Boolean, default=False)
    priority    = Column(String(16), nullable=True)         # URGENT/HIGH/ELEVATED/STANDARD/VERIFY

    # Triage
    triage_status = Column(String(32), default="open")
    triage_note   = Column(Text, nullable=True)
    triaged_at    = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    updated_at  = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
