"""
Risk Scoring Model — OpenSecX Phase 4

Stores per-scan and per-asset risk scores with breakdowns.
"""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import Column, Integer, Float, String, JSON, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.db.session import Base


class RiskScore(Base):
    """Overall risk score for a scan (0–100, higher = worse)."""
    __tablename__ = "risk_scores"

    id              = Column(Integer, primary_key=True, index=True)
    scan_id         = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    target          = Column(String(255), nullable=False)

    # Composite score 0–100
    score           = Column(Float, default=0.0)     # Overall risk score
    grade           = Column(String(2), default="F") # A–F letter grade

    # Component scores
    vuln_score      = Column(Float, default=0.0)   # Weighted findings score
    exposure_score  = Column(Float, default=0.0)   # Open ports / internet-facing
    hygiene_score   = Column(Float, default=0.0)   # Headers, TLS, cookies
    kev_score       = Column(Float, default=0.0)   # CISA KEV penalty

    # Compliance coverage
    owasp_coverage  = Column(JSON, nullable=True)  # {category: {found, total, status}}
    cis_coverage    = Column(JSON, nullable=True)  # CIS Controls mapping
    nist_coverage   = Column(JSON, nullable=True)  # NIST CSF mapping

    # Raw data for breakdown display
    breakdown       = Column(JSON, nullable=True)

    created_at      = Column(DateTime(timezone=True), server_default=func.now())
    updated_at      = Column(DateTime(timezone=True), onupdate=func.now())
