"""
Asset SQLAlchemy model for Phase 1 — Attack Surface & Asset Inventory
"""
from sqlalchemy import Column, Integer, String, JSON, DateTime, Text
from sqlalchemy.sql import func
from app.db.session import Base


class Asset(Base):
    __tablename__ = "assets"

    id           = Column(Integer, primary_key=True, index=True)
    
    # Identity
    domain       = Column(String(255), index=True, nullable=True)
    hostname     = Column(String(255), nullable=True)
    ip_address   = Column(String(64), index=True, nullable=True)

    # Network
    ports        = Column(JSON, nullable=True)          # List[int]
    protocol     = Column(String(32), nullable=True)   # tcp / udp

    # Service / Tech
    service      = Column(String(128), nullable=True)
    technologies = Column(JSON, nullable=True)          # List[str]

    # DNS / TLS
    dns_records  = Column(JSON, nullable=True)          # dict
    certificate  = Column(JSON, nullable=True)          # dict: subject, issuer, expiry

    # OSINT metadata
    source       = Column(String(64), nullable=True)   # which tool found it
    asn          = Column(String(64), nullable=True)
    org          = Column(String(255), nullable=True)
    country      = Column(String(64), nullable=True)

    # Status
    status       = Column(String(32), default="Active")  # Active, Warning, Critical, Inactive
    notes        = Column(Text, nullable=True)

    # Timestamps
    first_seen   = Column(DateTime(timezone=True), server_default=func.now())
    last_seen    = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())
