from __future__ import annotations

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    environment = Column(String(32), nullable=True, default="prod")
    tags = Column(String(255), nullable=True)
    status = Column(String(32), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)

    assets = relationship("Asset", back_populates="target")
    scans = relationship("ScanJob", back_populates="target")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    asset_type = Column(String(32), nullable=False, default="domain")
    domain = Column(String(255), nullable=True)
    subdomain = Column(String(255), nullable=True)
    ip = Column(String(64), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True, default="tcp")
    url = Column(Text, nullable=True)
    service = Column(String(120), nullable=True)
    provider = Column(String(120), nullable=True)
    technology = Column(Text, nullable=True)
    exposure_class = Column(String(32), nullable=True)
    risk_score = Column(Float, nullable=True)
    metadata = Column(JSON, nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())

    target = relationship("Target", back_populates="assets")


class AssetEdge(Base):
    __tablename__ = "asset_edges"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    source_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    target_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    relation = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="queued")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(Text, nullable=True)

    target = relationship("Target", back_populates="scans")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=True, index=True)
    severity = Column(String(16), nullable=False, default="info")
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="open")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
