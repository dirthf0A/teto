from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from app.db import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, unique=True)
    billing_plan = Column(String(32), nullable=True, default="free")
    billing_status = Column(String(32), nullable=True, default="active")
    stripe_customer_id = Column(String(128), nullable=True)
    stripe_subscription_id = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    users = relationship("User", back_populates="organization")
    assets = relationship("Asset", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    email = Column(String(255), nullable=False, unique=True)
    role = Column(String(50), nullable=False, default="member")
    api_key = Column(String(128), nullable=True)
    password_hash = Column(String(255), nullable=True)
    oauth_provider = Column(String(32), nullable=True)
    oauth_subject = Column(String(255), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    organization = relationship("Organization", back_populates="users")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_type = Column(String(32), nullable=True, default="domain")
    domain = Column(String(255), nullable=True)
    subdomain = Column(String(255), nullable=True)
    ip = Column(String(64), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True, default="tcp")
    url = Column(Text, nullable=True)
    service = Column(String(120), nullable=True)
    technology = Column(Text, nullable=True)
    asn = Column(String(64), nullable=True)
    hosting_provider = Column(String(255), nullable=True)
    cdn = Column(String(120), nullable=True)
    country = Column(String(64), nullable=True)
    environment = Column(String(32), nullable=True, default="prod")
    tags = Column(String(255), nullable=True)
    importance = Column(Float, nullable=True, default=1.0)
    exposure_class = Column(String(32), nullable=True)
    exposure_score = Column(Float, nullable=True, default=1.0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    organization = relationship("Organization", back_populates="assets")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    scan_type = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="scheduled")
    scheduled_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    tool = Column(String(64), nullable=False)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    fingerprint = Column(String(128), nullable=True, index=True)
    severity = Column(String(16), nullable=False, default="info")
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    tool = Column(String(64), nullable=True)
    target = Column(Text, nullable=True)
    port = Column(Integer, nullable=True)
    cvss = Column(Float, nullable=True)
    cve = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="open")
    risk_score = Column(Float, nullable=True)
    exposure_score = Column(Float, nullable=True)
    asset_importance = Column(Float, nullable=True)
    false_positive = Column(Boolean, default=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    occurrences = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=True, index=True)
    alert_type = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="new")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    actor = Column(String(120), nullable=True)
    action = Column(String(120), nullable=False)
    target_type = Column(String(120), nullable=True)
    target_id = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AssetEdge(Base):
    __tablename__ = "asset_relationships"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    source_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    target_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    relation = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AssetSnapshot(Base):
    __tablename__ = "asset_history"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    fingerprint = Column(String(128), nullable=False, index=True)
    asset_type = Column(String(32), nullable=True)
    domain = Column(String(255), nullable=True)
    subdomain = Column(String(255), nullable=True)
    ip = Column(String(64), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    url = Column(Text, nullable=True)
    service = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AssetChange(Base):
    __tablename__ = "asset_changes"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    change_type = Column(String(64), nullable=False)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Plan(Base):
    __tablename__ = "plans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    price_monthly = Column(Float, nullable=False, default=0.0)
    currency = Column(String(8), nullable=False, default="usd")
    stripe_price_id = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="trialing")
    stripe_customer_id = Column(String(120), nullable=True)
    stripe_subscription_id = Column(String(120), nullable=True)
    current_period_end = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    provider = Column(String(40), nullable=False)
    provider_user_id = Column(String(128), nullable=False)
    email = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Asset Ownership
# ---------------------------------------------------------------------------

class AssetOwnership(Base):
    __tablename__ = "asset_ownership"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    team_name = Column(String(120), nullable=False)
    owner_email = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class AttackSurfaceScore(Base):
    __tablename__ = "attack_surface_scores"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    domain = Column(String(255), nullable=True)
    score = Column(Float, nullable=False, default=0.0)
    total_assets = Column(Integer, nullable=False, default=0)
    exposed_services = Column(Integer, nullable=False, default=0)
    critical_vulns = Column(Integer, nullable=False, default=0)
    high_vulns = Column(Integer, nullable=False, default=0)
    public_buckets = Column(Integer, nullable=False, default=0)
    open_high_risk_ports = Column(Integer, nullable=False, default=0)
    breakdown = Column(Text, nullable=True)  # JSON
    computed_at = Column(DateTime(timezone=True), server_default=func.now())


class NucleiTemplate(Base):
    """Custom nuclei template uploaded by user."""
    __tablename__ = "nuclei_templates"

    id          = Column(Integer, primary_key=True, index=True)
    org_id      = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name        = Column(String(200), nullable=False)
    slug        = Column(String(200), nullable=False, index=True)  # filename-safe id
    description = Column(Text, nullable=True)
    severity    = Column(String(16), nullable=False, default="medium")
    tags        = Column(String(255), nullable=True)
    content     = Column(Text, nullable=False)   # YAML template body
    enabled     = Column(Boolean, nullable=False, default=True)
    created_by  = Column(String(255), nullable=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    updated_at  = Column(DateTime(timezone=True), onupdate=func.now())
