from datetime import datetime, timedelta
from io import BytesIO, StringIO
import csv
import secrets
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import config
from app.db import SessionLocal, init_db
from app.models import (
    ActivityLog,
    Alert,
    Asset,
    AssetChange,
    AssetEdge,
    AssetSnapshot,
    Finding,
    Organization,
    Plan,
    Scan,
    Subscription,
    OAuthAccount,
    User,
)
from app.schemas import (
    ActivityLogOut,
    AlertOut,
    ApiKeyOut,
    AssetEdgeOut,
    AssetIngestRequest,
    AssetInventoryOut,
    AssetOut,
    AssetUpdate,
    AssetChangeOut,
    AssetHistoryOut,
    BillingCheckoutOut,
    BillingCheckoutRequest,
    FindingOut,
    LoginRequest,
    OAuthStartOut,
    OrganizationCreate,
    OrganizationOut,
    PlanOut,
    RegisterRequest,
    ScanCreate,
    ScanOut,
    SubscriptionOut,
    TokenOut,
)
from app.security import authenticate_user, create_access_token, get_current_user, hash_password, require_role
from app.services import (
    analysis,
    asset_discovery,
    asset_enrichment,
    asset_graph_builder,
    asset_intelligence,
    billing,
    oauth,
)


app = FastAPI(title="Enterprise ASM Platform")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_SCAN_TYPES = {
    "asset_discovery",
    "service",
    "web",
    "api",
    "misconfig",
    "tls",
    "headers",
    "exposed",
    "vuln",
    "deep",
    "secret",
}


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_activity(
    db: Session,
    org_id: int,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    details: Optional[str] = None,
    actor: Optional[str] = None,
) -> None:
    entry = ActivityLog(
        org_id=org_id,
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
    )
    db.add(entry)
    db.commit()


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.post("/auth/register", response_model=TokenOut)
@limiter.limit(config.get_rate_limit())
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    existing = db.execute(select(User).where(User.email == payload.email)).scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    org = Organization(name=payload.org_name)
    db.add(org)
    db.flush()

    user = User(
        org_id=org.id,
        email=payload.email,
        role="admin",
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    token = create_access_token(payload.email)
    return TokenOut(access_token=token)


@app.post("/auth/token", response_model=TokenOut)
@limiter.limit(config.get_rate_limit())
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    user = authenticate_user(db, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user.email)
    return TokenOut(access_token=token)


@app.get("/auth/oauth/{provider}/start", response_model=OAuthStartOut)
def oauth_start(provider: str) -> OAuthStartOut:
    try:
        url = oauth.build_authorization_url(provider)
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return OAuthStartOut(authorization_url=url)


@app.get("/auth/oauth/{provider}/callback", response_model=TokenOut)
def oauth_callback(
    provider: str,
    code: str = Query(..., min_length=3),
    db: Session = Depends(get_db),
) -> TokenOut:
    try:
        profile = oauth.fetch_profile(provider, code)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="OAuth exchange failed") from exc
    email = profile.get("email")
    provider_user_id = profile.get("provider_user_id")
    if not email or not provider_user_id:
        raise HTTPException(status_code=400, detail="OAuth provider did not return email")

    user = db.execute(select(User).where(User.email == email)).scalars().first()
    if not user:
        org_name = email.split("@")[-1]
        org = db.execute(select(Organization).where(Organization.name == org_name)).scalars().first()
        if not org:
            org = Organization(name=org_name)
            db.add(org)
            db.flush()
        user = User(org_id=org.id, email=email, role="admin")
        db.add(user)
        db.flush()

    existing_account = (
        db.execute(
            select(OAuthAccount).where(
                OAuthAccount.user_id == user.id,
                OAuthAccount.provider == provider.lower(),
                OAuthAccount.provider_user_id == provider_user_id,
            )
        )
        .scalars()
        .first()
    )
    if not existing_account:
        db.add(
            OAuthAccount(
                user_id=user.id,
                provider=provider.lower(),
                provider_user_id=provider_user_id,
                email=email,
            )
        )
    db.commit()
    token = create_access_token(user.email)
    return TokenOut(access_token=token)


@app.post("/auth/api-key", response_model=ApiKeyOut)
@limiter.limit(config.get_rate_limit())
def issue_api_key(
    request: Request,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> ApiKeyOut:
    api_key = secrets.token_urlsafe(32)
    current_user.api_key = api_key
    db.commit()
    return ApiKeyOut(api_key=api_key)


@app.get("/billing/plans", response_model=List[PlanOut])
def list_billing_plans(db: Session = Depends(get_db)) -> List[PlanOut]:
    return billing.ensure_default_plans(db)


@app.get("/billing/subscription", response_model=SubscriptionOut)
def get_billing_subscription(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> SubscriptionOut:
    return billing.get_or_create_subscription(db, current_user.org_id)


@app.post("/billing/checkout", response_model=BillingCheckoutOut)
def create_billing_checkout(
    payload: BillingCheckoutRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BillingCheckoutOut:
    try:
        url = billing.create_checkout_session(db, current_user.org_id, payload.plan_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return BillingCheckoutOut(checkout_url=url)


@app.post("/billing/webhook")
async def billing_webhook(request: Request, db: Session = Depends(get_db)) -> Dict[str, str]:
    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    event = billing.parse_webhook(payload, signature)
    if not event:
        raise HTTPException(status_code=400, detail="Invalid webhook payload")
    billing.apply_webhook_event(db, event)
    return {"status": "ok"}


@app.post("/orgs", response_model=OrganizationOut)
def create_org(
    payload: OrganizationCreate,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> OrganizationOut:
    org = Organization(name=payload.name)
    db.add(org)
    db.commit()
    db.refresh(org)
    log_activity(db, org_id=current_user.org_id, action="org_created", actor=current_user.email)
    return org


@app.post("/assets/ingest", response_model=List[AssetOut])
@limiter.limit(config.get_rate_limit())
def ingest_assets(
    payload: AssetIngestRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AssetOut]:
    if not payload.domain and not payload.ip_range:
        raise HTTPException(status_code=400, detail="domain or ip_range is required")

    candidates = []
    if payload.domain:
        candidates.extend(asset_discovery.ingest_domain(payload.domain, payload.environment))
    if payload.ip_range:
        try:
            candidates.extend(asset_discovery.ingest_ip_range(payload.ip_range, payload.environment))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"invalid ip_range: {exc}") from exc

    if not candidates:
        raise HTTPException(status_code=400, detail="no assets discovered")

    existing = {
        (
            asset.asset_type,
            asset.domain,
            asset.subdomain,
            asset.ip,
            asset.port,
            asset.protocol,
            asset.url,
        )
        for asset in db.execute(select(Asset).where(Asset.org_id == current_user.org_id)).scalars().all()
    }

    created: List[Asset] = []
    domain_asset = None
    if payload.domain:
        domain_asset = (
            db.execute(
                select(Asset).where(
                    Asset.org_id == current_user.org_id,
                    Asset.domain == payload.domain,
                    Asset.asset_type == "domain",
                )
            )
            .scalars()
            .first()
        )

    for candidate in candidates:
        candidate = asset_discovery.discover_services(candidate)
        key = (
            candidate.asset_type,
            candidate.domain,
            candidate.subdomain,
            candidate.ip,
            candidate.port,
            candidate.protocol,
            candidate.url,
        )
        if key in existing:
            continue
        importance = payload.importance or asset_intelligence.compute_asset_importance(
            candidate.environment, payload.tags, candidate.asset_type
        )
        exposure_class = asset_intelligence.classify_exposure(
            candidate.environment, payload.tags, candidate.asset_type, ip=candidate.ip
        )
        exposure_score = asset_intelligence.exposure_score(exposure_class)
        asset = Asset(
            org_id=current_user.org_id,
            asset_type=candidate.asset_type,
            domain=candidate.domain,
            subdomain=candidate.subdomain,
            ip=candidate.ip,
            port=candidate.port,
            protocol=candidate.protocol,
            url=candidate.url,
            service=candidate.service,
            asn=candidate.asn,
            hosting_provider=candidate.hosting_provider,
            cdn=candidate.cdn,
            country=candidate.country,
            environment=candidate.environment,
            tags=payload.tags,
            importance=importance,
            exposure_class=exposure_class,
            exposure_score=exposure_score,
        )
        db.add(asset)
        created.append(asset)
        if candidate.asset_type == "domain":
            domain_asset = asset

    db.commit()
    for asset in created:
        db.refresh(asset)

    if domain_asset:
        for edge in asset_graph_builder.edges_for_domain(domain_asset, created):
            db.add(
                AssetEdge(
                    org_id=current_user.org_id,
                    source_asset_id=edge.source_id,
                    target_asset_id=edge.target_id,
                    relation=edge.relation,
                )
            )
        db.commit()

        subdomains = [asset.subdomain for asset in created if asset.asset_type == "subdomain" and asset.subdomain]
        if subdomains:
            host_enrich, ip_enrich = asset_enrichment.enrich_hosts(subdomains)
            edge_keys = {
                (edge.source_asset_id, edge.target_asset_id, edge.relation)
                for edge in (
                    db.execute(
                        select(AssetEdge).where(AssetEdge.org_id == current_user.org_id)
                    )
                    .scalars()
                    .all()
                )
            }
            sub_asset_map = {
                asset.subdomain: asset
                for asset in created
                if asset.asset_type == "subdomain" and asset.subdomain
            }
            ip_asset_map: Dict[str, Asset] = {}
            for ip, meta in ip_enrich.items():
                ip_asset = (
                    db.execute(
                        select(Asset).where(
                            Asset.org_id == current_user.org_id,
                            Asset.asset_type == "ip",
                            Asset.ip == ip,
                        )
                    )
                    .scalars()
                    .first()
                )
                if not ip_asset:
                    ip_asset = Asset(
                        org_id=current_user.org_id,
                        asset_type="ip",
                        domain=None,
                        subdomain=None,
                        ip=ip,
                        port=None,
                        protocol=None,
                        url=None,
                        service=None,
                        environment=payload.environment,
                        tags=payload.tags,
                        importance=payload.importance,
                        exposure_class=asset_intelligence.classify_exposure(
                            payload.environment, payload.tags, "ip", ip=ip
                        ),
                        exposure_score=asset_intelligence.exposure_score(
                            asset_intelligence.classify_exposure(payload.environment, payload.tags, "ip", ip=ip)
                        ),
                        asn=meta.asn,
                        hosting_provider=meta.hosting_provider,
                        country=meta.country,
                    )
                    db.add(ip_asset)
                    db.flush()
                else:
                    if meta.asn and not ip_asset.asn:
                        ip_asset.asn = meta.asn
                    if meta.hosting_provider and not ip_asset.hosting_provider:
                        ip_asset.hosting_provider = meta.hosting_provider
                    if meta.country and not ip_asset.country:
                        ip_asset.country = meta.country
                ip_asset_map[ip] = ip_asset

            for host, info in host_enrich.items():
                sub_asset = sub_asset_map.get(host)
                if not sub_asset:
                    continue
                if info.cdn and not sub_asset.cdn:
                    sub_asset.cdn = info.cdn
            for edge in asset_graph_builder.edges_for_resolution(sub_asset_map, ip_asset_map, host_enrich):
                key = (edge.source_id, edge.target_id, edge.relation)
                if key in edge_keys:
                    continue
                db.add(
                    AssetEdge(
                        org_id=current_user.org_id,
                        source_asset_id=edge.source_id,
                        target_asset_id=edge.target_id,
                        relation=edge.relation,
                    )
                )
                edge_keys.add(key)
            db.commit()

    log_activity(
        db,
        org_id=current_user.org_id,
        action="asset_ingest",
        target_type="asset",
        details=f"created={len(created)}",
        actor=current_user.email,
    )
    return created


@app.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AssetOut:
    asset = db.get(Asset, asset_id)
    if not asset or asset.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="asset not found")

    if payload.environment is not None:
        asset.environment = payload.environment
    if payload.tags is not None:
        asset.tags = payload.tags
    if payload.importance is not None:
        asset.importance = payload.importance
    if payload.exposure_class is not None:
        asset.exposure_class = payload.exposure_class
    if payload.environment is not None or payload.tags is not None:
        if payload.exposure_class is None:
            asset.exposure_class = asset_intelligence.classify_exposure(
                asset.environment, asset.tags, asset.asset_type, ip=asset.ip
            )
        asset.exposure_score = asset_intelligence.exposure_score(asset.exposure_class or "low")
    if payload.exposure_score is not None:
        asset.exposure_score = payload.exposure_score

    db.commit()
    db.refresh(asset)
    log_activity(
        db,
        org_id=current_user.org_id,
        action="asset_update",
        target_type="asset",
        target_id=asset.id,
        actor=current_user.email,
    )
    return asset


@app.get("/assets", response_model=List[AssetInventoryOut])
def list_assets(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> List[AssetInventoryOut]:
    assets = (
        db.execute(select(Asset).where(Asset.org_id == current_user.org_id).order_by(Asset.id.desc()))
        .scalars()
        .all()
    )
    risk_rows = db.execute(
        select(Finding.asset_id, func.max(Finding.risk_score))
        .where(Finding.org_id == current_user.org_id)
        .group_by(Finding.asset_id)
    ).all()
    risk_map = {row[0]: float(row[1] or 0.0) for row in risk_rows}
    results: List[AssetInventoryOut] = []
    for asset in assets:
        exposure_class = asset.exposure_class or asset_intelligence.classify_exposure(
            asset.environment, asset.tags, asset.asset_type, ip=asset.ip
        )
        exposure_score = asset.exposure_score or asset_intelligence.exposure_score(exposure_class)
        results.append(
            AssetInventoryOut(
                **AssetOut.from_orm(asset).dict(),
                risk_score=risk_map.get(asset.id, 0.0),
                exposure_class=exposure_class,
                exposure_score=exposure_score,
            )
        )
    return results


@app.get("/services", response_model=List[AssetInventoryOut])
def list_services(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> List[AssetInventoryOut]:
    services = (
        db.execute(
            select(Asset)
            .where(Asset.org_id == current_user.org_id, Asset.asset_type == "service")
            .order_by(Asset.id.desc())
        )
        .scalars()
        .all()
    )
    risk_rows = db.execute(
        select(Finding.asset_id, func.max(Finding.risk_score))
        .where(Finding.org_id == current_user.org_id)
        .group_by(Finding.asset_id)
    ).all()
    risk_map = {row[0]: float(row[1] or 0.0) for row in risk_rows}
    results: List[AssetInventoryOut] = []
    for asset in services:
        exposure_class = asset.exposure_class or asset_intelligence.classify_exposure(
            asset.environment, asset.tags, asset.asset_type, ip=asset.ip
        )
        exposure_score = asset.exposure_score or asset_intelligence.exposure_score(exposure_class)
        results.append(
            AssetInventoryOut(
                **AssetOut.from_orm(asset).dict(),
                risk_score=risk_map.get(asset.id, 0.0),
                exposure_class=exposure_class,
                exposure_score=exposure_score,
            )
        )
    return results


@app.get("/assets/edges", response_model=List[AssetEdgeOut])
def list_asset_edges(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> List[AssetEdgeOut]:
    edges = (
        db.execute(select(AssetEdge).where(AssetEdge.org_id == current_user.org_id).order_by(AssetEdge.id.desc()))
        .scalars()
        .all()
    )
    return edges


@app.post("/scans", response_model=ScanOut)
@limiter.limit(config.get_rate_limit())
def create_scan(
    payload: ScanCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanOut:
    if payload.scan_type not in ALLOWED_SCAN_TYPES:
        raise HTTPException(status_code=400, detail="unsupported scan_type")

    if payload.asset_id is not None:
        asset = db.get(Asset, payload.asset_id)
        if not asset or asset.org_id != current_user.org_id:
            raise HTTPException(status_code=404, detail="asset not found")

    from app.services.monitoring import create_scheduled_scan
    scan = create_scheduled_scan(
        db,
        org_id=current_user.org_id,
        scan_type=payload.scan_type,
        asset_id=payload.asset_id,
    )
    if not scan:
        raise HTTPException(status_code=500, detail="failed to create scan")
    log_activity(
        db,
        org_id=current_user.org_id,
        action="scan_scheduled",
        target_type="scan",
        target_id=scan.id,
        details=f"type={payload.scan_type}",
        actor=current_user.email,
    )
    return scan


@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> List[ScanOut]:
    scans = (
        db.execute(select(Scan).where(Scan.org_id == current_user.org_id).order_by(Scan.id.desc()))
        .scalars()
        .all()
    )
    return scans


@app.get("/findings", response_model=List[FindingOut])
def list_findings(
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[FindingOut]:
    stmt = select(Finding).where(Finding.org_id == current_user.org_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    findings = db.execute(stmt.order_by(Finding.id.desc())).scalars().all()
    return findings


@app.get("/vulnerabilities", response_model=List[FindingOut])
def list_vulnerabilities(
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[FindingOut]:
    return list_findings(severity=severity, current_user=current_user, db=db)


@app.get("/alerts", response_model=List[AlertOut])
def list_alerts(
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AlertOut]:
    stmt = select(Alert).where(Alert.org_id == current_user.org_id)
    if status:
        stmt = stmt.where(Alert.status == status)
    alerts = db.execute(stmt.order_by(Alert.id.desc())).scalars().all()
    return alerts


@app.get("/changes", response_model=List[AssetChangeOut])
def list_changes(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> List[AssetChangeOut]:
    changes = (
        db.execute(select(AssetChange).where(AssetChange.org_id == current_user.org_id).order_by(AssetChange.id.desc()))
        .scalars()
        .all()
    )
    return changes


@app.get("/assets/history", response_model=List[AssetHistoryOut])
def list_asset_history(
    asset_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    limit: int = Query(500, ge=1, le=5000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AssetHistoryOut]:
    query = select(AssetSnapshot).where(AssetSnapshot.org_id == current_user.org_id)
    if asset_id:
        query = query.where(AssetSnapshot.asset_id == asset_id)
    if scan_id:
        query = query.where(AssetSnapshot.scan_id == scan_id)
    snapshots = (
        db.execute(query.order_by(AssetSnapshot.id.desc()).limit(limit))
        .scalars()
        .all()
    )
    return snapshots


@app.get("/activity", response_model=List[ActivityLogOut])
def list_activity(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> List[ActivityLogOut]:
    logs = (
        db.execute(select(ActivityLog).where(ActivityLog.org_id == current_user.org_id).order_by(ActivityLog.id.desc()))
        .scalars()
        .all()
    )
    return logs


@app.get("/dashboard/overview")
def dashboard_overview(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Dict[str, object]:
    asset_count = db.execute(
        select(func.count()).select_from(Asset).where(Asset.org_id == current_user.org_id)
    ).scalar_one()
    findings_total = db.execute(
        select(func.count()).select_from(Finding).where(Finding.org_id == current_user.org_id)
    ).scalar_one()
    open_alerts = db.execute(
        select(func.count()).select_from(Alert).where(Alert.org_id == current_user.org_id, Alert.status == "new")
    ).scalar_one()

    severity_rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.org_id == current_user.org_id)
        .group_by(Finding.severity)
    ).all()
    findings_by_severity = {severity: count for severity, count in severity_rows}

    latest_scan = db.execute(
        select(func.max(Scan.completed_at)).where(Scan.org_id == current_user.org_id)
    ).scalar()

    return {
        "asset_count": asset_count,
        "findings_total": findings_total,
        "findings_by_severity": findings_by_severity,
        "open_alerts": open_alerts,
        "latest_scan_completed_at": latest_scan,
    }


@app.get("/dashboard/attack-surface")
def dashboard_attack_surface(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Dict[str, object]:
    domain_count = db.execute(
        select(func.count()).select_from(Asset).where(Asset.org_id == current_user.org_id, Asset.asset_type == "domain")
    ).scalar_one()
    subdomain_count = db.execute(
        select(func.count()).select_from(Asset).where(
            Asset.org_id == current_user.org_id, Asset.asset_type == "subdomain"
        )
    ).scalar_one()
    service_count = db.execute(
        select(func.count()).select_from(Asset).where(Asset.org_id == current_user.org_id, Asset.asset_type == "service")
    ).scalar_one()
    endpoint_count = db.execute(
        select(func.count()).select_from(Asset).where(
            Asset.org_id == current_user.org_id, Asset.asset_type == "endpoint"
        )
    ).scalar_one()
    ip_count = db.execute(
        select(func.count()).select_from(Asset).where(Asset.org_id == current_user.org_id, Asset.asset_type == "ip")
    ).scalar_one()
    return {
        "domains": domain_count,
        "subdomains": subdomain_count,
        "services": service_count,
        "endpoints": endpoint_count,
        "ips": ip_count,
    }


@app.get("/dashboard/graph")
def dashboard_graph(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Dict[str, object]:
    assets = (
        db.execute(select(Asset).where(Asset.org_id == current_user.org_id).order_by(Asset.id.asc()))
        .scalars()
        .all()
    )
    edges = (
        db.execute(select(AssetEdge).where(AssetEdge.org_id == current_user.org_id).order_by(AssetEdge.id.asc()))
        .scalars()
        .all()
    )
    # Build risk map for nodes
    risk_rows = db.execute(
        select(Finding.asset_id, func.max(Finding.risk_score))
        .where(Finding.org_id == current_user.org_id, Finding.status == "open")
        .group_by(Finding.asset_id)
    ).all()
    risk_map = {row[0]: float(row[1] or 0.0) for row in risk_rows}

    nodes = [
        {
            "id":             asset.id,
            "label":          asset.url or asset.subdomain or asset.domain or asset.ip or f"asset-{asset.id}",
            "type":           asset.asset_type,
            "exposure_class": asset.exposure_class or "internal",
            "risk_score":     risk_map.get(asset.id, 0.0),
            "technology":     asset.technology,
            "ip":             asset.ip,
            "port":           asset.port,
        }
        for asset in assets
    ]
    links = [
        {"source": edge.source_asset_id, "target": edge.target_asset_id, "relation": edge.relation}
        for edge in edges
    ]
    return {"nodes": nodes, "links": links}


@app.get("/dashboard/timeline")
def dashboard_timeline(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Dict[str, object]:
    scans = (
        db.execute(select(Scan).where(Scan.org_id == current_user.org_id).order_by(Scan.id.desc()).limit(50))
        .scalars()
        .all()
    )
    return {
        "scans": [
            {
                "id": scan.id,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "scheduled_at": scan.scheduled_at,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
            }
            for scan in scans
        ]
    }


@app.get("/dashboard/risk")
def dashboard_risk(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Dict[str, object]:
    avg_risk = db.execute(
        select(func.avg(Finding.risk_score)).where(Finding.org_id == current_user.org_id)
    ).scalar()
    max_risk = db.execute(
        select(func.max(Finding.risk_score)).where(Finding.org_id == current_user.org_id)
    ).scalar()
    asset_risk_rows = db.execute(
        select(Asset.id, Asset.domain, Asset.subdomain, Asset.url, func.sum(Finding.risk_score))
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Asset.org_id == current_user.org_id)
        .group_by(Asset.id)
        .order_by(func.sum(Finding.risk_score).desc())
        .limit(5)
    ).all()
    top_assets = [
        {
            "asset_id": row[0],
            "label": row[3] or row[2] or row[1] or f"asset-{row[0]}",
            "risk_score": float(row[4] or 0.0),
        }
        for row in asset_risk_rows
    ]
    # Severity distribution
    sev_rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.org_id == current_user.org_id, Finding.status == "open")
        .group_by(Finding.severity)
    ).all()
    by_severity = {sev: cnt for sev, cnt in sev_rows}

    # Top 20 risky assets with exposure + finding count
    top_assets_extended = db.execute(
        select(
            Asset.id, Asset.domain, Asset.subdomain, Asset.url, Asset.ip,
            Asset.asset_type, Asset.exposure_class, Asset.technology,
            func.sum(Finding.risk_score),
            func.count(Finding.id),
        )
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Asset.org_id == current_user.org_id, Finding.status == "open")
        .group_by(Asset.id)
        .order_by(func.sum(Finding.risk_score).desc())
        .limit(20)
    ).all()
    top_assets = [
        {
            "asset_id":       row[0],
            "label":          row[3] or row[2] or row[1] or row[4] or f"asset-{row[0]}",
            "asset_type":     row[5],
            "exposure_class": row[6] or "internal",
            "technology":     row[7],
            "risk_score":     float(row[8] or 0.0),
            "finding_count":  int(row[9] or 0),
        }
        for row in top_assets_extended
    ]

    return {
        "avg_risk":      float(avg_risk or 0.0),
        "max_risk":      float(max_risk or 0.0),
        "top_assets":    top_assets,
        "by_severity":   by_severity,
        "total_open":    sum(by_severity.values()),
    }


@app.get("/dashboard/risk-trend")
def dashboard_risk_trend(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Dict[str, object]:
    since = datetime.utcnow() - timedelta(days=14)
    rows = (
        db.execute(
            select(func.date(Finding.created_at), func.avg(Finding.risk_score), func.count())
            .where(Finding.org_id == current_user.org_id, Finding.created_at >= since)
            .group_by(func.date(Finding.created_at))
            .order_by(func.date(Finding.created_at))
        )
        .all()
    )
    return {
        "days": [
            {"date": str(row[0]), "avg_risk": float(row[1] or 0.0), "count": int(row[2] or 0)}
            for row in rows
        ]
    }


@app.get("/reports/summary")
def report_summary(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Dict[str, object]:
    avg_risk = db.execute(
        select(func.avg(Finding.risk_score)).where(Finding.org_id == current_user.org_id)
    ).scalar()
    avg_risk = avg_risk or 0.0
    security_posture_score = max(0.0, 100.0 - (avg_risk))

    top_findings = (
        db.execute(
            select(Finding)
            .where(Finding.org_id == current_user.org_id)
            .order_by(Finding.risk_score.desc(), Finding.id.desc())
            .limit(10)
        )
        .scalars()
        .all()
    )

    assets_by_env_rows = db.execute(
        select(Asset.environment, func.count())
        .where(Asset.org_id == current_user.org_id)
        .group_by(Asset.environment)
    ).all()
    assets_by_env = {env or "unknown": count for env, count in assets_by_env_rows}

    return {
        "security_posture_score": round(security_posture_score, 2),
        "top_vulnerabilities": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "cve": finding.cve,
            }
            for finding in top_findings
        ],
        "recommended_fixes": [
            "Patch critical and high findings first.",
            "Validate exposed services and close unused ports.",
            "Harden TLS and security headers across public endpoints.",
        ],
        "asset_summary": assets_by_env,
    }


@app.get("/reports/executive")
def report_executive(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Dict[str, object]:
    summary = report_summary(current_user=current_user, db=db)
    total_assets = sum(summary["asset_summary"].values()) if summary.get("asset_summary") else 0
    critical_count = len([item for item in summary["top_vulnerabilities"] if item["severity"] == "critical"])
    executive_text = (
        f"Security posture score is {summary['security_posture_score']}. "
        f"Total assets tracked: {total_assets}. "
        f"Top vulnerabilities include {critical_count} critical findings. "
        "Focus on patching critical/high items and closing exposed services."
    )
    return {"executive_summary": executive_text, "summary": summary}


@app.get("/reports/summary.pdf")
def report_summary_pdf(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Response:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=501, detail="PDF export not installed") from exc

    summary = report_summary(current_user=current_user, db=db)
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle("Attack Surface Report")
    pdf.drawString(40, 760, "Attack Surface Report")
    pdf.drawString(40, 742, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d')}")
    pdf.drawString(40, 724, f"Security Posture Score: {summary['security_posture_score']}")
    pdf.drawString(40, 706, "Asset Summary:")
    y = 690
    for env, count in summary.get("asset_summary", {}).items():
        pdf.drawString(50, y, f"- {env}: {count} assets")
        y -= 14
        if y < 120:
            pdf.showPage()
            y = 760
    pdf.drawString(40, y, "Top Vulnerabilities:")
    y -= 20
    for item in summary["top_vulnerabilities"][:10]:
        pdf.drawString(50, y, f"- {item['severity'].upper()} {item['title']} (risk {item['risk_score']})")
        y -= 14
        if y < 80:
            pdf.showPage()
            y = 760
    pdf.save()
    buffer.seek(0)
    return Response(buffer.read(), media_type="application/pdf")


@app.get("/reports/attack-surface.pdf")
def report_attack_surface_pdf(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Response:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=501, detail="PDF export not installed") from exc

    summary = report_summary(current_user=current_user, db=db)
    asset_counts = (
        db.execute(
            select(Asset.asset_type, func.count())
            .where(Asset.org_id == current_user.org_id)
            .group_by(Asset.asset_type)
        )
        .all()
    )
    severity_rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.org_id == current_user.org_id)
        .group_by(Finding.severity)
    ).all()
    findings_by_severity = {severity: count for severity, count in severity_rows}

    now = datetime.utcnow()
    quarter = (now.month - 1) // 3 + 1
    report_title = f"Attack Surface Report Q{quarter} {now.year}"

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle(report_title)
    pdf.drawString(40, 760, report_title)
    pdf.drawString(40, 742, f"Organization ID: {current_user.org_id}")
    pdf.drawString(40, 726, f"Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}")

    y = 700
    pdf.drawString(40, y, "Asset Summary")
    y -= 16
    total_assets = sum(count for _, count in asset_counts)
    pdf.drawString(50, y, f"Total assets tracked: {total_assets}")
    y -= 14
    for asset_type, count in asset_counts:
        pdf.drawString(50, y, f"- {asset_type}: {count}")
        y -= 12

    y -= 8
    pdf.drawString(40, y, "Risk Snapshot")
    y -= 16
    pdf.drawString(50, y, f"Security posture score: {summary['security_posture_score']}")
    y -= 14
    pdf.drawString(50, y, f"Open findings: {sum(findings_by_severity.values())}")
    y -= 14
    for severity, count in findings_by_severity.items():
        pdf.drawString(50, y, f"- {severity}: {count}")
        y -= 12

    y -= 8
    pdf.drawString(40, y, "Top Vulnerabilities")
    y -= 16
    for item in summary["top_vulnerabilities"][:10]:
        pdf.drawString(50, y, f"- {item['severity'].upper()} {item['title']} (risk {item['risk_score']})")
        y -= 12
        if y < 80:
            pdf.showPage()
            y = 760

    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return Response(buffer.read(), media_type="application/pdf")


@app.get("/reports/vulnerabilities")
def report_vulnerabilities(
    format: str = Query("json", pattern="^(json|csv)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> object:
    findings = (
        db.execute(select(Finding).where(Finding.org_id == current_user.org_id).order_by(Finding.id.desc()))
        .scalars()
        .all()
    )
    if format == "json":
        return [
            {
                "id": finding.id,
                "asset_id": finding.asset_id,
                "severity": finding.severity,
                "title": finding.title,
                "risk_score": finding.risk_score,
                "status": finding.status,
                "cve": finding.cve,
            }
            for finding in findings
        ]

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "asset_id", "severity", "title", "risk_score", "status", "cve"])
    for finding in findings:
        writer.writerow(
            [finding.id, finding.asset_id, finding.severity, finding.title, finding.risk_score, finding.status, finding.cve]
        )
    return PlainTextResponse(output.getvalue(), media_type="text/csv")


# ---------------------------------------------------------------------------
# New API endpoints for enhanced modules
# ---------------------------------------------------------------------------

@app.get("/dashboard/monitoring")
@limiter.limit(config.get_rate_limit())
def dashboard_monitoring(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Continuous monitoring status: last scan times, next scheduled, recent changes."""
    from app.services.continuous_monitor import get_org_monitoring_status
    return get_org_monitoring_status(db, current_user.org_id)


@app.get("/assets/{asset_id}/timeline")
@limiter.limit(config.get_rate_limit())
def asset_timeline(
    request: Request,
    asset_id: int,
    days: int = Query(90, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list:
    """Return chronological timeline of events for a specific asset."""
    from app.services.asset_history import get_asset_timeline
    return get_asset_timeline(db, current_user.org_id, asset_id, days=days)


@app.get("/assets/{asset_id}/history-summary")
@limiter.limit(config.get_rate_limit())
def asset_history_summary(
    request: Request,
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Full history and finding summary for a single asset."""
    from app.services.asset_history import get_asset_history_summary
    return get_asset_history_summary(db, current_user.org_id, asset_id)


@app.get("/dashboard/org-timeline")
@limiter.limit(config.get_rate_limit())
def org_timeline(
    request: Request,
    days: int = Query(30, ge=1, le=180),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list:
    """Recent change events across all org assets."""
    from app.services.asset_history import get_org_timeline
    return get_org_timeline(db, current_user.org_id, days=days, limit=limit)


@app.get("/dashboard/risk-aggregate")
@limiter.limit(config.get_rate_limit())
def risk_aggregate(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Enhanced org-level risk aggregate with breakdown by component."""
    from app.services.risk_engine import aggregate_org_risk, risk_label
    from sqlalchemy import func as sa_func

    asset_scores = db.execute(
        select(Asset.exposure_score).where(
            Asset.org_id == current_user.org_id,
            Asset.exposure_score.is_not(None),
        )
    ).scalars().all()

    finding_scores_raw = db.execute(
        select(Finding.risk_score).where(
            Finding.org_id == current_user.org_id,
            Finding.status == "open",
            Finding.risk_score.is_not(None),
        )
    ).scalars().all()

    return aggregate_org_risk(
        [float(s) for s in asset_scores],
        [float(s) for s in finding_scores_raw],
    )


@app.get("/assets/{asset_id}/correlation")
@limiter.limit(config.get_rate_limit())
def asset_correlation_graph(
    request: Request,
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Asset correlation graph — neighbors and relationship edges for an asset."""
    from app.services.asset_correlation import get_asset_graph
    graph = get_asset_graph(db, current_user.org_id, asset_id=asset_id)
    return {
        "nodes": [
            {
                "id": a.id,
                "type": a.asset_type,
                "label": a.subdomain or a.domain or a.ip or str(a.id),
                "url": a.url,
                "technology": a.technology,
                "exposure_class": a.exposure_class,
            }
            for a in graph.nodes
        ],
        "edges": [
            {"source": e.source_id, "target": e.target_id, "relation": e.relation}
            for e in graph.edges
        ],
    }


@app.post("/assets/deduplicate")
@limiter.limit(config.get_rate_limit())
def deduplicate_assets(
    request: Request,
    dry_run: bool = Query(False),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Run asset deduplication for the organization. Requires admin role."""
    from app.services.asset_normalizer import deduplicate_org_assets
    return deduplicate_org_assets(db, current_user.org_id, dry_run=dry_run)


@app.post("/assets/correlate")
@limiter.limit(config.get_rate_limit())
def run_correlation(
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Re-run asset correlation for the organization. Requires admin role."""
    from app.services.asset_correlation import correlate_org_assets
    new_edges = correlate_org_assets(db, current_user.org_id)
    return {"new_edges_created": new_edges}


@app.get("/queue/status")
@limiter.limit(config.get_rate_limit())
def queue_status(
    request: Request,
    current_user: User = Depends(require_role("admin")),
) -> dict:
    """Queue depth and inflight scan status. Requires admin role."""
    from app.services.queue import get_queue_depth
    depth = get_queue_depth()
    return depth or {"status": "queue_unavailable"}


# ---------------------------------------------------------------------------
# Worker & alert management endpoints
# ---------------------------------------------------------------------------

@app.get("/workers/status")
@limiter.limit(config.get_rate_limit())
def workers_status(
    request: Request,
    current_user: User = Depends(require_role("admin")),
) -> dict:
    """All registered distributed worker stats from Redis. Admin only."""
    from app.services.distributed_worker import get_all_worker_stats
    workers = get_all_worker_stats()
    queue_depth = None
    try:
        from app.services.queue import get_queue_depth
        queue_depth = get_queue_depth()
    except Exception as e:
        logger.warning('unexpected error', error=str(e))
        pass
    return {
        "workers": workers or [],
        "queue": queue_depth or {},
        "worker_count": len(workers) if workers else 0,
    }


@app.get("/alerts/stats")
@limiter.limit(config.get_rate_limit())
def alert_stats(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Alert statistics: counts by type and severity, open vs acknowledged."""
    from sqlalchemy import func as sa_func
    since = datetime.utcnow() - timedelta(days=days)
    all_alerts = db.execute(
        select(Alert).where(
            Alert.org_id == current_user.org_id,
            Alert.created_at >= since,
        )
    ).scalars().all()

    from app.services.alert_engine import SEVERITY_MAP
    by_type: dict = {}
    by_severity: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_status: dict = {"new": 0, "acknowledged": 0, "escalated": 0, "resolved": 0}

    for a in all_alerts:
        by_type[a.alert_type] = by_type.get(a.alert_type, 0) + 1
        sev = SEVERITY_MAP.get(a.alert_type, "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_status[a.status] = by_status.get(a.status, 0) + 1

    return {
        "total": len(all_alerts),
        "period_days": days,
        "by_type": by_type,
        "by_severity": by_severity,
        "by_status": by_status,
    }


@app.post("/alerts/{alert_id}/acknowledge")
@limiter.limit(config.get_rate_limit())
def acknowledge_alert(
    request: Request,
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Acknowledge an alert to prevent escalation."""
    alert = db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == current_user.org_id)
    ).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "acknowledged"
    db.commit()
    return {"id": alert.id, "status": alert.status}


@app.get("/findings/{finding_id}/enrich")
@limiter.limit(config.get_rate_limit())
def enrich_finding_detail(
    request: Request,
    finding_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Fetch live NVD CVSS, KEV status, and exploit intel for a finding."""
    from app.models import Finding as FindingModel
    finding = db.execute(
        select(FindingModel).where(
            FindingModel.id == finding_id,
            FindingModel.org_id == current_user.org_id,
        )
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    result: dict = {
        "id": finding.id,
        "cve": finding.cve,
        "severity": finding.severity,
        "cvss": finding.cvss,
        "is_kev": False,
        "has_exploit": False,
        "exploit_refs": [],
        "nvd_cvss": None,
        "nvd_vector": None,
    }

    if finding.cve:
        try:
            from app.services.vuln_scanner import get_kev_cve_set, _fetch_nvd_cve, _extract_nvd_cvss, _check_poc_in_github, _check_exploitdb
            kev_set = get_kev_cve_set()
            result["is_kev"] = finding.cve.upper() in kev_set

            cve_data = _fetch_nvd_cve(finding.cve)
            if cve_data:
                cvss, vector = _extract_nvd_cvss(cve_data)
                result["nvd_cvss"] = cvss
                result["nvd_vector"] = vector

            found_poc, poc_refs = _check_poc_in_github(finding.cve)
            result["has_exploit"] = found_poc
            result["exploit_refs"] = poc_refs
        except Exception as e:
            logger.debug('optional feature error', error=str(e))
            pass

    return result


# ---------------------------------------------------------------------------
# Attack Path Engine endpoints
# ---------------------------------------------------------------------------

@app.get("/attack-paths")
@limiter.limit(config.get_rate_limit())
def get_attack_paths(
    request: Request,
    max_paths: int = Query(20, ge=1, le=50),
    min_score: float = Query(15.0, ge=0.0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Compute attack paths through the asset graph. Returns paths, choke points, heatmap."""
    from app.services.attack_path_engine import analyze_attack_surface, path_to_dict, build_attack_graph
    surface = analyze_attack_surface(
        db, current_user.org_id,
        max_paths=max_paths,
        max_hops=config.get_attack_path_max_hops(),
        min_score=min_score,
    )
    nodes, _ = build_attack_graph(db, current_user.org_id)
    return {
        "total_paths": surface.total_paths,
        "critical_paths": surface.critical_paths,
        "paths": [path_to_dict(p, nodes) for p in surface.attack_paths],
        "choke_points": [
            {"asset_id": aid, "paths_blocked": cnt}
            for aid, cnt in surface.choke_points
        ],
        "risk_heatmap": surface.risk_heatmap,
        "entry_points": [
            {"asset_id": n.asset_id, "label": n.label, "node_risk": n.node_risk, "exposure": n.exposure_class}
            for n in surface.entry_points[:15]
        ],
        "high_value_targets": [
            {"asset_id": n.asset_id, "label": n.label, "value_score": n.value_score}
            for n in surface.high_value_targets[:10]
        ],
    }


@app.get("/attack-paths/summary")
@limiter.limit(config.get_rate_limit())
def attack_path_summary(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Quick attack surface summary without full path computation."""
    from app.services.attack_path_engine import build_attack_graph, _is_high_value_node, _is_entry_point
    nodes, adj = build_attack_graph(db, current_user.org_id)
    entry_count = sum(1 for n in nodes.values() if n.exposure_class == "public")
    hv_count = sum(1 for n in nodes.values() if _is_high_value_node(n))
    rce_nodes = sum(1 for n in nodes.values() if n.has_rce)
    kev_nodes = sum(1 for n in nodes.values() if n.is_kev)
    return {
        "total_assets": len(nodes),
        "entry_points": entry_count,
        "high_value_targets": hv_count,
        "assets_with_rce": rce_nodes,
        "assets_with_kev": kev_nodes,
        "max_node_risk": round(max((n.node_risk for n in nodes.values()), default=0), 2),
    }


# ---------------------------------------------------------------------------
# Threat Intelligence endpoints
# ---------------------------------------------------------------------------

@app.get("/threat-intel/asset/{asset_id}")
@limiter.limit(config.get_rate_limit())
def asset_threat_intel(
    request: Request,
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Run all TI checks for a single asset (cached). Returns ThreatProfile."""
    if not config.get_ti_enabled():
        raise HTTPException(status_code=400, detail="Threat intelligence not enabled")
    asset = db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == current_user.org_id)
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    from app.services.threat_intelligence import profile_asset
    label = asset.url or asset.subdomain or asset.domain or asset.ip or f"#{asset.id}"
    profile = profile_asset(
        asset_id=asset.id, label=label,
        ip=asset.ip, domain=asset.subdomain or asset.domain,
    )
    return {
        "asset_id": profile.asset_id,
        "label": profile.label,
        "overall_level": profile.overall_level,
        "confidence": profile.confidence,
        "abuseipdb_score": profile.abuseipdb_score,
        "virustotal_positives": profile.virustotal_positives,
        "greynoise_classification": profile.greynoise_classification,
        "shodan_tags": profile.shodan_tags,
        "shodan_vulns": profile.shodan_vulns,
        "threat_actor_tags": profile.threat_actor_tags,
        "malware_families": profile.malware_families,
        "indicators": [
            {
                "source": i.source,
                "type": i.indicator_type,
                "level": i.threat_level,
                "confidence": i.confidence,
                "description": i.description,
                "tags": i.tags,
                "refs": i.references[:2],
            }
            for i in profile.indicators
        ],
        "checked_at": profile.checked_at,
    }


@app.get("/threat-intel/org-summary")
@limiter.limit(config.get_rate_limit())
def org_threat_intel_summary(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Scan all public org assets for threat intelligence. Returns OrgThreatSummary."""
    if not config.get_ti_enabled():
        raise HTTPException(status_code=400, detail="Threat intelligence not enabled")
    from app.services.threat_intelligence import scan_org_threat_intel
    summary = scan_org_threat_intel(db, current_user.org_id, limit=limit)
    return {
        "org_id": summary.org_id,
        "threat_level": summary.threat_level,
        "total_assets_checked": summary.total_assets_checked,
        "critical": summary.critical_assets,
        "malicious": summary.malicious_assets,
        "suspect": summary.suspect_assets,
        "clean": summary.clean_assets,
        "top_threats": [
            {"asset_id": p.asset_id, "label": p.label, "level": p.overall_level,
             "confidence": p.confidence, "actors": p.threat_actor_tags}
            for p in summary.top_threats[:5]
        ],
        "trending_malware": summary.trending_malware,
        "active_cve_exploits": summary.active_cve_exploits,
    }


# ---------------------------------------------------------------------------
# Enhanced Asset Timeline endpoints
# ---------------------------------------------------------------------------

@app.get("/assets/{asset_id}/timeline")
@limiter.limit(config.get_rate_limit())
def asset_timeline_v2(
    request: Request,
    asset_id: int,
    days: int = Query(90, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list:
    """Full asset timeline with diffs, vuln lifecycle, KEV events, tech changes."""
    from app.services.asset_history import get_asset_timeline
    events = get_asset_timeline(db, current_user.org_id, asset_id, days=days)
    return [e.to_dict() for e in events]


@app.get("/assets/{asset_id}/risk-trajectory")
@limiter.limit(config.get_rate_limit())
def asset_risk_trajectory(
    request: Request,
    asset_id: int,
    days: int = Query(90, ge=7, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Asset risk score over time with trend direction."""
    from app.services.asset_history import get_risk_trajectory, get_risk_trend
    trajectory = get_risk_trajectory(db, current_user.org_id, asset_id=asset_id, days=days)
    trend = get_risk_trend(trajectory)
    return {
        "asset_id": asset_id,
        "snapshots": [s.to_dict() for s in trajectory],
        "trend": trend,
    }


@app.get("/dashboard/risk-trajectory")
@limiter.limit(config.get_rate_limit())
def org_risk_trajectory(
    request: Request,
    days: int = Query(90, ge=7, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Org-wide risk trajectory with trend direction."""
    from app.services.asset_history import get_risk_trajectory, get_risk_trend
    trajectory = get_risk_trajectory(db, current_user.org_id, days=days)
    trend = get_risk_trend(trajectory)
    return {"snapshots": [s.to_dict() for s in trajectory], "trend": trend}


@app.get("/dashboard/org-timeline")
@limiter.limit(config.get_rate_limit())
def org_timeline_v2(
    request: Request,
    days: int = Query(30, ge=1, le=180),
    limit: int = Query(200, ge=1, le=500),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list:
    """Org-wide timeline with filtering by severity and event type."""
    from app.services.asset_history import get_org_timeline
    event_types = event_type.split(",") if event_type else None
    events = get_org_timeline(
        db, current_user.org_id, days=days, limit=limit,
        severity_filter=severity, event_type_filter=event_types,
    )
    return [e.to_dict() for e in events]


# ---------------------------------------------------------------------------
# Distributed scan endpoints
# ---------------------------------------------------------------------------

@app.get("/scans/{scan_id}/progress")
@limiter.limit(config.get_rate_limit())
def scan_progress(
    request: Request,
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Real-time sub-scan progress for a distributed master scan."""
    try:
        from app.services.distributed_scan import ScanCoordinator
        coord = ScanCoordinator()
        prog = coord.get_progress(scan_id)
        return {
            "scan_id": prog.scan_id,
            "total_subscans": prog.total_subscans,
            "done": prog.done_subscans,
            "failed": prog.failed_subscans,
            "findings": prog.findings_total,
            "progress_pct": prog.progress_pct,
            "is_complete": prog.is_complete,
            "subscans": [
                {
                    "id": ss.id,
                    "type": ss.scan_type,
                    "status": ss.status.value,
                    "targets_count": len(ss.targets),
                    "findings": ss.findings_count,
                    "worker": ss.worker_id,
                    "chunk": f"{ss.chunk_index+1}/{ss.total_chunks}",
                }
                for ss in prog.subscans
            ],
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Distributed scan coordinator unavailable")


# ── Import new models ──────────────────────────────────────────────────────
from app.models import AssetOwnership, AttackSurfaceScore
from app.logger import get_logger
logger = get_logger('app.main')


# ── Attack Surface Score ───────────────────────────────────────────────────

@app.post("/score/compute")
@limiter.limit(config.get_rate_limit())
def compute_score(
    request: Request,
    domain: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Compute and persist the current attack surface score."""
    from app.services.attack_surface_score import compute_score as _compute, score_label
    record = _compute(db, current_user.org_id, domain=domain)
    return {
        "score": record.score,
        "label": score_label(record.score),
        "total_assets": record.total_assets,
        "exposed_services": record.exposed_services,
        "critical_vulns": record.critical_vulns,
        "high_vulns": record.high_vulns,
        "public_buckets": record.public_buckets,
        "open_high_risk_ports": record.open_high_risk_ports,
        "breakdown": json.loads(record.breakdown or "{}"),
        "computed_at": record.computed_at.isoformat() if record.computed_at else None,
    }


@app.get("/score/latest")
@limiter.limit(config.get_rate_limit())
def latest_score(
    request: Request,
    domain: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Latest attack surface score + trend + history for chart."""
    from app.services.attack_surface_score import get_latest_score
    result = get_latest_score(db, current_user.org_id, domain=domain)
    if not result:
        raise HTTPException(status_code=404, detail="No score computed yet. POST /score/compute first.")
    return result


# ── Security Reports ───────────────────────────────────────────────────────

@app.get("/reports/security.md")
@limiter.limit(config.get_rate_limit())
def report_markdown(
    request: Request,
    domain: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate Markdown security report."""
    from app.services.report_generator import generate_markdown
    md = generate_markdown(db, current_user.org_id, domain=domain)
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=security-report.md"},
    )


@app.get("/reports/security.html")
@limiter.limit(config.get_rate_limit())
def report_html(
    request: Request,
    domain: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate HTML security report."""
    from app.services.report_generator import generate_html
    html = generate_html(db, current_user.org_id, domain=domain)
    return Response(content=html, media_type="text/html")


@app.get("/reports/security.pdf")
@limiter.limit(config.get_rate_limit())
def report_pdf(
    request: Request,
    domain: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate PDF security report (requires reportlab)."""
    from app.services.report_generator import generate_pdf
    pdf_bytes = generate_pdf(db, current_user.org_id, domain=domain)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=security-report.pdf"},
    )


# ── Asset Ownership ────────────────────────────────────────────────────────

@app.post("/assets/{asset_id}/owner")
@limiter.limit(config.get_rate_limit())
def set_asset_owner(
    request: Request,
    asset_id: int,
    team_name: str = Query(...),
    owner_email: Optional[str] = Query(None),
    notes: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Assign ownership of an asset to a team."""
    from app.services.asset_ownership import assign_owner
    o = assign_owner(db, current_user.org_id, asset_id, team_name, owner_email, notes)
    return {"asset_id": o.asset_id, "team_name": o.team_name, "owner_email": o.owner_email}


@app.get("/assets/{asset_id}/owner")
@limiter.limit(config.get_rate_limit())
def get_asset_owner_route(
    request: Request,
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Get ownership info for an asset."""
    from app.services.asset_ownership import get_asset_owner
    result = get_asset_owner(db, current_user.org_id, asset_id)
    if not result:
        raise HTTPException(status_code=404, detail="No owner assigned")
    return result


@app.delete("/assets/{asset_id}/owner")
@limiter.limit(config.get_rate_limit())
def delete_asset_owner(
    request: Request,
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    from app.services.asset_ownership import remove_owner
    removed = remove_owner(db, current_user.org_id, asset_id)
    return {"removed": removed}


@app.post("/assets/bulk-assign-owner")
@limiter.limit(config.get_rate_limit())
def bulk_assign_owner(
    request: Request,
    pattern: str = Query(..., description="Glob pattern e.g. '*.api.*'"),
    team_name: str = Query(...),
    owner_email: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Bulk assign ownership by hostname glob pattern."""
    from app.services.asset_ownership import bulk_assign_by_pattern
    count = bulk_assign_by_pattern(db, current_user.org_id, pattern, team_name, owner_email)
    return {"assigned": count, "team_name": team_name, "pattern": pattern}


@app.get("/ownership/teams")
@limiter.limit(config.get_rate_limit())
def list_teams(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list:
    """List all teams with ownership assignments."""
    from app.services.asset_ownership import get_all_teams
    return get_all_teams(db, current_user.org_id)


@app.get("/ownership/team-exposure")
@limiter.limit(config.get_rate_limit())
def team_exposure(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list:
    """Per-team risk summary: assets, open findings, severity breakdown."""
    from app.services.asset_ownership import get_team_exposure
    return get_team_exposure(db, current_user.org_id)


@app.get("/ownership/unowned")
@limiter.limit(config.get_rate_limit())
def unowned_assets(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list:
    """Public-facing assets with no ownership assignment."""
    from app.services.asset_ownership import get_unowned_assets
    return get_unowned_assets(db, current_user.org_id, limit=limit)

import json as _json

# ── SIEM Export ───────────────────────────────────────────────────────────

@app.post("/export/siem")
@limiter.limit(config.get_rate_limit())
def export_to_siem(
    request: Request,
    since_hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Export recent findings to all configured SIEM destinations.

    Supports: Splunk HEC, Elasticsearch, Loki, generic webhook.
    Configured via ASM_SPLUNK_HEC_URL, ASM_ELASTIC_URL, etc.
    """
    try:
        from app.services.siem_export import export_org_findings
        result = export_org_findings(db, current_user.org_id, [], since_hours=since_hours)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/export/findings.csv")
@limiter.limit(config.get_rate_limit())
def export_findings_csv(
    request: Request,
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export findings as CSV for offline analysis / Excel."""
    from fastapi.responses import PlainTextResponse
    from app.services.siem_export import findings_to_csv
    from sqlalchemy import select as sa_select
    stmt = sa_select(Finding).where(Finding.org_id == current_user.org_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    findings = db.execute(stmt.order_by(Finding.id.desc())).scalars().all()
    csv_str = findings_to_csv(findings)
    return PlainTextResponse(
        csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@app.get("/export/findings.ndjson")
@limiter.limit(config.get_rate_limit())
def export_findings_ndjson(
    request: Request,
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export findings as NDJSON (OCSF format) for SIEM ingestion."""
    from fastapi.responses import PlainTextResponse
    from app.services.siem_export import findings_to_ndjson
    from sqlalchemy import select as sa_select
    stmt = sa_select(Finding).where(Finding.org_id == current_user.org_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    findings = db.execute(stmt.order_by(Finding.id.desc()).limit(10000)).scalars().all()

    asset_ids = {f.asset_id for f in findings if f.asset_id}
    asset_map = {}
    if asset_ids:
        for a in db.execute(sa_select(Asset).where(Asset.id.in_(asset_ids))).scalars().all():
            asset_map[a.id] = a

    ndjson = findings_to_ndjson(findings, asset_map)
    return PlainTextResponse(
        ndjson,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=findings.ndjson"},
    )


# ── Circuit breaker status ─────────────────────────────────────────────────

@app.get("/system/circuit-breakers")
@limiter.limit(config.get_rate_limit())
def circuit_breaker_stats(
    request: Request,
    current_user: User = Depends(require_role("admin")),
) -> dict:
    """Status of all circuit breakers (open/closed/half-open)."""
    from app.services.circuit_breaker import all_breaker_stats
    return {"breakers": all_breaker_stats()}


@app.post("/system/circuit-breakers/{name}/reset")
@limiter.limit(config.get_rate_limit())
def reset_circuit_breaker(
    request: Request,
    name: str,
    current_user: User = Depends(require_role("admin")),
) -> dict:
    """Manually reset a circuit breaker to CLOSED state."""
    from app.services.circuit_breaker import get_breaker
    breaker = get_breaker(name)
    breaker.reset()
    return {"name": name, "state": "closed"}


# ── Deep crawl endpoint ────────────────────────────────────────────────────

@app.post("/assets/{asset_id}/deep-crawl")
@limiter.limit(config.get_rate_limit())
def trigger_deep_crawl(
    request: Request,
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Trigger a deep multi-strategy crawl on a specific asset.

    Runs: katana + gau + passive HTML + JS endpoint scan + robots.txt
    Returns discovered URL count and high-value endpoints.
    """
    asset = db.get(Asset, asset_id)
    if not asset or asset.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="asset not found")

    base_url = asset.url or (f"https://{asset.subdomain}" if asset.subdomain else None) or \
               (f"https://{asset.domain}" if asset.domain else None)
    if not base_url:
        raise HTTPException(status_code=400, detail="asset has no URL, subdomain, or domain")

    try:
        from app.services.crawler import crawl_and_extract
        result = crawl_and_extract([base_url], deep=True)
        return {
            "asset_id":        asset_id,
            "base_url":        base_url,
            "total_urls":      len(result["all"]),
            "high_value":      result["high_value"][:20],
            "js_apis":         result["js_apis"][:10],
            "robots_paths":    result["robots_paths"][:10],
            "high_value_count": len(result["high_value"]),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Scan with deep crawl ───────────────────────────────────────────────────

@app.post("/scans/deep-crawl")
@limiter.limit(config.get_rate_limit())
def create_deep_crawl_scan(
    request: Request,
    domain: str = Query(..., description="Root domain to scan"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Schedule a full ASM pipeline scan with deep crawl for a domain.

    Creates a 'deep' scan type which runs:
      asset discovery → subdomain enum → deep crawl → vuln scan → risk scoring
    """
    # Validate domain
    from app.schemas import validate_domain
    try:
        domain = validate_domain(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Find or verify domain asset exists
    from sqlalchemy import select as sa_select
    domain_asset = db.execute(
        sa_select(Asset).where(
            Asset.org_id == current_user.org_id,
            Asset.domain == domain,
            Asset.asset_type == "domain",
        )
    ).scalars().first()

    scan = Scan(
        org_id=current_user.org_id,
        asset_id=domain_asset.id if domain_asset else None,
        scan_type="deep",
        status="scheduled",
        scheduled_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    log_activity(
        db, org_id=current_user.org_id,
        action="deep_crawl_scan_scheduled",
        target_type="scan", target_id=scan.id,
        details=f"domain={domain}",
        actor=current_user.email,
    )
    return {
        "scan_id":   scan.id,
        "domain":    domain,
        "scan_type": "deep",
        "status":    "scheduled",
        "message":   "Deep crawl scan scheduled. Pipeline: discovery → crawl → vuln scan → risk scoring.",
    }

from app.models import NucleiTemplate as NucleiTemplateModel


# ── Custom Nuclei Templates ────────────────────────────────────────────────

@app.post("/templates")
@limiter.limit(config.get_rate_limit())
async def upload_template(
    request: Request,
    name: Optional[str] = Query(None, max_length=200),
    description: Optional[str] = Query(None, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Upload a custom nuclei template (YAML body).

    Template is validated for structure before storing.
    Existing templates with the same ID are updated.
    """
    content = (await request.body()).decode("utf-8", errors="ignore")
    if not content:
        raise HTTPException(status_code=400, detail="request body must contain template YAML")
    try:
        from app.services.template_engine import upsert_template
        tmpl = upsert_template(
            db, current_user.org_id, content,
            name=name, description=description,
            created_by=current_user.email,
        )
        return {
            "id":          tmpl.id,
            "slug":        tmpl.slug,
            "name":        tmpl.name,
            "severity":    tmpl.severity,
            "tags":        tmpl.tags,
            "enabled":     tmpl.enabled,
            "created_at":  tmpl.created_at.isoformat() if tmpl.created_at else None,
        }
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.get("/templates")
@limiter.limit(config.get_rate_limit())
def list_templates(
    request: Request,
    enabled_only: bool = Query(True),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list:
    """List all custom nuclei templates for this organization."""
    from app.services.template_engine import list_templates as _list
    templates = _list(db, current_user.org_id, enabled_only=enabled_only)
    return [
        {
            "id":          t.id,
            "slug":        t.slug,
            "name":        t.name,
            "description": t.description,
            "severity":    t.severity,
            "tags":        t.tags,
            "enabled":     t.enabled,
            "created_by":  t.created_by,
            "created_at":  t.created_at.isoformat() if t.created_at else None,
        }
        for t in templates
    ]


@app.get("/templates/{template_id}")
@limiter.limit(config.get_rate_limit())
def get_template(
    request: Request,
    template_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Get a custom template including its YAML content."""
    tmpl = db.execute(
        select(NucleiTemplateModel).where(
            NucleiTemplateModel.id == template_id,
            NucleiTemplateModel.org_id == current_user.org_id,
        )
    ).scalar_one_or_none()
    if not tmpl:
        raise HTTPException(status_code=404, detail="template not found")
    return {
        "id":          tmpl.id,
        "slug":        tmpl.slug,
        "name":        tmpl.name,
        "description": tmpl.description,
        "severity":    tmpl.severity,
        "tags":        tmpl.tags,
        "enabled":     tmpl.enabled,
        "content":     tmpl.content,
        "created_by":  tmpl.created_by,
        "created_at":  tmpl.created_at.isoformat() if tmpl.created_at else None,
    }


@app.patch("/templates/{template_id}")
@limiter.limit(config.get_rate_limit())
def update_template(
    request: Request,
    template_id: int,
    enabled: Optional[bool] = Query(None),
    name: Optional[str] = Query(None, max_length=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Enable/disable or rename a custom template."""
    tmpl = db.execute(
        select(NucleiTemplateModel).where(
            NucleiTemplateModel.id == template_id,
            NucleiTemplateModel.org_id == current_user.org_id,
        )
    ).scalar_one_or_none()
    if not tmpl:
        raise HTTPException(status_code=404, detail="template not found")
    if enabled is not None:
        tmpl.enabled = enabled
    if name is not None:
        tmpl.name = name
    db.commit()
    return {"id": tmpl.id, "slug": tmpl.slug, "enabled": tmpl.enabled, "name": tmpl.name}


@app.delete("/templates/{template_id}")
@limiter.limit(config.get_rate_limit())
def delete_template(
    request: Request,
    template_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Delete a custom template."""
    tmpl = db.execute(
        select(NucleiTemplateModel).where(
            NucleiTemplateModel.id == template_id,
            NucleiTemplateModel.org_id == current_user.org_id,
        )
    ).scalar_one_or_none()
    if not tmpl:
        raise HTTPException(status_code=404, detail="template not found")
    db.delete(tmpl)
    db.commit()
    return {"deleted": template_id}


@app.post("/templates/run")
@limiter.limit(config.get_rate_limit())
def run_custom_templates_scan(
    request: Request,
    asset_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Run all enabled custom templates against org assets.

    Optionally scope to a single asset_id.
    Creates a scan record and enqueues it.
    """
    from app.services.template_engine import list_templates as _list
    from app.services.queue import get_queue

    templates = _list(db, current_user.org_id, enabled_only=True)
    if not templates:
        raise HTTPException(status_code=400, detail="no enabled custom templates found")

    scan = Scan(
        org_id=current_user.org_id,
        asset_id=asset_id,
        scan_type="vuln",
        status="scheduled",
        scheduled_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        q = get_queue()
        if q:
            q.enqueue(scan.id, scan_type="vuln")
    except Exception as e:
        logger.warning("queue enqueue failed, scan will be picked up by DB poll", scan_id=scan.id, error=str(e))

    return {
        "scan_id":           scan.id,
        "templates_queued":  len(templates),
        "status":            "scheduled",
    }


# ── Alert test + config ────────────────────────────────────────────────────

@app.post("/alerts/test")
@limiter.limit(config.get_rate_limit())
def test_alert_channel(
    request: Request,
    channel: str = Query(..., pattern="^(slack|email|discord|teams|webhook|pagerduty|telegram)$"),
    current_user: User = Depends(require_role("admin")),
) -> dict:
    """Send a test alert to verify channel configuration.

    Supported: slack, email, discord, teams, webhook, pagerduty, telegram
    """
    test_msg = f"[TEST] ASM alert channel test from org {current_user.org_id}"
    test_payload = {
        "alert_type": "test",
        "severity": "info",
        "org_id": current_user.org_id,
        "message": test_msg,
    }
    result = {"channel": channel, "sent": False, "error": None}

    try:
        if channel == "slack":
            url = config.get_slack_webhook()
            if not url:
                raise ValueError("ASM_SLACK_WEBHOOK not configured")
            from app.services.notifications import send_slack
            result["sent"] = send_slack(url, test_msg, alert_type="test", severity="info")

        elif channel == "email":
            to = config.get_email_to()
            if not to:
                raise ValueError("ASM_EMAIL_TO not configured")
            from app.services.notifications import send_email
            send_email(to, "[ASM Test] Alert Channel Verification", test_msg)
            result["sent"] = True

        elif channel == "discord":
            url = config.get_discord_webhook()
            if not url:
                raise ValueError("ASM_DISCORD_WEBHOOK not configured")
            from app.services.notifications import send_discord
            result["sent"] = send_discord(url, test_msg, severity="info", alert_type="test")

        elif channel == "teams":
            url = config.get_ms_teams_webhook()
            if not url:
                raise ValueError("ASM_MS_TEAMS_WEBHOOK not configured")
            from app.services.notifications import send_ms_teams
            result["sent"] = send_ms_teams(url, test_msg, alert_type="test", severity="info")

        elif channel == "webhook":
            url = config.get_alert_webhook()
            if not url:
                raise ValueError("ASM_ALERT_WEBHOOK not configured")
            from app.services.notifications import send_webhook
            result["sent"] = send_webhook(url, test_payload)

        elif channel == "pagerduty":
            key = config.get_pagerduty_routing_key()
            if not key:
                raise ValueError("ASM_PAGERDUTY_ROUTING_KEY not configured")
            from app.services.notifications import send_pagerduty
            import hashlib, time as _t
            dedup = hashlib.sha256(f"test-{current_user.org_id}-{_t.time()}".encode()).hexdigest()[:16]
            result["sent"] = send_pagerduty(key, test_msg, "test", "info", dedup)

        elif channel == "telegram":
            tok = config.get_telegram_bot_token()
            chat = config.get_telegram_chat_id()
            if not tok or not chat:
                raise ValueError("ASM_TELEGRAM_BOT_TOKEN or ASM_TELEGRAM_CHAT_ID not configured")
            from app.services.notifications import send_telegram
            result["sent"] = send_telegram(tok, chat, test_msg, severity="info", alert_type="test")

    except Exception as e:
        result["error"] = str(e)

    return result


@app.get("/alerts/config")
@limiter.limit(config.get_rate_limit())
def alert_config_status(
    request: Request,
    current_user: User = Depends(require_role("admin")),
) -> dict:
    """Show which alert channels are configured (without exposing credentials)."""
    return {
        "alerts_enabled":       config.get_alerts_enabled(),
        "severity_threshold":   config.get_alert_severity_threshold(),
        "dedup_window_hours":   config.get_alert_dedup_window_hours(),
        "channels": {
            "slack":      bool(config.get_slack_webhook()),
            "discord":    bool(config.get_discord_webhook()),
            "email":      bool(config.get_email_to() and config.get_smtp_host()),
            "teams":      bool(config.get_ms_teams_webhook()),
            "webhook":    bool(config.get_alert_webhook()),
            "pagerduty":  config.get_pagerduty_enabled(),
            "opsgenie":   config.get_opsgenie_enabled(),
            "telegram":   bool(config.get_telegram_bot_token()),
            "jira":       config.get_jira_enabled(),
        },
    }


# ── Risk heatmap endpoint ──────────────────────────────────────────────────

@app.get("/dashboard/risk-heatmap")
@limiter.limit(config.get_rate_limit())
def risk_heatmap(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Risk heatmap: asset grid with risk scores for visualization.

    Returns assets bucketed by (asset_type × exposure_class) with
    aggregate risk, count, and top assets per cell.
    """
    # All assets with their max finding risk
    rows = db.execute(
        select(
            Asset.asset_type,
            Asset.exposure_class,
            Asset.id,
            Asset.domain,
            Asset.subdomain,
            Asset.url,
            Asset.ip,
            func.coalesce(func.max(Finding.risk_score), 0.0),
            func.count(Finding.id),
        )
        .outerjoin(Finding, (Finding.asset_id == Asset.id) & (Finding.status == "open"))
        .where(Asset.org_id == current_user.org_id)
        .group_by(Asset.id)
    ).all()

    # Build cell grid: type × exposure
    cells: dict = {}
    for row in rows:
        atype     = row[0] or "unknown"
        exposure  = row[1] or "internal"
        asset_id  = row[2]
        label     = row[5] or row[4] or row[3] or row[6] or f"#{asset_id}"
        risk      = float(row[7] or 0.0)
        fcount    = int(row[8] or 0)

        cell_key = f"{atype}:{exposure}"
        if cell_key not in cells:
            cells[cell_key] = {
                "asset_type":    atype,
                "exposure_class": exposure,
                "count":         0,
                "avg_risk":      0.0,
                "max_risk":      0.0,
                "top_assets":    [],
                "_risk_sum":     0.0,
            }
        c = cells[cell_key]
        c["count"]    += 1
        c["_risk_sum"] += risk
        c["max_risk"]  = max(c["max_risk"], risk)
        if len(c["top_assets"]) < 5:
            c["top_assets"].append({
                "id":        asset_id,
                "label":     label,
                "risk":      round(risk, 1),
                "findings":  fcount,
            })

    # Finalise averages, remove internal field
    result_cells = []
    for c in cells.values():
        c["avg_risk"] = round(c["_risk_sum"] / c["count"], 1) if c["count"] else 0.0
        c["max_risk"] = round(c["max_risk"], 1)
        c.pop("_risk_sum", None)
        c["top_assets"].sort(key=lambda x: x["risk"], reverse=True)
        result_cells.append(c)

    result_cells.sort(key=lambda c: c["max_risk"], reverse=True)

    # Top 10 riskiest individual assets
    top_assets = sorted(
        [
            {
                "id":          row[2],
                "label":       row[5] or row[4] or row[3] or row[6] or f"#{row[2]}",
                "asset_type":  row[0],
                "exposure":    row[1],
                "risk_score":  round(float(row[7] or 0.0), 1),
                "findings":    int(row[8] or 0),
            }
            for row in rows
        ],
        key=lambda x: x["risk_score"],
        reverse=True,
    )[:10]

    return {
        "cells":      result_cells,
        "top_assets": top_assets,
        "total_assets": len(rows),
    }

from app.services.adaptive_scanner import (
    schedule_adaptive_scans,
    compute_exposure_index,
    detect_shadow_assets,
)

# ── Adaptive scan scheduling ───────────────────────────────────────────────

@app.post("/scans/adaptive")
@limiter.limit(config.get_rate_limit())
def trigger_adaptive_scan(
    request: Request,
    scan_type: str = Query("vuln", pattern="^(vuln|web|misconfig|tls|headers|api)$"),
    max_assets: int = Query(50, ge=1, le=200),
    dry_run: bool = Query(False),
    current_user: User = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    """Score all assets by risk and enqueue scans in priority order.

    High-risk (KEV, internet-facing, recent changes) assets are scanned first.
    Use dry_run=true to preview which assets would be enqueued.
    """
    result = schedule_adaptive_scans(
        db, current_user.org_id,
        scan_type=scan_type,
        max_assets=max_assets,
        dry_run=dry_run,
    )
    return result


@app.get("/assets/{asset_id}/scan-priority")
@limiter.limit(config.get_rate_limit())
def get_asset_scan_priority(
    request: Request,
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Compute the adaptive scan priority for a specific asset."""
    from app.services.adaptive_scanner import compute_asset_scan_priority

    asset = db.get(Asset, asset_id)
    if not asset or asset.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="asset not found")

    findings = db.execute(
        select(Finding).where(
            Finding.asset_id == asset_id,
            Finding.status == "open",
        )
    ).scalars().all()

    priority, score, reason = compute_asset_scan_priority(asset, findings)
    labels = {0: "critical", 1: "high", 2: "normal", 3: "low"}
    return {
        "asset_id":      asset_id,
        "priority_level": priority,
        "priority_label": labels.get(priority, "normal"),
        "priority_score": score,
        "reason":         reason,
        "open_findings":  len(findings),
        "exposure_class": asset.exposure_class,
    }


# ── Exposure index ──────────────────────────────────────────────────────────

@app.get("/dashboard/exposure-index")
@limiter.limit(config.get_rate_limit())
def exposure_index(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Compute the internet exposure index (0–100) for this organization.

    Factors: % public assets, high-risk ports, critical findings on public assets.
    """
    return compute_exposure_index(db, current_user.org_id)


# ── Shadow asset detection ──────────────────────────────────────────────────

@app.get("/assets/shadow")
@limiter.limit(config.get_rate_limit())
def shadow_assets(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Detect shadow assets — internet-facing assets with no ownership assigned.

    Shadow assets are high risk: no team is responsible for patching them.
    """
    return detect_shadow_assets(db, current_user.org_id)


# ── AI risk prioritization ──────────────────────────────────────────────────

@app.get("/findings/prioritized")
@limiter.limit(config.get_rate_limit())
def ai_prioritized_findings(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """AI-assisted risk prioritization of open findings.

    Uses weighted heuristic model (CVSS × KEV × exposure × attack_path).
    Returns findings bucketed into P1/P2/P3/P4 with rationale and deadline.
    """
    from app.services.ai_risk import prioritize_org_findings
    return prioritize_org_findings(db, current_user.org_id, limit=limit)


@app.get("/findings/{finding_id}/priority")
@limiter.limit(config.get_rate_limit())
def get_finding_priority(
    request: Request,
    finding_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Get AI priority assessment for a single finding."""
    from app.services.ai_risk import score_finding_ai

    finding = db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.org_id == current_user.org_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")

    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None

    kev_set = set()
    try:
        from app.services.vuln_scanner import get_kev_cve_set
        kev_set = get_kev_cve_set()
    except Exception as e:
        logger.debug("kev lookup unavailable", error=str(e))

    item = score_finding_ai(finding, asset, kev_set=kev_set)
    return {
        "finding_id":      item.finding_id,
        "title":           item.title,
        "priority":        item.priority_label,
        "action":          item.action,
        "rationale":       item.rationale,
        "risk_score":      item.risk_score,
        "effort":          item.estimated_effort,
        "deadline":        item.recommended_deadline,
        "is_kev":          item.is_kev,
        "has_exploit":     item.has_exploit,
        "exposure_class":  item.exposure_class,
        "tags":            item.tags,
    }


# ── RBAC user management ────────────────────────────────────────────────────

@app.get("/users")
@limiter.limit(config.get_rate_limit())
def list_users(
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> list:
    """List all users in the organization."""
    from app.models import User as UserModel
    users = db.execute(
        select(UserModel).where(UserModel.org_id == current_user.org_id)
    ).scalars().all()
    return [
        {
            "id":         u.id,
            "email":      u.email,
            "role":       u.role,
            "is_active":  u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@app.patch("/users/{user_id}/role")
@limiter.limit(config.get_rate_limit())
def update_user_role(
    request: Request,
    user_id: int,
    role: str = Query(..., pattern="^(admin|analyst|viewer)$"),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Update a user's role. Admin only."""
    from app.models import User as UserModel
    user = db.execute(
        select(UserModel).where(UserModel.id == user_id, UserModel.org_id == current_user.org_id)
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="cannot change your own role")
    old_role = user.role
    user.role = role
    db.commit()
    log_activity(
        db, org_id=current_user.org_id, action="user_role_changed",
        target_type="user", target_id=user.id,
        details=f"{old_role} → {role}",
        actor=current_user.email,
    )
    return {"user_id": user.id, "email": user.email, "role": role}


@app.patch("/users/{user_id}/status")
@limiter.limit(config.get_rate_limit())
def update_user_status(
    request: Request,
    user_id: int,
    is_active: bool = Query(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Activate or deactivate a user account."""
    from app.models import User as UserModel
    user = db.execute(
        select(UserModel).where(UserModel.id == user_id, UserModel.org_id == current_user.org_id)
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="cannot deactivate yourself")
    user.is_active = is_active
    db.commit()
    log_activity(
        db, org_id=current_user.org_id,
        action="user_activated" if is_active else "user_deactivated",
        target_type="user", target_id=user.id,
        actor=current_user.email,
    )
    return {"user_id": user.id, "is_active": is_active}


@app.get("/me/permissions")
@limiter.limit(config.get_rate_limit())
def my_permissions(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return current user's role and permission set."""
    from app.security import ROLE_PERMISSIONS, ROLE_HIERARCHY
    return {
        "user_id":     current_user.id,
        "email":       current_user.email,
        "role":        current_user.role,
        "permissions": sorted(ROLE_PERMISSIONS.get(current_user.org_id and current_user.role or "viewer", [])),
        "role_level":  ROLE_HIERARCHY.index(current_user.role) if current_user.role in ROLE_HIERARCHY else 0,
    }
