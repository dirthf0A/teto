from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.db import SessionLocal, init_db
from backend.models import Asset, AssetEdge, ScanJob, ScanResult, Target, Vulnerability
from backend.services.queue import get_queue


app = FastAPI(title="ASM API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    return value.astimezone(timezone.utc).isoformat()


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class ScanStartRequest(BaseModel):
    domain: str = Field(..., min_length=1)
    environment: str = "prod"


class ScanStartResponse(BaseModel):
    job_id: int
    target_id: int
    status: str


class ScanStatusResponse(BaseModel):
    job_id: int
    target_id: int
    status: str
    created_at: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    error: Optional[str]


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/scan/start", response_model=ScanStartResponse)
def start_scan(payload: ScanStartRequest, db: Session = Depends(get_db)) -> ScanStartResponse:
    domain = payload.domain.strip().lower().rstrip(".")
    if not domain:
        raise HTTPException(status_code=400, detail="domain is required")

    target = db.query(Target).filter(Target.domain == domain).one_or_none()
    if not target:
        target = Target(domain=domain, environment=payload.environment)
        db.add(target)
        db.commit()
        db.refresh(target)
    elif payload.environment and target.environment != payload.environment:
        target.environment = payload.environment
        db.commit()
        db.refresh(target)

    scan_job = ScanJob(target_id=target.id, status="queued")
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    queue = get_queue()
    queue.enqueue(scan_job.id)

    return ScanStartResponse(job_id=scan_job.id, target_id=target.id, status=scan_job.status)


@app.get("/scan/status", response_model=ScanStatusResponse)
def scan_status(job_id: int = Query(..., ge=1), db: Session = Depends(get_db)) -> ScanStatusResponse:
    job = db.query(ScanJob).filter(ScanJob.id == job_id).one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="scan job not found")
    return ScanStatusResponse(
        job_id=job.id,
        target_id=job.target_id,
        status=job.status,
        created_at=_to_iso(job.created_at),
        started_at=_to_iso(job.started_at),
        completed_at=_to_iso(job.completed_at),
        error=job.error,
    )


def _latest_scan_result(db: Session, target_id: Optional[int] = None) -> Optional[ScanResult]:
    query = db.query(ScanResult).join(ScanJob, ScanResult.scan_job_id == ScanJob.id)
    if target_id:
        query = query.filter(ScanJob.target_id == target_id)
    return query.order_by(desc(ScanResult.id)).first()


@app.get("/scan/results")
def scan_results(
    job_id: Optional[int] = Query(None, ge=1),
    target_id: Optional[int] = Query(None, ge=1),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    result: Optional[ScanResult] = None
    if job_id:
        result = db.query(ScanResult).filter(ScanResult.scan_job_id == job_id).order_by(desc(ScanResult.id)).first()
    else:
        result = _latest_scan_result(db, target_id=target_id)

    if not result:
        raise HTTPException(status_code=404, detail="scan results not found")

    return {
        "scan_job_id": result.scan_job_id,
        "created_at": _to_iso(result.created_at),
        "result": result.result or {},
    }


@app.get("/targets")
def list_targets(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    targets = db.query(Target).order_by(Target.id).all()
    response: List[Dict[str, Any]] = []
    for target in targets:
        latest_job = (
            db.query(ScanJob)
            .filter(ScanJob.target_id == target.id)
            .order_by(desc(ScanJob.created_at))
            .first()
        )
        response.append(
            {
                "id": target.id,
                "domain": target.domain,
                "environment": target.environment,
                "status": target.status,
                "created_at": _to_iso(target.created_at),
                "last_scanned_at": _to_iso(target.last_scanned_at),
                "latest_job_id": latest_job.id if latest_job else None,
                "latest_job_status": latest_job.status if latest_job else None,
            }
        )
    return response


@app.get("/assets")
def list_assets(target_id: Optional[int] = Query(None, ge=1), db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    query = db.query(Asset)
    if target_id:
        query = query.filter(Asset.target_id == target_id)
    assets = query.order_by(Asset.id).all()
    return [
        {
            "id": asset.id,
            "target_id": asset.target_id,
            "asset_type": asset.asset_type,
            "domain": asset.domain,
            "subdomain": asset.subdomain,
            "ip": asset.ip,
            "port": asset.port,
            "protocol": asset.protocol,
            "url": asset.url,
            "service": asset.service,
            "provider": asset.provider,
            "technology": asset.technology,
            "exposure_class": asset.exposure_class,
            "risk_score": asset.risk_score,
            "metadata": asset.metadata,
            "first_seen": _to_iso(asset.first_seen),
            "last_seen": _to_iso(asset.last_seen),
        }
        for asset in assets
    ]


@app.get("/vulnerabilities")
def list_vulnerabilities(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    vulnerabilities = db.query(Vulnerability).order_by(Vulnerability.id).all()
    return [
        {
            "id": vuln.id,
            "asset_id": vuln.asset_id,
            "scan_job_id": vuln.scan_job_id,
            "severity": vuln.severity,
            "title": vuln.title,
            "description": vuln.description,
            "evidence": vuln.evidence,
            "status": vuln.status,
            "created_at": _to_iso(vuln.created_at),
        }
        for vuln in vulnerabilities
    ]


@app.get("/graph")
def graph(target_id: Optional[int] = Query(None, ge=1), db: Session = Depends(get_db)) -> Dict[str, Any]:
    result = _latest_scan_result(db, target_id=target_id)
    if not result or not result.result:
        return {"nodes": [], "links": []}

    payload = result.result
    assets = payload.get("assets", [])
    edges = payload.get("edges", [])

    nodes: List[Dict[str, Any]] = []
    node_ids: Dict[str, str] = {}

    def _asset_label(asset: Dict[str, Any]) -> str:
        asset_type = asset.get("asset_type")
        if asset_type == "subdomain":
            return asset.get("subdomain") or ""
        if asset_type == "ip":
            return asset.get("ip") or ""
        return asset.get("domain") or asset.get("url") or asset.get("ip") or ""

    for asset in assets:
        asset_type = asset.get("asset_type") or "asset"
        label = _asset_label(asset)
        if not label:
            continue
        node_id = f"{asset_type}:{label}"
        if node_id in node_ids:
            continue
        node_ids[node_id] = node_id
        nodes.append({"id": node_id, "label": label, "type": asset_type})

    links: List[Dict[str, Any]] = []
    for edge in edges:
        source_type = edge.get("source_type")
        target_type = edge.get("target_type")
        source = edge.get("source")
        target = edge.get("target")
        if not (source_type and target_type and source and target):
            continue
        source_id = f"{source_type}:{source}"
        target_id = f"{target_type}:{target}"
        if source_id not in node_ids or target_id not in node_ids:
            continue
        links.append({"source": source_id, "target": target_id, "relation": edge.get("relation")})

    return {"nodes": nodes, "links": links}
