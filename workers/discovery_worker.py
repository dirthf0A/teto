from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, Tuple

from backend.db import SessionLocal, init_db
from backend.models import Asset, AssetEdge, ScanJob, ScanResult, Target
from backend.services import scan_service
from backend.services.queue import get_queue


logging.basicConfig(level=logging.INFO, format="[worker] %(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _asset_key(data: Dict[str, object]) -> Tuple[object, ...]:
    return (
        data.get("asset_type"),
        data.get("domain"),
        data.get("subdomain"),
        data.get("ip"),
        data.get("url"),
        data.get("service"),
        data.get("provider"),
    )


def _asset_label(asset: Asset) -> str:
    if asset.asset_type == "subdomain":
        return asset.subdomain or ""
    if asset.asset_type == "ip":
        return asset.ip or ""
    return asset.domain or asset.url or asset.ip or ""


def _upsert_assets(session, target: Target, assets: Iterable[Dict[str, object]]) -> Dict[Tuple[str, str], int]:
    existing_assets = session.query(Asset).filter(Asset.target_id == target.id).all()
    existing_map = {_asset_key({
        "asset_type": asset.asset_type,
        "domain": asset.domain,
        "subdomain": asset.subdomain,
        "ip": asset.ip,
        "url": asset.url,
        "service": asset.service,
        "provider": asset.provider,
    }): asset for asset in existing_assets}

    now = _utcnow()
    label_map: Dict[Tuple[str, str], int] = {}

    for asset in existing_assets:
        label = _asset_label(asset)
        if label:
            label_map[(asset.asset_type, label)] = asset.id

    for data in assets:
        key = _asset_key(data)
        existing = existing_map.get(key)
        if existing:
            existing.last_seen = now
            existing.domain = data.get("domain")
            existing.subdomain = data.get("subdomain")
            existing.ip = data.get("ip")
            existing.url = data.get("url")
            existing.service = data.get("service")
            existing.provider = data.get("provider")
            existing.protocol = data.get("protocol")
            existing.port = data.get("port")
            existing.exposure_class = data.get("exposure_class")
            existing.risk_score = data.get("risk_score")
            existing.technology = data.get("technology")
            existing.metadata = data.get("metadata")
            asset_obj = existing
        else:
            asset_obj = Asset(
                target_id=target.id,
                asset_type=data.get("asset_type") or "asset",
                domain=data.get("domain"),
                subdomain=data.get("subdomain"),
                ip=data.get("ip"),
                port=data.get("port"),
                protocol=data.get("protocol"),
                url=data.get("url"),
                service=data.get("service"),
                provider=data.get("provider"),
                technology=data.get("technology"),
                exposure_class=data.get("exposure_class"),
                risk_score=data.get("risk_score"),
                metadata=data.get("metadata"),
                first_seen=now,
                last_seen=now,
            )
            session.add(asset_obj)
            session.flush()

        label = _asset_label(asset_obj)
        if label:
            label_map[(asset_obj.asset_type, label)] = asset_obj.id

    return label_map


def _store_edges(session, target: Target, label_map: Dict[Tuple[str, str], int], edges: Iterable[Dict[str, object]]) -> None:
    session.query(AssetEdge).filter(AssetEdge.target_id == target.id).delete()

    edge_models = []
    for edge in edges:
        source_type = edge.get("source_type")
        target_type = edge.get("target_type")
        source = edge.get("source")
        target = edge.get("target")
        if not (source_type and target_type and source and target):
            continue
        source_id = label_map.get((source_type, source))
        target_id = label_map.get((target_type, target))
        if not source_id or not target_id:
            continue
        edge_models.append(
            AssetEdge(
                target_id=target.id,
                source_asset_id=source_id,
                target_asset_id=target_id,
                relation=edge.get("relation") or "linked",
            )
        )

    if edge_models:
        session.add_all(edge_models)


def process_job(job_id: int) -> None:
    session = SessionLocal()
    try:
        job = session.query(ScanJob).filter(ScanJob.id == job_id).one_or_none()
        if not job:
            logger.warning("scan job %s not found", job_id)
            return
        target = session.query(Target).filter(Target.id == job.target_id).one_or_none()
        if not target:
            job.status = "failed"
            job.error = "target not found"
            job.completed_at = _utcnow()
            session.commit()
            return

        job.status = "running"
        job.started_at = _utcnow()
        session.commit()

        result = scan_service.run_full_scan(target.domain, target.environment or "prod")

        scan_result = ScanResult(scan_job_id=job.id, result=result)
        session.add(scan_result)

        assets = result.get("assets", []) if isinstance(result, dict) else []
        edges = result.get("edges", []) if isinstance(result, dict) else []

        label_map = _upsert_assets(session, target, assets)
        _store_edges(session, target, label_map, edges)

        target.last_scanned_at = _utcnow()
        job.status = "completed"
        job.completed_at = _utcnow()
        session.commit()
        logger.info("scan job %s completed", job.id)
    except Exception as exc:
        session.rollback()
        job = session.query(ScanJob).filter(ScanJob.id == job_id).one_or_none()
        if job:
            job.status = "failed"
            job.error = str(exc)
            job.completed_at = _utcnow()
            session.commit()
        logger.exception("scan job %s failed", job_id)
    finally:
        session.close()


def main() -> None:
    init_db()
    queue = get_queue()
    logger.info("worker started")
    while True:
        job_id = queue.dequeue(timeout=5)
        if not job_id:
            time.sleep(1)
            continue
        process_job(job_id)


if __name__ == "__main__":
    main()
