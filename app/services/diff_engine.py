from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetChange, Scan


@dataclass
class ScanDiff:
    new_assets: List[AssetChange]
    new_ports: List[AssetChange]
    new_endpoints: List[AssetChange]
    new_vulnerabilities: List[AssetChange]


def collect_scan_diff(db: Session, scan: Scan) -> ScanDiff:
    changes = (
        db.execute(select(AssetChange).where(AssetChange.scan_id == scan.id))
        .scalars()
        .all()
    )
    new_assets = [change for change in changes if change.change_type == "asset_discovered"]
    new_ports = [change for change in changes if change.change_type == "port_exposed"]
    new_endpoints = [change for change in changes if change.change_type == "endpoint_discovered"]
    new_vulns = [change for change in changes if change.change_type == "vuln_discovered"]
    return ScanDiff(
        new_assets=new_assets,
        new_ports=new_ports,
        new_endpoints=new_endpoints,
        new_vulnerabilities=new_vulns,
    )


def diff_summary(diff: ScanDiff) -> Dict[str, List[str]]:
    return {
        "new_assets": [change.detail or "" for change in diff.new_assets],
        "new_ports": [change.detail or "" for change in diff.new_ports],
        "new_endpoints": [change.detail or "" for change in diff.new_endpoints],
        "new_vulnerabilities": [change.detail or "" for change in diff.new_vulnerabilities],
    }
