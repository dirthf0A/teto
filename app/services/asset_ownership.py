"""Asset Ownership Mapping — maps assets to teams/owners.

Features:
  - Assign assets to teams with optional owner email + notes
  - Bulk assign by domain pattern (e.g. all *.api.* → backend team)
  - Team exposure dashboard: findings & risk per team
  - Unowned asset report
  - Ownership history via ActivityLog
"""
from __future__ import annotations

import fnmatch
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetOwnership, Finding


# ── Core CRUD ──────────────────────────────────────────────────────────────

def assign_owner(db: Session, org_id: int, asset_id: int,
                 team_name: str, owner_email: Optional[str] = None,
                 notes: Optional[str] = None) -> AssetOwnership:
    """Assign or update ownership of an asset."""
    existing = db.execute(
        select(AssetOwnership).where(
            AssetOwnership.org_id == org_id,
            AssetOwnership.asset_id == asset_id,
        )
    ).scalar_one_or_none()

    if existing:
        existing.team_name = team_name
        existing.owner_email = owner_email
        existing.notes = notes
        db.commit()
        db.refresh(existing)
        return existing

    ownership = AssetOwnership(
        org_id=org_id,
        asset_id=asset_id,
        team_name=team_name,
        owner_email=owner_email,
        notes=notes,
    )
    db.add(ownership)
    db.commit()
    db.refresh(ownership)
    return ownership


def remove_owner(db: Session, org_id: int, asset_id: int) -> bool:
    existing = db.execute(
        select(AssetOwnership).where(
            AssetOwnership.org_id == org_id,
            AssetOwnership.asset_id == asset_id,
        )
    ).scalar_one_or_none()
    if not existing:
        return False
    db.delete(existing)
    db.commit()
    return True


def get_asset_owner(db: Session, org_id: int, asset_id: int) -> Optional[dict]:
    o = db.execute(
        select(AssetOwnership).where(
            AssetOwnership.org_id == org_id,
            AssetOwnership.asset_id == asset_id,
        )
    ).scalar_one_or_none()
    if not o:
        return None
    return {
        "asset_id": o.asset_id,
        "team_name": o.team_name,
        "owner_email": o.owner_email,
        "notes": o.notes,
        "created_at": o.created_at.isoformat() if o.created_at else None,
    }


def bulk_assign_by_pattern(db: Session, org_id: int,
                            pattern: str, team_name: str,
                            owner_email: Optional[str] = None) -> int:
    """Assign ownership to all assets whose label matches a glob pattern.

    E.g. pattern='*.api.*' assigns all API subdomains to a team.
    Returns count of assets assigned.
    """
    assets = db.execute(select(Asset).where(Asset.org_id == org_id)).scalars().all()
    count = 0
    for asset in assets:
        label = asset.subdomain or asset.domain or asset.ip or ""
        if fnmatch.fnmatch(label.lower(), pattern.lower()):
            assign_owner(db, org_id, asset.id, team_name, owner_email)
            count += 1
    return count


# ── Team exposure dashboard ────────────────────────────────────────────────

def get_team_exposure(db: Session, org_id: int) -> List[dict]:
    """Return per-team risk summary: asset count, open findings, severity breakdown."""
    ownerships = db.execute(
        select(AssetOwnership).where(AssetOwnership.org_id == org_id)
    ).scalars().all()

    asset_to_team: Dict[int, str] = {o.asset_id: o.team_name for o in ownerships}
    teams: Dict[str, dict] = {}

    for o in ownerships:
        if o.team_name not in teams:
            teams[o.team_name] = {
                "team_name": o.team_name,
                "asset_count": 0,
                "open_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "risk_score": 0.0,
                "assets": [],
            }
        teams[o.team_name]["asset_count"] += 1

    # Attach findings per team
    findings = db.execute(
        select(Finding).where(Finding.org_id == org_id, Finding.status == "open")
    ).scalars().all()

    for f in findings:
        if not f.asset_id:
            continue
        team = asset_to_team.get(f.asset_id)
        if not team or team not in teams:
            continue
        teams[team]["open_findings"] += 1
        sev = f.severity or "info"
        if sev in teams[team]:
            teams[team][sev] += 1
        risk = float(f.risk_score or 0)
        if risk > teams[team]["risk_score"]:
            teams[team]["risk_score"] = risk

    # Collect asset labels
    asset_ids = list(asset_to_team.keys())
    if asset_ids:
        assets = db.execute(select(Asset).where(Asset.id.in_(asset_ids))).scalars().all()
        for a in assets:
            team = asset_to_team.get(a.id)
            if team and team in teams:
                label = a.subdomain or a.domain or a.ip or f"#{a.id}"
                teams[team]["assets"].append({
                    "id": a.id,
                    "label": label,
                    "exposure": a.exposure_class,
                    "type": a.asset_type,
                })

    result = sorted(teams.values(), key=lambda t: t["open_findings"], reverse=True)
    return result


def get_unowned_assets(db: Session, org_id: int, limit: int = 100) -> List[dict]:
    """Return assets with no ownership assignment — helps track coverage gaps."""
    owned_ids = db.execute(
        select(AssetOwnership.asset_id).where(AssetOwnership.org_id == org_id)
    ).scalars().all()
    owned_set = set(owned_ids)

    assets = db.execute(
        select(Asset).where(
            Asset.org_id == org_id,
            Asset.exposure_class == "public",
        ).order_by(Asset.importance.desc()).limit(limit * 3)
    ).scalars().all()

    result = []
    for a in assets:
        if a.id in owned_set:
            continue
        result.append({
            "id": a.id,
            "label": a.subdomain or a.domain or a.ip or f"#{a.id}",
            "type": a.asset_type,
            "exposure": a.exposure_class,
            "technology": a.technology,
        })
        if len(result) >= limit:
            break
    return result


def get_all_teams(db: Session, org_id: int) -> List[str]:
    """Return list of all team names for this org."""
    rows = db.execute(
        select(AssetOwnership.team_name).where(AssetOwnership.org_id == org_id).distinct()
    ).scalars().all()
    return sorted(set(rows))
