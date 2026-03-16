"""Asset correlation engine.

Links assets together to build the attack surface graph:
  domain → subdomains → IPs → cloud assets → buckets → services

Creates AssetEdge relationships in the database and exposes helpers
to compute the full correlated asset graph.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetEdge


# ---------------------------------------------------------------------------
# Edge types
# ---------------------------------------------------------------------------
RELATION_SUBDOMAIN_OF = "subdomain_of"
RELATION_RESOLVES_TO = "resolves_to"
RELATION_HOSTED_ON = "hosted_on"           # asset hosted on cloud/IP
RELATION_SHARES_IP = "shares_ip"
RELATION_SAME_PROVIDER = "same_provider"
RELATION_BUCKET_OF = "bucket_of"          # cloud bucket linked to domain/subdomain
RELATION_SERVES_SERVICE = "serves_service"  # IP/host runs a service


@dataclass
class CorrelationEdge:
    source_id: int
    target_id: int
    relation: str
    detail: Optional[str] = None


@dataclass
class AssetGraph:
    nodes: List[Asset] = field(default_factory=list)
    edges: List[CorrelationEdge] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Correlation logic
# ---------------------------------------------------------------------------

def _edge_key(source_id: int, target_id: int, relation: str) -> Tuple:
    return (source_id, target_id, relation)


def _upsert_edge(
    db: Session,
    org_id: int,
    source_id: int,
    target_id: int,
    relation: str,
    detail: Optional[str] = None,
) -> None:
    existing = db.execute(
        select(AssetEdge).where(
            AssetEdge.org_id == org_id,
            AssetEdge.source_id == source_id,
            AssetEdge.target_id == target_id,
            AssetEdge.relation == relation,
        )
    ).scalar_one_or_none()

    if not existing:
        edge = AssetEdge(
            org_id=org_id,
            source_id=source_id,
            target_id=target_id,
            relation=relation,
        )
        db.add(edge)


def correlate_org_assets(db: Session, org_id: int) -> int:
    """Run full correlation for all assets in an org. Returns count of new edges created."""
    assets = db.execute(
        select(Asset).where(Asset.org_id == org_id)
    ).scalars().all()

    # Build lookup indexes
    by_domain: Dict[str, List[Asset]] = {}     # domain string → assets
    by_subdomain: Dict[str, List[Asset]] = {}  # subdomain string → assets
    by_ip: Dict[str, List[Asset]] = {}         # IP → assets
    by_provider: Dict[str, List[Asset]] = {}   # hosting_provider → assets

    for asset in assets:
        if asset.domain:
            by_domain.setdefault(asset.domain, []).append(asset)
        if asset.subdomain:
            by_subdomain.setdefault(asset.subdomain, []).append(asset)
        if asset.ip:
            by_ip.setdefault(asset.ip, []).append(asset)
        if asset.hosting_provider:
            by_provider.setdefault(asset.hosting_provider.lower(), []).append(asset)

    edges_before = db.execute(
        select(AssetEdge).where(AssetEdge.org_id == org_id)
    ).scalars().all()
    seen_edges: Set[Tuple] = {(e.source_id, e.target_id, e.relation) for e in edges_before}

    new_edges = 0

    def add(src: Asset, tgt: Asset, rel: str, detail: Optional[str] = None) -> None:
        nonlocal new_edges
        k = (src.id, tgt.id, rel)
        if k not in seen_edges:
            seen_edges.add(k)
            _upsert_edge(db, org_id, src.id, tgt.id, rel, detail)
            new_edges += 1

    for asset in assets:
        # 1. subdomain → parent domain
        if asset.asset_type == "subdomain" and asset.domain:
            for parent in by_domain.get(asset.domain, []):
                if parent.asset_type == "domain" and parent.id != asset.id:
                    add(asset, parent, RELATION_SUBDOMAIN_OF)

        # 2. Subdomain/domain → IP (resolves_to)
        if asset.ip and asset.subdomain:
            for ip_asset in by_ip.get(asset.ip, []):
                if ip_asset.asset_type == "ip" and ip_asset.id != asset.id:
                    add(asset, ip_asset, RELATION_RESOLVES_TO)

        # 3. IP-sharing: multiple subdomains → same IP
        if asset.asset_type == "ip" and asset.ip:
            co_assets = by_ip.get(asset.ip, [])
            for other in co_assets:
                if other.id != asset.id and other.asset_type in ("subdomain", "domain"):
                    add(other, asset, RELATION_RESOLVES_TO)
                    # Also mark as shares_ip with each other
                    for peer in co_assets:
                        if peer.id != other.id and peer.id != asset.id:
                            add(other, peer, RELATION_SHARES_IP)

        # 4. Cloud asset → parent domain/subdomain
        if asset.asset_type == "cloud" and asset.domain:
            # Match cloud asset domain to subdomains (e.g. api.example.com → bucket)
            host = asset.domain.lower()
            for sub_asset in by_subdomain.get(host, []):
                if sub_asset.id != asset.id:
                    add(sub_asset, asset, RELATION_HOSTED_ON, asset.service)
            for dom_asset in by_domain.get(host, []):
                if dom_asset.id != asset.id:
                    add(dom_asset, asset, RELATION_HOSTED_ON, asset.service)

        # 5. Same hosting provider
        if asset.hosting_provider:
            provider = asset.hosting_provider.lower()
            for peer in by_provider.get(provider, []):
                if peer.id != asset.id and peer.asset_type != asset.asset_type:
                    add(asset, peer, RELATION_SAME_PROVIDER, provider)

        # 6. Bucket assets → linked subdomains (s3 bucket often named same as subdomain)
        if asset.service in ("s3", "gcs", "azure-storage") and asset.domain:
            bucket_name = asset.domain.split(".")[0]
            for sub_asset in assets:
                if sub_asset.subdomain and sub_asset.subdomain.split(".")[0] == bucket_name:
                    add(sub_asset, asset, RELATION_BUCKET_OF)

    db.commit()
    return new_edges


def get_asset_graph(db: Session, org_id: int, asset_id: Optional[int] = None) -> AssetGraph:
    """Build asset graph for an org, optionally filtered to neighbors of a specific asset."""
    if asset_id:
        # Get 2-hop neighborhood
        direct_edges = db.execute(
            select(AssetEdge).where(
                AssetEdge.org_id == org_id,
                (AssetEdge.source_id == asset_id) | (AssetEdge.target_id == asset_id),
            )
        ).scalars().all()

        related_ids: Set[int] = {asset_id}
        for e in direct_edges:
            related_ids.add(e.source_id)
            related_ids.add(e.target_id)

        assets = db.execute(
            select(Asset).where(Asset.id.in_(related_ids))
        ).scalars().all()

        edges = direct_edges
    else:
        assets = db.execute(select(Asset).where(Asset.org_id == org_id)).scalars().all()
        edges = db.execute(select(AssetEdge).where(AssetEdge.org_id == org_id)).scalars().all()

    graph = AssetGraph(nodes=list(assets))
    for e in edges:
        graph.edges.append(CorrelationEdge(
            source_id=e.source_id,
            target_id=e.target_id,
            relation=e.relation,
        ))

    return graph


def get_attack_surface_summary(db: Session, org_id: int) -> Dict:
    """Return high-level summary of correlated attack surface."""
    assets = db.execute(select(Asset).where(Asset.org_id == org_id)).scalars().all()

    counts: Dict[str, int] = {}
    providers: Dict[str, int] = {}
    exposed_count = 0

    for asset in assets:
        atype = asset.asset_type or "unknown"
        counts[atype] = counts.get(atype, 0) + 1
        if asset.hosting_provider:
            p = asset.hosting_provider.lower()
            providers[p] = providers.get(p, 0) + 1
        if asset.exposure_class == "public":
            exposed_count += 1

    edges_count = db.execute(
        select(AssetEdge).where(AssetEdge.org_id == org_id)
    ).scalars().all()

    return {
        "total_assets": len(assets),
        "by_type": counts,
        "by_provider": providers,
        "public_exposed": exposed_count,
        "correlation_edges": len(edges_count),
    }
