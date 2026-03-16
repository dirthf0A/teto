from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

from app.services import asset_enrichment


@dataclass
class EdgeSpec:
    source_id: int
    target_id: int
    relation: str


def edges_for_domain(domain_asset, assets: Iterable) -> List[EdgeSpec]:
    edges: List[EdgeSpec] = []
    for asset in assets:
        if asset.asset_type == "subdomain":
            edges.append(EdgeSpec(domain_asset.id, asset.id, "subdomain"))
        if asset.asset_type == "cloud":
            edges.append(EdgeSpec(domain_asset.id, asset.id, "cloud_asset"))
    return edges


def edges_for_resolution(
    sub_assets: Dict[str, object],
    ip_assets: Dict[str, object],
    host_enrich: Dict[str, asset_enrichment.HostEnrichment],
) -> List[EdgeSpec]:
    edges: List[EdgeSpec] = []
    for host, enrichment in host_enrich.items():
        sub_asset = sub_assets.get(host)
        if not sub_asset:
            continue
        for ip in enrichment.ips:
            ip_asset = ip_assets.get(ip)
            if not ip_asset:
                continue
            edges.append(EdgeSpec(sub_asset.id, ip_asset.id, "resolves_to"))
    return edges
