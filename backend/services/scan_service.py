from __future__ import annotations

from typing import Dict, List

from backend.engine import (
    asset_discovery,
    bucket_scanner,
    cloud_asset_discovery,
    dns_bruteforce,
    reverse_ip_discovery,
)


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def run_full_scan(domain: str, environment: str = "prod") -> Dict[str, object]:
    root = _normalize_domain(domain)
    if not root:
        raise ValueError("domain is required")

    candidates = asset_discovery.ingest_domain(root, environment)

    subdomains = set()
    ips = set()
    for candidate in candidates:
        if candidate.subdomain:
            subdomains.add(candidate.subdomain)
        if candidate.ip:
            ips.add(candidate.ip)

    # DNS enumeration
    dns_hits = dns_bruteforce.discover(root)
    for entry in dns_hits:
        if entry.hostname:
            subdomains.add(entry.hostname)

    # Reverse IP discovery
    reverse_hosts = reverse_ip_discovery.discover_hosts(ips, root_domain=root, include_external=False)
    for host in reverse_hosts:
        subdomains.add(host)

    hosts = {root}
    hosts.update(subdomains)

    # Cloud assets
    cloud_assets = cloud_asset_discovery.discover_from_hosts(hosts)
    cloud_buckets = cloud_asset_discovery.discover_bucket_assets(hosts)

    # Bucket scanning
    bucket_candidates = bucket_scanner.generate_bucket_candidates(hosts)
    bucket_hits = bucket_scanner.probe_buckets(bucket_candidates)

    assets: List[Dict[str, object]] = [
        {
            "asset_type": "domain",
            "domain": root,
            "subdomain": None,
            "ip": None,
            "url": None,
            "service": None,
            "provider": None,
        }
    ]

    assets.extend(
        {
            "asset_type": "subdomain",
            "domain": root,
            "subdomain": subdomain,
            "ip": None,
            "url": None,
            "service": "http",
            "provider": None,
        }
        for subdomain in sorted(subdomains)
    )

    assets.extend(
        {
            "asset_type": "ip",
            "domain": None,
            "subdomain": None,
            "ip": ip,
            "url": None,
            "service": None,
            "provider": None,
        }
        for ip in sorted(ips)
    )

    assets.extend(
        {
            "asset_type": "cloud",
            "domain": asset.host,
            "subdomain": None,
            "ip": None,
            "url": asset.url,
            "service": asset.service,
            "provider": asset.provider,
        }
        for asset in cloud_assets
    )

    assets.extend(
        {
            "asset_type": "cloud",
            "domain": asset.host,
            "subdomain": None,
            "ip": None,
            "url": asset.url,
            "service": asset.service,
            "provider": asset.provider,
        }
        for asset in cloud_buckets
    )

    assets.extend(
        {
            "asset_type": "bucket",
            "domain": hit.name,
            "subdomain": None,
            "ip": None,
            "url": hit.url,
            "service": "bucket",
            "provider": hit.provider,
            "metadata": {"status_code": hit.status_code},
        }
        for hit in bucket_hits
    )

    edges: List[Dict[str, object]] = []
    max_edges = 2000

    for subdomain in subdomains:
        edges.append(
            {
                "source_type": "domain",
                "source": root,
                "target_type": "subdomain",
                "target": subdomain,
                "relation": "subdomain",
            }
        )
        if len(edges) >= max_edges:
            break

    if edges and len(edges) < max_edges:
        for subdomain in subdomains:
            for ip in ips:
                edges.append(
                    {
                        "source_type": "subdomain",
                        "source": subdomain,
                        "target_type": "ip",
                        "target": ip,
                        "relation": "resolves_to",
                    }
                )
                if len(edges) >= max_edges:
                    break
            if len(edges) >= max_edges:
                break

    if len(edges) < max_edges and cloud_assets:
        for ip in ips or {"unknown"}:
            for asset in cloud_assets:
                edges.append(
                    {
                        "source_type": "ip",
                        "source": ip,
                        "target_type": "cloud",
                        "target": asset.host,
                        "relation": "cloud_asset",
                    }
                )
                if len(edges) >= max_edges:
                    break
            if len(edges) >= max_edges:
                break

    if len(edges) < max_edges and bucket_hits:
        for asset in cloud_assets or cloud_buckets:
            for bucket in bucket_hits:
                edges.append(
                    {
                        "source_type": "cloud",
                        "source": asset.host,
                        "target_type": "bucket",
                        "target": bucket.name,
                        "relation": "bucket",
                    }
                )
                if len(edges) >= max_edges:
                    break
            if len(edges) >= max_edges:
                break

    return {
        "domain": root,
        "environment": environment,
        "counts": {
            "subdomains": len(subdomains),
            "ips": len(ips),
            "cloud_assets": len(cloud_assets) + len(cloud_buckets),
            "buckets": len(bucket_hits),
        },
        "assets": assets,
        "edges": edges,
        "dns_bruteforce": [entry.hostname for entry in dns_hits if entry.hostname],
        "reverse_ip_hosts": reverse_hosts,
        "bucket_candidates": bucket_candidates,
    }
