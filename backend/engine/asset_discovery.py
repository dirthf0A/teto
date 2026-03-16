from dataclasses import dataclass
import ipaddress
import json
import shutil
import subprocess
from typing import Iterable, List, Optional

from backend import config
from backend.engine import (
    asset_enrichment,
    asn_discovery,
    certificate_enum,
    cloud_asset_discovery,
    dns_bruteforce,
    ip_range_scan,
    js_subdomain_extractor,
    passive_sources,
    reverse_ip_discovery,
    scanning,
    subdomain_permutator,
)


@dataclass
class AssetCandidate:
    asset_type: str
    domain: Optional[str]
    subdomain: Optional[str]
    ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    url: Optional[str]
    service: Optional[str]
    environment: str
    source: Optional[str] = None
    asn: Optional[str] = None
    hosting_provider: Optional[str] = None
    cdn: Optional[str] = None
    country: Optional[str] = None


def _normalize_host(raw: str) -> Optional[str]:
    if not raw:
        return None
    value = str(raw).strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value or None


def _merge_source(existing: Optional[str], new: str) -> str:
    if not existing:
        return new
    if not new or new in existing.split(","):
        return existing
    return f"{existing},{new}"


def _cloud_candidates(cloud_assets: Iterable[cloud_asset_discovery.CloudAsset], environment: str) -> List[AssetCandidate]:
    candidates: List[AssetCandidate] = []
    for asset in cloud_assets:
        candidates.append(
            AssetCandidate(
                asset_type="cloud",
                domain=asset.host,
                subdomain=None,
                ip=None,
                port=443,
                protocol="tcp",
                url=asset.url,
                service=asset.service,
                environment=environment,
                source=asset.provider,
            )
        )
    return candidates


def ingest_domain(domain: str, environment: str) -> List[AssetCandidate]:
    candidates = [
        AssetCandidate(
            asset_type="domain",
            domain=domain,
            subdomain=None,
            ip=None,
            port=None,
            protocol=None,
            url=None,
            service=None,
            environment=environment,
        )
    ]
    subdomain_candidates = discover_subdomains(domain, environment)
    candidates.extend(subdomain_candidates)
    host_inputs = [
        candidate.subdomain or candidate.domain
        for candidate in subdomain_candidates
        if candidate.subdomain or candidate.domain
    ]
    host_inputs.append(domain)
    candidates.extend(_cloud_candidates(cloud_asset_discovery.discover_from_hosts(host_inputs), environment))
    bucket_domains = {domain}
    for host in host_inputs:
        if host and host.endswith(domain):
            bucket_domains.add(host)
    candidates.extend(_cloud_candidates(cloud_asset_discovery.discover_bucket_assets(bucket_domains), environment))
    return candidates


def discover_subdomains(domain: str, environment: str) -> List[AssetCandidate]:
    root_domain = _normalize_host(domain)
    if not root_domain:
        return []

    include_external = config.get_reverse_ip_include_external()
    results: dict[str, scanning.SubdomainResult] = {}
    external_hosts: set[str] = set()

    def _add_host(raw: str, source: str, allow_external: bool = False) -> None:
        hostname = _normalize_host(raw)
        if not hostname:
            return
        is_internal = hostname.endswith(root_domain)
        if not is_internal and not allow_external:
            return
        existing = results.get(hostname)
        if existing:
            existing.source = _merge_source(existing.source, source)
        else:
            results[hostname] = scanning.SubdomainResult(hostname=hostname, source=source)
        if not is_internal:
            external_hosts.add(hostname)

    def _run_sources(suffix: str) -> None:
        for entry in passive_sources.discover(suffix):
            _add_host(entry.hostname, entry.source)

        for entry in scanning.run_chaos(suffix):
            _add_host(entry.hostname, entry.source)
        for hostname in scanning.run_pdns(suffix):
            _add_host(hostname, "passive-dns")
        for hostname in scanning.run_censys_hosts(suffix):
            _add_host(hostname, "censys")
        for hostname in scanning.run_securitytrails_hosts(suffix):
            _add_host(hostname, "securitytrails")
        for hostname in scanning.run_dnsdumpster_hosts(suffix):
            _add_host(hostname, "dnsdumpster")
        for hostname in scanning.run_shodan_hosts(suffix):
            _add_host(hostname, "shodan")
        for hostname in scanning.run_cloudflare_hosts(suffix):
            _add_host(hostname, "cloudflare")

        for entry in certificate_enum.discover(suffix):
            _add_host(entry.hostname, entry.source)

        for hostname in scanning.run_dns_bruteforce(suffix):
            _add_host(hostname, "dns-bruteforce-cmd")
        for hostname in scanning.run_dns_bruteforce_wordlist(suffix):
            _add_host(hostname, "dnsx-bruteforce")
        for hostname in scanning.run_puredns(suffix):
            _add_host(hostname, "puredns")
        for hostname in scanning.run_massdns(suffix):
            _add_host(hostname, "massdns")
        for entry in dns_bruteforce.discover(suffix):
            _add_host(entry.hostname, entry.source)

    recursive_enabled = config.get_recursive_enabled()
    max_depth = max(1, config.get_recursive_max_depth()) if recursive_enabled else 1
    max_new = config.get_recursive_max_new()
    seen_hosts: set[str] = set()
    seen_suffixes: set[str] = set()
    pending: set[str] = {root_domain}
    depth = 0

    while pending and depth < max_depth:
        depth += 1
        batch = list(pending)
        pending.clear()
        for suffix in batch:
            if suffix in seen_suffixes:
                continue
            seen_suffixes.add(suffix)
            _run_sources(suffix)
            targets = [f"https://{suffix}", f"http://{suffix}"]
            for host in js_subdomain_extractor.extract_from_targets(targets, root_domain):
                _add_host(host, "js")

        for host in subdomain_permutator.discover(results.keys(), root_domain):
            _add_host(host, "permutation")

        enrich_targets = list(results.keys()) if include_external else [host for host in results if host.endswith(root_domain)]
        host_enrich, ip_enrich = asset_enrichment.enrich_hosts(enrich_targets)

        for host in reverse_ip_discovery.discover_hosts(
            ip_enrich.keys(), root_domain=root_domain, include_external=include_external
        ):
            _add_host(host, "reverse-ip", allow_external=include_external)

        if config.get_asn_discovery_enabled():
            asns = asn_discovery.discover_asns(ip_enrich.keys(), hosts=enrich_targets)
            for host in ip_range_scan.discover_hosts_from_asns(asns):
                _add_host(host, "asn-range", allow_external=include_external)

        if recursive_enabled and depth < max_depth:
            new_hosts = set(results) - seen_hosts
            seen_hosts.update(new_hosts)
            for host in list(new_hosts):
                if host == root_domain:
                    continue
                if not host.endswith(root_domain):
                    continue
                if host.count(".") <= root_domain.count("."):
                    continue
                if host in seen_suffixes:
                    continue
                pending.add(host)
                if len(pending) >= max_new:
                    break

    if not results:
        _add_host(f"www.{root_domain}", "stub")
        _add_host(f"api.{root_domain}", "stub")

    enrich_targets = list(results.keys()) if include_external else [host for host in results if host.endswith(root_domain)]
    host_enrich, ip_enrich = asset_enrichment.enrich_hosts(enrich_targets)

    candidates: List[AssetCandidate] = []
    for hostname, result in results.items():
        if hostname == root_domain:
            continue
        is_external = hostname in external_hosts or not hostname.endswith(root_domain)
        enrichment = host_enrich.get(hostname)
        candidates.append(
            AssetCandidate(
                asset_type="external_domain" if is_external else "subdomain",
                domain=None if is_external else root_domain,
                subdomain=hostname,
                ip=None,
                port=None,
                protocol=None,
                url=None,
                service="http",
                environment=environment,
                source=result.source,
                cdn=enrichment.cdn if enrichment else None,
            )
        )

    for ip, meta in ip_enrich.items():
        candidates.append(
            AssetCandidate(
                asset_type="ip",
                domain=None,
                subdomain=None,
                ip=ip,
                port=None,
                protocol=None,
                url=None,
                service=None,
                environment=environment,
                source="enrichment",
                asn=meta.asn,
                hosting_provider=meta.hosting_provider,
                country=meta.country,
            )
        )
    return candidates


def discover_services(target: AssetCandidate) -> AssetCandidate:
    # Placeholder for service discovery on a single asset.
    if not target.service:
        if target.subdomain or target.domain:
            target.service = "http"
        else:
            target.service = "unknown"
    return target


def discover_cloud_assets(environment: str) -> List[AssetCandidate]:
    candidates: List[AssetCandidate] = []
    providers = {provider.lower() for provider in config.get_cloud_providers()}

    if "aws" in providers:
        aws = shutil.which("aws")
        if aws:
            try:
                output = subprocess.run(
                    [aws, "s3api", "list-buckets", "--output", "json"],
                    capture_output=True,
                    text=True,
                    timeout=config.get_scanner_timeout(),
                    check=False,
                )
                if output.returncode == 0:
                    data = json.loads(output.stdout or "{}")
                    for bucket in data.get("Buckets", []):
                        name = bucket.get("Name")
                        if not name:
                            continue
                        candidates.append(
                            AssetCandidate(
                                asset_type="cloud",
                                domain=f"{name}.s3.amazonaws.com",
                                subdomain=None,
                                ip=None,
                                port=443,
                                protocol="tcp",
                                url=f"https://{name}.s3.amazonaws.com",
                                service="s3",
                                environment=environment,
                                source="aws",
                            )
                        )
            except (OSError, json.JSONDecodeError):
                pass

    if "gcp" in providers:
        gcloud = shutil.which("gcloud")
        if gcloud:
            try:
                output = subprocess.run(
                    [gcloud, "storage", "buckets", "list", "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=config.get_scanner_timeout(),
                    check=False,
                )
                if output.returncode == 0:
                    data = json.loads(output.stdout or "[]")
                    for bucket in data:
                        name = bucket.get("name") or bucket.get("id")
                        if not name:
                            continue
                        candidates.append(
                            AssetCandidate(
                                asset_type="cloud",
                                domain=f"{name}.storage.googleapis.com",
                                subdomain=None,
                                ip=None,
                                port=443,
                                protocol="tcp",
                                url=f"https://storage.googleapis.com/{name}",
                                service="gcs",
                                environment=environment,
                                source="gcp",
                            )
                        )
            except (OSError, json.JSONDecodeError):
                pass

    if "azure" in providers:
        az = shutil.which("az")
        if az:
            try:
                output = subprocess.run(
                    [az, "storage", "account", "list", "--output", "json"],
                    capture_output=True,
                    text=True,
                    timeout=config.get_scanner_timeout(),
                    check=False,
                )
                if output.returncode == 0:
                    data = json.loads(output.stdout or "[]")
                    for account in data:
                        name = account.get("name")
                        if not name:
                            continue
                        candidates.append(
                            AssetCandidate(
                                asset_type="cloud",
                                domain=f"{name}.blob.core.windows.net",
                                subdomain=None,
                                ip=None,
                                port=443,
                                protocol="tcp",
                                url=f"https://{name}.blob.core.windows.net",
                                service="azure-storage",
                                environment=environment,
                                source="azure",
                            )
                        )
            except (OSError, json.JSONDecodeError):
                pass

    if not candidates:
        candidates.append(
            AssetCandidate(
                asset_type="cloud",
                domain="cloud.example",
                subdomain=None,
                ip="10.0.0.1",
                port=443,
                protocol="tcp",
                url="https://cloud.example",
                service="https",
                environment=environment,
                source="stub",
            )
        )
    return candidates


def ingest_ip_range(ip_range: str, environment: str) -> List[AssetCandidate]:
    network = ipaddress.ip_network(ip_range, strict=False)
    candidates: List[AssetCandidate] = []
    limit = config.get_ip_range_scan_limit()
    for idx, ip in enumerate(network.hosts()):
        if idx >= limit:
            break
        candidates.append(
            AssetCandidate(
                asset_type="ip",
                domain=None,
                subdomain=None,
                ip=str(ip),
                port=None,
                protocol=None,
                url=None,
                service=None,
                environment=environment,
            )
        )
    return candidates
