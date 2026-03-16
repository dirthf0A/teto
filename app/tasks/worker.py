import json
import time
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse

from sqlalchemy import select

from app import config
from app.db import SessionLocal, init_db
from app.models import Alert, Asset, AssetChange, AssetEdge, Finding, Scan, ScanResult
from app.services import (
    analysis,
    asset_discovery,
    asset_enrichment,
    asset_intelligence,
    asset_snapshot_engine,
    cloud_asset_discovery,
    crawler,
    diff_engine,
    notifications,
    reverse_ip_discovery,
    scanning,
)
from app.services.queue import get_queue
from app.logger import get_logger
logger = get_logger('app.tasks.worker')


MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 120
DISCOVERY_SCAN_TYPES = {"asset_discovery", "service", "exposed", "deep"}
VULN_SCAN_TYPES = {"vuln", "web", "api", "misconfig", "tls", "headers"}
SECRET_SCAN_TYPES = {"secret"}


def create_alert(
    db,
    org_id: int,
    alert_type: str,
    message: str,
    asset_id: Optional[int] = None,
    finding_id: Optional[int] = None,
) -> None:
    try:
        from app.services.alert_engine import dispatch_alert as ae_dispatch
        ae_dispatch(db, org_id, alert_type, message, asset_id=asset_id, finding_id=finding_id)
    except ImportError:
        # Fallback to original behaviour
        alert = Alert(
            org_id=org_id,
            asset_id=asset_id,
            finding_id=finding_id,
            alert_type=alert_type,
            message=message,
            status="new",
        )
        db.add(alert)
        notifications.dispatch_alert(
            message,
            {
                "org_id": org_id,
                "alert_type": alert_type,
                "asset_id": asset_id,
                "finding_id": finding_id,
                "message": message,
            },
        )


def create_risk_increase_alert(
    db,
    org_id: int,
    asset_id: Optional[int],
    finding_id: Optional[int],
    title: str,
    delta: float,
) -> None:
    message = f"Risk increased: {title} (+{delta:.1f})"
    create_alert(
        db,
        org_id=org_id,
        asset_id=asset_id,
        finding_id=finding_id,
        alert_type="risk_increase",
        message=message,
    )


def worker_allows_scan(scan_type: str) -> bool:
    mode = config.get_worker_mode()
    if mode in {"discovery", "asset"}:
        return scan_type in DISCOVERY_SCAN_TYPES
    if mode in {"vuln", "vulnerability"}:
        return scan_type in VULN_SCAN_TYPES
    if mode in {"secret"}:
        return scan_type in SECRET_SCAN_TYPES
    return True


def load_asset_cache(db, org_id: int) -> Dict[str, Dict]:
    assets = db.execute(select(Asset).where(Asset.org_id == org_id)).scalars().all()
    cache = {
        "by_key": {},
        "by_url": {},
        "by_subdomain": {},
        "by_ip": {},
    }
    for asset in assets:
        key = asset_intelligence.asset_key(
            asset.asset_type, asset.domain, asset.subdomain, asset.ip, asset.port, asset.protocol, asset.url
        )
        cache["by_key"][key] = asset
        if asset.url:
            cache["by_url"][asset.url] = asset
        if asset.subdomain:
            cache["by_subdomain"][asset.subdomain] = asset
        if asset.ip:
            cache["by_ip"][asset.ip] = asset
    return cache


def load_edge_cache(db, org_id: int) -> set:
    edges = db.execute(select(AssetEdge).where(AssetEdge.org_id == org_id)).scalars().all()
    return {asset_intelligence.edge_key(edge.source_asset_id, edge.target_asset_id, edge.relation) for edge in edges}


def upsert_asset(
    db,
    cache: Dict[str, Dict],
    org_id: int,
    asset_type: str,
    domain: Optional[str],
    subdomain: Optional[str],
    ip: Optional[str],
    port: Optional[int],
    protocol: Optional[str],
    url: Optional[str],
    service: Optional[str],
    environment: str,
    technology: Optional[str] = None,
    asn: Optional[str] = None,
    hosting_provider: Optional[str] = None,
    cdn: Optional[str] = None,
    country: Optional[str] = None,
    tags: Optional[str] = None,
    importance: Optional[float] = None,
    exposure_class: Optional[str] = None,
    exposure_score: Optional[float] = None,
) -> tuple[Asset, bool]:
    key = asset_intelligence.asset_key(asset_type, domain, subdomain, ip, port, protocol, url)
    now = datetime.utcnow()
    if key in cache["by_key"]:
        asset = cache["by_key"][key]
        asset.last_seen = now
        if importance is not None:
            asset.importance = importance
        if exposure_score is not None:
            asset.exposure_score = exposure_score
        if exposure_class is not None:
            asset.exposure_class = exposure_class
        if asset.exposure_class is None:
            asset.exposure_class = asset_intelligence.classify_exposure(
                asset.environment, asset.tags, asset.asset_type, ip=asset.ip
            )
        if asset.exposure_score is None and asset.exposure_class:
            asset.exposure_score = asset_intelligence.exposure_score(asset.exposure_class)
        if technology:
            asset.technology = asset_intelligence.merge_technology(asset.technology, technology)
        if asn and not asset.asn:
            asset.asn = asn
        if hosting_provider and not asset.hosting_provider:
            asset.hosting_provider = hosting_provider
        if cdn and not asset.cdn:
            asset.cdn = cdn
        if country and not asset.country:
            asset.country = country
        return asset, False

    if importance is None:
        importance = asset_intelligence.compute_asset_importance(environment, tags, asset_type)
    if exposure_class is None:
        exposure_class = asset_intelligence.classify_exposure(environment, tags, asset_type, ip=ip)
    if exposure_score is None:
        exposure_score = asset_intelligence.exposure_score(exposure_class)

    asset = Asset(
        org_id=org_id,
        asset_type=asset_type,
        domain=domain,
        subdomain=subdomain,
        ip=ip,
        port=port,
        protocol=protocol,
        url=url,
        service=service,
        technology=technology,
        asn=asn,
        hosting_provider=hosting_provider,
        cdn=cdn,
        country=country,
        environment=environment,
        tags=tags,
        importance=importance,
        exposure_class=exposure_class,
        exposure_score=exposure_score,
        first_seen=now,
        last_seen=now,
    )
    try:
        db.add(asset)
        db.flush()
    except Exception:
        # Concurrent worker inserted the same asset — roll back and fetch existing
        db.rollback()
        existing_in_db = db.execute(
            select(Asset).where(
                Asset.org_id == org_id,
                Asset.asset_type == asset_type,
                Asset.domain == domain,
                Asset.subdomain == subdomain,
                Asset.ip == ip,
                Asset.port == port,
            )
        ).scalars().first()
        if existing_in_db:
            cache["by_key"][key] = existing_in_db
            return existing_in_db, False
        # Re-raise if it's not a uniqueness conflict
        raise

    cache["by_key"][key] = asset
    if url:
        cache["by_url"][url] = asset
    if subdomain:
        cache["by_subdomain"][subdomain] = asset
    if ip:
        cache["by_ip"][ip] = asset
    return asset, True


def upsert_edge(
    db,
    edge_keys: set,
    org_id: int,
    source_asset: Asset,
    target_asset: Asset,
    relation: str,
) -> None:
    key = asset_intelligence.edge_key(source_asset.id, target_asset.id, relation)
    if key in edge_keys:
        return
    db.add(
        AssetEdge(
            org_id=org_id,
            source_asset_id=source_asset.id,
            target_asset_id=target_asset.id,
            relation=relation,
        )
    )
    edge_keys.add(key)


def ingest_cloud_assets(
    db,
    scan: Scan,
    cache: Dict[str, Dict],
    candidates: Iterable[asset_discovery.AssetCandidate],
    parent_asset: Optional[Asset] = None,
    edge_keys: Optional[set] = None,
) -> None:
    for cloud in candidates:
        cloud_asset, created = upsert_asset(
            db,
            cache,
            org_id=scan.org_id,
            asset_type=cloud.asset_type,
            domain=cloud.domain,
            subdomain=cloud.subdomain,
            ip=cloud.ip,
            port=cloud.port,
            protocol=cloud.protocol,
            url=cloud.url,
            service=cloud.service,
            environment=cloud.environment,
        )
        if parent_asset and edge_keys is not None:
            upsert_edge(db, edge_keys, scan.org_id, parent_asset, cloud_asset, "cloud_asset")
        if created:
            create_alert(
                db,
                org_id=scan.org_id,
                asset_id=cloud_asset.id,
                alert_type="new_cloud_asset",
                message=f"New cloud asset discovered: {cloud_asset.domain}",
            )
        if config.get_cloud_public_check() and cloud_asset.url:
            if scanning.is_public_url(cloud_asset.url):
                public_finding = scanning.ScanFinding(
                    title="Public cloud asset",
                    severity="high",
                    description="Cloud storage appears publicly accessible.",
                    evidence=cloud_asset.url,
                    tool="cloud-check",
                    target=cloud_asset.url,
                )
                db_finding, created, risk_increase, risk_delta = upsert_finding(
                    db, cache, scan.org_id, cloud_asset, scan, public_finding
                )
                if created:
                    create_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=cloud_asset.id,
                        finding_id=db_finding.id,
                        alert_type="public_cloud_asset",
                        message=f"Public cloud asset detected: {cloud_asset.url}",
                    )
                if risk_increase:
                    create_risk_increase_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=cloud_asset.id,
                        finding_id=db_finding.id,
                        title=db_finding.title,
                        delta=risk_delta,
                    )


def resolve_asset_for_target(cache: Dict[str, Dict], target: str) -> Optional[Asset]:
    if target in cache["by_url"]:
        return cache["by_url"][target]
    parsed = urlparse(target) if "://" in target else None
    host = parsed.hostname if parsed else target
    if host in cache["by_subdomain"]:
        return cache["by_subdomain"][host]
    if host in cache["by_ip"]:
        return cache["by_ip"][host]
    return None


def upsert_finding(
    db,
    cache: Dict[str, Dict],
    org_id: int,
    asset: Asset,
    scan: Scan,
    finding: scanning.ScanFinding,
) -> tuple[Finding, bool, bool, float]:
    fingerprint = asset_intelligence.fingerprint_for_finding(finding, finding.target)
    existing = (
        db.execute(
            select(Finding).where(
                Finding.org_id == org_id,
                Finding.asset_id == asset.id,
                Finding.fingerprint == fingerprint,
            )
        )
        .scalars()
        .first()
    )
    now = datetime.utcnow()
    severity = analysis.classify_severity(finding)
    exposure_class = asset.exposure_class or asset_intelligence.classify_exposure(
        asset.environment, asset.tags, asset.asset_type, ip=asset.ip
    )
    exposure_score = asset.exposure_score or asset_intelligence.exposure_score(exposure_class)
    if not asset.exposure_class:
        asset.exposure_class = exposure_class
    if asset.exposure_score is None:
        asset.exposure_score = exposure_score
    importance = asset.importance or asset_intelligence.compute_asset_importance(
        asset.environment, asset.tags, asset.asset_type
    )

    # CVSS-aware risk scoring: uses NVD CVSS, KEV status, exploit availability
    is_kev = False
    has_exploit = False
    if finding.cve:
        try:
            from app.services.vuln_scanner import get_kev_cve_set
            is_kev = finding.cve.upper() in get_kev_cve_set()
        except Exception as e:
            logger.debug("kev lookup skipped", error=str(e))

    risk_score = analysis.score_finding_cvss_aware(
        finding, exposure_class, importance,
        is_kev=is_kev, has_exploit=has_exploit,
    )
    previous_risk = existing.risk_score if existing and existing.risk_score is not None else 0.0
    risk_delta = risk_score - float(previous_risk or 0.0)
    risk_increase = bool(existing) and risk_delta >= config.get_risk_increase_threshold()

    if existing:
        existing.last_seen = now
        existing.occurrences = (existing.occurrences or 1) + 1
        existing.risk_score = risk_score
        existing.scan_id = scan.id
        if existing.status != "open":
            existing.status = "open"
        # Escalate severity if KEV and currently below critical
        if is_kev and existing.severity not in ("critical",):
            existing.severity = "critical"
        return existing, False, risk_increase, risk_delta

    db_finding = Finding(
        org_id=org_id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint=fingerprint,
        severity="critical" if is_kev else severity,  # KEV always → critical
        title=finding.title,
        description=finding.description,
        evidence=finding.evidence,
        tool=finding.tool,
        target=finding.target,
        port=finding.port,
        cvss=finding.cvss,
        cve=finding.cve,
        risk_score=risk_score,
        exposure_score=exposure_score,
        asset_importance=importance,
        first_seen=now,
        last_seen=now,
    )
    db.add(db_finding)
    db.flush()
    db.add(
        AssetChange(
            org_id=org_id,
            scan_id=scan.id,
            asset_id=asset.id,
            change_type="vuln_discovered",
            detail=finding.title,
        )
    )
    return db_finding, True, False, 0.0


def pipeline_for_domain(
    db,
    scan: Scan,
    domain_asset: Asset,
    cache: Dict[str, Dict],
    edge_keys: set,
    run_vuln: bool = True,
) -> None:
    if not domain_asset.domain:
        return
    domain_name = domain_asset.domain.strip().lower().rstrip(".")
    domain_asset.last_seen = datetime.utcnow()

    # Stage 1: Subdomain discovery (isolated — failure here doesn't abort pipeline)
    subdomain_candidates = []
    try:
        subdomain_candidates = asset_discovery.discover_subdomains(domain_name, domain_asset.environment or "prod")
        logger.debug("subdomain discovery complete", domain=domain_name, found=len(subdomain_candidates))
    except Exception as e:
        logger.error("subdomain discovery failed, continuing", domain=domain_name, error=str(e))

    subdomain_hosts = {domain_name}
    sub_asset_map: Dict[str, Asset] = {}
    for candidate in subdomain_candidates:
        if candidate.asset_type == "subdomain" and candidate.subdomain:
            sub_asset, created = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="subdomain",
                domain=domain_name,
                subdomain=candidate.subdomain,
                ip=None,
                port=None,
                protocol=None,
                url=None,
                service="http",
                environment=domain_asset.environment or "prod",
                cdn=candidate.cdn,
            )
            sub_asset_map[candidate.subdomain] = sub_asset
            upsert_edge(db, edge_keys, scan.org_id, domain_asset, sub_asset, "subdomain")
            subdomain_hosts.add(candidate.subdomain)
            if created:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=sub_asset.id,
                    alert_type="new_subdomain",
                    message=f"New subdomain discovered: {candidate.subdomain}",
                )
        if candidate.asset_type == "ip" and candidate.ip:
            ip_asset, ip_created = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="ip",
                domain=None,
                subdomain=None,
                ip=candidate.ip,
                port=None,
                protocol=None,
                url=None,
                service=None,
                environment=domain_asset.environment or "prod",
                asn=candidate.asn,
                hosting_provider=candidate.hosting_provider,
                country=candidate.country,
            )
            if ip_created:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=ip_asset.id,
                    alert_type="new_asset",
                    message=f"New IP discovered: {candidate.ip}",
                )
        if candidate.asset_type == "external_domain" and candidate.subdomain:
            external_asset, created = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="external_domain",
                domain=None,
                subdomain=candidate.subdomain,
                ip=None,
                port=None,
                protocol=None,
                url=None,
                service="http",
                environment=domain_asset.environment or "prod",
                tags="external",
            )
            if created:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=external_asset.id,
                    alert_type="related_domain",
                    message=f"Related domain discovered: {candidate.subdomain}",
                )
            upsert_edge(db, edge_keys, scan.org_id, domain_asset, external_asset, "related_domain")

    # Stage 2: DNS resolution (isolated)
    dnsx_results = []
    enrich_hosts, enrich_ips = {}, {}
    try:
        dnsx_results = scanning.run_dnsx(subdomain_hosts)
        enrich_hosts, enrich_ips = asset_enrichment.enrich_from_dnsx(dnsx_results)
        logger.debug("dns resolution complete", domain=domain_name, resolved=len(dnsx_results))
    except Exception as e:
        logger.error("dns resolution failed, continuing", domain=domain_name, error=str(e))
    resolved_hosts: set[str] = set()
    resolved_ips: set[str] = set()
    for result in dnsx_results:
        host = (result.host or "").strip().lower().rstrip(".")
        if not host:
            continue
        if result.a or result.aaaa:
            resolved_hosts.add(host)

        sub_asset = sub_asset_map.get(host) or cache["by_subdomain"].get(host)
        host_enrichment = enrich_hosts.get(host)
        if sub_asset and host_enrichment and host_enrichment.cdn and not sub_asset.cdn:
            sub_asset.cdn = host_enrichment.cdn
        for ip in result.a + result.aaaa:
            if not ip:
                continue
            resolved_ips.add(ip)
            ip_meta = enrich_ips.get(ip)
            ip_asset, ip_created = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="ip",
                domain=None,
                subdomain=None,
                ip=ip,
                port=None,
                protocol=None,
                url=None,
                service=None,
                environment=domain_asset.environment or "prod",
                asn=ip_meta.asn if ip_meta else None,
                hosting_provider=ip_meta.hosting_provider if ip_meta else None,
                country=ip_meta.country if ip_meta else None,
            )
            if sub_asset:
                upsert_edge(db, edge_keys, scan.org_id, sub_asset, ip_asset, "resolves_to")
            if ip_created:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=ip_asset.id,
                    alert_type="new_asset",
                    message=f"New IP discovered: {ip}",
                )

        if result.cname:
            cname_value = result.cname.rstrip(".")
            cname_domain = domain_name if cname_value.endswith(domain_name) else None
            cname_asset, _ = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="subdomain",
                domain=cname_domain,
                subdomain=cname_value,
                ip=None,
                port=None,
                protocol=None,
                url=None,
                service="dns",
                environment=domain_asset.environment or "prod",
            )
            if sub_asset:
                upsert_edge(db, edge_keys, scan.org_id, sub_asset, cname_asset, "cname_to")

            if not (result.a or result.aaaa):
                dns_finding = scanning.ScanFinding(
                    title="Potential dangling CNAME",
                    severity="medium",
                    description=f"{host} resolves to {cname_value} with no A/AAAA records.",
                    evidence=result.cname,
                    tool="dnsx",
                    target=host,
                )
                asset_for_finding = sub_asset or domain_asset
                db_finding, created, risk_increase, risk_delta = upsert_finding(
                    db, cache, scan.org_id, asset_for_finding, scan, dns_finding
                )
                if created:
                    create_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=asset_for_finding.id,
                        finding_id=db_finding.id,
                        alert_type="dns_misconfig",
                        message=f"DNS misconfiguration: {host}",
                    )
                if risk_increase:
                    create_risk_increase_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=asset_for_finding.id,
                        finding_id=db_finding.id,
                        title=db_finding.title,
                        delta=risk_delta,
                    )

        for record_host in result.mx + result.ns:
            record_host = (record_host or "").rstrip(".")
            if not record_host:
                continue
            record_domain = domain_name if record_host.endswith(domain_name) else None
            dns_asset, created = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="dns_record",
                domain=record_domain,
                subdomain=record_host,
                ip=None,
                port=None,
                protocol=None,
                url=None,
                service="mx" if record_host in result.mx else "ns",
                environment=domain_asset.environment or "prod",
            )
            if sub_asset:
                upsert_edge(db, edge_keys, scan.org_id, sub_asset, dns_asset, "dns_record")
            if created and record_domain:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=dns_asset.id,
                    alert_type="new_dns_record",
                    message=f"New DNS record discovered: {record_host}",
                )

        for txt_record in result.txt:
            txt_value = (txt_record or "").strip()
            if not txt_value:
                continue
            txt_finding = scanning.ScanFinding(
                title="TXT record observed",
                severity="info",
                description="TXT record discovered during DNS intelligence collection.",
                evidence=txt_value[:200],
                tool="dnsx",
                target=host,
            )
            upsert_finding(db, cache, scan.org_id, sub_asset or domain_asset, scan, txt_finding)

    if resolved_ips:
        reverse_limit = config.get_reverse_ip_limit()
        include_external = config.get_reverse_ip_include_external()
        reverse_results = reverse_ip_discovery.discover(list(resolved_ips)[:reverse_limit])
        for result in reverse_results:
            ip = result.ip
            ip_asset = cache["by_ip"].get(ip)
            if not ip_asset:
                ip_meta = enrich_ips.get(ip)
                ip_asset, _ = upsert_asset(
                    db,
                    cache,
                    org_id=scan.org_id,
                    asset_type="ip",
                    domain=None,
                    subdomain=None,
                    ip=ip,
                    port=None,
                    protocol=None,
                    url=None,
                    service=None,
                    environment=domain_asset.environment or "prod",
                    asn=ip_meta.asn if ip_meta else None,
                    hosting_provider=ip_meta.hosting_provider if ip_meta else None,
                    country=ip_meta.country if ip_meta else None,
                )
            for host in result.hosts:
                if not host:
                    continue
                host_value = host.strip().lower().rstrip(".")
                if not host_value:
                    continue
                is_internal = host_value.endswith(domain_name)
                if not is_internal and not include_external:
                    continue
                reverse_asset, created = upsert_asset(
                    db,
                    cache,
                    org_id=scan.org_id,
                    asset_type="subdomain" if is_internal else "external_domain",
                    domain=domain_name if is_internal else None,
                    subdomain=host_value,
                    ip=None,
                    port=None,
                    protocol=None,
                    url=None,
                    service="http",
                    environment=domain_asset.environment or "prod",
                    tags="reverse-ip",
                )
                upsert_edge(db, edge_keys, scan.org_id, ip_asset, reverse_asset, "reverse_ip")
                subdomain_hosts.add(host_value)
                if created and is_internal:
                    create_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=reverse_asset.id,
                        alert_type="new_subdomain",
                        message=f"New subdomain discovered: {host_value}",
                    )

    cloud_candidates: List[asset_discovery.AssetCandidate] = []
    cloud_assets = cloud_asset_discovery.discover_from_hosts(subdomain_hosts)
    bucket_domains = {domain_name}
    for host in subdomain_hosts:
        if host.endswith(domain_name):
            bucket_domains.add(host)
    bucket_assets = cloud_asset_discovery.discover_bucket_assets(bucket_domains)
    for asset in cloud_assets + bucket_assets:
        cloud_candidates.append(
            asset_discovery.AssetCandidate(
                asset_type="cloud",
                domain=asset.host,
                subdomain=None,
                ip=None,
                port=443,
                protocol="tcp",
                url=asset.url,
                service=asset.service,
                environment=domain_asset.environment or "prod",
                source=asset.provider,
            )
        )
    if cloud_candidates:
        ingest_cloud_assets(db, scan, cache, cloud_candidates, parent_asset=domain_asset, edge_keys=edge_keys)

    # Stage 3: HTTP probe (isolated)
    httpx_results = []
    alive_targets: List[str] = []
    naabu_targets: List[str] = list(resolved_ips)
    try:
        httpx_targets = resolved_hosts or subdomain_hosts
        httpx_results = scanning.run_httpx(httpx_targets)
        logger.debug("httpx probe complete", domain=domain_name, alive=len(httpx_results))
    except Exception as e:
        logger.error("httpx probe failed, continuing", domain=domain_name, error=str(e))
    for result in httpx_results:
        host = result.host or result.url
        sub_asset = None
        if host:
            sub_asset, _ = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="subdomain",
                domain=domain_name,
                subdomain=host,
                ip=None,
                port=None,
                protocol=None,
                url=None,
                service="http",
                environment=domain_asset.environment or "prod",
            )
            upsert_edge(db, edge_keys, scan.org_id, domain_asset, sub_asset, "subdomain")

        ip_asset = None
        if result.ip:
            ip_asset, ip_created = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="ip",
                domain=None,
                subdomain=None,
                ip=result.ip,
                port=None,
                protocol=None,
                url=None,
                service=None,
                environment=domain_asset.environment or "prod",
            )
            if sub_asset:
                upsert_edge(db, edge_keys, scan.org_id, sub_asset, ip_asset, "resolves_to")
            if ip_created:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=ip_asset.id,
                    alert_type="new_asset",
                    message=f"New IP discovered: {result.ip}",
                )

        service_asset, service_created = upsert_asset(
            db,
            cache,
            org_id=scan.org_id,
            asset_type="service",
            domain=domain_name,
            subdomain=host,
            ip=result.ip,
            port=result.port,
            protocol=result.protocol,
            url=result.url,
            service="http",
            technology=",".join(result.tech) if result.tech else None,
            environment=domain_asset.environment or "prod",
        )
        if sub_asset:
            upsert_edge(db, edge_keys, scan.org_id, sub_asset, service_asset, "alive_host")
        if ip_asset:
            upsert_edge(db, edge_keys, scan.org_id, ip_asset, service_asset, "serves")
        if service_created:
            create_alert(
                db,
                org_id=scan.org_id,
                asset_id=service_asset.id,
                alert_type="new_service",
                message=f"New service discovered: {service_asset.url or service_asset.subdomain}",
            )

        if result.url:
            alive_targets.append(result.url)
        if result.ip or host:
            naabu_targets.append(result.ip or host)

    # Stage 4: Port scan (isolated)
    naabu_results = []
    try:
        if naabu_targets:
            naabu_results = scanning.run_naabu(naabu_targets)
            logger.debug("port scan complete", domain=domain_name, open_ports=len(naabu_results))
    except Exception as e:
        logger.error("port scan failed, continuing", domain=domain_name, error=str(e))

    for result in naabu_results:
        ip_asset = None
        if result.ip:
            ip_asset, _ = upsert_asset(
                db,
                cache,
                org_id=scan.org_id,
                asset_type="ip",
                domain=None,
                subdomain=None,
                ip=result.ip,
                port=None,
                protocol=None,
                url=None,
                service=None,
                environment=domain_asset.environment or "prod",
            )

        service_asset, created = upsert_asset(
            db,
            cache,
            org_id=scan.org_id,
            asset_type="service",
            domain=domain_name,
            subdomain=result.host or None,
            ip=result.ip,
            port=result.port,
            protocol=result.protocol,
            url=None,
            service="tcp",
            environment=domain_asset.environment or "prod",
        )
        if ip_asset:
            upsert_edge(db, edge_keys, scan.org_id, ip_asset, service_asset, "open_port")
        if created:
            create_alert(
                db,
                org_id=scan.org_id,
                asset_id=service_asset.id,
                alert_type="new_exposed_service",
                message=f"New open port detected: {result.port}/{result.protocol}",
            )

    endpoint_urls: List[str] = []
    _ep_limit = config.get_endpoint_limit()

    def _add_endpoints(new_urls):
        """Add URLs to endpoint_urls with early cap to prevent memory growth."""
        remaining = _ep_limit - len(endpoint_urls)
        if remaining <= 0:
            return
        seen = set(endpoint_urls)
        for url in new_urls:
            if url and url not in seen and len(endpoint_urls) < _ep_limit:
                endpoint_urls.append(url)
                seen.add(url)

    if scan.scan_type in {"asset_discovery", "deep"}:
        # Stage 5: Crawl (isolated, capped)
        try:
            crawled = crawler.crawl_urls(alive_targets)
            priority = crawler.extract_high_value_endpoints(crawled)
            _add_endpoints(priority + crawled)
        except Exception as e:
            logger.warning("crawl failed, continuing", domain=domain_name, error=str(e))

        try:
            _add_endpoints(scanning.run_gau(domain_name))
        except Exception as e:
            logger.debug("gau failed", domain=domain_name, error=str(e))

        try:
            _add_endpoints(scanning.run_waybackurls(domain_name))
        except Exception as e:
            logger.debug("waybackurls failed", domain=domain_name, error=str(e))

        if len(endpoint_urls) < _ep_limit:
            try:
                _add_endpoints(scanning.run_ffuf(alive_targets))
            except Exception as e:
                logger.debug("ffuf failed", domain=domain_name, error=str(e))

        if len(endpoint_urls) < _ep_limit:
            try:
                _add_endpoints(scanning.run_dirsearch(alive_targets))
            except Exception as e:
                logger.debug("dirsearch failed", domain=domain_name, error=str(e))

        logger.debug("endpoint discovery complete", domain=domain_name, endpoints=len(endpoint_urls))

    for url in endpoint_urls[: config.get_endpoint_limit()]:
        parsed = urlparse(url)
        host = parsed.hostname
        endpoint_asset, created = upsert_asset(
            db,
            cache,
            org_id=scan.org_id,
            asset_type="endpoint",
            domain=domain_name,
            subdomain=host,
            ip=None,
            port=parsed.port,
            protocol=parsed.scheme,
            url=url,
            service="http",
            environment=domain_asset.environment or "prod",
        )
        parent_asset = resolve_asset_for_target(cache, host or "") or domain_asset
        if parent_asset:
            upsert_edge(db, edge_keys, scan.org_id, parent_asset, endpoint_asset, "endpoint")
        service_asset = None
        if parsed.scheme and parsed.netloc:
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            service_asset = cache["by_url"].get(base_url)
        if service_asset:
            upsert_edge(db, edge_keys, scan.org_id, service_asset, endpoint_asset, "endpoint")
        if created:
            create_alert(
                db,
                org_id=scan.org_id,
                asset_id=endpoint_asset.id,
                alert_type="new_endpoint",
                message=f"New endpoint discovered: {url}",
            )

    if scan.scan_type in {"asset_discovery", "deep"}:
        cloud_inputs = list(subdomain_hosts) + endpoint_urls + alive_targets
        cloud_assets = cloud_asset_discovery.discover_from_hosts(cloud_inputs)
        bucket_domains = {domain_name}
        for host in subdomain_hosts:
            if host.endswith(domain_name):
                bucket_domains.add(host)
        bucket_assets = cloud_asset_discovery.discover_bucket_assets(bucket_domains)
        cloud_candidates = []
        for asset in cloud_assets + bucket_assets:
            cloud_candidates.append(
                asset_discovery.AssetCandidate(
                    asset_type="cloud",
                    domain=asset.host,
                    subdomain=None,
                    ip=None,
                    port=443,
                    protocol="tcp",
                    url=asset.url,
                    service=asset.service,
                    environment=domain_asset.environment or "prod",
                    source=asset.provider,
                )
            )
        if cloud_candidates:
            ingest_cloud_assets(db, scan, cache, cloud_candidates, parent_asset=domain_asset, edge_keys=edge_keys)

    if scan.scan_type in {"asset_discovery", "deep"}:
        secret_findings = scanning.run_endpoint_secret_scan(endpoint_urls)
        for finding in secret_findings:
            asset = resolve_asset_for_target(cache, finding.target) or domain_asset
            db_finding, created, risk_increase, risk_delta = upsert_finding(
                db, cache, scan.org_id, asset, scan, finding
            )
            if created:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=asset.id,
                    finding_id=db_finding.id,
                    alert_type="secret_detection",
                    message=f"Secret detected: {db_finding.title}",
                )
            if risk_increase:
                create_risk_increase_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=asset.id,
                    finding_id=db_finding.id,
                    title=db_finding.title,
                    delta=risk_delta,
                )

    if scan.scan_type in {"asset_discovery", "deep"}:
        takeover_findings = scanning.run_nuclei(subdomain_hosts, tags=["takeover"])
        for finding in takeover_findings:
            asset = resolve_asset_for_target(cache, finding.target) or domain_asset
            db_finding, created, risk_increase, risk_delta = upsert_finding(
                db, cache, scan.org_id, asset, scan, finding
            )
            if created:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=asset.id,
                    finding_id=db_finding.id,
                    alert_type="subdomain_takeover_risk",
                    message=f"Potential takeover: {db_finding.title}",
                )
            if risk_increase:
                create_risk_increase_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=asset.id,
                    finding_id=db_finding.id,
                    title=db_finding.title,
                    delta=risk_delta,
                )

    if run_vuln:
        targets = list(dict.fromkeys([*alive_targets, *endpoint_urls]))  # dedup, preserve order
        if targets:
            try:
                from app.services.vuln_scanner import (
                    full_vuln_pipeline,
                    enriched_to_scan_finding,
                    NucleiScanOptions,
                )
                scan_type = scan.scan_type if scan.scan_type in (
                    "web", "misconfig", "tls", "headers", "api", "secret", "deep", "cve"
                ) else "web"
                vuln_result = full_vuln_pipeline(
                    targets=targets,
                    scan_type=scan_type,
                    run_tech_detection=True,
                    run_port_scan=False,   # ports already scanned by naabu above
                    run_exploit_intel=False,
                    fetch_nvd_data=True,
                )
                # Collect all enriched findings: nuclei + tech-CVE + port risks
                all_enriched = (
                    [ef for ef in vuln_result.findings if not ef.suppressed] +
                    vuln_result.port_findings +
                    vuln_result.tech_cve_findings
                )
                if vuln_result.suppressed_count:
                    logger.debug("FP suppressed", count=vuln_result.suppressed_count, domain=domain_name)
                if vuln_result.kev_count:
                    logger.warning("KEV findings detected", count=vuln_result.kev_count, domain=domain_name)

                for ef in all_enriched:
                    # Convert enriched finding back to ScanFinding for upsert
                    scan_finding = enriched_to_scan_finding(ef)
                    asset = resolve_asset_for_target(cache, scan_finding.target) or domain_asset
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, asset, scan, scan_finding
                    )
                    db.add(ScanResult(scan_id=scan.id, tool=scan_finding.tool, raw_output=scan_finding.evidence))
                    if created:
                        if db_finding.severity in {"critical", "high"} or ef.is_kev:
                            create_alert(
                                db,
                                org_id=scan.org_id,
                                asset_id=asset.id,
                                finding_id=db_finding.id,
                                alert_type="critical_vulnerability",
                                message=f"{'[KEV] ' if ef.is_kev else ''}Critical finding: {db_finding.title}",
                            )
                        else:
                            create_alert(
                                db,
                                org_id=scan.org_id,
                                asset_id=asset.id,
                                finding_id=db_finding.id,
                                alert_type="new_vulnerability",
                                message=f"New vulnerability: {db_finding.title}",
                            )
                    if risk_increase:
                        create_risk_increase_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=asset.id,
                            finding_id=db_finding.id,
                            title=db_finding.title,
                            delta=risk_delta,
                        )

            except ImportError:
                # vuln_scanner not available — fall back to raw nuclei
                tags = tags_for_scan_type(scan.scan_type)
                findings = scanning.run_nuclei(targets, tags=tags)
                for finding in analysis.filter_false_positives(analysis.deduplicate_by_fingerprint(findings)):
                    asset = resolve_asset_for_target(cache, finding.target) or domain_asset
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, asset, scan, finding
                    )
                    db.add(ScanResult(scan_id=scan.id, tool=finding.tool, raw_output=finding.evidence))
                    if created:
                        create_alert(
                            db, org_id=scan.org_id, asset_id=asset.id,
                            finding_id=db_finding.id, alert_type="new_vulnerability",
                            message=f"New vulnerability: {db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db, org_id=scan.org_id, asset_id=asset.id,
                            finding_id=db_finding.id, title=db_finding.title, delta=risk_delta,
                        )
            except Exception as e:
                logger.error("vuln pipeline error", domain=domain_name, error=str(e), exc_info=True)


def tags_for_scan_type(scan_type: str) -> Optional[List[str]]:
    if scan_type == "tls":
        return ["ssl", "tls"]
    if scan_type == "headers":
        return ["headers"]
    if scan_type == "api":
        return ["api"]
    if scan_type == "misconfig":
        return ["misconfig", "config"]
    if scan_type == "secret":
        return ["secret", "token", "exposure"]
    return None


def mark_fixed_findings(db, scan: Scan) -> None:
    if scan.scan_type not in {"asset_discovery", "deep", "vuln", "web", "api", "misconfig", "tls", "headers"}:
        return
    if not scan.started_at:
        return
    touched_assets = select(Asset.id).where(
        Asset.org_id == scan.org_id,
        Asset.last_seen >= scan.started_at,
    )
    candidates = (
        db.execute(
            select(Finding).where(
                Finding.org_id == scan.org_id,
                Finding.asset_id.in_(touched_assets),
                Finding.status == "open",
                Finding.scan_id != scan.id,
                Finding.last_seen < scan.started_at,
            )
        )
        .scalars()
        .all()
    )
    for finding in candidates:
        finding.status = "fixed"
        db.add(
            AssetChange(
                org_id=scan.org_id,
                scan_id=scan.id,
                asset_id=finding.asset_id,
                change_type="vuln_fixed",
                detail=finding.title,
            )
        )
        create_alert(
            db,
            org_id=scan.org_id,
            asset_id=finding.asset_id,
            finding_id=finding.id,
            alert_type="vuln_fixed",
            message=f"Vulnerability fixed: {finding.title}",
        )


def process_scan(db, scan: Scan) -> None:
    cache = load_asset_cache(db, scan.org_id)
    edge_keys = load_edge_cache(db, scan.org_id)

    if scan.scan_type == "asset_discovery" or scan.scan_type == "deep":
        if scan.asset_id:
            domain_assets = [db.get(Asset, scan.asset_id)]
        else:
            domain_assets = (
                db.execute(
                    select(Asset).where(
                        Asset.org_id == scan.org_id,
                        Asset.asset_type == "domain",
                    )
                )
                .scalars()
                .all()
            )
        for domain_asset in filter(None, domain_assets):
            pipeline_for_domain(db, scan, domain_asset, cache, edge_keys, run_vuln=True)

        if domain_assets:
            leak_findings = scanning.run_github_leaks()
            for finding in leak_findings:
                asset = domain_assets[0]
                db_finding, created, risk_increase, risk_delta = upsert_finding(
                    db, cache, scan.org_id, asset, scan, finding
                )
                if created:
                    create_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=asset.id,
                        finding_id=db_finding.id,
                        alert_type="github_leak",
                        message=f"GitHub leak detected: {db_finding.title}",
                    )
                if risk_increase:
                    create_risk_increase_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=asset.id,
                        finding_id=db_finding.id,
                        title=db_finding.title,
                        delta=risk_delta,
                    )
            public_repo_findings = scanning.run_public_repo_scan()
            for finding in public_repo_findings:
                asset = domain_assets[0]
                db_finding, created, risk_increase, risk_delta = upsert_finding(
                    db, cache, scan.org_id, asset, scan, finding
                )
                if created:
                    create_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=asset.id,
                        finding_id=db_finding.id,
                        alert_type="secret_detection",
                        message=f"Secret detected: {db_finding.title}",
                    )
                if risk_increase:
                    create_risk_increase_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=asset.id,
                        finding_id=db_finding.id,
                        title=db_finding.title,
                        delta=risk_delta,
                    )
            for domain_asset in domain_assets:
                if not domain_asset or not domain_asset.domain:
                    continue
                github_hits = scanning.run_github_code_search(domain_asset.domain)
                for finding in github_hits:
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, domain_asset, scan, finding
                    )
                    if created:
                        create_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            alert_type="code_reference",
                            message=f"GitHub code exposure: {db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            title=db_finding.title,
                            delta=risk_delta,
                        )
                gitlab_hits = scanning.run_gitlab_code_search(domain_asset.domain)
                for finding in gitlab_hits:
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, domain_asset, scan, finding
                    )
                    if created:
                        create_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            alert_type="code_reference",
                            message=f"GitLab code exposure: {db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            title=db_finding.title,
                            delta=risk_delta,
                        )
                bitbucket_hits = scanning.run_bitbucket_code_search(domain_asset.domain)
                for finding in bitbucket_hits:
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, domain_asset, scan, finding
                    )
                    if created:
                        create_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            alert_type="code_reference",
                            message=f"Bitbucket code exposure: {db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            title=db_finding.title,
                            delta=risk_delta,
                        )

        cloud_assets = asset_discovery.discover_cloud_assets(environment="prod")
        ingest_cloud_assets(db, scan, cache, cloud_assets)

        mark_fixed_findings(db, scan)
        db.commit()
        return

    if scan.scan_type in {"service", "exposed"}:
        if scan.asset_id:
            domain_assets = [db.get(Asset, scan.asset_id)]
        else:
            domain_assets = (
                db.execute(
                    select(Asset).where(
                        Asset.org_id == scan.org_id,
                        Asset.asset_type == "domain",
                    )
                )
                .scalars()
                .all()
            )
        for domain_asset in filter(None, domain_assets):
            pipeline_for_domain(db, scan, domain_asset, cache, edge_keys, run_vuln=False)
        db.commit()
        return

    if scan.scan_type in {"vuln", "web", "api", "misconfig", "tls", "headers"}:
        raw_targets = [
            asset.url or asset.subdomain or asset.domain or asset.ip
            for asset in cache["by_key"].values()
            if asset.asset_type in {"service", "subdomain", "domain"}
        ]
        targets = list(dict.fromkeys(t for t in raw_targets if t))  # dedup + filter None

        if targets:
            try:
                from app.services.vuln_scanner import full_vuln_pipeline, enriched_to_scan_finding
                vuln_result = full_vuln_pipeline(
                    targets=targets,
                    scan_type=scan.scan_type,
                    run_tech_detection=True,
                    run_port_scan=False,
                    fetch_nvd_data=True,
                )
                if vuln_result.kev_count:
                    logger.warning("KEV findings in vuln scan", count=vuln_result.kev_count)

                all_enriched = (
                    [ef for ef in vuln_result.findings if not ef.suppressed] +
                    vuln_result.port_findings +
                    vuln_result.tech_cve_findings
                )
                for ef in all_enriched:
                    scan_finding = enriched_to_scan_finding(ef)
                    asset = resolve_asset_for_target(cache, scan_finding.target) or \
                            next(iter(cache["by_key"].values()), None)
                    if not asset:
                        continue
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, asset, scan, scan_finding
                    )
                    db.add(ScanResult(scan_id=scan.id, tool=scan_finding.tool, raw_output=scan_finding.evidence))
                    if created:
                        alert_type = "critical_vulnerability" if (
                            db_finding.severity in {"critical", "high"} or ef.is_kev
                        ) else "new_vulnerability"
                        create_alert(
                            db, org_id=scan.org_id, asset_id=asset.id,
                            finding_id=db_finding.id, alert_type=alert_type,
                            message=f"{'[KEV] ' if ef.is_kev else ''}{db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db, org_id=scan.org_id, asset_id=asset.id,
                            finding_id=db_finding.id, title=db_finding.title, delta=risk_delta,
                        )
            except ImportError:
                findings = scanning.run_nuclei(targets, tags=tags_for_scan_type(scan.scan_type))
                for finding in analysis.filter_false_positives(
                    analysis.deduplicate_by_fingerprint(findings)
                ):
                    asset = resolve_asset_for_target(cache, finding.target) or \
                            next(iter(cache["by_key"].values()), None)
                    if not asset:
                        continue
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, asset, scan, finding
                    )
                    db.add(ScanResult(scan_id=scan.id, tool=finding.tool, raw_output=finding.evidence))
                    if created:
                        create_alert(
                            db, org_id=scan.org_id, asset_id=asset.id,
                            finding_id=db_finding.id, alert_type="new_vulnerability",
                            message=f"New vulnerability: {db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db, org_id=scan.org_id, asset_id=asset.id,
                            finding_id=db_finding.id, title=db_finding.title, delta=risk_delta,
                        )
            except Exception as e:
                logger.error("vuln scan failed", scan_id=scan.id, error=str(e), exc_info=True)

        mark_fixed_findings(db, scan)
        db.commit()
        return

    if scan.scan_type == "secret":
        domain_assets = (
            db.execute(
                select(Asset).where(
                    Asset.org_id == scan.org_id,
                    Asset.asset_type == "domain",
                )
            )
            .scalars()
            .all()
        )
        seen_urls: set[str] = set()
        endpoint_urls: List[str] = []
        for asset in cache["by_key"].values():
            if not asset.url or asset.asset_type not in {"endpoint", "service"}:
                continue
            if asset.url in seen_urls:
                continue
            seen_urls.add(asset.url)
            endpoint_urls.append(asset.url)
        for finding in scanning.run_endpoint_secret_scan(endpoint_urls):
            asset = resolve_asset_for_target(cache, finding.target) or (domain_assets[0] if domain_assets else None)
            if not asset:
                continue
            db_finding, created, risk_increase, risk_delta = upsert_finding(
                db, cache, scan.org_id, asset, scan, finding
            )
            if created:
                create_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=asset.id,
                    finding_id=db_finding.id,
                    alert_type="secret_detection",
                    message=f"Secret detected: {db_finding.title}",
                )
            if risk_increase:
                create_risk_increase_alert(
                    db,
                    org_id=scan.org_id,
                    asset_id=asset.id,
                    finding_id=db_finding.id,
                    title=db_finding.title,
                    delta=risk_delta,
                )
        if domain_assets:
            leak_findings = scanning.run_github_leaks()
            public_repo_findings = scanning.run_public_repo_scan()
            for finding in leak_findings + public_repo_findings:
                asset = domain_assets[0]
                db_finding, created, risk_increase, risk_delta = upsert_finding(
                    db, cache, scan.org_id, asset, scan, finding
                )
                if created:
                    create_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=asset.id,
                        finding_id=db_finding.id,
                        alert_type="secret_detection",
                        message=f"Secret detected: {db_finding.title}",
                    )
                if risk_increase:
                    create_risk_increase_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=asset.id,
                        finding_id=db_finding.id,
                        title=db_finding.title,
                        delta=risk_delta,
                    )
            for domain_asset in domain_assets:
                if not domain_asset or not domain_asset.domain:
                    continue
                for finding in scanning.run_github_code_search(domain_asset.domain):
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, domain_asset, scan, finding
                    )
                    if created:
                        create_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            alert_type="code_reference",
                            message=f"GitHub code exposure: {db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            title=db_finding.title,
                            delta=risk_delta,
                        )
                for finding in scanning.run_gitlab_code_search(domain_asset.domain):
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, domain_asset, scan, finding
                    )
                    if created:
                        create_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            alert_type="code_reference",
                            message=f"GitLab code exposure: {db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            title=db_finding.title,
                            delta=risk_delta,
                        )
                for finding in scanning.run_bitbucket_code_search(domain_asset.domain):
                    db_finding, created, risk_increase, risk_delta = upsert_finding(
                        db, cache, scan.org_id, domain_asset, scan, finding
                    )
                    if created:
                        create_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            alert_type="code_reference",
                            message=f"Bitbucket code exposure: {db_finding.title}",
                        )
                    if risk_increase:
                        create_risk_increase_alert(
                            db,
                            org_id=scan.org_id,
                            asset_id=domain_asset.id,
                            finding_id=db_finding.id,
                            title=db_finding.title,
                            delta=risk_delta,
                        )
        db.commit()
        return

    db.commit()


def claim_scan(db, scan: Scan) -> bool:
    """Atomically claim a scan using UPDATE WHERE status='scheduled'.

    Returns True if successfully claimed (this worker owns it).
    Returns False if another worker already claimed it (race condition handled).
    Uses an UPDATE-based claim to avoid SELECT+UPDATE race between concurrent workers.
    """
    from sqlalchemy import update as sa_update

    result = db.execute(
        sa_update(Scan)
        .where(Scan.id == scan.id, Scan.status == "scheduled")
        .values(
            status="running",
            started_at=datetime.utcnow(),
            attempts=(scan.attempts or 0) + 1,
        )
        .execution_options(synchronize_session="fetch")
    )
    db.commit()
    db.refresh(scan)
    claimed = result.rowcount > 0
    if not claimed:
        logger.warning("scan already claimed by another worker", scan_id=scan.id)
    return claimed


def schedule_retry(db, scan: Scan, error: str) -> None:
    scan.error = error
    if scan.attempts < MAX_RETRIES:
        scan.status = "scheduled"
        scan.scheduled_at = datetime.utcnow() + timedelta(seconds=RETRY_BACKOFF_SECONDS * scan.attempts)
    else:
        scan.status = "failed"
    db.commit()


def run_worker(poll_interval: int = 5) -> None:
    # Try distributed worker first (requires Redis)
    try:
        from app.services.distributed_worker import run_worker as dw_run
        dw_run()
        return
    except Exception as e:
        logger.warning('unexpected error', error=str(e))
        pass

    # Fallback: original single-threaded loop
    init_db()
    try:
        queue = get_queue()
    except Exception:  # noqa: BLE001
        queue = None
    while True:
        db = SessionLocal()
        try:
            scan = None
            if queue:
                scan_id = queue.dequeue(timeout=poll_interval)
                if scan_id:
                    scan = db.get(Scan, scan_id)
            else:
                scan = (
                    db.execute(
                        select(Scan)
                        .where(Scan.status == "scheduled")
                        .order_by(Scan.scheduled_at.asc())
                    )
                    .scalars()
                    .first()
                )

            if not scan:
                time.sleep(poll_interval)
                continue

            if not worker_allows_scan(scan.scan_type):
                if queue:
                    queue.enqueue(scan.id)
                scan.status = "scheduled"
                scan.scheduled_at = datetime.utcnow() + timedelta(seconds=30)
                db.commit()
                continue

            if not claim_scan(db, scan):
                # Another worker claimed this scan — skip it
                db.close()
                continue
            try:
                process_scan(db, scan)
                snapshots, changes = asset_snapshot_engine.snapshot_and_diff(db, scan)
                diff = diff_engine.collect_scan_diff(db, scan)
                diff_payload = diff_engine.diff_summary(diff)
                if any(diff_payload.values()):
                    db.add(ScanResult(scan_id=scan.id, tool="diff_engine", raw_output=json.dumps(diff_payload)))

                # Auto-correlate assets after every discovery scan
                if scan.scan_type in {"asset_discovery", "deep", "service"}:
                    try:
                        from app.services.asset_correlation import correlate_org_assets
                        correlate_org_assets(db, scan.org_id)
                    except Exception as e:
                        logger.debug('post-scan optional feature error', error=str(e))
                        pass

                # Auto-dedup (lightweight — catches races from concurrent workers)
                if scan.scan_type in {"asset_discovery", "deep"}:
                    try:
                        from app.services.asset_normalizer import deduplicate_org_assets
                        deduplicate_org_assets(db, scan.org_id)
                    except Exception as e:
                        logger.debug('post-scan optional feature error', error=str(e))
                        pass

                # Auto-compute attack surface score after every completed scan
                try:
                    from app.services.attack_surface_score import compute_score as _compute_score
                    _compute_score(db, scan.org_id, scan_id=scan.id)
                except Exception as e:
                    logger.debug('post-scan optional feature error', error=str(e))
                    pass
                asset_ids = {change.asset_id for change in changes if change.asset_id}
                asset_map = {
                    asset.id: asset
                    for asset in (
                        db.execute(select(Asset).where(Asset.id.in_(asset_ids))).scalars().all()
                        if asset_ids
                        else []
                    )
                }
                existing_alerts = set()
                if scan.started_at:
                    existing_alerts = {
                        (alert.alert_type, alert.asset_id)
                        for alert in (
                            db.execute(
                                select(Alert).where(
                                    Alert.org_id == scan.org_id,
                                    Alert.created_at >= scan.started_at,
                                )
                            )
                            .scalars()
                            .all()
                        )
                    }
                for change in changes:
                    asset = asset_map.get(change.asset_id)
                    if asset and scan.started_at and asset.first_seen and asset.first_seen >= scan.started_at:
                        continue
                    if change.change_type == "port_exposed":
                        alert_type = "new_port"
                        message = f"New port exposed: {change.detail}"
                    elif change.change_type == "endpoint_discovered":
                        alert_type = "new_endpoint"
                        message = f"New endpoint discovered: {change.detail}"
                    else:
                        alert_type = "new_asset"
                        message = f"New asset discovered: {change.detail}"
                    if (alert_type, change.asset_id) in existing_alerts:
                        continue
                    create_alert(
                        db,
                        org_id=scan.org_id,
                        asset_id=change.asset_id,
                        alert_type=alert_type,
                        message=message,
                    )
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.error = None
                db.commit()
                if queue:
                    try:
                        queue.complete(scan.id)
                    except Exception as e:
                        logger.warning('queue operation error', error=str(e))
                        pass
            except Exception as exc:  # noqa: BLE001
                schedule_retry(db, scan, str(exc))
                if queue:
                    try:
                        queue.fail(scan.id, str(exc))
                    except Exception as e:
                        logger.warning('queue operation error', error=str(e))
                        pass
        finally:
            db.close()


if __name__ == "__main__":
    run_worker()
