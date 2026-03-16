"""Attack Path Engine — models how an attacker moves through the asset graph.

An "attack path" is a sequence of assets an attacker can traverse from an
initial entry point to a high-value target, exploiting relationships and
vulnerabilities at each hop.

Algorithm:
  1. Build a directed attack graph from AssetEdge relationships
  2. Annotate each node with its vulnerability severity and exposure score
  3. Run Dijkstra-style shortest path to find highest-risk traversal paths
  4. Score each path by its cumulative exploitability
  5. Classify paths as: initial_access → lateral_movement → privilege_escalation → impact

Attack node types:
  - INTERNET_FACING  : public subdomains, exposed APIs, S3 buckets
  - LATERAL_MOVE     : internal IPs reachable from compromised host
  - PRIVILEGE_ESC    : services running as root, cloud IAM roles, admin panels
  - HIGH_VALUE_TARGET: databases, cloud storage, internal services

Path scoring (0-100):
  - Exploitability  : CVSS × KEV weight
  - Exposure chain  : product of exposure scores along path
  - Hop count       : shorter paths score higher
  - Choke points    : assets reachable from many entry points score higher

Output:
  - List of AttackPath objects with full hop-by-hop breakdown
  - Risk heatmap over the asset graph
  - Choke point assets (removing them breaks the most paths)
  - MITRE ATT&CK technique mapping per hop
"""
from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterator, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetEdge, Finding


# ── MITRE ATT&CK mapping ───────────────────────────────────────────────────

# Maps (relation_type, asset_type, finding_keyword) → ATT&CK technique
_MITRE_MAP: List[Tuple[str, str, str, str, str]] = [
    # (relation,         asset_type,   keyword,          technique_id, technique_name)
    ("subdomain_of",    "subdomain",   "",               "T1584.001",  "Acquire Infrastructure: Domains"),
    ("resolves_to",     "ip",          "",               "T1590.005",  "Gather Victim Network Information: IP Addresses"),
    ("hosted_on",       "cloud",       "",               "T1584.006",  "Acquire Infrastructure: Web Services"),
    ("hosted_on",       "cloud",       "s3",             "T1530",      "Data from Cloud Storage Object"),
    ("open_port",       "service",     "ssh",            "T1021.004",  "Remote Services: SSH"),
    ("open_port",       "service",     "rdp",            "T1021.001",  "Remote Services: RDP"),
    ("open_port",       "service",     "smb",            "T1021.002",  "Remote Services: SMB/Windows Admin Shares"),
    ("serves",          "service",     "mysql",          "T1190",      "Exploit Public-Facing Application"),
    ("serves",          "service",     "redis",          "T1190",      "Exploit Public-Facing Application"),
    ("serves",          "service",     "elasticsearch",  "T1190",      "Exploit Public-Facing Application"),
    ("endpoint",        "endpoint",    "api",            "T1190",      "Exploit Public-Facing Application"),
    ("endpoint",        "endpoint",    "admin",          "T1078",      "Valid Accounts"),
    ("reverse_ip",      "subdomain",   "",               "T1589",      "Gather Victim Identity Information"),
    ("cname_to",        "subdomain",   "",               "T1584",      "Compromise Infrastructure"),
    ("bucket_of",       "cloud",       "",               "T1530",      "Data from Cloud Storage Object"),
    ("same_provider",   "ip",          "",               "T1583",      "Acquire Infrastructure"),
    ("alive_host",      "service",     "http",           "T1190",      "Exploit Public-Facing Application"),
    ("",                "",            "xss",            "T1059.007",  "Command and Scripting: JavaScript"),
    ("",                "",            "sqli",           "T1190",      "Exploit Public-Facing Application"),
    ("",                "",            "rce",            "T1059",      "Command and Scripting Interpreter"),
    ("",                "",            "ssrf",           "T1090",      "Proxy: Internal Proxy"),
    ("",                "",            "lfi",            "T1083",      "File and Directory Discovery"),
    ("",                "",            "takeover",       "T1584.001",  "Compromise Infrastructure: Domains"),
    ("",                "",            "secret",         "T1552",      "Unsecured Credentials"),
    ("",                "",            "bucket",         "T1530",      "Data from Cloud Storage"),
]


def _lookup_mitre(relation: str, asset_type: str, context: str) -> Optional[Tuple[str, str]]:
    context_lower = context.lower()
    for r, at, kw, tid, tname in _MITRE_MAP:
        relation_match = not r or r == relation
        type_match = not at or at == asset_type
        kw_match = not kw or kw in context_lower
        if relation_match and type_match and kw_match:
            return tid, tname
    return None


# ── Attack graph node ──────────────────────────────────────────────────────

@dataclass
class AttackNode:
    asset_id: int
    asset_type: str
    label: str              # display name
    exposure_class: str     # public / vpn / internal
    exposure_score: float   # 0-30
    importance: float       # 0-50
    max_vuln_cvss: float    # highest CVSS of open findings
    max_vuln_severity: str  # critical/high/medium/low/info
    is_kev: bool            # any finding is in CISA KEV
    has_rce: bool           # any RCE-class finding
    open_findings: int
    technologies: List[str] = field(default_factory=list)

    @property
    def exploitability_score(self) -> float:
        """0-100: how easy is it to exploit this node."""
        base = self.max_vuln_cvss * 8.0 if self.max_vuln_cvss else 5.0
        if self.is_kev:    base += 20.0
        if self.has_rce:   base += 15.0
        if self.exposure_class == "public": base += 10.0
        return min(base, 100.0)

    @property
    def value_score(self) -> float:
        """0-100: how valuable is this node to an attacker."""
        return min(self.importance + self.exposure_score * 0.5, 100.0)

    @property
    def node_risk(self) -> float:
        return round((self.exploitability_score * 0.6 + self.value_score * 0.4), 2)


@dataclass
class AttackHop:
    from_asset_id: int
    to_asset_id: int
    relation: str
    technique_id: Optional[str]
    technique_name: Optional[str]
    hop_score: float          # risk contribution of this hop
    requires_vuln: bool       # true if a vulnerability is needed to traverse


@dataclass
class AttackPath:
    id: str
    entry_point_id: int       # starting asset (internet-facing)
    target_id: int            # final high-value asset
    hops: List[AttackHop]
    nodes: List[AttackNode]
    total_score: float        # cumulative risk score (0-100)
    category: str             # initial_access / lateral_movement / data_exfiltration
    mitre_techniques: List[str]  # unique technique IDs along path
    likelihood: str           # critical / high / medium / low
    description: str          # human-readable narrative

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    @property
    def requires_auth(self) -> bool:
        return any(h.relation in ("open_port", "alive_host") for h in self.hops)


@dataclass
class AttackSurface:
    entry_points: List[AttackNode]    # publicly reachable assets
    high_value_targets: List[AttackNode]  # databases, cloud storage, internal services
    attack_paths: List[AttackPath]
    choke_points: List[Tuple[int, int]]  # (asset_id, paths_blocked_if_removed)
    risk_heatmap: Dict[int, float]       # asset_id → attack risk score
    total_paths: int
    critical_paths: int


# ── Graph builder ──────────────────────────────────────────────────────────

def _asset_label(asset: Asset) -> str:
    return asset.url or asset.subdomain or asset.domain or asset.ip or f"asset#{asset.id}"


def _is_entry_point(asset: Asset) -> bool:
    return asset.exposure_class in ("public", None) and asset.asset_type in (
        "subdomain", "domain", "service", "endpoint", "cloud"
    )


def _is_high_value(asset: Asset) -> bool:
    label = _asset_label(asset).lower()
    tech = (asset.technology or "").lower()
    service = (asset.service or "").lower()
    high_value_keywords = {
        "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
        "vault", "secret", "admin", "dashboard", "payment", "finance",
        "billing", "internal", "prod", "s3", "bucket", "storage",
    }
    return any(kw in label or kw in tech or kw in service for kw in high_value_keywords)


def _max_cvss_for_asset(findings: List[Finding]) -> Tuple[float, str, bool, bool]:
    """Returns (max_cvss, max_severity, is_kev, has_rce) for asset's open findings."""
    max_cvss = 0.0
    max_sev = "info"
    is_kev = False
    has_rce = False
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for f in findings:
        if f.status != "open":
            continue
        if f.cvss and f.cvss > max_cvss:
            max_cvss = f.cvss
        if sev_order.get(f.severity, 0) > sev_order.get(max_sev, 0):
            max_sev = f.severity
        title_lower = (f.title or "").lower()
        desc_lower  = (f.description or "").lower()
        if "rce" in title_lower or "remote code" in title_lower or "rce" in desc_lower:
            has_rce = True

    return max_cvss, max_sev, is_kev, has_rce


def build_attack_graph(db: Session, org_id: int) -> Tuple[Dict[int, AttackNode], Dict[int, List[Tuple[int, str]]]]:
    """Build the attack graph: nodes annotated with risk, adjacency list of edges.

    Returns:
        nodes: asset_id → AttackNode
        adj:   asset_id → [(neighbor_id, relation)]
    """
    assets = db.execute(select(Asset).where(Asset.org_id == org_id)).scalars().all()
    edges  = db.execute(select(AssetEdge).where(AssetEdge.org_id == org_id)).scalars().all()
    all_findings = db.execute(select(Finding).where(Finding.org_id == org_id)).scalars().all()

    # Group findings per asset
    findings_by_asset: Dict[int, List[Finding]] = {}
    for f in all_findings:
        if f.asset_id:
            findings_by_asset.setdefault(f.asset_id, []).append(f)

    # Build nodes
    nodes: Dict[int, AttackNode] = {}
    for asset in assets:
        asset_findings = findings_by_asset.get(asset.id, [])
        cvss, sev, is_kev, has_rce = _max_cvss_for_asset(asset_findings)
        techs = [t.strip() for t in (asset.technology or "").split(",") if t.strip()]
        nodes[asset.id] = AttackNode(
            asset_id=asset.id,
            asset_type=asset.asset_type or "unknown",
            label=_asset_label(asset),
            exposure_class=asset.exposure_class or "internal",
            exposure_score=float(asset.exposure_score or 5.0),
            importance=float(asset.importance or 10.0),
            max_vuln_cvss=cvss,
            max_vuln_severity=sev,
            is_kev=is_kev,
            has_rce=has_rce,
            open_findings=len([f for f in asset_findings if f.status == "open"]),
            technologies=techs,
        )

    # Build adjacency list (directed: attacker moves source→target)
    adj: Dict[int, List[Tuple[int, str]]] = {aid: [] for aid in nodes}
    for edge in edges:
        src, tgt, rel = edge.source_asset_id, edge.target_asset_id, edge.relation
        if src in adj:
            adj[src].append((tgt, rel))
        # Some relations are bidirectional for attack purposes
        if rel in ("shares_ip", "same_provider", "cname_to"):
            if tgt in adj:
                adj[tgt].append((src, rel))

    return nodes, adj


# ── Path finder ────────────────────────────────────────────────────────────

def _hop_score(from_node: AttackNode, to_node: AttackNode, relation: str) -> float:
    """Score the risk contribution of one hop."""
    base = to_node.exploitability_score * 0.5 + to_node.value_score * 0.3
    # High-risk relations get a bonus
    relation_bonus = {
        "open_port": 15, "bucket_of": 12, "resolves_to": 5,
        "alive_host": 8, "endpoint": 6, "reverse_ip": 4,
    }.get(relation, 2)
    return min(base + relation_bonus, 100.0)


def find_attack_paths(
    nodes: Dict[int, AttackNode],
    adj: Dict[int, List[Tuple[int, str]]],
    max_paths: int = 30,
    max_hops: int = 8,
    min_score: float = 20.0,
) -> List[AttackPath]:
    """Find top attack paths using modified Dijkstra (maximize risk, not minimize cost)."""
    entry_points = [aid for aid, n in nodes.items() if n.exposure_class == "public"]
    targets = [aid for aid, n in nodes.items() if _is_high_value_node(n)]

    if not entry_points or not targets:
        return []

    paths: List[AttackPath] = []
    seen_paths: Set[FrozenSet[int]] = set()

    for entry_id in entry_points:
        if len(paths) >= max_paths:
            break
        entry_node = nodes.get(entry_id)
        if not entry_node:
            continue

        # BFS/DFS to find paths to high-value targets
        # Use (negative_score, path_node_ids, path_hops) as heap entry
        heap: List[Tuple[float, List[int], List[AttackHop]]] = []
        heapq.heappush(heap, (0.0, [entry_id], []))

        visited_for_entry: Set[Tuple[int, ...]] = set()

        while heap and len(paths) < max_paths:
            neg_score, path_ids, path_hops = heapq.heappop(heap)
            current_id = path_ids[-1]
            current_score = -neg_score

            path_key = tuple(sorted(path_ids))
            if path_key in visited_for_entry:
                continue
            visited_for_entry.add(path_key)

            # Check if we reached a high-value target
            if current_id in targets and len(path_ids) > 1:
                fs = frozenset(path_ids)
                if fs not in seen_paths:
                    seen_paths.add(fs)
                    if current_score >= min_score:
                        path_obj = _build_path(path_ids, path_hops, nodes, current_score)
                        paths.append(path_obj)
                continue

            if len(path_ids) >= max_hops:
                continue

            current_node = nodes.get(current_id)
            if not current_node:
                continue

            # Expand neighbors
            for neighbor_id, relation in adj.get(current_id, []):
                if neighbor_id in path_ids:  # no cycles
                    continue
                neighbor_node = nodes.get(neighbor_id)
                if not neighbor_node:
                    continue

                hop_s = _hop_score(current_node, neighbor_node, relation)
                new_score = current_score + hop_s

                mitre = _lookup_mitre(relation, neighbor_node.asset_type, neighbor_node.label)
                hop = AttackHop(
                    from_asset_id=current_id,
                    to_asset_id=neighbor_id,
                    relation=relation,
                    technique_id=mitre[0] if mitre else None,
                    technique_name=mitre[1] if mitre else None,
                    hop_score=hop_s,
                    requires_vuln=neighbor_node.open_findings > 0,
                )
                heapq.heappush(heap, (
                    -new_score,
                    path_ids + [neighbor_id],
                    path_hops + [hop],
                ))

    # Sort by score descending
    paths.sort(key=lambda p: p.total_score, reverse=True)
    return paths[:max_paths]


def _is_high_value_node(node: AttackNode) -> bool:
    label = node.label.lower()
    tech_str = " ".join(node.technologies).lower()
    return any(kw in label or kw in tech_str for kw in {
        "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
        "vault", "admin", "payment", "billing", "internal", "s3", "storage", "secret",
    })


def _build_path(
    path_ids: List[int],
    hops: List[AttackHop],
    nodes: Dict[int, AttackNode],
    score: float,
) -> AttackPath:
    import hashlib
    path_id = hashlib.sha256(str(path_ids).encode()).hexdigest()[:12]

    path_nodes = [nodes[aid] for aid in path_ids if aid in nodes]
    techniques = list({h.technique_id for h in hops if h.technique_id})

    # Classify path
    if any(n.exposure_class == "public" for n in path_nodes[:2]):
        category = "initial_access"
    elif any("internal" in n.label.lower() for n in path_nodes):
        category = "lateral_movement"
    elif any(n.asset_type == "cloud" for n in path_nodes):
        category = "data_exfiltration"
    else:
        category = "lateral_movement"

    # Normalize score to 0-100
    normalized = round(min(score / max(len(path_ids), 1), 100.0), 2)

    # Likelihood
    if normalized >= 70:   likelihood = "critical"
    elif normalized >= 50: likelihood = "high"
    elif normalized >= 30: likelihood = "medium"
    else:                  likelihood = "low"

    # Human-readable description
    entry = path_nodes[0].label if path_nodes else "?"
    target = path_nodes[-1].label if path_nodes else "?"
    desc = (
        f"Attacker starts at internet-facing asset '{entry}' and reaches "
        f"'{target}' in {len(hops)} hop(s) via "
        f"{', '.join(h.relation for h in hops[:3])}."
    )
    if any(h.technique_id for h in hops):
        desc += f" MITRE techniques: {', '.join(techniques[:4])}."

    return AttackPath(
        id=path_id,
        entry_point_id=path_ids[0],
        target_id=path_ids[-1],
        hops=hops,
        nodes=path_nodes,
        total_score=normalized,
        category=category,
        mitre_techniques=techniques,
        likelihood=likelihood,
        description=desc,
    )


# ── Choke point analysis ───────────────────────────────────────────────────

def find_choke_points(paths: List[AttackPath]) -> List[Tuple[int, int]]:
    """Find assets whose removal blocks the most attack paths.

    Returns sorted list of (asset_id, paths_blocked) desc.
    """
    counter: Dict[int, int] = {}
    for path in paths:
        for node in path.nodes[1:-1]:  # skip entry and target
            counter[node.asset_id] = counter.get(node.asset_id, 0) + 1
    return sorted(counter.items(), key=lambda x: x[1], reverse=True)


def build_risk_heatmap(nodes: Dict[int, AttackNode], paths: List[AttackPath]) -> Dict[int, float]:
    """Assign attack risk score to each asset based on how many paths run through it."""
    heatmap: Dict[int, float] = {}
    for path in paths:
        path_contribution = path.total_score / max(len(path.nodes), 1)
        for node in path.nodes:
            heatmap[node.asset_id] = round(
                min(heatmap.get(node.asset_id, 0) + path_contribution, 100.0), 2
            )
    # Assets not in any path still have their base node risk
    for aid, node in nodes.items():
        if aid not in heatmap:
            heatmap[aid] = round(node.node_risk * 0.3, 2)
    return heatmap


# ── Main API ───────────────────────────────────────────────────────────────

def analyze_attack_surface(
    db: Session,
    org_id: int,
    max_paths: int = 20,
    max_hops: int = 7,
    min_score: float = 15.0,
) -> AttackSurface:
    """Full attack surface analysis: paths, choke points, heatmap.

    Returns AttackSurface with all paths and supporting data.
    """
    nodes, adj = build_attack_graph(db, org_id)

    entry_points = [n for n in nodes.values() if n.exposure_class == "public"]
    high_value    = [n for n in nodes.values() if _is_high_value_node(n)]

    paths = find_attack_paths(nodes, adj, max_paths=max_paths, max_hops=max_hops, min_score=min_score)
    choke = find_choke_points(paths)
    heatmap = build_risk_heatmap(nodes, paths)

    critical_paths = sum(1 for p in paths if p.likelihood == "critical")

    return AttackSurface(
        entry_points=sorted(entry_points, key=lambda n: n.node_risk, reverse=True)[:30],
        high_value_targets=sorted(high_value, key=lambda n: n.value_score, reverse=True)[:20],
        attack_paths=paths,
        choke_points=choke[:10],
        risk_heatmap=heatmap,
        total_paths=len(paths),
        critical_paths=critical_paths,
    )


def path_to_dict(path: AttackPath, nodes: Dict[int, AttackNode]) -> dict:
    """Serialize AttackPath for API response."""
    return {
        "id": path.id,
        "entry_point_id": path.entry_point_id,
        "target_id": path.target_id,
        "total_score": path.total_score,
        "category": path.category,
        "likelihood": path.likelihood,
        "hop_count": path.hop_count,
        "description": path.description,
        "mitre_techniques": path.mitre_techniques,
        "hops": [
            {
                "from": h.from_asset_id,
                "to": h.to_asset_id,
                "relation": h.relation,
                "technique_id": h.technique_id,
                "technique_name": h.technique_name,
                "hop_score": round(h.hop_score, 2),
                "requires_vuln": h.requires_vuln,
            }
            for h in path.hops
        ],
        "nodes": [
            {
                "asset_id": n.asset_id,
                "label": n.label,
                "type": n.asset_type,
                "exposure": n.exposure_class,
                "node_risk": n.node_risk,
                "max_cvss": n.max_vuln_cvss,
                "severity": n.max_vuln_severity,
                "is_kev": n.is_kev,
                "has_rce": n.has_rce,
            }
            for n in path.nodes
        ],
    }
