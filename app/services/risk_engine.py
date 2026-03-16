"""Enterprise risk engine — full CVSS + exposure + asset criticality scoring.

Three scoring layers:
  1. Finding risk  — CVSS base + KEV bonus + exploit bonus + exposure weight
  2. Asset risk    — exposure class + open ports + tech risk + finding aggregate
  3. Org risk      — weighted aggregate (top-N heavy) with trend + distribution

All scores are 0-100 floats. Labels: low / medium / high / critical.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Base weight tables
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 15.0,
    "high":     10.0,
    "medium":    6.0,
    "low":       3.0,
    "info":      1.0,
}

EXPOSURE_SCORES: Dict[str, float] = {
    "public":   30.0,
    "vpn":      15.0,
    "internal":  5.0,
}

ENVIRONMENT_IMPORTANCE: Dict[str, float] = {
    "prod":       50.0,
    "production": 50.0,
    "staging":    20.0,
    "stage":      20.0,
    "qa":         20.0,
    "dev":        10.0,
    "test":       10.0,
}

# Port risk bonus — added on top of base asset risk for dangerous open ports
PORT_RISK_BONUS: Dict[int, float] = {
    3389: 20.0,   # RDP
    445:  20.0,   # SMB
    3306: 15.0,   # MySQL
    5432: 15.0,   # PostgreSQL
    6379: 20.0,   # Redis
    27017: 20.0,  # MongoDB
    9200: 20.0,   # Elasticsearch
    2375: 25.0,   # Docker daemon
    11211: 15.0,  # Memcached
    5900: 20.0,   # VNC
    22:    5.0,   # SSH
    21:   10.0,   # FTP
    23:   15.0,   # Telnet
    4444: 25.0,   # Backdoor/Metasploit
    8888: 10.0,   # Jupyter
    7001: 20.0,   # WebLogic
}

# Cloud misconfig severity bonus
CLOUD_MISCONFIG_BONUS: Dict[str, float] = {
    "public_bucket":    25.0,
    "public_cloud_asset": 20.0,
    "cloud_exposed":    18.0,
    "bucket_acl_public": 22.0,
}

# Finding type bonus — based on title keyword matching
FINDING_TYPE_BONUS: Dict[str, float] = {
    "rce":                  20.0,
    "remote code execution": 20.0,
    "sqli":                 15.0,
    "sql injection":        15.0,
    "xss":                   8.0,
    "cross-site scripting":  8.0,
    "ssrf":                 12.0,
    "lfi":                  10.0,
    "local file inclusion": 10.0,
    "idor":                 10.0,
    "auth bypass":          15.0,
    "authentication bypass": 15.0,
    "secret":               15.0,
    "exposed credentials":  20.0,
    "takeover":             18.0,
    "subdomain takeover":   18.0,
    "actively exploited":   15.0,
    "default credentials":  18.0,
    "path traversal":       12.0,
    "xxe":                  12.0,
    "ssti":                 15.0,
    "open redirect":         6.0,
}

RISK_LABELS: List[Tuple[float, str]] = [
    (76.0, "critical"),
    (51.0, "high"),
    (26.0, "medium"),
    (0.0,  "low"),
]


# ---------------------------------------------------------------------------
# Core scoring helpers
# ---------------------------------------------------------------------------

def risk_label(score: float) -> str:
    """Convert numeric 0–100 score to label."""
    for threshold, label in RISK_LABELS:
        if score >= threshold:
            return label
    return "low"


def severity_weight(severity: Optional[str]) -> float:
    if not severity:
        return SEVERITY_WEIGHTS["info"]
    return SEVERITY_WEIGHTS.get(severity.lower(), SEVERITY_WEIGHTS["info"])


def classify_exposure(
    environment: Optional[str],
    tags: Optional[str],
    asset_type: Optional[str],
    ip: Optional[str] = None,
    is_public: Optional[bool] = None,
) -> str:
    """Classify asset exposure: public / vpn / internal."""
    tag_value = (tags or "").lower()
    env = (environment or "prod").lower()

    # IP-based: RFC1918 is always internal
    if ip:
        try:
            if ipaddress.ip_address(ip).is_private:
                return "internal"
        except ValueError:
            pass

    if is_public is True:
        return "public"

    # Tag-based overrides
    if any(kw in tag_value for kw in ("public", "internet", "external")):
        return "public"
    if any(kw in tag_value for kw in ("vpn", "partner", "restricted")):
        return "vpn"
    if any(kw in tag_value for kw in ("internal", "intranet", "private")):
        return "internal"

    # Environment-based
    if env in ("dev", "test", "internal", "intranet"):
        return "internal"
    if env in ("staging", "qa", "stage"):
        return "vpn"
    if env in ("prod", "production"):
        return "public"

    # Asset type fallback
    if asset_type in ("service", "endpoint") and env == "prod":
        return "public"

    return "internal"


def exposure_score(exposure_class: str) -> float:
    return EXPOSURE_SCORES.get(exposure_class, EXPOSURE_SCORES["internal"])


def importance_score(
    environment: Optional[str],
    tags: Optional[str],
    asset_type: Optional[str],
) -> float:
    """Compute asset importance score (0–100)."""
    env = (environment or "prod").lower()
    base = ENVIRONMENT_IMPORTANCE.get(env, ENVIRONMENT_IMPORTANCE["prod"])
    tag_value = (tags or "").lower()
    if any(kw in tag_value for kw in ("critical", "tier-0", "crown-jewel")):
        base += 10.0
    if asset_type in ("service", "endpoint"):
        base += 5.0
    if asset_type == "domain":
        base += 3.0
    return min(base, 100.0)


def score_risk(
    severity: Union[str, float, int, None],
    exposure_class: Union[str, float, int],
    importance: float,
) -> float:
    """Legacy scoring: severity + exposure + importance (used by analysis.py)."""
    if isinstance(severity, (int, float)):
        sev_value = float(severity)
    else:
        sev_value = severity_weight(severity)
    if isinstance(exposure_class, (int, float)):
        exp_value = float(exposure_class)
    else:
        exp_value = exposure_score(exposure_class)
    risk = sev_value + exp_value + importance
    return round(max(0.0, min(risk, 100.0)), 2)


# ---------------------------------------------------------------------------
# Enhanced finding risk scoring (v2)
# ---------------------------------------------------------------------------

def score_finding_risk(
    severity: Optional[str],
    exposure_class: str,
    importance: float,
    finding_title: Optional[str] = None,
    cvss: Optional[float] = None,
    is_kev: bool = False,
    has_exploit: bool = False,
) -> Dict:
    """CVSS-aware finding risk score with KEV and exploit bonuses.

    Returns dict: {score, label, breakdown}.
    """
    breakdown: Dict[str, float] = {}

    # Base severity — CVSS overrides categorical severity when available
    sev_score = severity_weight(severity)
    if cvss is not None:
        # CVSS 10.0 -> 15.0 points, proportionally
        cvss_score = (cvss / 10.0) * 15.0
        sev_score = max(sev_score, cvss_score)
    breakdown["severity"] = round(sev_score, 2)

    # Exposure
    exp_score = exposure_score(exposure_class)
    breakdown["exposure"] = exp_score

    # Asset importance contribution (15% weight)
    imp_score = importance * 0.15
    breakdown["importance"] = round(imp_score, 2)

    # Finding type bonus
    type_bonus = 0.0
    if finding_title:
        title_lower = finding_title.lower()
        for keyword, bonus in FINDING_TYPE_BONUS.items():
            if keyword in title_lower:
                type_bonus = max(type_bonus, bonus)
    breakdown["finding_type"] = type_bonus

    # KEV bonus — actively exploited = always critical priority
    kev_bonus = 15.0 if is_kev else 0.0
    breakdown["kev_bonus"] = kev_bonus

    # Exploit availability bonus
    exploit_bonus = 10.0 if has_exploit else 0.0
    breakdown["exploit_bonus"] = exploit_bonus

    total = sum(breakdown.values())
    score = round(max(0.0, min(total, 100.0)), 2)
    return {"score": score, "label": risk_label(score), "breakdown": breakdown}


# ---------------------------------------------------------------------------
# Enhanced asset risk scoring (v2)
# ---------------------------------------------------------------------------

def score_asset_risk(
    environment: Optional[str],
    tags: Optional[str],
    asset_type: Optional[str],
    ip: Optional[str] = None,
    is_public: Optional[bool] = None,
    open_ports: Optional[List[int]] = None,
    technologies: Optional[List[str]] = None,
    finding_count_by_severity: Optional[Dict[str, int]] = None,
    cloud_misconfiguration: Optional[str] = None,
) -> Dict:
    """Multi-factor asset risk score with breakdown.

    Factors:
      - Exposure class (public/vpn/internal)
      - Environment importance
      - High-risk open ports
      - Technology stack risk
      - Vulnerability aggregate (by severity count)
      - Cloud misconfiguration

    Returns dict: {score, label, exposure_class, breakdown}.
    """
    breakdown: Dict[str, float] = {}

    exposure_class = classify_exposure(environment, tags, asset_type, ip=ip, is_public=is_public)
    exp_score = exposure_score(exposure_class)
    breakdown["exposure"] = exp_score

    imp_score = importance_score(environment, tags, asset_type) * 0.3
    breakdown["importance"] = round(imp_score, 2)

    # Open port risk — take highest-risk port bonus
    port_bonus = 0.0
    if open_ports:
        for port in open_ports:
            port_bonus = max(port_bonus, PORT_RISK_BONUS.get(port, 0.0))
    breakdown["port_risk"] = port_bonus

    # Cloud misconfiguration bonus
    misconfig_bonus = 0.0
    if cloud_misconfiguration:
        misconfig_bonus = CLOUD_MISCONFIG_BONUS.get(cloud_misconfiguration.lower(), 10.0)
    breakdown["cloud_misconfig"] = misconfig_bonus

    # Vulnerability aggregate (capped at 30 to prevent single vector domination)
    vuln_score = 0.0
    if finding_count_by_severity:
        for sev, count in finding_count_by_severity.items():
            weight = SEVERITY_WEIGHTS.get(sev.lower(), 1.0)
            vuln_score += weight * min(count, 5)   # cap per-severity contribution
        vuln_score = min(vuln_score, 30.0)
    breakdown["vulnerabilities"] = vuln_score

    # Technology risk (CMS / legacy stacks)
    tech_risk = 0.0
    _HIGH_RISK_TECH = {"wordpress", "joomla", "drupal", "magento", "php", "coldfusion",
                       "struts", "log4j", "spring"}
    if technologies:
        for tech in technologies:
            if any(kw in tech.lower() for kw in _HIGH_RISK_TECH):
                tech_risk = max(tech_risk, 5.0)
    breakdown["technology_risk"] = tech_risk

    total = sum(breakdown.values())
    score = round(max(0.0, min(total, 100.0)), 2)
    return {
        "score": score,
        "label": risk_label(score),
        "exposure_class": exposure_class,
        "breakdown": breakdown,
    }


# ---------------------------------------------------------------------------
# Attack path impact scoring
# ---------------------------------------------------------------------------

def score_attack_path_impact(
    path_nodes: List[Dict],
    choke_point_count: int = 0,
) -> Dict:
    """Score the criticality of an attack path.

    path_nodes: list of {asset_id, label, exposure_class, has_rce, is_kev, risk_score}

    Returns {score, label, factors}.
    """
    if not path_nodes:
        return {"score": 0.0, "label": "low", "factors": {}}

    factors: Dict[str, float] = {}

    # Path length penalty — longer paths are harder but not impossible
    hop_count = len(path_nodes)
    hop_penalty = max(0.0, 15.0 - hop_count * 2.0)
    factors["path_depth"] = round(hop_penalty, 2)

    # Entry point exposure
    entry = path_nodes[0]
    entry_exp = exposure_score(entry.get("exposure_class", "internal"))
    factors["entry_exposure"] = entry_exp

    # RCE nodes along path
    rce_count = sum(1 for n in path_nodes if n.get("has_rce"))
    factors["rce_nodes"] = min(rce_count * 10.0, 25.0)

    # KEV nodes along path
    kev_count = sum(1 for n in path_nodes if n.get("is_kev"))
    factors["kev_nodes"] = min(kev_count * 8.0, 20.0)

    # Choke point bonus — blocking this path blocks many others
    factors["choke_point"] = min(choke_point_count * 5.0, 15.0)

    # Max node risk along path
    max_node_risk = max((float(n.get("risk_score", 0)) for n in path_nodes), default=0.0)
    factors["max_node_risk"] = round(max_node_risk * 0.3, 2)

    total = sum(factors.values())
    score = round(max(0.0, min(total, 100.0)), 2)
    return {"score": score, "label": risk_label(score), "factors": factors}


# ---------------------------------------------------------------------------
# Org-level risk aggregate
# ---------------------------------------------------------------------------

def aggregate_org_risk(
    asset_scores: List[float],
    finding_scores: List[float],
) -> Dict:
    """Organization-level risk aggregate.

    Uses top-decile weighting: the worst 10% of assets/findings
    contribute 60% of the weight — ensures outliers are visible.

    Returns {overall_score, label, asset_risk, finding_risk, risk_distribution,
             critical_count, high_count}.
    """
    def _weighted_avg(scores: List[float]) -> float:
        if not scores:
            return 0.0
        scores_sorted = sorted(scores, reverse=True)
        n = len(scores_sorted)
        top_n = max(1, n // 10)
        top_avg = sum(scores_sorted[:top_n]) / top_n
        rest = scores_sorted[top_n:]
        rest_avg = sum(rest) / len(rest) if rest else 0.0
        return top_avg * 0.6 + rest_avg * 0.4

    asset_risk = round(_weighted_avg(asset_scores), 2) if asset_scores else 0.0
    finding_risk = round(_weighted_avg(finding_scores), 2) if finding_scores else 0.0
    overall = round(asset_risk * 0.4 + finding_risk * 0.6, 2)

    distribution: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for s in asset_scores + finding_scores:
        distribution[risk_label(s)] = distribution.get(risk_label(s), 0) + 1

    return {
        "overall_score": overall,
        "label": risk_label(overall),
        "asset_risk": asset_risk,
        "finding_risk": finding_risk,
        "risk_distribution": distribution,
        "critical_count": distribution.get("critical", 0),
        "high_count": distribution.get("high", 0),
    }


# ---------------------------------------------------------------------------
# CVSS vector parsing (standalone helper)
# ---------------------------------------------------------------------------

_CVSS31_AV_WEIGHTS = {"N": 1.0, "A": 0.6, "L": 0.4, "P": 0.2}
_CVSS31_PR_WEIGHTS = {"N": 1.0, "L": 0.6, "H": 0.3}
_CVSS31_UI_WEIGHTS = {"N": 1.0, "R": 0.6}


def parse_cvss_vector(vector_string: Optional[str]) -> Dict:
    """Parse a CVSS v3.x vector string into component weights.

    Returns dict with av, pr, ui, scope, exploitability_weight.
    Useful for fine-grained risk adjustment beyond just the base score.
    """
    if not vector_string:
        return {}
    try:
        parts = {}
        for segment in vector_string.split("/"):
            if ":" in segment:
                k, v = segment.split(":", 1)
                parts[k] = v
        av = _CVSS31_AV_WEIGHTS.get(parts.get("AV", "N"), 1.0)
        pr = _CVSS31_PR_WEIGHTS.get(parts.get("PR", "N"), 1.0)
        ui = _CVSS31_UI_WEIGHTS.get(parts.get("UI", "N"), 1.0)
        scope = parts.get("S", "U")
        exploitability = av * pr * ui
        return {
            "attack_vector": parts.get("AV"),
            "privileges_required": parts.get("PR"),
            "user_interaction": parts.get("UI"),
            "scope": scope,
            "exploitability_weight": round(exploitability, 3),
            "network_exploitable": parts.get("AV") == "N",
            "no_auth_required": parts.get("PR") == "N",
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Convenience re-exports (keep backward compat with asset_intelligence.py)
# ---------------------------------------------------------------------------

def compute_asset_importance(
    environment: Optional[str],
    tags: Optional[str],
    asset_type: Optional[str],
) -> float:
    """Alias for importance_score — used by asset_intelligence module."""
    return importance_score(environment, tags, asset_type)
