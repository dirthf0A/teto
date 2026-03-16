"""Analysis helpers — thin wrappers over risk_engine for backward compat.

Also provides:
  score_finding_cvss_aware  — CVSS + KEV + exploit bonuses (new, preferred)
  filter_false_positives    — heuristic FP filter using vuln_scanner patterns
  deduplicate_findings      — fingerprint-based dedup
"""
from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Optional, Set, Tuple

from app.services.scanning import ScanFinding
from app.services import risk_engine


SEVERITY_SCORES: Dict[str, float] = dict(risk_engine.SEVERITY_WEIGHTS)

# FP heuristics (mirrors vuln_scanner._is_false_positive for standalone use)
_FP_TITLE_PATTERNS = [
    "test page", "example domain", "it works", "default installation",
    "placeholder", "under construction", "coming soon",
]
_FP_PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


def deduplicate_findings(findings: Iterable[ScanFinding]) -> List[ScanFinding]:
    """Deduplicate by (title, tool) — fast path for raw scanner output."""
    seen: Set[Tuple[str, str]] = set()
    deduped: List[ScanFinding] = []
    for finding in findings:
        key = (finding.title or "", finding.tool or "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def deduplicate_by_fingerprint(findings: Iterable[ScanFinding]) -> List[ScanFinding]:
    """Deduplicate by SHA256 fingerprint — stronger than (title, tool)."""
    seen: Set[str] = set()
    deduped: List[ScanFinding] = []
    for finding in findings:
        raw = "|".join([
            finding.tool or "",
            getattr(finding, "template_id", None) or "",
            finding.title or "",
            finding.target or "",
            str(finding.port or ""),
            finding.cve or "",
        ])
        fp = hashlib.sha256(raw.encode()).hexdigest()[:32]
        if fp in seen:
            continue
        seen.add(fp)
        deduped.append(finding)
    return deduped


def classify_severity(finding: ScanFinding) -> str:
    sev = (finding.severity or "").lower()
    return sev if sev in SEVERITY_SCORES else "info"


def vulnerability_score(finding: ScanFinding) -> float:
    return risk_engine.severity_weight(finding.severity)


def exposure_classification(
    environment: Optional[str],
    tags: Optional[str] = None,
    asset_type: Optional[str] = None,
    ip: Optional[str] = None,
    is_public: Optional[bool] = None,
) -> str:
    return risk_engine.classify_exposure(
        environment, tags, asset_type, ip=ip, is_public=is_public
    )


def exposure_from_environment(
    environment: str,
    tags: Optional[str] = None,
    asset_type: Optional[str] = None,
    ip: Optional[str] = None,
) -> float:
    exposure_class = exposure_classification(
        environment, tags=tags, asset_type=asset_type, ip=ip
    )
    return risk_engine.exposure_score(exposure_class)


def score_risk(
    severity: object, exposure_class: object, importance: float
) -> float:
    """Legacy scorer — no CVSS/KEV awareness. Use score_finding_cvss_aware() instead."""
    return risk_engine.score_risk(severity, exposure_class, importance)


def score_finding_cvss_aware(
    finding: ScanFinding,
    exposure_class: str,
    importance: float,
    is_kev: bool = False,
    has_exploit: bool = False,
) -> float:
    """CVSS-aware risk scoring with KEV and exploit bonuses.

    Uses risk_engine.score_finding_risk() which applies:
      - CVSS base score (overrides categorical severity when available)
      - KEV bonus +15
      - Public exploit bonus +10
      - Finding type bonus (RCE, SQLi, SSRF, etc.)
      - Exposure and importance weights

    Returns a 0–100 float.
    """
    result = risk_engine.score_finding_risk(
        severity=classify_severity(finding),
        exposure_class=exposure_class,
        importance=importance,
        finding_title=finding.title,
        cvss=finding.cvss,
        is_kev=is_kev,
        has_exploit=has_exploit,
    )
    return result["score"]


def filter_false_positives(findings: Iterable[ScanFinding]) -> List[ScanFinding]:
    """Heuristic false-positive filter.

    Removes:
    - Findings whose title matches known FP patterns (test pages, default pages)
    - info-severity findings on RFC1918 / internal targets (no CVE)
    """
    clean: List[ScanFinding] = []
    for finding in findings:
        title = (finding.title or "").lower()
        target = (finding.target or "").lower()
        evidence = (finding.evidence or "").lower()

        # Title-based FP
        if any(p in title for p in _FP_TITLE_PATTERNS):
            continue

        # Target-based FP (localhost / example.com)
        if any(p in target or p in evidence for p in ("127.0.0.1", "localhost", "example.com", "test.local")):
            continue

        # Info on private IPs without a CVE
        if (finding.severity or "") == "info" and not finding.cve:
            if any(target.startswith(prefix) for prefix in _FP_PRIVATE_PREFIXES) or \
                    any(kw in target for kw in ("internal", "intranet")):
                continue

        clean.append(finding)
    return clean
