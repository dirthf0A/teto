"""Custom Nuclei Template Engine.

Manages user-uploaded nuclei templates stored in the database.
Supports:
  - Store / validate YAML templates
  - Write to temp directory for nuclei execution
  - Merge with built-in nuclei profiles for combined scans
  - Template variable substitution ({{target}}, {{hostname}})
  - Basic YAML structure validation before storing

Template YAML must conform to nuclei template format:
  id: custom-<slug>
  info:
    name: ...
    severity: critical|high|medium|low|info
    tags: custom,...
  requests:
    - ...
"""
from __future__ import annotations

import os
import re
import tempfile
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.logger import get_logger
from app.models import NucleiTemplate

logger = get_logger("app.services.template_engine")

# Allowed severities
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Nuclei template fields we require
_REQUIRED_FIELDS = ("id:", "info:", "name:", "severity:")


def validate_template_yaml(content: str) -> tuple[bool, str]:
    """Basic structural validation of a nuclei template.

    Returns (is_valid, error_message).
    Does NOT execute the template — only checks structure.
    """
    if not content or not content.strip():
        return False, "template content is empty"
    if len(content) > 512_000:
        return False, "template too large (max 512 KB)"

    # Must contain required keys
    for field in _REQUIRED_FIELDS:
        if field not in content:
            return False, f"missing required field: '{field}'"

    # Extract severity
    sev_match = re.search(r"severity:\s*(\w+)", content)
    if sev_match:
        sev = sev_match.group(1).lower()
        if sev not in VALID_SEVERITIES:
            return False, f"invalid severity '{sev}', must be one of: {', '.join(VALID_SEVERITIES)}"

    # Reject shell injection attempts in template ID
    id_match = re.search(r"^id:\s*(.+)$", content, re.MULTILINE)
    if id_match:
        tid = id_match.group(1).strip()
        if re.search(r"[;&|`$(){}\[\]<>]", tid):
            return False, "template id contains invalid characters"

    # Must have at least one request/network/dns block
    has_requests = any(
        kw in content
        for kw in ("requests:", "network:", "dns:", "headless:", "websocket:", "ssl:", "whois:")
    )
    if not has_requests:
        return False, "template must contain at least one request block"

    return True, ""


def _extract_meta(content: str) -> dict:
    """Extract id, name, severity, tags from template YAML."""
    meta = {"slug": "", "name": "", "severity": "medium", "tags": ""}
    id_m = re.search(r"^id:\s*(.+)$", content, re.MULTILINE)
    if id_m:
        meta["slug"] = re.sub(r"[^a-z0-9\-_]", "", id_m.group(1).strip().lower())[:80]
    name_m = re.search(r"^\s+name:\s*(.+)$", content, re.MULTILINE)
    if name_m:
        meta["name"] = name_m.group(1).strip()[:200]
    sev_m = re.search(r"severity:\s*(\w+)", content)
    if sev_m:
        meta["severity"] = sev_m.group(1).lower()
    tags_m = re.search(r"tags:\s*(.+)$", content, re.MULTILINE)
    if tags_m:
        meta["tags"] = tags_m.group(1).strip()[:255]
    return meta


def upsert_template(
    db: Session,
    org_id: int,
    content: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    created_by: Optional[str] = None,
) -> NucleiTemplate:
    """Validate and store a custom template. Updates if slug already exists."""
    valid, err = validate_template_yaml(content)
    if not valid:
        raise ValueError(f"Invalid template: {err}")

    meta = _extract_meta(content)
    slug = meta["slug"] or "custom-template"

    existing = db.execute(
        select(NucleiTemplate).where(
            NucleiTemplate.org_id == org_id,
            NucleiTemplate.slug == slug,
        )
    ).scalar_one_or_none()

    if existing:
        existing.content = content
        existing.severity = meta["severity"]
        existing.tags = meta["tags"]
        if name:
            existing.name = name
        if description:
            existing.description = description
        db.commit()
        db.refresh(existing)
        logger.info("template updated", slug=slug, org_id=org_id)
        return existing

    tmpl = NucleiTemplate(
        org_id=org_id,
        name=name or meta["name"] or slug,
        slug=slug,
        description=description,
        severity=meta["severity"],
        tags=meta["tags"],
        content=content,
        enabled=True,
        created_by=created_by,
    )
    db.add(tmpl)
    db.commit()
    db.refresh(tmpl)
    logger.info("template created", slug=slug, org_id=org_id)
    return tmpl


def list_templates(db: Session, org_id: int, enabled_only: bool = True) -> List[NucleiTemplate]:
    stmt = select(NucleiTemplate).where(NucleiTemplate.org_id == org_id)
    if enabled_only:
        stmt = stmt.where(NucleiTemplate.enabled == True)
    return db.execute(stmt.order_by(NucleiTemplate.created_at.desc())).scalars().all()


def write_templates_to_dir(templates: List[NucleiTemplate]) -> str:
    """Write template YAML files to a temp directory for nuclei -t execution.

    Returns the directory path. Caller must clean up.
    """
    tmpdir = tempfile.mkdtemp(prefix="asm-tmpl-")
    for tmpl in templates:
        fname = f"{tmpl.slug}.yaml"
        path = os.path.join(tmpdir, fname)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(tmpl.content)
        except Exception as e:
            logger.warning("failed to write template file", slug=tmpl.slug, error=str(e))
    logger.debug("templates written", count=len(templates), dir=tmpdir)
    return tmpdir


def run_custom_templates(
    db: Session,
    org_id: int,
    targets: List[str],
    severity_filter: Optional[List[str]] = None,
) -> List[dict]:
    """Run all enabled custom templates against targets via nuclei.

    Returns raw findings list (same format as nuclei_scan).
    """
    import shutil
    templates = list_templates(db, org_id, enabled_only=True)
    if not templates:
        return []

    if severity_filter:
        templates = [t for t in templates if t.severity in severity_filter]
    if not templates:
        return []

    tmpdir = write_templates_to_dir(templates)
    try:
        from app.services.vuln_scanner import nuclei_scan, NucleiScanOptions
        opts = NucleiScanOptions(
            templates=[tmpdir],
            severity=severity_filter,
        )
        findings = nuclei_scan(targets, opts=opts)
        logger.info(
            "custom template scan complete",
            org_id=org_id,
            templates=len(templates),
            targets=len(targets),
            findings=len(findings),
        )
        return findings
    except Exception as e:
        logger.error("custom template scan failed", error=str(e), exc_info=True)
        return []
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception as e:
            logger.debug("template dir cleanup failed", error=str(e))
