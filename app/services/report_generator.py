"""Security Report Generator — one-click reports in PDF, Markdown, HTML.

Generates professional security reports for:
  - Pentesters / security consultants (PDF export)
  - Dev teams (Markdown for GitHub/Confluence)
  - Executives (HTML summary with charts)

Report sections:
  1. Executive Summary — score, trend, key risk metrics
  2. Asset Inventory — breakdown by type, exposure, hosting
  3. Top Exposures — critical findings with remediation guidance
  4. Attack Surface Evolution — change over time
  5. Vulnerability Distribution — severity pie, CVE list
  6. Team Ownership Summary — risks per team
  7. Recommendations — prioritized action items

The report engine pulls data from all existing services:
  - attack_surface_score  → score + trend
  - asset_history         → timeline events
  - asset_ownership       → team mapping
  - findings              → vulnerability list
  - alerts                → recent alert summary
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from io import BytesIO
from typing import Dict, List, Optional

from sqlalchemy import func as sa_func
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert, Asset, AssetChange, Finding, Organization, Scan


# ── Data collection ────────────────────────────────────────────────────────

def _gather_report_data(db: Session, org_id: int, domain: Optional[str] = None) -> dict:
    """Collect all data needed for the report."""
    org = db.execute(select(Organization).where(Organization.id == org_id)).scalar_one_or_none()

    # Assets
    asset_q = select(Asset).where(Asset.org_id == org_id)
    if domain:
        asset_q = asset_q.where(
            (Asset.domain == domain) | (Asset.subdomain.contains(domain))
        )
    assets = db.execute(asset_q).scalars().all()

    # Findings (open)
    findings = db.execute(
        select(Finding).where(Finding.org_id == org_id, Finding.status == "open")
        .order_by(Finding.risk_score.desc().nullslast())
    ).scalars().all()

    # Recent changes (30d)
    since_30d = datetime.utcnow() - timedelta(days=30)
    changes = db.execute(
        select(AssetChange).where(
            AssetChange.org_id == org_id,
            AssetChange.created_at >= since_30d,
        ).order_by(AssetChange.created_at.desc()).limit(50)
    ).scalars().all()

    # Recent alerts (7d)
    since_7d = datetime.utcnow() - timedelta(days=7)
    alerts = db.execute(
        select(Alert).where(
            Alert.org_id == org_id,
            Alert.created_at >= since_7d,
        ).order_by(Alert.created_at.desc()).limit(20)
    ).scalars().all()

    # Score
    from app.services.attack_surface_score import get_latest_score, score_label
    score_data = get_latest_score(db, org_id, domain=domain) or {}

    # Ownership
    from app.services.asset_ownership import get_team_exposure
    teams = get_team_exposure(db, org_id)

    # Asset breakdown
    by_type: Dict[str, int] = {}
    by_exposure: Dict[str, int] = {}
    by_provider: Dict[str, int] = {}
    for a in assets:
        by_type[a.asset_type or "unknown"] = by_type.get(a.asset_type or "unknown", 0) + 1
        by_exposure[a.exposure_class or "unknown"] = by_exposure.get(a.exposure_class or "unknown", 0) + 1
        if a.hosting_provider:
            p = a.hosting_provider.lower()
            by_provider[p] = by_provider.get(p, 0) + 1

    # Finding breakdown
    by_severity: Dict[str, int] = {}
    by_tool: Dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_tool[f.tool or "unknown"] = by_tool.get(f.tool or "unknown", 0) + 1

    # Top 10 critical/high findings
    top_findings = [f for f in findings if f.severity in ("critical", "high")][:10]

    # Recommendations
    recs = _generate_recommendations(findings, assets, score_data)

    return {
        "org_name": org.name if org else "Unknown Org",
        "domain": domain or "All domains",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "score": score_data,
        "assets": {
            "total": len(assets),
            "by_type": by_type,
            "by_exposure": by_exposure,
            "by_provider": by_provider,
            "public_count": by_exposure.get("public", 0),
        },
        "findings": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_tool": by_tool,
            "top": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "target": f.target,
                    "cve": f.cve,
                    "cvss": f.cvss,
                    "risk_score": f.risk_score,
                    "description": (f.description or "")[:300],
                }
                for f in top_findings
            ],
            "kev_count": sum(1 for f in findings if f.cve),
        },
        "changes_30d": [
            {"type": c.change_type, "detail": c.detail,
             "at": c.created_at.strftime("%Y-%m-%d") if c.created_at else ""}
            for c in changes[:20]
        ],
        "alerts_7d": len(alerts),
        "teams": teams[:8],
        "recommendations": recs,
    }


def _generate_recommendations(findings: list, assets: list, score_data: dict) -> List[dict]:
    """Generate prioritized remediation recommendations from findings and score."""
    recs = []
    sev_map = {f.title: f.severity for f in findings}

    # Critical vulns
    crit = sum(1 for f in findings if f.severity == "critical")
    if crit:
        recs.append({
            "priority": "immediate",
            "title": f"Remediate {crit} critical vulnerability{'s' if crit > 1 else ''}",
            "detail": "Critical vulnerabilities represent the highest risk. Patch within 24-48 hours.",
            "effort": "high",
        })

    # Public buckets
    buckets = sum(1 for a in assets if a.asset_type == "cloud"
                  and a.service in ("s3", "gcs", "azure-storage"))
    if buckets:
        recs.append({
            "priority": "immediate",
            "title": f"Restrict access on {buckets} cloud storage bucket{'s' if buckets > 1 else ''}",
            "detail": "Public cloud storage buckets can expose sensitive data to anyone on the internet.",
            "effort": "low",
        })

    # High-risk ports
    risky_ports = sum(1 for a in assets
                      if a.port in {3389, 6379, 27017, 9200, 2375}
                      and a.exposure_class == "public")
    if risky_ports:
        recs.append({
            "priority": "high",
            "title": f"Firewall {risky_ports} high-risk service{'s' if risky_ports > 1 else ''} from internet",
            "detail": "Services like Redis, MongoDB, Elasticsearch should never be exposed to the internet.",
            "effort": "medium",
        })

    # Unowned assets
    from app.models import AssetOwnership
    recs.append({
        "priority": "medium",
        "title": "Assign ownership to all public-facing assets",
        "detail": "Every public asset should have an owner team for accountability and faster incident response.",
        "effort": "low",
    })

    # SSL/TLS issues
    tls_issues = sum(1 for f in findings if "tls" in (f.title or "").lower() or "ssl" in (f.title or "").lower())
    if tls_issues:
        recs.append({
            "priority": "medium",
            "title": f"Fix {tls_issues} TLS/SSL configuration issue{'s' if tls_issues > 1 else ''}",
            "detail": "Weak TLS configurations can enable man-in-the-middle attacks.",
            "effort": "low",
        })

    recs.append({
        "priority": "low",
        "title": "Enable continuous monitoring for all domains",
        "detail": "Automated daily scans catch new exposures before attackers do.",
        "effort": "low",
    })

    return recs[:7]


# ── Markdown report ────────────────────────────────────────────────────────

def generate_markdown(db: Session, org_id: int, domain: Optional[str] = None) -> str:
    d = _gather_report_data(db, org_id, domain)
    score = d["score"]
    score_val = score.get("score", 0)
    score_lbl = score.get("label", "unknown").upper()

    sev_order = ["critical", "high", "medium", "low", "info"]

    lines = [
        f"# Attack Surface Report",
        f"**Organization:** {d['org_name']}  ",
        f"**Target:** {d['domain']}  ",
        f"**Generated:** {d['generated_at']}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Attack Surface Score | **{score_val}/100** ({score_lbl}) |",
        f"| Total Assets | {d['assets']['total']} |",
        f"| Public Exposed | {d['assets']['public_count']} |",
        f"| Open Findings | {d['findings']['total']} |",
        f"| Critical Vulns | {d['findings']['by_severity'].get('critical', 0)} |",
        f"| High Vulns | {d['findings']['by_severity'].get('high', 0)} |",
        f"| Public Cloud Buckets | {score.get('public_buckets', 0)} |",
        f"| Alerts (7 days) | {d['alerts_7d']} |",
        "",
    ]

    if score.get("trend"):
        trend_emoji = {"improving": "📉", "degrading": "📈", "stable": "➡️"}.get(score.get("trend"), "")
        lines += [
            f"> **Trend:** {trend_emoji} {score.get('trend', 'N/A').title()} "
            f"(Δ {score.get('delta', 0):+.1f} from last scan)",
            "",
        ]

    lines += [
        "## Asset Inventory",
        "",
        "**By Type:**",
    ]
    for atype, cnt in sorted(d["assets"]["by_type"].items(), key=lambda x: -x[1]):
        lines.append(f"- `{atype}`: {cnt}")

    lines += ["", "**By Exposure:**"]
    for exp, cnt in sorted(d["assets"]["by_exposure"].items(), key=lambda x: -x[1]):
        lines.append(f"- `{exp}`: {cnt}")

    lines += [
        "",
        "## Vulnerability Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in sev_order:
        cnt = d["findings"]["by_severity"].get(sev, 0)
        if cnt:
            lines.append(f"| {sev.capitalize()} | {cnt} |")

    if d["findings"]["top"]:
        lines += ["", "## Top Critical & High Findings", ""]
        for i, f in enumerate(d["findings"]["top"], 1):
            cve_str = f" — {f['cve']}" if f["cve"] else ""
            lines += [
                f"### {i}. [{f['severity'].upper()}] {f['title']}{cve_str}",
                f"**Target:** `{f['target'] or 'N/A'}`  ",
                f"**CVSS:** {f['cvss'] or 'N/A'}  **Risk Score:** {f['risk_score'] or 'N/A'}",
                "",
                f"{f['description']}",
                "",
            ]

    if d["changes_30d"]:
        lines += ["## Attack Surface Changes (Last 30 Days)", ""]
        for c in d["changes_30d"][:10]:
            lines.append(f"- `{c['at']}` **{c['type'].replace('_', ' ').title()}**: {c['detail'] or ''}")
        lines.append("")

    if d["teams"]:
        lines += ["## Team Ownership", "", "| Team | Assets | Open Findings | Critical |",
                  "|------|--------|--------------|---------|"]
        for t in d["teams"]:
            lines.append(
                f"| {t['team_name']} | {t['asset_count']} | {t['open_findings']} | {t.get('critical', 0)} |"
            )
        lines.append("")

    lines += ["## Recommendations", ""]
    priority_emoji = {"immediate": "🚨", "high": "⚠️", "medium": "🔔", "low": "ℹ️"}
    for rec in d["recommendations"]:
        emoji = priority_emoji.get(rec["priority"], "•")
        lines += [
            f"### {emoji} {rec['title']}",
            f"**Priority:** {rec['priority'].title()}  **Effort:** {rec['effort'].title()}",
            "",
            rec["detail"],
            "",
        ]

    lines += ["---", f"*Generated by Teto ASM Platform — {d['generated_at']}*"]
    return "\n".join(lines)


# ── HTML report ────────────────────────────────────────────────────────────

def generate_html(db: Session, org_id: int, domain: Optional[str] = None) -> str:
    d = _gather_report_data(db, org_id, domain)
    score = d["score"]
    score_val = score.get("score", 0)
    score_lbl = score.get("label", "unknown")
    score_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
    sc = score_colors.get(score_lbl, "#94a3b8")

    sev_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
                  "low": "#22c55e", "info": "#64748b"}
    sev_order = ["critical", "high", "medium", "low", "info"]

    def sev_badge(sev):
        col = sev_colors.get(sev, "#94a3b8")
        return f'<span style="background:{col}22;color:{col};padding:2px 8px;border-radius:4px;font-size:0.78rem;font-weight:600;text-transform:uppercase">{sev}</span>'

    trend_arrow = {"improving": "↓", "degrading": "↑", "stable": "→"}.get(score.get("trend", "stable"), "→")
    trend_color = {"improving": "#22c55e", "degrading": "#ef4444", "stable": "#94a3b8"}.get(score.get("trend", "stable"), "#94a3b8")

    findings_rows = "".join(
        f"""<tr>
          <td>{sev_badge(f['severity'])}</td>
          <td style="font-weight:500">{f['title']}</td>
          <td style="font-family:monospace;font-size:0.82rem">{f['target'] or '—'}</td>
          <td>{f['cve'] or '—'}</td>
          <td>{f['cvss'] or '—'}</td>
        </tr>"""
        for f in d["findings"]["top"]
    )

    team_rows = "".join(
        f"""<tr>
          <td style="font-weight:500">{t['team_name']}</td>
          <td>{t['asset_count']}</td>
          <td>{t['open_findings']}</td>
          <td style="color:#ef4444;font-weight:600">{t.get('critical',0)}</td>
          <td style="color:#f97316">{t.get('high',0)}</td>
        </tr>"""
        for t in d["teams"]
    )

    changes_rows = "".join(
        f'<tr><td style="color:#94a3b8;font-family:monospace">{c["at"]}</td>'
        f'<td style="color:#38bdf8">{c["type"].replace("_"," ").title()}</td>'
        f'<td>{c["detail"] or ""}</td></tr>'
        for c in d["changes_30d"][:10]
    )

    recs_html = ""
    p_emoji = {"immediate": "🚨", "high": "⚠️", "medium": "🔔", "low": "ℹ️"}
    p_colors = {"immediate": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
    for rec in d["recommendations"]:
        pc = p_colors.get(rec["priority"], "#94a3b8")
        recs_html += f"""
        <div style="padding:14px 18px;border-left:4px solid {pc};background:{pc}11;border-radius:4px;margin-bottom:12px">
          <div style="font-weight:600;margin-bottom:4px">{p_emoji.get(rec['priority'],'•')} {rec['title']}</div>
          <div style="font-size:0.82rem;color:#94a3b8">{rec['detail']}</div>
          <div style="margin-top:6px;font-size:0.75rem">Priority: <b>{rec['priority'].title()}</b> · Effort: <b>{rec['effort'].title()}</b></div>
        </div>"""

    sev_bars = ""
    total_f = d["findings"]["total"] or 1
    for sev in sev_order:
        cnt = d["findings"]["by_severity"].get(sev, 0)
        if not cnt:
            continue
        pct = round(cnt / total_f * 100)
        col = sev_colors.get(sev, "#94a3b8")
        sev_bars += f"""
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <span style="width:64px;font-size:0.78rem;color:{col};text-transform:capitalize">{sev}</span>
          <div style="flex:1;height:10px;border-radius:999px;background:rgba(148,163,184,0.15);overflow:hidden">
            <div style="height:100%;border-radius:999px;width:{pct}%;background:{col}"></div>
          </div>
          <span style="width:24px;text-align:right;font-size:0.82rem;color:{col};font-weight:600">{cnt}</span>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Surface Report — {d['domain']}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6;padding:40px}}
  .page{{max-width:960px;margin:auto}}
  .header{{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid rgba(148,163,184,0.2);border-radius:16px;padding:32px;margin-bottom:24px}}
  h1{{font-size:2rem;margin-bottom:4px}}
  h2{{font-size:1.2rem;margin:0 0 16px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em}}
  .meta{{color:#64748b;font-size:0.88rem}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}}
  .card{{background:rgba(30,41,59,0.8);border:1px solid rgba(148,163,184,0.15);border-radius:12px;padding:16px 18px}}
  .card-label{{font-size:0.78rem;color:#94a3b8;margin-bottom:6px}}
  .card-value{{font-size:1.8rem;font-weight:700}}
  .section{{background:rgba(15,23,42,0.8);border:1px solid rgba(148,163,184,0.15);border-radius:12px;padding:20px 24px;margin-bottom:20px}}
  table{{width:100%;border-collapse:collapse;font-size:0.88rem}}
  th{{text-align:left;padding:8px 12px;border-bottom:1px solid rgba(148,163,184,0.2);color:#94a3b8;font-weight:500;text-transform:uppercase;font-size:0.72rem}}
  td{{padding:9px 12px;border-bottom:1px solid rgba(148,163,184,0.08)}}
  .score-ring{{display:flex;align-items:center;gap:24px;margin-bottom:16px}}
  .ring{{width:100px;height:100px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.8rem;font-weight:700;border:6px solid {sc};box-shadow:0 0 24px {sc}44}}
  .footer{{text-align:center;color:#475569;font-size:0.78rem;margin-top:32px;padding-top:16px;border-top:1px solid rgba(148,163,184,0.1)}}
</style>
</head>
<body>
<div class="page">

<div class="header">
  <h1>🛡️ Attack Surface Report</h1>
  <div class="meta"><strong>{d['org_name']}</strong> · Target: {d['domain']} · {d['generated_at']}</div>
</div>

<div class="grid">
  <div class="card"><div class="card-label">Attack Surface Score</div><div class="card-value" style="color:{sc}">{score_val}/100</div><div style="font-size:0.78rem;color:{sc};text-transform:uppercase">{score_lbl}</div></div>
  <div class="card"><div class="card-label">Total Assets</div><div class="card-value" style="color:#38bdf8">{d['assets']['total']}</div></div>
  <div class="card"><div class="card-label">Public Exposed</div><div class="card-value" style="color:#f97316">{d['assets']['public_count']}</div></div>
  <div class="card"><div class="card-label">Open Findings</div><div class="card-value" style="color:#f87171">{d['findings']['total']}</div></div>
  <div class="card"><div class="card-label">Critical Vulns</div><div class="card-value" style="color:#ef4444">{d['findings']['by_severity'].get('critical',0)}</div></div>
  <div class="card"><div class="card-label">Trend</div><div class="card-value" style="color:{trend_color}">{trend_arrow}</div><div style="font-size:0.78rem;color:{trend_color}">{score.get('trend','N/A').title()} ({score.get('delta',0):+.1f})</div></div>
</div>

<div class="section">
  <h2>Vulnerability Distribution</h2>
  {sev_bars}
</div>

{f'''<div class="section">
  <h2>Top Critical & High Findings</h2>
  <table><thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>CVE</th><th>CVSS</th></tr></thead>
  <tbody>{findings_rows}</tbody></table>
</div>''' if d['findings']['top'] else ''}

{f'''<div class="section">
  <h2>Attack Surface Changes (Last 30 Days)</h2>
  <table><thead><tr><th>Date</th><th>Event</th><th>Detail</th></tr></thead>
  <tbody>{changes_rows}</tbody></table>
</div>''' if d['changes_30d'] else ''}

{f'''<div class="section">
  <h2>Team Ownership</h2>
  <table><thead><tr><th>Team</th><th>Assets</th><th>Open Findings</th><th>Critical</th><th>High</th></tr></thead>
  <tbody>{team_rows}</tbody></table>
</div>''' if d['teams'] else ''}

<div class="section">
  <h2>Recommendations</h2>
  {recs_html}
</div>

<div class="footer">Generated by Teto ASM Platform · {d['generated_at']}</div>
</div>
</body>
</html>"""


# ── PDF report ─────────────────────────────────────────────────────────────

def generate_pdf(db: Session, org_id: int, domain: Optional[str] = None) -> bytes:
    """Generate PDF using reportlab. Falls back to HTML-as-bytes if unavailable."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        d = _gather_report_data(db, org_id, domain)
        score = d["score"]
        score_val = score.get("score", 0)
        score_lbl = score.get("label", "unknown").upper()

        buf = BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=20*mm, bottomMargin=20*mm,
        )

        styles = getSampleStyleSheet()
        H1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=20, spaceAfter=6,
                             textColor=colors.HexColor("#e2e8f0"))
        H2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, spaceAfter=4,
                             textColor=colors.HexColor("#94a3b8"), spaceBefore=12)
        BODY = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9,
                               textColor=colors.HexColor("#cbd5e1"), spaceAfter=3)
        MONO = ParagraphStyle("Mono", parent=BODY, fontName="Courier", fontSize=8)

        sev_pdf_colors = {
            "critical": colors.HexColor("#ef4444"),
            "high": colors.HexColor("#f97316"),
            "medium": colors.HexColor("#eab308"),
            "low": colors.HexColor("#22c55e"),
            "info": colors.HexColor("#64748b"),
        }

        story = []

        # Header
        story.append(Paragraph("🛡 Attack Surface Report", H1))
        story.append(Paragraph(f"<b>{d['org_name']}</b> · Target: {d['domain']} · {d['generated_at']}", BODY))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e293b"), spaceAfter=10))

        # Score summary table
        story.append(Paragraph("Executive Summary", H2))
        score_color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
        sc_hex = score_color.get(score.get("label", ""), "#94a3b8")
        summary_data = [
            ["Metric", "Value"],
            ["Attack Surface Score", f"{score_val}/100  ({score_lbl})"],
            ["Total Assets", str(d["assets"]["total"])],
            ["Public Exposed", str(d["assets"]["public_count"])],
            ["Open Findings", str(d["findings"]["total"])],
            ["Critical Vulns", str(d["findings"]["by_severity"].get("critical", 0))],
            ["Trend", f"{score.get('trend','N/A').title()} ({score.get('delta',0):+.1f})"],
        ]
        tbl = Table(summary_data, colWidths=[80*mm, 80*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#94a3b8")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0f172a"), colors.HexColor("#1e293b")]),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 10))

        # Top findings
        if d["findings"]["top"]:
            story.append(Paragraph("Top Critical & High Findings", H2))
            f_data = [["Severity", "Title", "CVE", "CVSS"]]
            for f in d["findings"]["top"]:
                f_data.append([
                    f["severity"].upper(),
                    (f["title"] or "")[:60],
                    f["cve"] or "—",
                    str(f["cvss"] or "—"),
                ])
            f_tbl = Table(f_data, colWidths=[22*mm, 100*mm, 28*mm, 20*mm])
            row_styles = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#94a3b8")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0f172a"), colors.HexColor("#1e293b")]),
            ]
            for i, finding in enumerate(d["findings"]["top"], 1):
                sev = finding["severity"]
                col = sev_pdf_colors.get(sev, colors.HexColor("#94a3b8"))
                row_styles.append(("TEXTCOLOR", (0, i), (0, i), col))
            f_tbl.setStyle(TableStyle(row_styles))
            story.append(f_tbl)
            story.append(Spacer(1, 10))

        # Recommendations
        if d["recommendations"]:
            story.append(Paragraph("Recommendations", H2))
            p_icons = {"immediate": "🚨", "high": "⚠️", "medium": "🔔", "low": "ℹ️"}
            for rec in d["recommendations"]:
                icon = p_icons.get(rec["priority"], "•")
                story.append(Paragraph(f"<b>{icon} {rec['title']}</b>  "
                                        f"[{rec['priority'].title()} priority, {rec['effort'].title()} effort]", BODY))
                story.append(Paragraph(rec["detail"], MONO))
                story.append(Spacer(1, 4))

        # Footer
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e293b"), spaceBefore=10))
        story.append(Paragraph(f"Teto ASM Platform · {d['generated_at']}", BODY))

        doc.build(story)
        buf.seek(0)
        return buf.read()

    except ImportError:
        # Fallback: return HTML as bytes
        html = generate_html(db, org_id, domain)
        return html.encode("utf-8")
