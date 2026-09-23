"""
Report Export — OpenSecX Phase 3

Generates JSON and HTML exports of full scan reports combining:
  - Scan metadata
  - All discovered assets
  - All findings with evidence
  - Attack paths
  - Summary statistics
"""
from __future__ import annotations

import datetime
import json
import logging
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import ScanJob

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def build_report_data(scan_id: int, db: AsyncSession) -> dict:
    """Build complete report dict from DB — used for both JSON and HTML export."""
    # Load scan
    scan_res = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan: Optional[ScanJob] = scan_res.scalar_one_or_none()
    if not scan:
        return {}

    target = scan.target

    # Load assets
    assets_res = await db.execute(
        select(Asset).where(
            Asset.domain.like(f"%.{target}") | (Asset.domain == target)
        )
    )
    assets: List[Asset] = assets_res.scalars().all()

    # Load findings
    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings: List[Finding] = findings_res.scalars().all()
    findings_sorted = sorted(findings, key=lambda f: (not f.in_kev, SEVERITY_ORDER.get(f.severity or "info", 5)))

    # Build attack paths
    try:
        from app.services.attack_path import build_attack_paths
        attack_paths = await build_attack_paths(scan_id, target, db)
    except Exception as e:
        logger.warning("Attack paths failed: %s", e)
        attack_paths = []

    # Stats
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    kev_count = 0
    for f in findings:
        sev = f.severity or "info"
        if sev in sev_counts:
            sev_counts[sev] += 1
        if f.in_kev:
            kev_count += 1

    return {
        "meta": {
            "scan_id": scan_id,
            "target": target,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "tools": scan.tools or [],
        },
        "summary": {
            "assets_found": len(assets),
            "findings_total": len(findings),
            "findings_by_severity": sev_counts,
            "findings_in_kev": kev_count,
            "attack_paths": len(attack_paths),
        },
        "assets": [
            {
                "id": a.id,
                "domain": a.domain,
                "ip_address": a.ip_address,
                "ports": a.ports or [],
                "protocol": a.protocol,
                "service": a.service,
                "technologies": a.technologies or [],
                "dns_records": a.dns_records or {},
                "certificate": a.certificate or {},
                "org": a.org,
                "asn": a.asn,
                "country": a.country,
                "source": a.source,
                "status": a.status,
                "notes": a.notes,
            }
            for a in assets
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence or {},
                "grade": f.grade,
                "cve_id": f.cve_id,
                "cvss": f.cvss,
                "epss": f.epss,
                "in_kev": f.in_kev,
                "priority": f.priority,
                "triage_status": f.triage_status,
                "triage_note": f.triage_note,
            }
            for f in findings_sorted
        ],
        "attack_paths": attack_paths,
    }


def render_html_report(data: dict) -> str:
    """Render report data as a self-contained HTML file."""
    meta = data.get("meta", {})
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    assets = data.get("assets", [])

    sev_colors = {
        "critical": "#F28B82", "high": "#FFAB40",
        "medium": "#FDD663", "low": "#81C995", "info": "#A8C7FA",
    }

    def sev_badge(sev: str) -> str:
        c = sev_colors.get(sev, "#aaa")
        return f'<span style="background:{c}22;color:{c};border:1px solid {c}44;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{sev.upper()}</span>'

    findings_html = ""
    for f in findings:
        sev = f.get("severity", "info")
        kev = ' <span style="color:#F28B82;font-size:10px">⚠ KEV</span>' if f.get("in_kev") else ""
        cve = f'<a href="https://nvd.nist.gov/vuln/detail/{f["cve_id"]}" target="_blank" style="color:#A8C7FA">{f["cve_id"]}</a>' if f.get("cve_id") else ""
        cvss = f' · CVSS {f["cvss"]:.1f}' if f.get("cvss") else ""
        epss = f' · EPSS {f["epss"]*100:.1f}%' if f.get("epss") else ""
        findings_html += f"""
        <div style="border-left:3px solid {sev_colors.get(sev,'#aaa')};padding:12px 16px;margin-bottom:8px;background:#1e2430;border-radius:0 8px 8px 0">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            {sev_badge(sev)}{kev}
            <span style="color:#e2e8f0;font-weight:500;font-size:13px">{f.get("title","")}</span>
          </div>
          <div style="color:#94a3b8;font-size:12px;margin-bottom:4px">{f.get("category","")}{" · "+cve if cve else ""}{cvss}{epss}</div>
          <div style="color:#cbd5e1;font-size:12px;line-height:1.5">{f.get("description","")[:300]}</div>
          {"<div style='color:#81C995;font-size:11px;margin-top:6px;padding:6px;background:#0d1117;border-radius:4px'>🔧 " + f.get("remediation","")[:200] + "</div>" if f.get("remediation") else ""}
        </div>"""

    assets_rows = ""
    for a in assets[:50]:
        techs = ", ".join((a.get("technologies") or [])[:3])
        assets_rows += f"""
        <tr>
          <td style="padding:8px;color:#e2e8f0">{a.get("domain","")}</td>
          <td style="padding:8px;color:#94a3b8;font-family:monospace">{a.get("ip_address","—")}</td>
          <td style="padding:8px;color:#94a3b8">{", ".join(str(p) for p in (a.get("ports") or [])[:5]) or "—"}</td>
          <td style="padding:8px;color:#A8C7FA;font-size:11px">{techs or "—"}</td>
          <td style="padding:8px;color:#94a3b8;font-size:11px">{a.get("org","—")}</td>
        </tr>"""

    total = summary.get("findings_total", 0)
    by_sev = summary.get("findings_by_severity", {})

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenSecX Report · {meta.get("target","")} · {meta.get("generated_at","")[:10]}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e2e8f0;line-height:1.6}}
  .container{{max-width:1100px;margin:0 auto;padding:40px 24px}}
  h1{{font-size:28px;font-weight:300;letter-spacing:-0.5px;color:#fff}}
  h2{{font-size:16px;font-weight:500;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #1e2430}}
  .meta{{color:#64748b;font-size:13px;margin-top:6px}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:20px 0}}
  .stat{{background:#1e2430;border-radius:10px;padding:16px;text-align:center}}
  .stat .num{{font-size:28px;font-weight:300;font-family:monospace}}
  .stat .lbl{{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  thead tr{{background:#161b22}}
  th{{padding:10px 8px;text-align:left;color:#64748b;font-weight:500;font-size:10px;text-transform:uppercase;letter-spacing:1px}}
  tbody tr:nth-child(even){{background:#161b22}}
  .footer{{margin-top:40px;text-align:center;color:#334155;font-size:11px}}
</style>
</head>
<body>
<div class="container">
  <h1>OpenSecX Security Report</h1>
  <p class="meta">Target: <strong style="color:#A8C7FA">{meta.get("target","")}</strong> &nbsp;·&nbsp; Generated: {meta.get("generated_at","")[:19].replace("T"," ")} UTC &nbsp;·&nbsp; Scan #{meta.get("scan_id","")}</p>

  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat"><div class="num" style="color:#e2e8f0">{summary.get("assets_found",0)}</div><div class="lbl">Assets Found</div></div>
    <div class="stat"><div class="num" style="color:#e2e8f0">{total}</div><div class="lbl">Findings</div></div>
    <div class="stat"><div class="num" style="color:#F28B82">{by_sev.get("critical",0)}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num" style="color:#FFAB40">{by_sev.get("high",0)}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" style="color:#FDD663">{by_sev.get("medium",0)}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:#F28B82">{summary.get("findings_in_kev",0)}</div><div class="lbl">In CISA KEV</div></div>
  </div>

  <h2>Discovered Assets ({len(assets)})</h2>
  <table>
    <thead><tr><th>Domain</th><th>IP Address</th><th>Open Ports</th><th>Technologies</th><th>Organization</th></tr></thead>
    <tbody>{assets_rows}</tbody>
  </table>

  <h2>Findings ({total})</h2>
  {findings_html if findings_html else '<p style="color:#64748b">No findings recorded for this scan.</p>'}

  <div class="footer">
    Generated by OpenSecX · {meta.get("generated_at","")[:10]} · For authorized use only
  </div>
</div>
</body>
</html>"""
