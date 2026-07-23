"""
Self-contained HTML report — executive summary + findings table, no
external assets, suitable for emailing/archiving.
TODO(report-roadmap): PDF export (weasyprint/reportlab), CSV export,
severity charts, compliance-overview section.
"""
from __future__ import annotations

import html

from guardian.core.registry import register_reporter

_SEV_COLOR = {"Critical": "#b71c1c", "High": "#e65100",
              "Medium": "#f9a825", "Low": "#2e7d32", "Info": "#546e7a"}


@register_reporter
class HtmlReporter:
    name = "html"
    file_extension = ".html"

    def render(self, report: dict) -> str:
        repo = report.get("repository", {})
        risk = report.get("risk", {})
        scan = report.get("scan", {})
        domain = report.get("business_domain") or {}
        e = html.escape

        rows = []
        for f in scan.get("findings", []):
            sev = f.get("severity", "Medium")
            rows.append(
                f"<tr><td><span style='color:{_SEV_COLOR.get(sev, '#333')};font-weight:600'>{e(sev)}</span></td>"
                f"<td>{e(str(f.get('category', '')))}</td><td>{e(str(f.get('rule_id') or ''))}</td>"
                f"<td>{e(str(f.get('file', '')))}:{f.get('line', '')}</td>"
                f"<td><code>{e(str(f.get('snippet', ''))[:120])}</code></td>"
                f"<td>{e(str(f.get('recommendation', ''))[:160])}</td></tr>")

        scores = "".join(
            f"<div class='score'><div class='num'>{risk.get(k, '—')}</div><div class='lbl'>{lbl}</div></div>"
            for k, lbl in [("security_score", "Security"), ("alignment_score", "Alignment"),
                           ("maintainability_score", "Maintainability"), ("overall_risk_score", "Overall")])

        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI Code Guardian Report</title><style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#212121;background:#fafafa}}
h1{{margin-bottom:.2rem}} .sub{{color:#616161;margin-bottom:1.5rem}}
.scores{{display:flex;gap:1rem;margin:1rem 0}}
.score{{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem 1.5rem;text-align:center}}
.num{{font-size:1.6rem;font-weight:700}} .lbl{{color:#757575;font-size:.8rem}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:.85rem}}
th,td{{border:1px solid #e0e0e0;padding:.45rem .6rem;text-align:left;vertical-align:top}}
th{{background:#eceff1}} code{{font-size:.78rem}}
</style></head><body>
<h1>AI Code Guardian — Scan Report</h1>
<div class="sub">{e(str(repo.get('root', '')))} · {e(str(repo.get('primary_language', '')))}
 · {e(', '.join(repo.get('frameworks', []) or []))}
 · domain: {e(str(domain.get('domain', 'n/a')))} ({domain.get('confidence', 0):.0%} conf.)
 · merge decision: <b>{e(str(risk.get('merge_decision', 'n/a')))}</b></div>
<div class="scores">{scores}</div>
<p>{scan.get('total_findings', 0)} findings across {scan.get('files_scanned', 0)} scanned source files
 in {report.get('duration_seconds', '?')}s.</p>
<table><tr><th>Severity</th><th>Category</th><th>Rule</th><th>Location</th><th>Snippet</th><th>Recommendation</th></tr>
{''.join(rows)}</table>
</body></html>"""
