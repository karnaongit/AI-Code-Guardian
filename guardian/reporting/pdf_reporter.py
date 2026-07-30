"""
PDF / Printable Executive Summary Reporter — Clean, formatted report for CISO & security teams.
"""
from __future__ import annotations

from guardian.core.registry import register_reporter


@register_reporter
class PDFReporter:
    name = "pdf"
    file_extension = ".pdf.html"  # Printable HTML export suitable for PDF conversion

    def render(self, report_dict: dict) -> str:
        scan = report_dict.get("scan", {})
        # Prefer the unified risk assessment; fall back to the legacy report
        # so this reporter still works on an older report dict.
        risk = report_dict.get("unified_risk") or report_dict.get("risk", {})
        repo = report_dict.get("repository", {})
        domain = report_dict.get("business_domain") or {}

        findings = scan.get("findings", [])
        by_sev = scan.get("by_severity", {})

        rows = ""
        for f in findings:
            sev = f.get("severity", "Info")
            color = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#d97706", "Low": "#2563eb", "Info": "#4b5563"}.get(sev, "#4b5563")
            source = f.get("source", "DETERMINISTIC")
            source_style = ("background:#e8f5e9;color:#1b5e20" if source == "DETERMINISTIC"
                            else "background:#e3f2fd;color:#0d47a1")
            source_label = {"DETERMINISTIC": "Static", "AI_VALIDATED": "AI-validated",
                            "AI_SUGGESTED": "AI suggestion"}.get(source, source)
            location = f"{f.get('file')}:{f.get('line')}"
            if f.get("function"):
                location += f"<br><small style='color:#6b7280'>in {f.get('function')}()</small>"
            rows += f"""
            <tr style="border-bottom: 1px solid #e5e7eb;">
                <td style="padding: 8px;"><span style="background: {color}; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{sev}</span></td>
                <td style="padding: 8px;"><span style="{source_style}; padding: 2px 7px; border-radius: 10px; font-size: 10px; font-weight: 600;">{source_label}</span></td>
                <td style="padding: 8px;"><strong>{f.get('category')}</strong><br><small style="color: #6b7280;">{f.get('rule_id')}</small></td>
                <td style="padding: 8px;"><code>{location}</code></td>
                <td style="padding: 8px; font-family: monospace; font-size: 12px; background: #f9fafb;">{str(f.get('snippet', ''))[:100]}</td>
                <td style="padding: 8px; font-size: 12px;">{f.get('recommendation')}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AI Code Guardian — Executive Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #1f2937; }}
        .header {{ border-bottom: 2px solid #2563eb; padding-bottom: 15px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }}
        .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }}
        .metric {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px; text-align: center; }}
        .metric .value {{ font-size: 24px; font-weight: bold; color: #0f172a; }}
        .metric .label {{ font-size: 12px; color: #64748b; text-transform: uppercase; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th {{ background: #f1f5f9; text-align: left; padding: 10px; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #475569; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; color: #0f172a;">AI Code Guardian Security Report</h1>
            <p style="margin: 5px 0 0 0; color: #64748b;">Executive Vulnerability & Compliance Assessment</p>
        </div>
        <div style="text-align: right;">
            <span style="font-size: 18px; font-weight: bold; padding: 6px 12px; border-radius: 6px; background: {'#dcfce7' if risk.get('merge_decision') == 'ALLOW' else '#fee2e2'}; color: {'#166534' if risk.get('merge_decision') == 'ALLOW' else '#991b1b'};">
                {risk.get('merge_decision', 'REVIEW')}
            </span>
        </div>
    </div>

    <div class="grid">
        <div class="metric"><div class="value">{risk.get('security_score', 0):.1f}/100</div><div class="label">Security Score</div></div>
        <div class="metric"><div class="value">{risk.get('alignment_score', 0):.1f}/100</div><div class="label">Business Alignment</div></div>
        <div class="metric"><div class="value">{risk.get('quantum_readiness_score', 100):.1f}/100</div><div class="label">Quantum Readiness</div></div>
        <div class="metric"><div class="value">{risk.get('overall_risk_score', 0):.1f}/100</div><div class="label">Overall</div></div>
    </div>

    <div class="card">
        <h3 style="margin-top: 0;">Repository Profile</h3>
        <p style="margin: 0;">Primary Language: <strong>{repo.get('primary_language', 'Unknown')}</strong>
         | Files Scanned: <strong>{scan.get('files_scanned', 0)}</strong>
         | Total Findings: <strong>{scan.get('total_findings', 0)}</strong>
         | Business Domain: <strong>{domain.get('domain', 'Unclassified')}</strong></p>
        <p style="margin: 6px 0 0 0; font-size: 12px; color: #64748b;">Severity breakdown: {by_sev or 'none'}</p>
    </div>

    {self._business_section(report_dict)}
    {self._quantum_section(report_dict)}

    <h3>Detailed Vulnerability Findings</h3>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Source</th>
                <th>Category</th>
                <th>Location</th>
                <th>Code Snippet</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>
"""
        return html

    # ------------------------------------------------------------------
    @staticmethod
    def _business_section(report_dict: dict) -> str:
        """Business-intent verdicts, when requirements were supplied."""
        bi = report_dict.get("business_intent")
        if not bi or bi.get("status") != "analyzed":
            return ""
        colour = {"COMPLIANT": "#16a34a", "VIOLATION": "#dc2626",
                  "POTENTIAL_VIOLATION": "#ea580c",
                  "INSUFFICIENT_EVIDENCE": "#6b7280"}
        rows = "".join(
            f"<tr style='border-bottom:1px solid #e5e7eb'>"
            f"<td style='padding:8px;color:{colour.get(v.get('verdict'), '#374151')};"
            f"font-weight:600'>{v.get('verdict', '').replace('_', ' ').title()}</td>"
            f"<td style='padding:8px'>{v.get('policy', '')}</td>"
            f"<td style='padding:8px;font-size:12px;color:#6b7280'>"
            f"{', '.join(v.get('missing_control_in', []) or []) or '—'}</td></tr>"
            for v in bi.get("verdicts", []))
        return f"""
    <div class="card">
        <h3 style="margin-top: 0;">Business Intent — Requirements vs. Implementation</h3>
        <p style="margin:0 0 8px 0; font-size: 13px; color:#64748b;">
            Alignment {bi.get('alignment_score', 0):.0f}/100 across
            {bi.get('policies', {}).get('checkable', 0)} testable policies.</p>
        <table><thead><tr><th>Verdict</th><th>Policy</th><th>Control missing in</th></tr></thead>
        <tbody>{rows}</tbody></table>
    </div>"""

    @staticmethod
    def _quantum_section(report_dict: dict) -> str:
        """Cryptographic inventory and PQC migration posture."""
        cbom = report_dict.get("quantum")
        if not cbom or not cbom.get("entries"):
            return ""
        labels = {"quantum_vulnerable": "Quantum vulnerable",
                  "classically_broken": "Classically broken",
                  "quantum_weakened": "Grover-weakened",
                  "post_quantum": "Post-quantum", "quantum_safe": "Adequate today",
                  "unknown": "Unresolved"}
        rows = "".join(
            f"<tr style='border-bottom:1px solid #e5e7eb'>"
            f"<td style='padding:8px'><strong>{e.get('algorithm')}</strong></td>"
            f"<td style='padding:8px'>{labels.get(e.get('status'), e.get('status'))}</td>"
            f"<td style='padding:8px'>{e.get('occurrences', 0)}</td>"
            f"<td style='padding:8px;font-size:12px'>{e.get('migration_target') or '—'}"
            f"<br><small style='color:#6b7280'>{e.get('nist_standard') or ''}</small></td></tr>"
            for e in cbom.get("entries", []))
        return f"""
    <div class="card">
        <h3 style="margin-top: 0;">Quantum Readiness — Cryptographic Bill of Materials</h3>
        <p style="margin:0 0 8px 0; font-size: 13px; color:#64748b;">
            Readiness {cbom.get('readiness_score', 0):.0f}/100 ·
            {cbom.get('total_occurrences', 0)} operations ·
            {cbom.get('unresolved_call_sites', 0)} unresolved call site(s).</p>
        <table><thead><tr><th>Algorithm</th><th>Status</th><th>Uses</th>
        <th>Migration target</th></tr></thead><tbody>{rows}</tbody></table>
    </div>"""
