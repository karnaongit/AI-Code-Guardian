"""
Self-contained HTML report — no external assets, suitable for emailing
or archiving.

Unified across every engine: security findings, business intent, quantum
readiness, dependencies, IaC, risk dimensions and the evidence behind
each finding. Provenance is shown on every row, because a reader must be
able to tell a proven detection from a contextual AI claim at a glance.
"""
from __future__ import annotations

import html

from guardian.core.registry import register_reporter

_SEV_COLOR = {"Critical": "#b71c1c", "High": "#e65100",
              "Medium": "#f9a825", "Low": "#2e7d32", "Info": "#546e7a"}

_SOURCE_BADGE = {
    "DETERMINISTIC": ("#1b5e20", "#e8f5e9", "Static"),
    "AI_VALIDATED": ("#0d47a1", "#e3f2fd", "AI-validated"),
    "AI_SUGGESTED": ("#4a148c", "#f3e5f5", "AI suggestion"),
    "INSUFFICIENT_EVIDENCE": ("#616161", "#eeeeee", "Unproven"),
}

_STATUS_LABEL = {
    "quantum_vulnerable": "Quantum vulnerable",
    "classically_broken": "Classically broken",
    "quantum_weakened": "Grover-weakened",
    "post_quantum": "Post-quantum",
    "quantum_safe": "Adequate today",
    "unknown": "Unresolved",
}


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _badge(source: str) -> str:
    fg, bg, label = _SOURCE_BADGE.get(source, _SOURCE_BADGE["DETERMINISTIC"])
    return f"<span class='badge' style='color:{fg};background:{bg}'>{_e(label)}</span>"


@register_reporter
class HtmlReporter:
    name = "html"
    file_extension = ".html"

    def render(self, report: dict) -> str:
        repo = report.get("repository", {})
        scan = report.get("scan", {})
        risk = report.get("unified_risk") or report.get("risk", {})
        domain = report.get("business_domain") or {}
        ai = report.get("ai", {})

        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI Code Guardian Report</title><style>
body{{font-family:system-ui,-apple-system,sans-serif;margin:2rem;color:#212121;background:#fafafa}}
h1{{margin-bottom:.2rem}} h2{{margin-top:2.2rem;border-bottom:2px solid #e0e0e0;padding-bottom:.3rem}}
.sub{{color:#616161;margin-bottom:1.5rem;line-height:1.6}}
.scores{{display:flex;gap:1rem;margin:1rem 0;flex-wrap:wrap}}
.score{{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem 1.4rem;text-align:center;min-width:110px}}
.num{{font-size:1.6rem;font-weight:700}} .lbl{{color:#757575;font-size:.75rem;text-transform:uppercase}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:.85rem;margin-top:.6rem}}
th,td{{border:1px solid #e0e0e0;padding:.45rem .6rem;text-align:left;vertical-align:top}}
th{{background:#eceff1}} code{{font-size:.78rem;background:#f5f5f5;padding:1px 4px;border-radius:3px}}
.badge{{font-size:.7rem;padding:2px 7px;border-radius:10px;font-weight:600;white-space:nowrap}}
.reason{{color:#546e7a;font-size:.78rem;margin-top:.25rem}}
.ev{{color:#78909c;font-size:.72rem;font-family:monospace}}
.note{{background:#fff8e1;border-left:4px solid #ffb300;padding:.7rem 1rem;margin:1rem 0;font-size:.85rem}}
.ok{{background:#e8f5e9;border-left:4px solid #43a047;padding:.7rem 1rem;margin:1rem 0;font-size:.85rem}}
.empty{{color:#9e9e9e;font-style:italic;padding:.6rem 0}}
</style></head><body>
<h1>AI Code Guardian — Scan Report</h1>
<div class="sub">
 {_e(repo.get('root'))} · {_e(repo.get('primary_language'))}
 · {_e(', '.join(repo.get('frameworks', []) or []) or 'no framework detected')}
 · domain: {_e(domain.get('domain', 'n/a'))} ({domain.get('confidence', 0):.0%} confidence)<br>
 Merge decision: <b>{_e(risk.get('merge_decision', 'n/a'))}</b>
 · {scan.get('total_findings', 0)} findings across {scan.get('files_scanned', 0)} files
 in {report.get('duration_seconds', '?')}s
</div>
{self._scores(risk)}
{self._ai_status(ai)}
{self._findings(scan)}
{self._business_intent(report)}
{self._quantum(report)}
{self._analysis_basis(report)}
{self._errors(report)}
</body></html>"""

    # ------------------------------------------------------------------
    def _scores(self, risk: dict) -> str:
        pairs = [
            ("security_score", "Security"),
            ("alignment_score", "Business alignment"),
            ("quantum_readiness_score", "Quantum readiness"),
            ("dependency_risk_score", "Dependencies"),
            ("maintainability_score", "Maintainability"),
            ("overall_risk_score", "Overall"),
        ]
        cells = []
        for key, label in pairs:
            value = risk.get(key)
            if value is None:
                continue
            cells.append(f"<div class='score'><div class='num'>{value:.0f}</div>"
                         f"<div class='lbl'>{_e(label)}</div></div>")
        return f"<div class='scores'>{''.join(cells)}</div>"

    def _ai_status(self, ai: dict) -> str:
        if not ai:
            return ""
        if ai.get("configured"):
            return (f"<div class='ok'>Contextual analysis active — model "
                    f"<code>{_e(ai.get('model'))}</code>, {ai.get('calls', 0)} call(s), "
                    f"{ai.get('cache_hits', 0)} cached, {ai.get('failures', 0)} failed. "
                    f"Every AI claim below was validated against the evidence store.</div>")
        reason = ai.get("unavailable_reason") or ai.get("reason") or "not configured"
        return (f"<div class='note'>Contextual AI analysis unavailable: {_e(reason)}<br>"
                f"All findings shown are deterministic; nothing was inferred.</div>")

    def _findings(self, scan: dict) -> str:
        findings = scan.get("findings", [])
        if not findings:
            return "<h2>Security Findings</h2><div class='empty'>No findings.</div>"

        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        rows = []
        for f in sorted(findings, key=lambda x: (order.get(x.get("severity"), 5),
                                                 x.get("file", ""), x.get("line", 0))):
            sev = f.get("severity", "Medium")
            location = f"{_e(f.get('file'))}:{f.get('line', '')}"
            if f.get("function"):
                location += f"<br><small>in <code>{_e(f['function'])}()</code></small>"
            evidence = f.get("evidence_ids") or []
            detail = f"<code>{_e(str(f.get('snippet', ''))[:120])}</code>"
            if f.get("reason"):
                detail += f"<div class='reason'>{_e(str(f['reason'])[:300])}</div>"
            if evidence:
                detail += f"<div class='ev'>evidence: {_e(', '.join(evidence))}</div>"
            rows.append(
                f"<tr><td><span style='color:{_SEV_COLOR.get(sev, '#333')};"
                f"font-weight:600'>{_e(sev)}</span></td>"
                f"<td>{_badge(f.get('source', 'DETERMINISTIC'))}</td>"
                f"<td>{_e(f.get('category'))}<br><small>{_e(f.get('rule_id') or '')}</small></td>"
                f"<td>{_e(f.get('language'))}</td>"
                f"<td>{location}</td><td>{detail}</td>"
                f"<td>{_e(str(f.get('recommendation', ''))[:220])}</td></tr>")

        return ("<h2>Security Findings</h2><table>"
                "<tr><th>Severity</th><th>Source</th><th>Category</th><th>Lang</th>"
                "<th>Location</th><th>Evidence</th><th>Recommendation</th></tr>"
                f"{''.join(rows)}</table>")

    def _business_intent(self, report: dict) -> str:
        bi = report.get("business_intent")
        if not bi:
            return ""
        if bi.get("status") == "no_requirements":
            return f"<h2>Business Intent</h2><div class='note'>{_e(bi.get('message'))}</div>"

        verdict_colour = {
            "COMPLIANT": "#2e7d32", "VIOLATION": "#b71c1c",
            "POTENTIAL_VIOLATION": "#e65100", "INSUFFICIENT_EVIDENCE": "#616161",
        }
        rows = []
        for v in bi.get("verdicts", []):
            verdict = v.get("verdict", "")
            implementations = ", ".join(
                f"{i.get('function')}() @ {i.get('file')}:{i.get('line')}"
                for i in v.get("implementations", [])) or "—"
            rows.append(
                f"<tr><td><b style='color:{verdict_colour.get(verdict, '#333')}'>"
                f"{_e(verdict.replace('_', ' ').title())}</b></td>"
                f"<td>{_e(v.get('policy'))}<div class='reason'>"
                f"&ldquo;{_e(str(v.get('requirement', ''))[:200])}&rdquo;</div></td>"
                f"<td>{_e(implementations)}</td>"
                f"<td>{_e(', '.join(v.get('missing_control_in', []) or []) or '—')}</td></tr>")

        policies = bi.get("policies", {})
        return (f"<h2>Business Intent</h2>"
                f"<div class='sub'>Alignment {bi.get('alignment_score', 0):.0f}/100 · "
                f"{policies.get('checkable', 0)} testable policies extracted from "
                f"{_e(', '.join(bi.get('documents', []) or []))}</div>"
                "<table><tr><th>Verdict</th><th>Policy</th>"
                "<th>Implementation found</th><th>Control missing in</th></tr>"
                f"{''.join(rows)}</table>")

    def _quantum(self, report: dict) -> str:
        cbom = report.get("quantum")
        if not cbom:
            return ""
        rows = []
        for entry in cbom.get("entries", []):
            status = entry.get("status", "unknown")
            rows.append(
                f"<tr><td><b>{_e(entry.get('algorithm'))}</b></td>"
                f"<td>{_e(_STATUS_LABEL.get(status, status))}</td>"
                f"<td>{entry.get('occurrences', 0)}</td>"
                f"<td>{_e(', '.join(entry.get('operations', []) or []))}</td>"
                f"<td>{_e(', '.join(entry.get('files', [])[:4]))}</td>"
                f"<td>{_e(entry.get('migration_target') or '—')}"
                f"<br><small>{_e(entry.get('nist_standard') or '')}</small></td></tr>")

        unresolved = cbom.get("unresolved_call_sites", 0)
        unresolved_note = (
            f"<div class='note'>{unresolved} call site(s) invoke a cryptographic API "
            f"whose algorithm is supplied at runtime and cannot be determined "
            f"statically. They are listed as <i>unresolved</i> rather than guessed.</div>"
            if unresolved else "")

        deps = cbom.get("crypto_dependencies", [])
        dep_note = (f"<div class='sub'>Cryptographic libraries in use: "
                    f"{_e(', '.join(sorted({d.get('name', '') for d in deps}))[:400])}</div>"
                    if deps else "")

        return (f"<h2>Quantum Readiness</h2>"
                f"<div class='sub'>Readiness {cbom.get('readiness_score', 0):.0f}/100 · "
                f"{cbom.get('total_occurrences', 0)} cryptographic operations across "
                f"{cbom.get('total_algorithms', 0)} algorithms</div>"
                f"{unresolved_note}{dep_note}"
                "<table><tr><th>Algorithm</th><th>Status</th><th>Uses</th>"
                "<th>Operations</th><th>Files</th><th>Migration target</th></tr>"
                f"{''.join(rows) if rows else '<tr><td colspan=6>No cryptography detected.</td></tr>'}"
                "</table>")

    def _analysis_basis(self, report: dict) -> str:
        ust = report.get("ust") or {}
        evidence = report.get("evidence") or {}
        if not ust and not evidence:
            return ""
        parsers = ", ".join(f"{k}: {v}" for k, v in (ust.get("parsers") or {}).items())
        languages = ", ".join(f"{k} ({v})" for k, v in (ust.get("languages") or {}).items())
        evidence_types = ", ".join(f"{k}: {v}"
                                   for k, v in (evidence.get("by_type") or {}).items())
        return (f"<h2>Analysis Basis</h2><div class='sub'>"
                f"Unified syntax tree: {ust.get('files', 0)} files, "
                f"{ust.get('nodes', 0)} nodes, {ust.get('parse_failures', 0)} parse failures<br>"
                f"Languages: {_e(languages or 'none')}<br>"
                f"Parsers: {_e(parsers or 'none')}<br>"
                f"Evidence collected: {evidence.get('total', 0)} items — "
                f"{_e(evidence_types)}</div>")

    def _errors(self, report: dict) -> str:
        errors = report.get("errors") or []
        if not errors:
            return ""
        items = "".join(f"<li><code>{_e(e.get('stage'))}</code>: {_e(e.get('error'))}</li>"
                        for e in errors[:20])
        return (f"<h2>Partial Results</h2><div class='note'>"
                f"{len(errors)} stage(s) failed and were skipped. Everything else "
                f"completed normally.<ul>{items}</ul></div>")
