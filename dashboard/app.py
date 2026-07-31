"""
AI Code Guardian — Streamlit Dashboard
======================================
Drives the unified ScanPipeline and renders its report:

    Repository / Upload -> Scan -> Overview -> Security -> Business Intent
    -> Quantum Readiness -> Dependencies -> IaC -> Risk -> Recommendations
    -> Reports

Every findings table distinguishes provenance — Static (deterministic),
AI-validated, or AI suggestion — and exposes the UST and evidence behind
a result so a reviewer can see why it exists rather than trusting it.

Run with: streamlit run dashboard/app.py
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from guardian.config import GuardianConfig
from guardian.core.pipeline import ScanPipeline
from guardian.core.registry import load_builtin_plugins

def _to_csv(records: list[dict]) -> str:
    if not records:
        return ""
    out = io.StringIO()
    if isinstance(records[0], dict):
        fieldnames = list(records[0].keys())
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    else:
        writer = csv.writer(out)
        for row in records:
            writer.writerow([row] if not isinstance(row, (list, tuple)) else row)
    return out.getvalue()

def st_dataframe(data, use_container_width=True, height=None):
    if not data:
        st.caption("No data.")
        return
    if isinstance(data, dict):
        data = [{"Key": k, "Value": v} for k, v in data.items()]
    if not isinstance(data, list):
        return
    keys = list(data[0].keys()) if data and isinstance(data[0], dict) else ["Value"]
    html = ["<div style='max-height: 500px; overflow-y: auto; border: 1px solid #e6e6e6; border-radius: 4px;'>"]
    html.append("<table style='width:100%; border-collapse: collapse; font-size: 14px;'>")
    html.append("<thead><tr style='background-color: #f8f9fa; border-bottom: 2px solid #dee2e6;'>")
    for k in keys:
        html.append(f"<th style='padding: 10px; text-align: left; position: sticky; top: 0; background-color: #f8f9fa;'>{k}</th>")
    html.append("</tr></thead><tbody>")
    for row in data:
        html.append("<tr style='border-bottom: 1px solid #eee;'>")
        if isinstance(row, dict):
            for k in keys:
                val = row.get(k, '')
                if val is None: val = ''
                html.append(f"<td style='padding: 8px;'>{val}</td>")
        else:
            val = row if row is not None else ''
            html.append(f"<td style='padding: 8px;'>{val}</td>")
        html.append("</tr>")
    html.append("</tbody></table></div>")
    st.markdown("".join(html), unsafe_allow_html=True)

def st_bar_chart(data: dict):
    if not data:
        return
    if isinstance(data, list) and isinstance(data[0], dict):
        # if it's a list of dicts with single key
        pass
    max_val = max((v for v in data.values() if isinstance(v, (int, float))), default=1)
    if max_val == 0: max_val = 1
    html = ["<div style='margin-top: 10px; margin-bottom: 20px;'>"]
    for k, v in data.items():
        if not isinstance(v, (int, float)): continue
        width = int((v / max_val) * 100)
        html.append(f"<div style='display: flex; align-items: center; margin-bottom: 8px;'>")
        html.append(f"<div style='width: 140px; font-size: 13px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; padding-right: 10px;'>{k}</div>")
        html.append(f"<div style='flex-grow: 1; background: #f0f2f6; height: 24px; border-radius: 4px; overflow: hidden;'>")
        html.append(f"<div style='width: {width}%; background: #ff4b4b; height: 100%; border-radius: 4px;'></div>")
        html.append("</div>")
        html.append(f"<div style='width: 40px; text-align: right; font-size: 13px; font-weight: 600; padding-left: 10px;'>{v}</div>")
        html.append("</div>")
    html.append("</div>")
    st.markdown("".join(html), unsafe_allow_html=True)

def _get_file_icon(filename: str) -> str:
    ext = filename.split(".")[-1].lower() if "." in filename else ""
    return {
        "py": "🐍",
        "java": "☕",
        "js": "📜",
        "jsx": "📜",
        "ts": "🟦",
        "tsx": "🟦",
        "rs": "🦀",
        "json": "⚙️",
        "yaml": "⚙️",
        "yml": "⚙️",
        "md": "📄",
        "txt": "📝",
        "zip": "📦",
        "xml": "📋",
        "html": "🌐",
        "css": "🎨"
    }.get(ext, "📄")

def _render_sidebar_explorer(report: dict | None, scanned_files: list[str]):
    st.sidebar.header("📁 Repository Explorer")
    
    if not scanned_files and report:
        findings = report.get("scan", {}).get("findings", [])
        evidence_items = report.get("evidence_items", [])
        scanned_files = sorted(list({f.get("file").replace("\\", "/") for f in findings if f.get("file")} |
                                   {e.get("file").replace("\\", "/") for e in evidence_items if e.get("file")}))

    if not scanned_files:
        st.sidebar.info("⬆️ Upload code or enter a GitHub repository URL to inspect directory structure and files.")
        return

    # Build finding severity lookup per file
    finding_severities = {}
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    if report:
        for f in report.get("scan", {}).get("findings", []):
            fp = f.get("file", "").replace("\\", "/")
            if fp:
                sev = f.get("severity", "Info")
                if fp not in finding_severities or order.get(sev, 5) < order.get(finding_severities[fp], 5):
                    finding_severities[fp] = sev

    # Overview stats in sidebar
    st.sidebar.caption(f"📊 **{len(scanned_files)}** files scanned in repository")
    
    search_q = st.sidebar.text_input("🔍 Search files...", key="sidebar_file_search", placeholder="e.g. app.py, Auth.java")
    filter_text = search_q.strip().lower()

    # Organize files into directory tree
    tree = {}
    for path in scanned_files:
        clean_path = path.replace("\\", "/").strip("/")
        if not clean_path: continue
        parts = clean_path.split("/")
        curr = tree
        for part in parts[:-1]:
            if part not in curr or not isinstance(curr[part], dict):
                curr[part] = {}
            curr = curr[part]
        curr[parts[-1]] = clean_path

    def _render_dict(d: dict):
        for name, val in sorted(d.items(), key=lambda x: (not isinstance(x[1], dict), x[0].lower())):
            if isinstance(val, dict):
                # Subdirectory
                if filter_text:
                    def _matches(subd):
                        for k, v in subd.items():
                            if isinstance(v, dict) and _matches(v): return True
                            if isinstance(v, str) and filter_text in v.lower(): return True
                        return False
                    if not _matches(val):
                        continue
                with st.sidebar.expander(f"📁 {name}/", expanded=bool(filter_text)):
                    _render_dict(val)
            else:
                rel_path = val
                if filter_text and filter_text not in rel_path.lower():
                    continue
                icon = _get_file_icon(name)
                badge = ""
                if rel_path in finding_severities:
                    s = finding_severities[rel_path]
                    badge = " 🔴" if s in ("Critical", "High") else (" 🟡" if s in ("Medium", "Low") else " 🔵")
                st.sidebar.markdown(f"<div style='font-size: 13px; margin-left: 6px; font-family: monospace;'>{icon} {name}{badge}</div>", unsafe_allow_html=True)

    _render_dict(tree)

# ─── Page config ────────────────────────────────────────────────────────────
st.set_page_config(page_title="AI Code Guardian", layout="wide", page_icon="🛡️")

# ─── Custom CSS ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
.upload-box {
    border: 2px dashed #4a9eff;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 12px;
    background: #f0f6ff;
}
.upload-label {
    font-weight: 600;
    font-size: 0.95rem;
    color: #1a1a2e;
    margin-bottom: 6px;
}
.upload-hint {
    font-size: 0.78rem;
    color: #666;
    margin-top: 4px;
}
.result-banner {
    padding: 12px 16px;
    border-radius: 8px;
    margin: 8px 0;
}
</style>
""", unsafe_allow_html=True)

# ─── Header ─────────────────────────────────────────────────────────────────
col_logo, col_title = st.columns([1, 8])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.title("AI Code Guardian")
    st.caption("Secure · Correct · Business-Aligned · Quantum-Ready")

st.divider()

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — FILE UPLOAD PANEL
# ═══════════════════════════════════════════════════════════════════════════
st.subheader("📁 Upload Files to Scan")

upload_col1, upload_col2, upload_col3 = st.columns(3)

# ── Column 1: Code ──────────────────────────────────────────────────────────
with upload_col1:
    st.markdown('<div class="upload-label">🗂️ Code Repository</div>', unsafe_allow_html=True)
    st.markdown('<div class="upload-hint">Upload a <b>.zip</b> of your repo, or individual '
                '<b>.java</b> / <b>.py</b> / <b>.js</b> / <b>.ts</b> / <b>.rs</b> source files.</div>',
                unsafe_allow_html=True)
    code_files = st.file_uploader(
        "Code files",
        type=["zip", "java", "py", "js", "jsx", "ts", "tsx", "rs"],
        accept_multiple_files=True,
        key="code_upload",
        label_visibility="collapsed",
        help="ZIP = whole repo scan. Individual source files = targeted scan."
    )
    if code_files:
        zips   = [f for f in code_files if f.name.endswith(".zip")]
        src    = [f for f in code_files if not f.name.endswith(".zip")]
        if zips:
            st.success(f"✅ {len(zips)} zip archive(s) — {sum(f.size for f in zips)//1024} KB total")
        if src:
            st.success(f"✅ {len(src)} source file(s) uploaded")

    st.markdown('<div class="upload-hint"><b>OR</b> enter a GitHub Repository URL / Slug:</div>', unsafe_allow_html=True)
    github_url = st.text_input(
        "GitHub URL",
        placeholder="https://github.com/owner/repo or owner/repo",
        key="github_url_input",
        label_visibility="collapsed"
    )
    if github_url.strip():
        st.success(f"🔗 GitHub target: {github_url.strip()}")

# ── Column 2: Requirements ──────────────────────────────────────────────────
with upload_col2:
    st.markdown('<div class="upload-label">📋 Requirements / User Stories</div>', unsafe_allow_html=True)
    st.markdown('<div class="upload-hint">Jira XLSX, JSON, BRD Markdown, or plain TXT. Optional — enables Business Intent analysis.</div>', unsafe_allow_html=True)
    req_files = st.file_uploader(
        "Requirements files",
        type=["xlsx", "xls", "json", "md", "txt", "csv", "yaml", "yml", "pdf", "docx"],
        accept_multiple_files=True,
        key="req_upload",
        label_visibility="collapsed",
        help="Supports Jira XLSX export, custom JSON, Markdown BRD, plain text SRS."
    )
    if req_files:
        st.success(f"✅ {len(req_files)} requirement file(s): {', '.join(f.name for f in req_files)}")

# ── Column 3: Policy ────────────────────────────────────────────────────────
with upload_col3:
    st.markdown('<div class="upload-label">📜 Company Security Policy</div>', unsafe_allow_html=True)
    st.markdown('<div class="upload-hint">Optional Markdown or TXT policy file. Used to flag policy violations in Business Intent analysis.</div>', unsafe_allow_html=True)
    policy_file = st.file_uploader(
        "Policy file",
        type=["md", "txt"],
        accept_multiple_files=False,
        key="policy_upload",
        label_visibility="collapsed",
        help="e.g. Company_Security_Policy.md"
    )
    if policy_file:
        st.success(f"✅ Policy loaded: {policy_file.name}")

st.divider()

# ── Scan button ─────────────────────────────────────────────────────────────
btn_col, hint_col = st.columns([2, 5])
with btn_col:
    has_target = bool(code_files) or bool(github_url.strip())
    run_btn = st.button("🚀 Run Full Scan", type="primary",
                         use_container_width=True,
                         disabled=not has_target)
with hint_col:
    if not has_target:
        st.info("⬆️ Upload code files or provide a GitHub URL above to enable scanning.")
    else:
        total_files = len(code_files) if code_files else 0
        zips_count  = sum(1 for f in code_files if f.name.endswith(".zip")) if code_files else 0
        target_desc = f"{github_url.strip()}" if github_url.strip() and not code_files else f"{total_files} file(s) uploaded"
        st.caption(
            f"Ready: {target_desc}"
            + (f" ({zips_count} zip archive{'s' if zips_count>1 else ''})" if zips_count else "")
            + (f" · {len(req_files)} requirements file(s)" if req_files else "")
            + (f" · policy: {policy_file.name}" if policy_file else "")
        )


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS — save uploaded bytes to temp dir
# ═══════════════════════════════════════════════════════════════════════════

def _save_uploaded_code(uploaded_files: list, dest_dir: Path, github_url: str = "") -> Path:
    """
    Save uploaded code files or fetch GitHub repo into dest_dir.
    ZIP files are extracted. Individual .java/.py are placed flat.
    Returns dest_dir.
    """
    if github_url.strip() and not uploaded_files:
        from guardian.discovery.github_service import GitHubService
        fetched = GitHubService().fetch_repository(github_url.strip())
        for item in fetched.iterdir():
            if item.is_dir():
                shutil.copytree(item, dest_dir / item.name, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest_dir / item.name)
        return dest_dir

    for uf in uploaded_files:
        data = uf.read()
        if uf.name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                # Skip hidden / __pycache__ / .git / .venv entries
                for member in zf.namelist():
                    parts = Path(member).parts
                    skip_dirs = {".git", "__pycache__", ".venv", "node_modules",
                                 ".idea", ".vs", "bin", "build", "target"}
                    if any(p in skip_dirs for p in parts):
                        continue
                    if member.endswith("/"):
                        continue
                    out = dest_dir / member
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(zf.read(member))
        else:
            (dest_dir / uf.name).write_bytes(data)
    return dest_dir


def _save_uploaded_requirements(req_files: list, dest_dir: Path) -> list[Path]:
    """Save requirement files to dest_dir, return list of saved paths."""
    paths = []
    for uf in req_files:
        p = dest_dir / uf.name
        p.write_bytes(uf.read())
        paths.append(p)
    return paths


from typing import Optional

def _save_policy(policy_file, dest_dir: Path) -> Optional[Path]:
    if not policy_file:
        return None
    p = dest_dir / policy_file.name
    p.write_bytes(policy_file.read())
    return p




def _build_results_zip(report: dict) -> bytes:
    """Pack every artefact the pipeline produced into a downloadable ZIP."""
    buf = io.BytesIO()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    registry = load_builtin_plugins()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        root = f"acg_scan_{ts}"
        zf.writestr(f"{root}/full_report.json",
                    json.dumps(report, indent=2, default=str))

        # Every registered reporter, so the ZIP matches the CLI's outputs.
        for name in ("csv", "sarif", "html", "pdf"):
            reporter = registry.reporter(name)
            if reporter is None:
                continue
            try:
                zf.writestr(f"{root}/guardian_report{reporter.file_extension}",
                            reporter.render(report))
            except Exception as exc:  # noqa: BLE001 — one format, not the ZIP
                zf.writestr(f"{root}/{name}_ERROR.txt", str(exc))

        findings = report.get("scan", {}).get("findings", [])
        if findings:
            zf.writestr(f"{root}/all_findings.csv", _to_csv(findings))

        evidence = report.get("evidence_items", [])
        if evidence:
            zf.writestr(f"{root}/evidence.csv", _to_csv(evidence))

        cbom = report.get("quantum")
        if cbom and cbom.get("entries"):
            zf.writestr(f"{root}/quantum_cbom.csv", _to_csv(cbom["entries"]))

        bi = report.get("business_intent")
        if bi:
            zf.writestr(f"{root}/business_intent.json",
                        json.dumps(bi, indent=2, default=str))
            if bi.get("verdicts"):
                zf.writestr(f"{root}/business_intent_verdicts.csv",
                            _to_csv([{k: v for k, v in row.items()
                                     if k != "implementations"}
                                    for row in bi["verdicts"]]))

        zf.writestr(f"{root}/executive_summary.txt", _executive_summary(report))

    buf.seek(0)
    return buf.read()


def _executive_summary(report: dict) -> str:
    scan = report.get("scan", {})
    risk = report.get("unified_risk") or report.get("risk", {})
    ust = report.get("ust", {})
    bi = report.get("business_intent") or {}
    cbom = report.get("quantum") or {}

    lines = [
        "AI Code Guardian — Scan Summary",
        "=" * 46,
        f"Scan date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Target         : {scan.get('target', '')}",
        f"Files scanned  : {scan.get('files_scanned', 0)}",
        f"UST nodes      : {ust.get('nodes', 0)} across {ust.get('files', 0)} files",
        f"Evidence items : {report.get('evidence', {}).get('total', 0)}",
        f"Total findings : {scan.get('total_findings', 0)}",
        "",
        "SCORES",
        f"  Security          : {risk.get('security_score', 0):.1f}/100",
        f"  Business alignment: {risk.get('alignment_score', 0):.1f}/100",
        f"  Quantum readiness : {risk.get('quantum_readiness_score', 100):.1f}/100",
        f"  Dependencies      : {risk.get('dependency_risk_score', 100):.1f}/100",
        f"  Maintainability   : {risk.get('maintainability_score', 0):.1f}/100",
        f"  Overall           : {risk.get('overall_risk_score', 0):.1f}/100",
        "",
        f"Merge decision : {risk.get('merge_decision', 'n/a')}",
        "",
        "FINDINGS BY SEVERITY",
    ]
    lines += [f"  {k}: {v}" for k, v in (scan.get("by_severity") or {}).items()] or ["  none"]

    if bi.get("status") == "analyzed":
        lines += ["", "BUSINESS INTENT"]
        for verdict in bi.get("verdicts", []):
            lines.append(f"  [{verdict['verdict']}] {verdict['policy']}")

    if cbom.get("entries"):
        lines += ["", "CRYPTOGRAPHIC INVENTORY"]
        for entry in cbom["entries"]:
            lines.append(f"  {entry['algorithm']:<12} {entry['status']:<20} "
                         f"{entry['occurrences']} use(s)")

    ai = report.get("ai") or {}
    lines += ["", "AI LAYER"]
    lines.append(f"  {'active — ' + str(ai.get('model')) if ai.get('configured') else 'not used: ' + str(ai.get('unavailable_reason') or ai.get('reason', 'disabled'))}")
    lines.append("  Deterministic findings are unaffected by AI availability.")
    return "\n".join(lines)


def _findings_frame(findings: list[dict]) -> list[dict]:
    """Findings table with provenance and evidence columns."""
    if not findings:
        return []
    return [{
        "Severity": f.get("severity", ""),
        "Source": {"DETERMINISTIC": "Static",
                   "AI_VALIDATED": "AI-validated",
                   "AI_SUGGESTED": "AI suggestion"}.get(f.get("source", ""), f.get("source", "")),
        "Category": f.get("category", ""),
        "Lang": f.get("language", ""),
        "File": f.get("file", ""),
        "Line": f.get("line", 0),
        "Function": f.get("function", ""),
        "Why": f.get("reason", "") or f.get("snippet", ""),
        "Recommendation": f.get("recommendation", ""),
        "Evidence": ", ".join(f.get("evidence_ids", []) or []),
        "Confidence": f.get("confidence", 0.0),
        "Rule": f.get("rule_id") or "",
    } for f in findings]


# ═══════════════════════════════════════════════════════════════════════════
# RUN SCAN — one call into the unified pipeline
# ═══════════════════════════════════════════════════════════════════════════
if run_btn and (code_files or github_url.strip()):
    if code_files:
        for uf in code_files:
            uf.seek(0)
    if req_files:
        for uf in req_files:
            uf.seek(0)
    if policy_file:
        policy_file.seek(0)

    tmp_root = Path(tempfile.mkdtemp(prefix="acg_"))
    try:
        code_dir = tmp_root / "code"
        code_dir.mkdir()
        with st.spinner("📦 Preparing code repository..."):
            _save_uploaded_code(code_files or [], code_dir, github_url.strip())
            scanned_files = sorted([str(p.relative_to(code_dir)).replace("\\", "/") for p in code_dir.rglob("*") if p.is_file()])
            st.session_state["scanned_files"] = scanned_files
            st.toast(f"✅ {len(scanned_files)} files ready")

        req_paths: list[Path] = []
        if req_files:
            req_dir = tmp_root / "requirements"
            req_dir.mkdir()
            req_paths = _save_uploaded_requirements(req_files, req_dir)
        if policy_file:
            saved_policy = _save_policy(policy_file, tmp_root)
            if saved_policy is not None:
                # The policy document is a requirement source too: it states
                # rules the code must satisfy.
                req_paths.append(saved_policy)

        cfg = GuardianConfig.load()
        cfg.enable_ai = True

        with st.spinner("🔬 Building unified syntax tree and running all engines..."):
            report = ScanPipeline(cfg).scan(
                code_dir,
                business_requirements=[str(p) for p in req_paths] or None)

        st.session_state.update({
            "report": report,
            "results_zip": _build_results_zip(report),
            "scan_ts": datetime.now().strftime("%Y%m%d_%H%M%S"),
        })
    except Exception as exc:  # noqa: BLE001 — surface, never crash the app
        st.error(f"Scan failed: {exc}")
        import traceback
        st.code(traceback.format_exc())
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
# RENDER RESULTS
# ═══════════════════════════════════════════════════════════════════════════
_render_sidebar_explorer(st.session_state.get("report"), st.session_state.get("scanned_files", []))

if "report" not in st.session_state:
    st.info("⬆️ Upload code (or supply a GitHub URL) and run a scan to see results.")
    st.stop()

report = st.session_state["report"]
scan = report.get("scan", {})
risk = report.get("unified_risk") or report.get("risk", {})
findings = scan.get("findings", [])
results_zip = st.session_state.get("results_zip")
scan_ts = st.session_state.get("scan_ts", "scan")

tab_overview, tab_sec, tab_bi, tab_q, tab_dep, tab_iac, tab_risk, tab_rec, tab_rep, tab_ai = st.tabs([
    "📊 Overview", "🔐 Security", "🎯 Business Intent", "⚛️ Quantum",
    "📦 Dependencies", "🏗️ IaC", "⚠️ Risk", "💡 Recommendations",
    "📄 Reports", "🤖 AI Copilot",
])

# ── Overview ────────────────────────────────────────────────────────────────
with tab_overview:
    st.subheader("📊 Scan Overview")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🔐 Security", f"{risk.get('security_score', 0):.0f}/100")
    c2.metric("🎯 Alignment", f"{risk.get('alignment_score', 0):.0f}/100")
    c3.metric("⚛️ Quantum Ready", f"{risk.get('quantum_readiness_score', 100):.0f}/100")
    c4.metric("📦 Dependencies", f"{risk.get('dependency_risk_score', 100):.0f}/100")
    c5.metric("⚠️ Overall", f"{risk.get('overall_risk_score', 0):.0f}/100")

    decision = risk.get("merge_decision", "n/a")
    colour = next((v for k, v in
                   {"Auto-Approve": "green", "Warn": "orange",
                    "Block": "red", "Hard": "red"}.items()
                   if decision.startswith(k)), "gray")
    st.markdown(f"### Merge Decision: :{colour}[{decision}]")

    ai = report.get("ai") or {}
    if ai.get("configured"):
        st.success(f"🤖 Contextual analysis active — `{ai.get('model')}` · "
                   f"{ai.get('calls', 0)} call(s), {ai.get('cache_hits', 0)} cached, "
                   f"{ai.get('failures', 0)} failed. Every AI claim was validated "
                   f"against the evidence store.")
    else:
        st.info(f"🤖 Contextual AI analysis not used: "
                f"{ai.get('unavailable_reason') or ai.get('reason', 'disabled')}. "
                f"All results below are deterministic.")

    st.divider()
    left, right = st.columns(2)
    with left:
        st.markdown("**Findings by severity**")
        by_sev = scan.get("by_severity") or {}
        if by_sev:
            st_bar_chart(by_sev)
        else:
            st.caption("No findings.")
        st.markdown("**Findings by provenance**")
        prov_counts = {}
        for f in findings:
            src = f.get("source", "DETERMINISTIC")
            prov_counts[src] = prov_counts.get(src, 0) + 1
        if prov_counts:
            st_bar_chart(prov_counts)

    with right:
        ust = report.get("ust") or {}
        st.markdown("**Unified syntax tree**")
        st.caption(f"{ust.get('nodes', 0)} nodes across {ust.get('files', 0)} files · "
                   f"{ust.get('parse_failures', 0)} parse failures")
        if ust.get("languages"):
            st_bar_chart(ust["languages"])
        st.caption(f"Parsers used: {ust.get('parsers', {})}")

        evidence = report.get("evidence") or {}
        st.markdown("**Evidence store**")
        st.caption(f"{evidence.get('total', 0)} observations published by "
                   f"{len(evidence.get('by_source', {}))} detectors")
        if evidence.get("by_type"):
            st_dataframe([{"Observation Type": k, "Count": v}
                          for k, v in evidence["by_type"].items()],
                         use_container_width=True)

    if report.get("errors"):
        st.warning(f"⚠️ {len(report['errors'])} stage(s) failed and were skipped — "
                   f"results below are partial but valid.")
        st_dataframe(report["errors"], use_container_width=True)


# ── Security ─────────────────────────────────────────────────────────────────
with tab_sec:
    security = [f for f in findings
                if f.get("category") not in ("Quantum Migration Inventory",
                                             "Quantum Readiness",
                                             "Business Intent Violation")]
    st.subheader(f"🔐 Security Findings ({len(security)})")

    if not security:
        st.success("No security findings.")
    else:
        col_a, col_b, col_c = st.columns(3)
        severities = col_a.multiselect(
            "Severity", sorted({f.get("severity", "") for f in security}),
            default=sorted({f.get("severity", "") for f in security}))
        sources = col_b.multiselect(
            "Source", sorted({f.get("source", "") for f in security}),
            default=sorted({f.get("source", "") for f in security}),
            help="Static = proven by rules/UST. AI-validated = model claim that "
                 "passed evidence validation. AI suggestion = grounded but not "
                 "fully corroborated.")
        languages = col_c.multiselect(
            "Language", sorted({f.get("language", "") for f in security if f.get("language")}),
            default=sorted({f.get("language", "") for f in security if f.get("language")}))

        filtered = [f for f in security
                    if f.get("severity") in severities
                    and f.get("source") in sources
                    and (not languages or f.get("language") in languages)]
        st_dataframe(_findings_frame(filtered), use_container_width=True, height=420)

        st.divider()
        st.markdown("#### 🔍 Explain a finding")
        labels = [f"[{f.get('severity')}] {f.get('category')} — "
                  f"{f.get('file')}:{f.get('line')}" for f in filtered]
        if labels:
            chosen = st.selectbox("Finding", range(len(labels)),
                                  format_func=lambda i: labels[i])
            finding = filtered[chosen]
            st.markdown(f"**Why this was raised** — {finding.get('reason') or '—'}")
            st.markdown(f"**Recommendation** — {finding.get('recommendation')}")
            st.caption(f"Provenance: {finding.get('source')} · engine "
                       f"{finding.get('engine')} · confidence {finding.get('confidence')}"
                       + (" · data-flow confirmed" if finding.get("tainted") else ""))
            evidence_ids = finding.get("evidence_ids") or []
            if evidence_ids:
                store = {e["id"]: e for e in report.get("evidence_items", [])}
                cited = [store[i] for i in evidence_ids if i in store]
                if cited:
                    st.markdown("**Supporting evidence**")
                    st_dataframe([{
                        "ID": e["id"], "Type": e["type"], "Detector": e["source"],
                        "Location": f"{e['file']}:{e['line']}",
                        "Observation": e["operation"],
                        "Detail": (e.get("description") or "")[:300],
                        "Confidence": e["confidence"],
                    } for e in cited], use_container_width=True)
            else:
                st.caption("No evidence records attached (legacy pattern detector).")


# ── Business Intent ──────────────────────────────────────────────────────────
with tab_bi:
    bi = report.get("business_intent")
    st.subheader("🎯 Business Intent — Requirements vs. Implementation")

    if not bi or bi.get("status") == "no_requirements":
        st.info((bi or {}).get("message")
                or "Upload requirement documents to compare the code against them.")
    else:
        policies = bi.get("policies", {})
        m1, m2, m3 = st.columns(3)
        m1.metric("Alignment", f"{bi.get('alignment_score', 0):.0f}/100")
        m2.metric("Testable policies", policies.get("checkable", 0))
        m3.metric("Documents", len(bi.get("documents", [])))

        verdicts = bi.get("verdicts", [])
        if verdicts:
            st.markdown("#### Verdicts")
            st_dataframe([{
                "Verdict": v["verdict"].replace("_", " ").title(),
                "Policy": v["policy"],
                "Requirement": (v.get("requirement") or "")[:180],
                "Implemented in": ", ".join(
                    f"{i['function']}() @ {i['file']}:{i['line']}"
                    for i in v.get("implementations", [])) or "—",
                "Control missing in": ", ".join(v.get("missing_control_in", []) or []) or "—",
            } for v in verdicts], use_container_width=True)

            st.markdown("#### Observed behaviour")
            st.caption("What the code actually does, read from the unified syntax "
                       "tree — this is the evidence each verdict is based on.")
            for v in verdicts:
                for impl in v.get("implementations", []):
                    with st.expander(f"{impl['function']}() — {impl['file']}:{impl['line']}"):
                        st.write(f"**Parameters:** {', '.join(impl.get('parameters', [])) or 'none'}")
                        st.write(f"**Calls:** {', '.join(impl.get('calls', [])[:15]) or 'none'}")
                        st.write(f"**Authorization checks:** "
                                 f"{', '.join(impl.get('authorization_checks', [])) or '❌ none found'}")
                        st.write(f"**Audit writes:** "
                                 f"{', '.join(impl.get('audit_writes', [])) or '❌ none found'}")
                        st.write(f"**Threshold comparisons:** "
                                 f"{', '.join(impl.get('threshold_comparisons', [])) or '❌ none found'}")
                        st.write(f"**State changes:** "
                                 f"{', '.join(impl.get('state_changes', [])) or 'none'}")

        bi_findings = [f for f in findings if f.get("category") == "Business Intent Violation"]
        if bi_findings:
            st.markdown("#### Findings")
            st_dataframe(_findings_frame(bi_findings), use_container_width=True)

        if policies.get("policies"):
            with st.expander("📋 Extracted policies (structured from your requirements)"):
                st_dataframe([{
                    "ID": p["policy_id"], "Action": p["action"],
                    "Required control": p["required_control"],
                    "Detail": p["control_detail"], "Condition": p["condition_text"],
                    "Testable": p["checkable"], "Source": p["source_text"][:140],
                } for p in policies["policies"]], use_container_width=True)


# ── Quantum ──────────────────────────────────────────────────────────────────
with tab_q:
    cbom = report.get("quantum")
    st.subheader("⚛️ Quantum Readiness — Cryptographic Bill of Materials")

    if not cbom:
        st.info("Quantum analysis disabled in configuration.")
    elif not cbom.get("entries"):
        st.success("No cryptographic operations detected in the scanned code.")
    else:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Readiness", f"{cbom.get('readiness_score', 0):.0f}/100")
        m2.metric("Crypto operations", cbom.get("total_occurrences", 0))
        m3.metric("Algorithms", cbom.get("total_algorithms", 0))
        m4.metric("Unresolved call sites", cbom.get("unresolved_call_sites", 0))

        if cbom.get("unresolved_call_sites"):
            st.warning(f"⚠️ {cbom['unresolved_call_sites']} call site(s) select their "
                       f"algorithm at runtime. They are reported as *unresolved* "
                       f"rather than guessed — review them manually.")

        labels = {"quantum_vulnerable": "🔴 Quantum vulnerable",
                  "classically_broken": "🟠 Classically broken",
                  "quantum_weakened": "🟡 Grover-weakened",
                  "unknown": "⚪ Unresolved",
                  "quantum_safe": "🟢 Adequate today",
                  "post_quantum": "🔵 Post-quantum"}
        st_dataframe([{
            "Algorithm": e["algorithm"],
            "Status": labels.get(e["status"], e["status"]),
            "Uses": e["occurrences"],
            "Operations": ", ".join(e.get("operations", [])),
            "Files": ", ".join(e.get("files", [])[:3]),
            "Migration target": e.get("migration_target") or "—",
            "NIST standard": e.get("nist_standard") or "—",
            "Rationale": e.get("rationale", "")[:200],
            "Evidence": ", ".join(e.get("evidence_ids", [])[:6]),
        } for e in cbom["entries"]], use_container_width=True)

        if cbom.get("crypto_dependencies"):
            with st.expander("📦 Cryptographic libraries in use"):
                st_dataframe(cbom["crypto_dependencies"], use_container_width=True)

        contextual = cbom.get("contextual_analysis") or {}
        if contextual.get("status") == "analyzed":
            st.markdown("#### 🤖 Contextual migration assessment")
            st.caption("Nemotron was asked about purpose, impact and migration "
                       "urgency — never whether the algorithm exists, which the "
                       "syntax tree already proved.")
            quantum_ai = [f for f in findings
                          if f.get("category") == "Quantum Readiness"
                          and f.get("source", "").startswith("AI")]
            if quantum_ai:
                st_dataframe(_findings_frame(quantum_ai), use_container_width=True)
            else:
                st.caption("No contextual claims survived evidence validation.")
        elif contextual.get("status") in ("unavailable", "skipped"):
            st.caption(f"Contextual assessment not run: {contextual.get('reason', '')}")

        inventory = [f for f in findings
                     if f.get("category") == "Quantum Migration Inventory"]
        if inventory:
            st.markdown("#### Migration inventory")
            st.caption("Informational: using RSA/ECC today is a migration-planning "
                       "item, not a present-day vulnerability, so these do not drive "
                       "the security score.")
            st_dataframe(_findings_frame(inventory), use_container_width=True)


# ── Dependencies ─────────────────────────────────────────────────────────────
with tab_dep:
    st.subheader("📦 Dependencies / SCA")
    dep_findings = [f for f in findings
                    if (f.get("engine") or "").endswith("dependencies")
                    or "DEP" in (f.get("rule_id") or "")]
    count = report.get("analyzers", {}).get("dependencies")
    if count is None:
        st.info("Dependency analysis disabled in configuration.")
    elif not dep_findings:
        st.success(f"No dependency issues found across "
                   f"{report.get('discovery', {}).get('manifest_files', 0)} manifest file(s).")
    else:
        st.metric("Dependency findings", len(dep_findings))
        st_dataframe(_findings_frame(dep_findings), use_container_width=True)


# ── Infrastructure as Code ───────────────────────────────────────────────────
with tab_iac:
    st.subheader("🏗️ Infrastructure as Code")
    iac_findings = [f for f in findings
                    if (f.get("engine") or "").endswith("infrastructure")
                    or "IAC" in (f.get("rule_id") or "")]
    count = report.get("analyzers", {}).get("infrastructure")
    infra_files = report.get("discovery", {}).get("infrastructure_files", 0)
    if count is None:
        st.info("Infrastructure analysis disabled in configuration.")
    elif not iac_findings:
        st.success(f"No misconfigurations found across {infra_files} "
                   f"infrastructure file(s).")
    else:
        st.metric("IaC findings", len(iac_findings))
        st_dataframe(_findings_frame(iac_findings), use_container_width=True)


# ── Risk ─────────────────────────────────────────────────────────────────────
with tab_risk:
    st.subheader("⚠️ Unified Risk Assessment")
    dimensions = risk.get("dimensions") or {}
    if dimensions:
        st.markdown("#### Dimensions and weights")
        weights = dimensions.get("weights", {})
        st_dataframe([{
            "Dimension": name.replace("_", " ").title(),
            "Score": dimensions.get(name),
            "Weight": weights.get(name, "—"),
        } for name in weights] or [], use_container_width=True)

    contribution = risk.get("ai_contribution") or {}
    if contribution:
        st.markdown("#### AI contribution")
        c1, c2 = st.columns(2)
        c1.metric("Deterministic findings", contribution.get("deterministic_findings", 0))
        c2.metric("AI findings", contribution.get("ai_findings", 0))
        st.caption(contribution.get("note", ""))

    finding_risks = risk.get("findings") or []
    if finding_risks:
        st.markdown("#### Per-finding scores")
        st.caption("Every input is shown so a score can be argued with rather "
                   "than merely accepted.")
        st_dataframe([{
            "Category": d.get("category"),
            "Severity": d.get("severity"),
            "Source": d.get("source"),
            "Score": d.get("score"),
            "Severity factor": d.get("severity_factor"),
            "Confidence": d.get("confidence_factor"),
            "Business impact": d.get("business_impact"),
            "Reachability": d.get("reachability"),
            "Exploit likelihood": d.get("exploit_likelihood"),
            "Source multiplier": d.get("source_multiplier"),
            "Evidence": d.get("evidence_count"),
            "Notes": "; ".join(d.get("notes", [])),
        } for d in finding_risks], use_container_width=True, height=380)


# ── Recommendations ──────────────────────────────────────────────────────────
with tab_rec:
    st.subheader("💡 Recommendations")
    if not findings:
        st.success("Nothing to remediate.")
    else:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        ranked = sorted(findings, key=lambda f: (order.get(f.get("severity"), 5),
                                                 -float(f.get("confidence", 0))))
        st.markdown("#### Priority order")
        for i, f in enumerate(ranked[:25], 1):
            badge = {"DETERMINISTIC": "🟢 Static",
                     "AI_VALIDATED": "🔵 AI-validated",
                     "AI_SUGGESTED": "🟣 AI suggestion"}.get(f.get("source"), f.get("source"))
            with st.expander(f"{i}. [{f.get('severity')}] {f.get('category')} — "
                             f"{f.get('file')}:{f.get('line')}  ·  {badge}"):
                if f.get("reason"):
                    st.markdown(f"**Why:** {f['reason']}")
                st.markdown(f"**Fix:** {f.get('recommendation')}")
                meta = [f"engine `{f.get('engine')}`", f"confidence {f.get('confidence')}"]
                if f.get("function"):
                    meta.append(f"function `{f['function']}()`")
                if f.get("cwe"):
                    meta.append(f.get("cwe"))
                if f.get("owasp"):
                    meta.append(f.get("owasp"))
                if f.get("evidence_ids"):
                    meta.append("evidence " + ", ".join(f["evidence_ids"]))
                st.caption(" · ".join(meta))

        cbom = report.get("quantum") or {}
        migration = [e for e in cbom.get("entries", [])
                     if e.get("status") in ("quantum_vulnerable", "classically_broken")]
        if migration:
            st.markdown("#### 🔄 Cryptographic migration plan")
            st_dataframe([{
                "Algorithm": e["algorithm"], "Uses": e["occurrences"],
                "Migrate to": e.get("migration_target"),
                "Standard": e.get("nist_standard"),
                "Files": ", ".join(e.get("files", [])[:3]),
            } for e in migration], use_container_width=True)


# ── Reports ──────────────────────────────────────────────────────────────────
with tab_rep:
    st.subheader("📄 Reports")
    if results_zip:
        st.download_button("⬇️ Download full scan package (.zip)", data=results_zip,
                           file_name=f"acg_scan_{scan_ts}.zip", mime="application/zip",
                           type="primary")
        st.caption(f"Package size ~{len(results_zip) // 1024} KB — includes JSON, "
                   f"SARIF, HTML, printable PDF, CSV exports, the evidence table "
                   f"and an executive summary.")

    st.divider()
    st.markdown("#### Individual formats")
    registry = load_builtin_plugins()
    columns = st.columns(4)
    for column, name in zip(columns, ("json", "sarif", "html", "csv")):
        reporter = registry.reporter(name)
        if reporter is None:
            continue
        with column:
            try:
                st.download_button(
                    f"{name.upper()}", data=reporter.render(report).encode(),
                    file_name=f"guardian_report{reporter.file_extension}",
                    mime="application/octet-stream", use_container_width=True)
            except Exception as exc:  # noqa: BLE001
                st.caption(f"{name}: {exc}")

    st.divider()
    with st.expander("🧾 Evidence store (the basis for every finding)"):
        evidence_items = report.get("evidence_items", [])
        if evidence_items:
            st_dataframe([{
                "ID": e["id"], "Type": e["type"], "Detector": e["source"],
                "Location": f"{e['file']}:{e['line']}" if e.get("file") else "",
                "Symbol": e.get("symbol", ""), "Observation": e.get("operation", ""),
                "Confidence": e.get("confidence"),
            } for e in evidence_items], use_container_width=True, height=380)
        else:
            st.caption("No evidence recorded.")

    with st.expander("📄 Raw report JSON"):
        st.json(report)


# ── AI Copilot ───────────────────────────────────────────────────────────────
with tab_ai:
    # The copilot needs a credential and the optional AI extras. Neither is
    # required for a scan, so every failure here is informational — an
    # unconfigured copilot must never take the results page down with it.
    try:
        from dashboard.chat_page import render_chat_page
        render_chat_page(report=report)
    except ImportError as exc:
        st.info("AI Copilot module not available. Install the AI extras: "
                "`pip install -r requirements_ai.txt`")
        st.caption(str(exc))
    except ValueError as exc:
        st.info("🤖 AI Copilot needs an NVIDIA API key.")
        st.caption(str(exc))
        st.caption("Everything in the other tabs is deterministic and complete "
                   "without it.")
    except Exception as exc:  # noqa: BLE001 — a chat failure is not a scan failure
        st.warning(f"AI Copilot unavailable: {exc}")
        st.caption("Deterministic results in the other tabs are unaffected.")
