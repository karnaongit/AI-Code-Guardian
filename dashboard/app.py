"""
AI Code Guardian — Streamlit Dashboard (v5 File-Upload Edition)
================================================================
All inputs are now st.file_uploader widgets — no manual path typing.

Upload sections
---------------
1. Code to scan       → .zip (whole repo) OR individual .java/.py files
2. Requirements       → .xlsx / .json / .md / .txt
3. Security Policy    → .md / .txt
4. Scan results       → downloadable .zip at the end

Run with: streamlit run dashboard/app.py
"""
from __future__ import annotations

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

import pandas as pd
import streamlit as st

from guardian.scanner._engine import SecurityRuleEngine
from guardian.core.risk import compute_risk_report
from guardian.quantum import QuantumReadinessEngine
from guardian.intent.legacy import BusinessIntentEngine
from guardian.core.models import ScanResult

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
    st.markdown('<div class="upload-hint">Upload a <b>.zip</b> of your repo, or individual <b>.java</b> / <b>.py</b> source files.</div>', unsafe_allow_html=True)
    code_files = st.file_uploader(
        "Code files",
        type=["zip", "java", "py"],
        accept_multiple_files=True,
        key="code_upload",
        label_visibility="collapsed",
        help="ZIP = whole repo scan. Individual .java/.py = targeted scan."
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
        type=["xlsx", "xls", "json", "md", "txt", "csv"],
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


def _build_results_zip(result, risk, q_report, bi_report) -> bytes:
    """Pack all scan results into a downloadable ZIP."""
    buf = io.BytesIO()
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:

        # Full scan JSON
        full = {
            "generated_at": datetime.now().isoformat(),
            "risk":    risk.to_dict(),
            "quantum": q_report.to_dict(),
            "business_intent": bi_report.to_dict() if bi_report else None,
            "scan":    result.to_dict(),
        }
        zf.writestr(f"acg_scan_{ts}/full_report.json",
                    json.dumps(full, indent=2, default=str))

        # Findings CSV
        rows = [f.to_dict() for f in result.findings]
        if rows:
            df_all = pd.DataFrame(rows)
            zf.writestr(f"acg_scan_{ts}/all_findings.csv",
                        df_all.to_csv(index=False))

        # Security findings CSV
        sec_rows = [f.to_dict() for f in result.findings
                    if f.category not in ("Weak Crypto","Business Intent")]
        if sec_rows:
            zf.writestr(f"acg_scan_{ts}/security_findings.csv",
                        pd.DataFrame(sec_rows).to_csv(index=False))

        # Quantum CBOM CSV
        if q_report.cbom.usages:
            cbom_rows = [u.to_dict() for u in q_report.cbom.usages]
            zf.writestr(f"acg_scan_{ts}/quantum_cbom.csv",
                        pd.DataFrame(cbom_rows).to_csv(index=False))

        # Business Intent findings + missing rules
        if bi_report:
            zf.writestr(f"acg_scan_{ts}/business_intent_report.json",
                        json.dumps(bi_report.to_dict(), indent=2, default=str))
            if bi_report.missing_rules:
                missing_rows = [{
                    "story_id": r.requirement_id,
                    "rule": r.plain_english,
                    "type": r.rule_type.value,
                    "priority": r.priority,
                    "condition": r.condition or "",
                } for r in bi_report.missing_rules]
                zf.writestr(f"acg_scan_{ts}/missing_business_rules.csv",
                            pd.DataFrame(missing_rows).to_csv(index=False))

        # Executive summary TXT
        summary_lines = [
            "AI Code Guardian — Scan Summary",
            "=" * 40,
            f"Scan date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target          : {result.target}",
            f"Files scanned   : {result.files_scanned}",
            f"Total findings  : {len(result.findings)}",
            "",
            "SCORES",
            f"  Security Score     : {risk.security_score:.1f}/100",
            f"  Alignment Score    : {risk.alignment_score:.1f}/100",
            f"  Maintainability    : {risk.maintainability_score:.1f}/100",
            f"  Quantum Readiness  : {q_report.readiness_score:.1f}/100",
            f"  Overall Risk Score : {risk.overall_risk_score:.1f}/100",
            "",
            f"Merge Decision  : {risk.merge_decision}",
            "",
        ]
        if bi_report:
            summary_lines += [
                "BUSINESS INTENT",
                bi_report.narrative,
                "",
            ]
        summary_lines += [
            "FINDINGS BY SEVERITY",
        ] + [f"  {k}: {v}" for k, v in result.counts_by_severity.items()]

        zf.writestr(f"acg_scan_{ts}/executive_summary.txt",
                    "\n".join(summary_lines))

    buf.seek(0)
    return buf.read()


# ═══════════════════════════════════════════════════════════════════════════
# RUN SCAN
# ═══════════════════════════════════════════════════════════════════════════

if run_btn and (code_files or github_url.strip()):

    # Reset pointer for all uploaded files (Streamlit rewinds on rerun)
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
        # 1. Save uploaded code or fetch GitHub repository
        code_dir = tmp_root / "code"
        code_dir.mkdir()
        with st.spinner("📦 Preparing code repository for scanning..."):
            _save_uploaded_code(code_files or [], code_dir, github_url.strip())
            actual_files = list(code_dir.rglob("*"))
            st.toast(f"✅ {len(actual_files)} files ready for scanning")

        # 2. Save requirements
        req_paths: list[Path] = []
        if req_files:
            req_dir = tmp_root / "requirements"
            req_dir.mkdir()
            req_paths = _save_uploaded_requirements(req_files, req_dir)

        # 3. Save policy
        policy_path_saved = _save_policy(policy_file, tmp_root) if policy_file else None

        # 4. Security scan
        with st.spinner("🔐 Running Security Rule Engine..."):
            sec_engine = SecurityRuleEngine()
            sec_result = sec_engine.scan_directory(code_dir)

        # 5. Quantum scan
        with st.spinner("⚛️ Running Quantum Readiness Engine..."):
            qe = QuantumReadinessEngine()
            q_report, q_findings = qe.analyze(code_dir)

        # 6. Business intent
        bi_report, bi_findings = None, []
        if req_paths:
            with st.spinner("🎯 Running Business Intent Engine..."):
                bie = BusinessIntentEngine()
                try:
                    bi_report, bi_findings = bie.analyze(
                        req_paths[0] if len(req_paths) == 1 else [str(p) for p in req_paths],
                        code_dir,
                        policy_path=policy_path_saved,
                    )
                except Exception as e:
                    st.warning(f"Business Intent Engine: {e}")

        # 7. Risk scoring
        all_findings = sec_result.findings + q_findings + bi_findings
        merged = ScanResult(
            target=f"{len(code_files)} uploaded file(s)",
            files_scanned=sec_result.files_scanned,
            findings=all_findings,
        )
        merged.finish()
        alignment = bi_report.alignment_score if bi_report else 75.0
        risk = compute_risk_report(
            merged, alignment_score=alignment,
            maintainability_score=q_report.readiness_score * 0.8 + 20,
        )

        # 8. Build downloadable results ZIP
        results_zip = _build_results_zip(merged, risk, q_report, bi_report)

        st.session_state.update({
            "result":      merged,
            "risk":        risk,
            "q_report":    q_report,
            "bi_report":   bi_report,
            "bi_findings": bi_findings,
            "results_zip": results_zip,
            "scan_ts":     datetime.now().strftime("%Y%m%d_%H%M%S"),
        })

    except Exception as e:
        st.error(f"Scan failed: {e}")
        import traceback
        st.code(traceback.format_exc())
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
# RENDER RESULTS
# ═══════════════════════════════════════════════════════════════════════════

if "result" not in st.session_state:
    st.stop()

result      = st.session_state["result"]
risk        = st.session_state["risk"]
q_report    = st.session_state["q_report"]
bi_report   = st.session_state.get("bi_report")
bi_findings = st.session_state.get("bi_findings", [])
results_zip = st.session_state.get("results_zip")
scan_ts     = st.session_state.get("scan_ts", "scan")

# ── Score banner ─────────────────────────────────────────────────────────────
st.subheader("📊 Risk Dashboard")
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("🔐 Security",        f"{risk.security_score:.0f}/100")
c2.metric("🎯 Alignment",       f"{risk.alignment_score:.0f}/100")
c3.metric("🔧 Maintainability", f"{risk.maintainability_score:.0f}/100")
c4.metric("⚛️ Quantum Ready",   f"{q_report.readiness_score:.0f}/100")
c5.metric("⚠️ Overall Risk",    f"{risk.overall_risk_score:.0f}/100")

# ── Merge decision + download ────────────────────────────────────────────────
dec_col, dl_col = st.columns([3, 2])
with dec_col:
    cmap      = {"Auto-Approve": "green", "Warn": "orange", "Block": "red", "Hard": "red"}
    dec_color = next((v for k, v in cmap.items() if risk.merge_decision.startswith(k)), "gray")
    st.markdown(f"### Merge Decision: :{dec_color}[{risk.merge_decision}]")
with dl_col:
    if results_zip:
        st.download_button(
            label="⬇️  Download Full Scan Report (.zip)",
            data=results_zip,
            file_name=f"acg_scan_{scan_ts}.zip",
            mime="application/zip",
            use_container_width=True,
            type="secondary",
        )

st.divider()

# ── Findings summary bar ─────────────────────────────────────────────────────
total_f = len(result.findings)
sev_counts = result.counts_by_severity
if total_f:
    badges = " · ".join(
        f"🔴 {sev_counts.get('Critical',0)} Critical  "
        f"🟠 {sev_counts.get('High',0)} High  "
        f"🟡 {sev_counts.get('Medium',0)} Medium  "
        f"🟢 {sev_counts.get('Low',0)} Low".split("  ")
    )
    st.caption(f"**{total_f} total findings** across {result.files_scanned} files · "
               + "  ".join([
                   f"🔴 {sev_counts.get('Critical',0)} Critical",
                   f"🟠 {sev_counts.get('High',0)} High",
                   f"🟡 {sev_counts.get('Medium',0)} Medium",
                   f"🟢 {sev_counts.get('Low',0)} Low",
               ]))

# ═══════════════════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════════════════
tab_sec, tab_q, tab_bi, tab_dl, tab_ai, tab_raw = st.tabs([
    "🔐 Security Findings",
    "⚛️ Quantum CBOM",
    "🎯 Business Intent",
    "⬇️ Download Results",
    "🤖 AI Copilot",
    "📄 Raw JSON",
])

# ── Security tab ──────────────────────────────────────────────────────────────
with tab_sec:
    sec_f = [f for f in result.findings if f.category not in ("Weak Crypto", "Business Intent")]
    st.subheader(f"Security Findings  ({len(sec_f)})")
    if sec_f:
        df_sec = pd.DataFrame([f.to_dict() for f in sec_f])
        col1, col2 = st.columns(2)
        with col1:
            st.caption("By Severity")
            st.bar_chart(df_sec["severity"].value_counts())
        with col2:
            st.caption("By Category")
            st.bar_chart(df_sec["category"].value_counts())

        sev_opts = df_sec["severity"].unique().tolist()
        sev_filter = st.multiselect("Filter by severity", sev_opts,
                                     default=sev_opts, key="sec_filter")
        filtered = df_sec[df_sec["severity"].isin(sev_filter)]

        # Per-finding expandable cards for high/critical
        high_sec = [f for f in sec_f if f.severity in ("Critical","High")]
        if high_sec:
            st.markdown(f"**{len(high_sec)} High/Critical findings — expand to see details:**")
            for f in high_sec[:10]:
                icon = "🔴" if f.severity == "Critical" else "🟠"
                with st.expander(f"{icon} [{f.severity}] {f.category} — `{Path(f.file).name}` line {f.line}"):
                    st.code(f.snippet, language="java" if f.file.endswith(".java") else "python")
                    st.markdown(f"**Recommendation:** {f.recommendation}")
                    st.caption(f"Rule: {f.rule_id} · Confidence: {f.confidence:.0%} · File: {f.file}")

        st.divider()
        st.caption("All security findings table")
        st.dataframe(
            filtered[["file","line","category","severity","confidence","tainted","snippet"]],
            use_container_width=True, hide_index=True,
        )

        # Per-file CSV download
        st.download_button(
            "⬇️ Download security findings CSV",
            data=df_sec.to_csv(index=False).encode(),
            file_name=f"security_findings_{scan_ts}.csv",
            mime="text/csv",
        )
    else:
        st.success("✅ No security findings detected.")

# ── Quantum tab ───────────────────────────────────────────────────────────────
with tab_q:
    st.subheader(f"Cryptographic Bill of Materials")
    score_col, info_col = st.columns([1, 3])
    with score_col:
        score_val = q_report.readiness_score
        color = "green" if score_val >= 75 else "orange" if score_val >= 40 else "red"
        st.markdown(f"### :{color}[{score_val:.0f}/100]")
        st.caption("Quantum Readiness Score")
    with info_col:
        st.info(
            "This score measures how much of your cryptography is already quantum-safe. "
            "100 = fully resistant to known quantum attacks. "
            "Algorithms like RSA, ECC, and SHA-1 are flagged as vulnerable."
        )

    cbom = q_report.cbom
    if cbom.usages:
        dq = pd.DataFrame([u.to_dict() for u in cbom.usages])
        col1, col2 = st.columns(2)
        with col1:
            st.caption("By Threat Level")
            st.bar_chart(dq["threat_level"].value_counts())
        with col2:
            st.caption("By Algorithm Family")
            st.bar_chart(dq["family"].value_counts())

        st.dataframe(
            dq[["file","line","algorithm","family","threat_level","context","snippet"]],
            use_container_width=True, hide_index=True,
        )

        st.download_button(
            "⬇️ Download CBOM CSV",
            data=dq.to_csv(index=False).encode(),
            file_name=f"quantum_cbom_{scan_ts}.csv",
            mime="text/csv",
        )

        if q_report.recommendations:
            st.divider()
            st.subheader("🔄 NIST PQC Migration Recommendations")
            for rec in q_report.recommendations:
                with st.expander(f"**{rec.vulnerable_algorithm}** → {rec.replacement_algorithm}  |  Effort: {rec.migration_effort}"):
                    st.markdown(f"**NIST Standard:** {rec.nist_standard}")
                    st.markdown(f"**Why migrate:** {rec.rationale}")
                    if rec.example_code:
                        st.code(rec.example_code, language="python")
                    if rec.references:
                        st.caption("References: " + " · ".join(rec.references[:2]))
    else:
        st.success("✅ No quantum-vulnerable algorithms detected.")

# ── Business Intent tab ───────────────────────────────────────────────────────
with tab_bi:
    if bi_report:
        st.subheader("📋 Business Alignment Summary")
        st.info(bi_report.narrative)

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Alignment",        f"{bi_report.alignment_score:.0f}/100")
        c2.metric("Total Rules",       bi_report.total_rules)
        c3.metric("✅ Matched",        bi_report.matched)
        c4.metric("⚠️ Partial",        bi_report.partial)
        c5.metric("❌ Not Implemented", bi_report.not_implemented)

        if bi_report.violated > 0:
            st.error(f"🚨 {bi_report.violated} rule(s) VIOLATED — code actively contradicts requirements!")

        if bi_findings:
            st.divider()
            st.subheader(f"📌 Business Intent Findings  ({len(bi_findings)})")

            for i, f in enumerate(bi_findings):
                icon = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(f.severity,"⚪")
                with st.expander(
                    f"{icon} [{f.severity}]  {f.snippet}",
                    expanded=(f.severity in ("Critical","High") and i < 5)
                ):
                    for line in f.recommendation.split("\n"):
                        if line.startswith("WHAT:"):
                            st.markdown(f"**What happened:** {line[5:].strip()}")
                        elif line.startswith("WHY:"):
                            st.warning(f"**Business Impact:** {line[4:].strip()}")
                        elif line.startswith("HOW:"):
                            st.markdown("**How to fix it:**")
                        elif re.match(r"^\s+\d+\.", line):
                            st.markdown(f"- {line.strip()}")
                        elif line.startswith("SOURCE REQUIREMENT:"):
                            st.caption(line)
                    st.markdown(f"*File: `{f.file}`  ·  Confidence: {f.confidence:.0%}*")

        if bi_report.missing_rules:
            st.divider()
            st.subheader("📋 Missing Business Rules")
            rows = [{"Story ID": r.requirement_id, "Rule": r.plain_english,
                     "Type": r.rule_type.value, "Priority": r.priority,
                     "Condition": r.condition or "—"} for r in bi_report.missing_rules]
            df_missing = pd.DataFrame(rows)
            st.dataframe(df_missing, use_container_width=True, hide_index=True)
            st.download_button(
                "⬇️ Download Missing Rules CSV",
                data=df_missing.to_csv(index=False).encode(),
                file_name=f"missing_rules_{scan_ts}.csv",
                mime="text/csv",
            )

        matched_matches = [m for m in bi_report.matches if m.status.value == "Matched"]
        if matched_matches:
            with st.expander(f"✅ {len(matched_matches)} correctly implemented rules"):
                for m in matched_matches[:20]:
                    st.markdown(f"- **{m.rule.plain_english}** — `{m.matched_artefact}`")
    else:
        st.info("Upload a requirements file (XLSX/JSON/MD/TXT) to enable Business Intent analysis.")
        st.markdown("""
**Supported requirement formats:**

| Format | Columns / Structure |
|---|---|
| `.xlsx` | Story_ID, Title, Business_Intent, Acceptance_Criteria, Priority |
| `.json` | `[{id, title, description, acceptance_criteria}]` |
| `.md` | Any Markdown with H2/H3 section headings |
| `.txt` | Plain text — each sentence analysed for rules |
        """)

# ── Download tab ──────────────────────────────────────────────────────────────
with tab_dl:
    st.subheader("⬇️ Download Scan Results")
    st.markdown("""
The scan results package contains:

| File | Contents |
|---|---|
| `full_report.json` | Complete machine-readable scan data |
| `all_findings.csv` | Every finding across all engines |
| `security_findings.csv` | Security-only findings |
| `quantum_cbom.csv` | Cryptographic Bill of Materials |
| `business_intent_report.json` | Business alignment detail |
| `missing_business_rules.csv` | Unimplemented requirements |
| `executive_summary.txt` | Plain-English summary for management |
    """)

    if results_zip:
        st.download_button(
            label="⬇️ Download Full Scan Report (.zip)",
            data=results_zip,
            file_name=f"acg_scan_{scan_ts}.zip",
            mime="application/zip",
            use_container_width=False,
            type="primary",
        )
        size_kb = len(results_zip) // 1024
        st.caption(f"Package size: ~{size_kb} KB")
    else:
        st.warning("Run a scan first to generate the download package.")

    st.divider()
    st.subheader("Per-Engine Downloads")
    dl1, dl2, dl3 = st.columns(3)

    # Security CSV
    sec_rows = [f.to_dict() for f in result.findings if f.category not in ("Weak Crypto","Business Intent")]
    with dl1:
        if sec_rows:
            st.download_button(
                "🔐 Security Findings\n(.csv)",
                data=pd.DataFrame(sec_rows).to_csv(index=False).encode(),
                file_name=f"security_{scan_ts}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        else:
            st.button("🔐 Security Findings\n(none)", disabled=True, use_container_width=True)

    # CBOM CSV
    with dl2:
        if q_report.cbom.usages:
            cbom_df = pd.DataFrame([u.to_dict() for u in q_report.cbom.usages])
            st.download_button(
                "⚛️ Quantum CBOM\n(.csv)",
                data=cbom_df.to_csv(index=False).encode(),
                file_name=f"cbom_{scan_ts}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        else:
            st.button("⚛️ Quantum CBOM\n(none)", disabled=True, use_container_width=True)

    # Business Intent JSON
    with dl3:
        if bi_report:
            st.download_button(
                "🎯 Business Intent\n(.json)",
                data=json.dumps(bi_report.to_dict(), indent=2, default=str).encode(),
                file_name=f"business_intent_{scan_ts}.json",
                mime="application/json",
                use_container_width=True,
            )
        else:
            st.button("🎯 Business Intent\n(no req file)", disabled=True, use_container_width=True)

# ── AI Copilot tab ───────────────────────────────────────────────────────────
with tab_ai:
    try:
        from dashboard.chat_page import render_chat_page
        render_chat_page(
            scan_result=result,
            risk_report=risk,
            bi_report=bi_report,
            quantum_report=q_report,
        )
    except ImportError as _e:
        st.info(
            "AI Copilot module not available. "
            "Install dependencies: `pip install faiss-cpu openai sentence-transformers transformers torch`"
        )
        st.caption(str(_e))

# ── Raw JSON tab ──────────────────────────────────────────────────────────────
with tab_raw:
    st.json({
        "risk":            risk.to_dict(),
        "quantum":         q_report.to_dict(),
        "business_intent": bi_report.to_dict() if bi_report else None,
        "scan":            result.to_dict(),
    })
