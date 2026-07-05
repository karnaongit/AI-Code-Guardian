"""
AI Code Guardian - Streamlit Dashboard (Day 8)
Run with: streamlit run dashboard/app.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import streamlit as st

from core.security_rule_engine import SecurityRuleEngine
from core.risk_scoring import compute_risk_report

st.set_page_config(page_title="AI Code Guardian", layout="wide")
st.title("🛡️ AI Code Guardian")
st.caption("Secure Code Analysis & Business Intent Validation")

with st.sidebar:
    st.header("Scan Configuration")
    target_path = st.text_input("Path to scan (file or directory)", value=".")
    alignment_score = st.slider("Business Alignment Score (stub)", 0, 100, 75)
    run_scan = st.button("Run Scan", type="primary")

if run_scan:
    engine = SecurityRuleEngine()
    p = Path(target_path)
    if not p.exists():
        st.error(f"Path not found: {target_path}")
        st.stop()

    with st.spinner("Scanning..."):
        result = p.is_dir() and engine.scan_directory(p) or engine.scan_file(p)
        risk = compute_risk_report(result, alignment_score=alignment_score)

    st.session_state["result"] = result
    st.session_state["risk"] = risk

if "result" in st.session_state:
    result = st.session_state["result"]
    risk = st.session_state["risk"]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Security Score", f"{risk.security_score:.0f}/100")
    col2.metric("Alignment Score", f"{risk.alignment_score:.0f}/100")
    col3.metric("Maintainability", f"{risk.maintainability_score:.0f}/100")
    col4.metric("Overall Risk", f"{risk.overall_risk_score:.0f}/100")

    decision_color = {
        "Auto-Approve": "green",
        "Warn": "orange",
        "Block": "red",
        "Hard Block": "red",
    }
    color = next((c for k, c in decision_color.items() if risk.merge_decision.startswith(k)), "gray")
    st.markdown(f"**Merge Decision:** :{color}[{risk.merge_decision}]")

    st.divider()
    st.subheader(f"Findings ({len(result.findings)} across {result.files_scanned} files)")

    if result.findings:
        df = pd.DataFrame([f.to_dict() for f in result.findings])

        c1, c2 = st.columns(2)
        with c1:
            st.bar_chart(df["severity"].value_counts())
        with c2:
            st.bar_chart(df["category"].value_counts())

        severity_filter = st.multiselect("Filter by severity", df["severity"].unique().tolist(),
                                          default=df["severity"].unique().tolist())
        filtered = df[df["severity"].isin(severity_filter)]
        st.dataframe(
            filtered[["file", "line", "category", "severity", "confidence", "tainted", "snippet"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No findings detected.")
else:
    st.info("Configure a scan path in the sidebar and click **Run Scan** to begin.")
