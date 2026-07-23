import streamlit as st


def show_summary(repo, files, analysis, scan):

    total_functions = len(analysis["functions"])
    total_classes = len(analysis["classes"])
    total_imports = len(analysis["imports"])
    total_variables = len(analysis["variables"])

    total_findings = len(scan.findings)

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric("📂 Files", len(files))
        st.metric("⚙ Functions", total_functions)

    with c2:
        st.metric("🏛 Classes", total_classes)
        st.metric("📦 Imports", total_imports)

    with c3:
        st.metric("🧩 Variables", total_variables)
        st.metric("🛡 Issues", total_findings)

    st.divider()