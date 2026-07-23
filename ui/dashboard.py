import streamlit as st

from ui.repository_view import show_repository
from ui.sidebar import show_sidebar
from ui.file_view import show_source_code
from ui.analysis_view import show_analysis
from ui.security_view import show_security
from ui.summary_view import show_summary

from github_api.file_service import FileService

from scanner.parser import PythonParser
from scanner.security_engine import SecurityEngine


def show_dashboard(repo, files):

    # -------------------------
    # Repository Information
    # -------------------------

    show_repository(repo)

    # -------------------------
    # Sidebar File Explorer
    # -------------------------

    selected = show_sidebar(files)

    if not selected:
        return

    # -------------------------
    # Load Selected File
    # -------------------------

    service = FileService()

    content = service.get_file_content(
        selected["download_url"]
    )

    # -------------------------
    # AST Analysis
    # -------------------------

    parser = PythonParser()

    analysis = parser.parse(content)

    # -------------------------
    # Security Scan
    # -------------------------

    engine = SecurityEngine()

    scan = engine.scan_source(
        content,
        selected["path"]
    )

    # -------------------------
    # Repository Summary
    # -------------------------

    show_summary(
        repo=repo,
        files=files,
        analysis=analysis,
        scan=scan
    )

    # -------------------------
    # Dashboard Tabs
    # -------------------------

    tab1, tab2, tab3 = st.tabs(
        [
            "📄 Source Code",
            "📊 Analysis",
            "🛡 Security"
        ]
    )

    # -------------------------
    # Source Code
    # -------------------------

    with tab1:

        show_source_code(content)

    # -------------------------
    # AST Analysis
    # -------------------------

    with tab2:

        if analysis:

            show_analysis(analysis)

        else:

            st.warning("Unable to analyze this file.")

    # -------------------------
    # Security Findings
    # -------------------------

    with tab3:

        show_security(scan)