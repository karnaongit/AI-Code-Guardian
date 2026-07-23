import streamlit as st

from github_api.repository_service import RepositoryService
from github_api.file_service import FileService

from ui.home import show_home
from ui.dashboard import show_dashboard

st.set_page_config(page_title="AI Code Guardian", layout="wide")

# Session state
if "repository_loaded" not in st.session_state:
    st.session_state.repository_loaded = False

if "repo" not in st.session_state:
    st.session_state.repo = None

if "files" not in st.session_state:
    st.session_state.files = []

repo_url = ""
analyze = False

if not st.session_state.repository_loaded:
    repo_url, analyze = show_home()

if analyze:

    repo_name = repo_url.replace(
        "https://github.com/",
        ""
    ).strip()

    repo_service = RepositoryService()
    file_service = FileService()

    st.session_state.repo = repo_service.get_repository_details(repo_name)
    st.session_state.files = file_service.get_python_files(repo_name)

    st.session_state.repository_loaded = True

if st.session_state.repository_loaded:

    show_dashboard(
        st.session_state.repo,
        st.session_state.files
    )