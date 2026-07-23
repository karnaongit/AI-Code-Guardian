"""
AI Code Guardian — AI Copilot Chat Page (Streamlit)
=====================================================
Renders the full RAG chatbot UI inside the existing dashboard.

Features
--------
- File upload to index a new repo or documents
- One-click "Index last scan results" to make findings searchable
- Streaming token-by-token responses
- Citations panel (what sources were used)
- Index stats sidebar
- Suggested questions for quick start
- Clear history button
- Model selector (NVIDIA Nemotron models available to the API key)

Designed to be imported by the main app.py:
    from dashboard.chat_page import render_chat_page
    render_chat_page(scan_result, risk_report, bi_report, quantum_report)
"""
from __future__ import annotations

import io
import json
import logging
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import os

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session-state key constants
# ---------------------------------------------------------------------------
_KEY_COPILOT     = "acg_copilot"
_KEY_CHAT_HIST   = "acg_chat_history"      # list of (role, text, citations)
_KEY_INDEXING    = "acg_indexing_done"


# ---------------------------------------------------------------------------
# Copilot singleton (one per Streamlit session)
# ---------------------------------------------------------------------------

def _get_copilot(chat_model: str = "llama3.1"):
    """Return the AISecurityCopilot singleton from session state."""
    if _KEY_COPILOT not in st.session_state:
        from guardian.ai.chatbot import AISecurityCopilot
        from guardian.ai.config import AssistantConfig
        cfg = AssistantConfig(chat_model=chat_model)
        with st.spinner("🤖 Initialising AI Copilot..."):
            st.session_state[_KEY_COPILOT] = AISecurityCopilot.create(cfg)
    return st.session_state[_KEY_COPILOT]


# ---------------------------------------------------------------------------
# Suggested prompts
# ---------------------------------------------------------------------------
_SUGGESTED = [
    "Explain the most critical vulnerability found",
    "Summarise the business intent findings",
    "Where is authentication implemented?",
    "Show all SQL injection risks",
    "Explain the quantum readiness report",
    "Which files violate the security policy?",
    "What is the overall risk score and why?",
    "Generate a threat model for this repository",
    "Where is JWT implemented?",
    "List all hardcoded secrets found",
    "Which business requirements are missing from the code?",
    "Explain the authentication flow in detail",
]


# ---------------------------------------------------------------------------
# Main render function
# ---------------------------------------------------------------------------

def render_chat_page(
    scan_result=None,
    risk_report=None,
    bi_report=None,
    quantum_report=None,
) -> None:
    """
    Render the full AI Copilot chat page.
    Call from the main dashboard tab.
    """
    st.subheader("🤖 AI Security Copilot")
    st.caption("Ask anything about your codebase, findings, or security policy — powered by NVIDIA Nemotron + local RAG.")

    # ── Sidebar controls ──────────────────────────────────────────────
    with st.sidebar:
        st.divider()
        st.markdown("### 🤖 AI Copilot Settings")

        # Model selector
        copilot_placeholder = st.empty()   # render after model select
        model_input = st.text_input(
            "Nemotron model",
            value=st.session_state.get(
                "acg_model",
                os.getenv("NVIDIA_MODEL", "nvidia/llama-3.3-nemotron-super-49b-v1")),
            help="Any NVIDIA NIM model your API key can access, e.g. "
                 "nvidia/llama-3.3-nemotron-super-49b-v1",
            key="acg_model_input",
        )
        if st.button("Apply model", key="acg_apply_model"):
            st.session_state["acg_model"] = model_input
            if _KEY_COPILOT in st.session_state:
                del st.session_state[_KEY_COPILOT]
            st.rerun()

        st.divider()
        if st.button("🗑️ Clear chat history", key="acg_clear_hist"):
            st.session_state.pop(_KEY_CHAT_HIST, None)
            if _KEY_COPILOT in st.session_state:
                st.session_state[_KEY_COPILOT].clear_history()
            st.rerun()

    # ── Init copilot ──────────────────────────────────────────────────
    chat_model = st.session_state.get("acg_model", model_input)
    copilot = _get_copilot(chat_model)

    # ── LLM provider health check ─────────────────────────────────────
    if not copilot.is_llm_healthy():
        st.error(
            "⚠️ **NVIDIA Nemotron is unreachable.**\n\n"
            "1. Set your API key: `export NVIDIA_API_KEY='nvapi-...'`\n"
            f"2. Confirm the model name is valid: `{chat_model}`\n"
            "3. Check network access to `integrate.api.nvidia.com`, then refresh."
        )
        _render_nemotron_setup_guide(chat_model)
        return

    # ── Index scan results (auto, once per session) ───────────────────
    _auto_index_reports(copilot, scan_result, risk_report, bi_report, quantum_report)

    # ── Two-column layout: chat | index panel ─────────────────────────
    chat_col, panel_col = st.columns([3, 1])

    with panel_col:
        _render_index_panel(copilot)
        _render_stats(copilot)

    with chat_col:
        _render_chat(copilot)


# ---------------------------------------------------------------------------
# Auto-index reports from the current scan session
# ---------------------------------------------------------------------------

def _auto_index_reports(copilot, scan_result, risk_report, bi_report, quantum_report) -> None:
    """Index the latest scan results into the vector store (once per session)."""
    if st.session_state.get(_KEY_INDEXING):
        return

    indexed_something = False
    with st.spinner("📚 Indexing scan results into AI knowledge base..."):
        try:
            if scan_result:
                copilot.index_scan_report(scan_result.to_dict(), "scan_report.json")
                indexed_something = True
            if risk_report:
                copilot.index_scan_report(risk_report.to_dict(), "risk_report.json")
                indexed_something = True
            if bi_report:
                copilot.index_business_intent(bi_report.to_dict())
                indexed_something = True
            if quantum_report:
                copilot.index_quantum_report(quantum_report.to_dict())
                indexed_something = True
        except Exception as exc:
            logger.warning("Auto-index failed: %s", exc)

    if indexed_something:
        st.session_state[_KEY_INDEXING] = True
        st.toast("✅ Scan results indexed — copilot is ready!", icon="🤖")


# ---------------------------------------------------------------------------
# Index panel (right column)
# ---------------------------------------------------------------------------

def _render_index_panel(copilot) -> None:
    st.markdown("#### 📁 Index Files")

    upload_tab, dir_tab = st.tabs(["Upload", "Directory"])

    with upload_tab:
        uploaded = st.file_uploader(
            "Add to knowledge base",
            type=["zip","java","py","md","txt","json","yaml","yml","pdf","docx","csv","xml","sql"],
            accept_multiple_files=True,
            key="acg_file_upload",
            label_visibility="collapsed",
        )
        if uploaded and st.button("📚 Index uploaded files", key="acg_idx_upload"):
            _index_uploaded_files(copilot, uploaded)

    with dir_tab:
        dir_path = st.text_input("Local path", key="acg_dir_path",
                                  placeholder="e.g. C:\\repos\\myproject")
        if st.button("📚 Index directory", key="acg_idx_dir"):
            p = Path(dir_path)
            if p.exists() and p.is_dir():
                with st.spinner(f"Indexing {p} ..."):
                    stats = copilot.index_directory(p)
                st.success(f"Indexed {stats.total_documents} chunks")
            else:
                st.error(f"Directory not found: {dir_path}")


def _index_uploaded_files(copilot, uploaded_files) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="acg_chat_"))
    paths = []
    for uf in uploaded_files:
        data = uf.read()
        if uf.name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(tmp)
            paths += list(tmp.rglob("*"))
        else:
            fp = tmp / uf.name
            fp.write_bytes(data)
            paths.append(fp)

    with st.spinner(f"Indexing {len(paths)} files..."):
        count = copilot.index_uploaded_files([p for p in paths if p.is_file()], root=tmp)
    st.success(f"✅ Indexed {count} chunks from {len(uploaded_files)} file(s)")


def _render_stats(copilot) -> None:
    with st.expander("📊 Index Stats", expanded=False):
        try:
            stats = copilot.get_stats()
            st.metric("Total chunks",   stats.total_documents)
            st.metric("Code vectors",   stats.code_vectors)
            st.metric("Doc vectors",    stats.doc_vectors)
            if stats.languages:
                st.caption("Languages: " + ", ".join(
                    f"{l}({c})" for l, c in list(stats.languages.items())[:5]
                ))
        except Exception:
            st.caption("Index not yet built")


# ---------------------------------------------------------------------------
# Main chat UI
# ---------------------------------------------------------------------------

def _render_chat(copilot) -> None:
    # Suggested questions (shown when history is empty)
    hist = st.session_state.get(_KEY_CHAT_HIST, [])
    if not hist:
        st.markdown("**💡 Suggested questions:**")
        cols = st.columns(3)
        for i, suggestion in enumerate(_SUGGESTED[:9]):
            with cols[i % 3]:
                if st.button(suggestion, key=f"sug_{i}", use_container_width=True):
                    _send_message(copilot, suggestion)
                    st.rerun()
        st.divider()

    # Render existing history
    for role, content, citations in st.session_state.get(_KEY_CHAT_HIST, []):
        with st.chat_message(role):
            st.markdown(content)
            if citations:
                with st.expander(f"📎 {len(citations)} source(s)", expanded=False):
                    for c in citations:
                        st.caption(f"• {c}")

    # Input box
    if prompt := st.chat_input("Ask about your code, findings, or security policy..."):
        _send_message(copilot, prompt)


def _send_message(copilot, question: str) -> None:
    """Render user message, stream response, update history."""
    if _KEY_CHAT_HIST not in st.session_state:
        st.session_state[_KEY_CHAT_HIST] = []

    # Show user message
    with st.chat_message("user"):
        st.markdown(question)
    st.session_state[_KEY_CHAT_HIST].append(("user", question, []))

    # Stream assistant response
    with st.chat_message("assistant"):
        response_placeholder = st.empty()
        citations_placeholder = st.empty()
        accumulated = ""
        citations   = []

        try:
            for token in copilot.ask_stream(question):
                accumulated += token
                response_placeholder.markdown(accumulated + "▌")

            response_placeholder.markdown(accumulated)

            # Extract citations from last memory entry
            hist = copilot.memory.get_history()
            if hist:
                last = hist[-1]
                citations = last.metadata.get("citations", [])
                if citations:
                    with citations_placeholder.expander(
                        f"📎 {len(citations)} source(s)", expanded=False
                    ):
                        for c in citations:
                            st.caption(f"• {c}")

        except Exception as exc:
            err = f"⚠️ Error: {exc}"
            response_placeholder.error(err)
            accumulated = err

    st.session_state[_KEY_CHAT_HIST].append(("assistant", accumulated, citations))


# ---------------------------------------------------------------------------
# Nemotron setup guide (shown when the provider is unreachable)
# ---------------------------------------------------------------------------

def _render_nemotron_setup_guide(model: str) -> None:
    with st.expander("📖 How to set up NVIDIA Nemotron", expanded=True):
        st.markdown(f"""
### Quick Setup Guide

**1. Get an NVIDIA API key**

Sign in at [build.nvidia.com](https://build.nvidia.com/) and create an API key
(starts with `nvapi-`).

**2. Configure credentials**
```bash
export NVIDIA_API_KEY='nvapi-...'
# optional overrides
export NVIDIA_MODEL='{model}'
export NVIDIA_BASE_URL='https://integrate.api.nvidia.com/v1'
```
Or copy `.env.example` to `.env` and fill it in.

**3. Install the client**
```bash
pip install openai sentence-transformers faiss-cpu
```

**4. Refresh this page**

> ⚠️ **Data-residency note:** Nemotron is a hosted API. Code snippets and
> findings selected for analysis leave your network. Secrets are redacted
> before transmission by the guardrail layer, and embeddings are computed
> locally — but review this against your data-handling policy before
> scanning confidential repositories.
        """)
