"""
AI Code Guardian — RAG Pipeline
==================================
End-to-end pipeline:

    Question
      → RAGQuery
      → Retriever.retrieve()   (FAISS search, context merge)
      → PromptBuilder.build()  (structured prompt)
      → BaseLLM.chat()         (LLM generation, provider-agnostic)
      → AssistantResponse      (answer + citations + grounding flag)

Also provides a streaming variant for Streamlit token-by-token rendering.

Evaluation
----------
When config.eval_enabled is True, each response is logged to eval_log.jsonl
with metrics: retrieval_count, grounded, latency_ms.
"""
from __future__ import annotations

import logging
import time
from typing import  Optional

from typer import prompt
from rag.llm import SecurityLLM
from ai.conversation_memory import ConversationMemory
from ai.scan_context import exact_match_context, get_scan_summary_context
from ai.validator import ResponseValidator
from ai.models import (
    AssistantResponse,
    ChatMessage,
    MessageRole,
)
from rag.llm import SecurityLLM
from ai.prompt_builder import PromptBuilder
from rag.retriever import Retriever

logger = logging.getLogger(__name__)

_NOT_FOUND_MARKER = "I could not find evidence in the indexed repository"


import re

_GREETING_PATTERNS = {
    re.compile(r"^(hi|hello|hey|greetings|good\s+(morning|afternoon|evening))\b[\!\?\. ]*$", re.I):
        "Hello! How can I help you with your repository security scan or code review today?",
    re.compile(r"^(who\s+are\s+you|what\s+can\s+you\s+do|help|what\s+is\s+this)\b[\!\?\. ]*$", re.I):
        "I am your AI Code Guardian Assistant! I can help explain security vulnerabilities, risk scores, post-quantum crypto risks, and business intent findings.",
    re.compile(r"^(thanks|thank\s+you|thx|awesome|great|cool)\b[\!\?\. ]*$", re.I):
        "You're welcome! Let me know if you have any more questions about your codebase.",
    re.compile(r"^(bye|goodbye|cya|see\s+you)\b[\!\?\. ]*$", re.I):
        "Goodbye! Have a great day.",
}


def _get_conversational_response(question: str) -> Optional[str]:
    q = question.strip()
    for pat, resp in _GREETING_PATTERNS.items():
        if pat.match(q):
            return resp
    return None


class RAGPipeline:
    """
    The central coordinator. Inject all sub-components for testability.
    """

    def __init__(
        self,
        retriever,
        llm,
        prompt_builder,
        memory,
    ):
        self._retriever = retriever
        self._llm = llm
        self._builder = prompt_builder
        self._memory = memory

        self._scan_report = None
        self._validator = None
        
        
    def attach_scan_context(self, scan_report: dict | None = None,
                            repo_root: str | None = None) -> None:
        """Attach a scan report + repo root: enables exact-match finding
        injection and mechanical answer validation."""
        self._scan_report = scan_report
        self._validator = ResponseValidator(repo_root=repo_root,
                                            scan_report=scan_report)

    def set_retriever_index(self, index_name: str) -> None:
        """Switch the retriever to search a different FAISS index (e.g. a specific repository)."""
        if hasattr(self._retriever, "load_index"):
            self._retriever.load_index(index_name)

    # ------------------------------------------------------------------
    # Non-streaming
    # ------------------------------------------------------------------

    def ask(self, question: str, top_k: Optional[int] = None, investigation_context: str | None = None) -> AssistantResponse:
        t0 = time.time()

        # Handle greetings
        conv_resp = _get_conversational_response(question)
        if conv_resp:
            response = AssistantResponse(
                answer=conv_resp,
                citations=[],
                grounded=True,
                chunks_used=[],
                latency_ms=round((time.time() - t0) * 1000, 1),
            )
            self._memory.add_user_message(question)
            self._memory.add_assistant_message(response)
            return response

        # Retrieve relevant context
        context = ""
        retrieved_docs = []
        
        if investigation_context:
            context += "### Investigated Vulnerability Context\n"
            context += investigation_context + "\n\n"
        else:
            # Retrieve relevant context only if not in a scoped investigation
            retrieved_docs = self._retriever.search(question)

            # Inject scan findings if available
            exact_ctx = exact_match_context(question, self._scan_report)
            summary_ctx = get_scan_summary_context(self._scan_report)

            if summary_ctx:
                context += summary_ctx + "\n\n"

            if exact_ctx:
                context += exact_ctx + "\n\n"

            for doc in retrieved_docs:
                doc_type = doc.get("document_type", "security_reference")
                if doc_type == "repository":
                    context += f"""
            File: {doc.get('file')}
            Repository: {doc.get('repo')}
            Language: {doc.get('language')}
            Content:
            {doc.get('content')}

            """
                else:
                    context += f"""
            Source: {doc.get('source')}
            Vulnerability: {doc.get('vulnerability')}
            Description: {doc.get('description')}
            Recommendation: {doc.get('recommendation')}
            Reference: {doc.get('url')}

            """
        # Nothing found
        if not context.strip():
            response = AssistantResponse(
                answer=(
                    "I could not find relevant evidence in the indexed repository "
                    "or scan report."
                ),
                citations=[],
                grounded=False,
                chunks_used=[],
                latency_ms=round((time.time() - t0) * 1000, 1),
            )

            self._memory.add_user_message(question)
            self._memory.add_assistant_message(response)

            return response

        # Build prompt
        prompt = self._builder.build(
    question=question,
    context=context,
    history=self._memory.get_history(),
)

        # Ask LLM
        raw_answer = self._llm.chat(prompt)

        grounded = True

        # Validate response
        if self._validator:
            verdict = self._validator.validate(raw_answer)

            if not verdict.ok:
                raw_answer += verdict.warning_block()
                grounded = False

        latency = round((time.time() - t0) * 1000, 1)

        citations = []
        for doc in retrieved_docs:
            if doc.get("document_type") == "repository" and doc.get("file"):
                citations.append(doc.get("file"))
            elif doc.get("source"):
                citations.append(doc.get("source"))

        response = AssistantResponse(
            answer=self._append_citations(
                raw_answer,
                citations,
                grounded,
            ),
            citations=citations,
            grounded=grounded,
            chunks_used=retrieved_docs,
            latency_ms=latency,
        )

        self._memory.add_user_message(question)
        self._memory.add_assistant_message(response)

        return response

    def take_action(self, session, action, question=None, workspace_id=None):
        from ai.langgraph_orchestrator import LangGraphOrchestrator
        from ai.models import InvestigationResult
        import json
        
        # Instantiate orchestrator with existing dependencies
        orchestrator = LangGraphOrchestrator(self._llm, self._retriever)
        
        # Build initial state
        initial_state = {
            "workspace_id": workspace_id,
            "action": action,
            "session": session,
            "question": question,
            "repo_name": session.repository_id if session else "",
            "finding_id": session.finding_id if session else "",
            "evidence": "",
            "retrieved_context": "",
            "graph_context": "",
            "response": None,
            "error": None
        }
        
        # Invoke graph
        final_state = orchestrator.invoke(initial_state)
        
        # Return response
        if final_state.get("response"):
            return final_state["response"]
            
        return InvestigationResult(summary="Action failed to produce a response.")

    # ------------------------------------------------------------------
    # Streaming (for Streamlit st.write_stream)
    # ------------------------------------------------------------------

    def clear_history(self) -> None:
        self._memory.clear()

    def get_retrieval_context(self, question: str, top_k: int = 5):
        return self._retriever.search(question, top_k)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _append_citations(answer: str, citations: list[str], grounded: bool) -> str:
        if not citations or not grounded:
            return answer
        block = "\n\n---\n**Sources:**\n" + "\n".join(f"- {c}" for c in citations)
        # Don't duplicate if the LLM already added a Sources section
        if "Sources:" in answer or "sources:" in answer.lower():
            return answer
        return answer + block

