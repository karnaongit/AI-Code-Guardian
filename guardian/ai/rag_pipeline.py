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

import json
import logging
import time
from pathlib import Path
from typing import Generator, Optional

from guardian.ai.config import AssistantConfig
from guardian.ai.conversation_memory import ConversationMemory
from guardian.ai.scan_context import exact_match_context
from guardian.ai.validator import ResponseValidator
from guardian.ai.models import (
    AssistantResponse, ChatMessage, MessageRole, RAGQuery, RAGResult,
)
from guardian.llm.base import BaseLLM, LLMError
from guardian.ai.prompt_builder import PromptBuilder
from guardian.ai.retriever import Retriever

logger = logging.getLogger(__name__)

_NOT_FOUND_MARKER = "I could not find evidence in the indexed repository"


class RAGPipeline:
    """
    The central coordinator. Inject all sub-components for testability.
    """

    def __init__(
        self,
        config: AssistantConfig,
        llm: BaseLLM,
        retriever: Retriever,
        prompt_builder: PromptBuilder,
        memory: ConversationMemory,
    ):
        self._cfg     = config
        self._llm     = llm
        self._retriever = retriever
        self._builder   = prompt_builder
        self._memory    = memory
        # Grounding + validation state (set via attach_scan_context)
        self._scan_report: dict | None = None
        self._validator: ResponseValidator | None = None

    def attach_scan_context(self, scan_report: dict | None = None,
                            repo_root: str | None = None) -> None:
        """Attach a scan report + repo root: enables exact-match finding
        injection and mechanical answer validation."""
        self._scan_report = scan_report
        self._validator = ResponseValidator(repo_root=repo_root,
                                            scan_report=scan_report)

    # ------------------------------------------------------------------
    # Non-streaming
    # ------------------------------------------------------------------

    def ask(self, question: str, top_k: Optional[int] = None) -> AssistantResponse:
        """
        Ask a question and return a complete AssistantResponse.
        Records the turn in conversation memory.
        """
        t0 = time.time()
        rag_query = RAGQuery(
            question=question,
            top_k=top_k or self._cfg.retrieval_top_k,
        )
        rag_result = self._retriever.retrieve(rag_query)
        exact_ctx = exact_match_context(question, self._scan_report)

        # Deterministic refusal: with no retrieved chunks passing the
        # relevance threshold AND no exact scan-report match, calling the
        # LLM can only produce fabrication. Refuse without inference.
        if not rag_result.chunks and not exact_ctx:
            refusal = ("I could not find evidence in the indexed repository "
                       "or scan report for this question. Try rephrasing, or "
                       "index the relevant documents/scan first.")
            response = AssistantResponse(
                answer=refusal, citations=[], grounded=False,
                chunks_used=[], latency_ms=round((time.time() - t0) * 1000, 1))
            self._memory.add_user_message(question)
            self._memory.add_assistant_message(response)
            return response

        if exact_ctx:
            rag_result.merged_context = exact_ctx + "\n\n" + rag_result.merged_context

        messages   = self._builder.build(
            question=question,
            rag_result=rag_result,
            history=self._memory.get_history(),
            repo_summary=self._memory.context.repo_summary,
        )

        try:
            raw_answer = self._llm.chat(messages).content
        except LLMError as exc:
            raw_answer = f"⚠️ LLM error: {exc}\n\nCheck NVIDIA_API_KEY and network connectivity."

        latency = (time.time() - t0) * 1000
        grounded = _NOT_FOUND_MARKER not in raw_answer and (bool(rag_result.chunks) or bool(exact_ctx))

        # Mechanical hallucination check (Master Design Doc §9.1):
        # unverifiable file/line/rule references demote the answer to
        # ungrounded and append an explicit warning for the user.
        if self._validator is not None:
            verdict = self._validator.validate(raw_answer)
            if not verdict.ok:
                raw_answer += verdict.warning_block()
                grounded = False

        response = AssistantResponse(
            answer=self._append_citations(raw_answer, rag_result.citations, grounded),
            citations=rag_result.citations,
            grounded=grounded,
            chunks_used=rag_result.chunks,
            latency_ms=round(latency, 1),
        )

        # Record in memory
        self._memory.add_user_message(question)
        self._memory.add_assistant_message(response)

        if self._cfg.eval_enabled:
            self._log_eval(question, rag_result, response)

        return response

    # ------------------------------------------------------------------
    # Streaming (for Streamlit st.write_stream)
    # ------------------------------------------------------------------

    def ask_stream(
        self,
        question: str,
        top_k: Optional[int] = None,
    ) -> Generator[str, None, None]:
        """
        Streaming version — yields token strings.
        Memory is updated after the generator is exhausted.
        """
        t0 = time.time()
        rag_query = RAGQuery(
            question=question,
            top_k=top_k or self._cfg.retrieval_top_k,
        )
        rag_result = self._retriever.retrieve(rag_query)
        messages   = self._builder.build(
            question=question,
            rag_result=rag_result,
            history=self._memory.get_history(),
            repo_summary=self._memory.context.repo_summary,
        )

        self._memory.add_user_message(question)
        accumulated = ""

        try:
            for token in self._llm.chat_stream(messages):
                accumulated += token
                yield token
        except LLMError as exc:
            error_msg = (
                f"\n\n⚠️ LLM error: {exc}\n"
                f"Check NVIDIA_API_KEY, model '{self._cfg.chat_model}', and connectivity."
            )
            accumulated += error_msg
            yield error_msg

        # Append citations after stream ends
        latency = (time.time() - t0) * 1000
        grounded = _NOT_FOUND_MARKER not in accumulated and bool(rag_result.chunks)
        citation_block = self._citation_block(rag_result.citations, grounded)
        if citation_block:
            yield citation_block
            accumulated += citation_block

        self._memory.add_assistant_text(accumulated, rag_result.citations)

    # ------------------------------------------------------------------
    # Context management
    # ------------------------------------------------------------------

    def clear_history(self) -> None:
        self._memory.clear()

    def get_retrieval_context(self, question: str, top_k: int = 5) -> RAGResult:
        """Expose raw retrieval result (used by Streamlit debug panel)."""
        return self._retriever.retrieve(
            RAGQuery(question=question, top_k=top_k)
        )

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

    @staticmethod
    def _citation_block(citations: list[str], grounded: bool) -> str:
        if not citations or not grounded:
            return ""
        return "\n\n---\n**Sources:**\n" + "\n".join(f"- {c}" for c in citations)

    def _log_eval(self, question: str, rag_result: RAGResult, response: AssistantResponse) -> None:
        """Append evaluation record to JSONL file."""
        record = {
            "question":         question,
            "retrieval_count":  len(rag_result.chunks),
            "grounded":         response.grounded,
            "latency_ms":       response.latency_ms,
            "top_sources":      response.citations[:3],
            "answer_length":    len(response.answer),
        }
        try:
            with open(self._cfg.eval_log_file, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass
