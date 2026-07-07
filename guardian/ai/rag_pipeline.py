"""
AI Code Guardian — RAG Pipeline
==================================
End-to-end pipeline:

    Question
      → RAGQuery
      → Retriever.retrieve()   (FAISS search, context merge)
      → PromptBuilder.build()  (structured prompt)
      → OllamaClient.chat()    (LLM generation)
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
from guardian.ai.models import (
    AssistantResponse, ChatMessage, MessageRole, RAGQuery, RAGResult,
)
from guardian.ai.ollama_client import OllamaClient, OllamaClientError
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
        ollama_client: OllamaClient,
        retriever: Retriever,
        prompt_builder: PromptBuilder,
        memory: ConversationMemory,
    ):
        self._cfg     = config
        self._ollama  = ollama_client
        self._retriever = retriever
        self._builder   = prompt_builder
        self._memory    = memory

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
        messages   = self._builder.build(
            question=question,
            rag_result=rag_result,
            history=self._memory.get_history(),
            repo_summary=self._memory.context.repo_summary,
        )

        try:
            raw_answer = self._ollama.chat(messages)
        except OllamaClientError as exc:
            raw_answer = f"⚠️ Ollama error: {exc}\n\nMake sure Ollama is running and the model '{self._cfg.chat_model}' is pulled."

        latency = (time.time() - t0) * 1000
        grounded = _NOT_FOUND_MARKER not in raw_answer and bool(rag_result.chunks)

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
            for token in self._ollama.chat_stream(messages):
                accumulated += token
                yield token
        except OllamaClientError as exc:
            error_msg = (
                f"\n\n⚠️ Ollama error: {exc}\n"
                f"Make sure Ollama is running and '{self._cfg.chat_model}' is pulled."
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
