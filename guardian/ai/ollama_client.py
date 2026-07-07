"""
AI Code Guardian — Ollama Client
==================================
Thin wrapper around the Ollama Python SDK.

Responsibilities
----------------
- Chat completions (streaming + non-streaming)
- Text embeddings via nomic-embed-text (or any configured model)
- Health check (is Ollama running? is the model pulled?)
- Retry logic and timeout handling

This module is the ONLY place that talks to Ollama.
All other modules call this client — no direct Ollama SDK usage elsewhere.
"""
from __future__ import annotations

import logging
import time
from typing import Generator, Optional

from guardian.ai.config import AssistantConfig

logger = logging.getLogger(__name__)


class OllamaClientError(Exception):
    """Raised when the Ollama server is unreachable or returns an error."""


class OllamaClient:
    """
    Thread-safe Ollama client.
    Designed for injection — pass one instance to all components that need it.
    """

    def __init__(self, config: AssistantConfig):
        self._cfg = config
        self._client = self._build_client()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _build_client(self):
        try:
            import ollama
            return ollama.Client(host=self._cfg.ollama_base_url)
        except ImportError:
            raise OllamaClientError(
                "ollama Python package not installed. Run: pip install ollama"
            )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def is_healthy(self) -> bool:
        """Return True if Ollama is reachable and the chat model is available."""
        try:
            models = self._client.list()
            names = [m.model for m in models.models]
            return any(self._cfg.chat_model in n for n in names)
        except Exception as exc:
            logger.warning("Ollama health check failed: %s", exc)
            return False

    def available_models(self) -> list[str]:
        """Return list of model names currently pulled in Ollama."""
        try:
            return [m.model for m in self._client.list().models]
        except Exception:
            return []

    def ensure_model(self, model: str) -> None:
        """Pull model if not already available. Blocks until complete."""
        available = self.available_models()
        if not any(model in n for n in available):
            logger.info("Pulling Ollama model: %s", model)
            self._client.pull(model)

    # ------------------------------------------------------------------
    # Chat completion
    # ------------------------------------------------------------------

    def chat(self, messages: list[dict], model: Optional[str] = None) -> str:
        """
        Non-streaming chat completion.

        Parameters
        ----------
        messages : list of {"role": str, "content": str}
        model    : override the config model for this call

        Returns
        -------
        str — the assistant reply
        """
        model = model or self._cfg.chat_model
        try:
            resp = self._client.chat(
                model=model,
                messages=messages,
                options={"num_ctx": 8192},
            )
            return resp.message.content
        except Exception as exc:
            logger.error("Ollama chat error: %s", exc)
            raise OllamaClientError(f"Ollama chat failed: {exc}") from exc

    def chat_stream(
        self,
        messages: list[dict],
        model: Optional[str] = None,
    ) -> Generator[str, None, None]:
        """
        Streaming chat completion — yields token strings as they arrive.
        Use in Streamlit with st.write_stream().
        """
        model = model or self._cfg.chat_model
        try:
            stream = self._client.chat(
                model=model,
                messages=messages,
                stream=True,
                options={"num_ctx": 8192},
            )
            for chunk in stream:
                token = chunk.message.content
                if token:
                    yield token
        except Exception as exc:
            logger.error("Ollama stream error: %s", exc)
            raise OllamaClientError(f"Ollama stream failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Embeddings
    # ------------------------------------------------------------------

    def embed(self, text: str, model: Optional[str] = None) -> list[float]:
        """
        Embed a single text string.
        Returns a list of floats (the embedding vector).
        """
        model = model or self._cfg.embed_model
        try:
            resp = self._client.embeddings(model=model, prompt=text)
            return resp.embedding
        except Exception as exc:
            logger.error("Ollama embed error: %s", exc)
            raise OllamaClientError(f"Ollama embed failed: {exc}") from exc

    def embed_batch(
        self,
        texts: list[str],
        model: Optional[str] = None,
        show_progress: bool = False,
    ) -> list[list[float]]:
        """
        Embed multiple texts. Calls embed() individually (Ollama has no
        native batch endpoint) but logs progress for large batches.
        """
        model = model or self._cfg.embed_model
        vectors = []
        total = len(texts)
        for i, text in enumerate(texts):
            vectors.append(self.embed(text, model=model))
            if show_progress and (i + 1) % 50 == 0:
                logger.info("Embedded %d/%d texts", i + 1, total)
        return vectors
