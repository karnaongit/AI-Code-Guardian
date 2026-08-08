from __future__ import annotations

import os
import time

import google.generativeai as genai

from scanner.language_learning.query_generator import BaseLLM


class GeminiLLM(BaseLLM):
    """
    Gemini implementation of BaseLLM.

    Responsible only for communicating with Gemini.
    """

    DEFAULT_MODEL = "gemini-2.5-flash"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        temperature: float = 0.0,
        retries: int = 3,
    ):

        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

        if not self.api_key:
            raise RuntimeError(
                "GEMINI_API_KEY environment variable is not set."
            )

        genai.configure(api_key=self.api_key)

        self.model = genai.GenerativeModel(model)

        self.config = genai.GenerationConfig(
            temperature=temperature
        )

        self.retries = retries

    def generate(self, prompt: str) -> str:

        last_error = None

        for attempt in range(self.retries):

            try:

                response = self.model.generate_content(
                    prompt,
                    generation_config=self.config,
                )

                text = getattr(response, "text", None)

                if not text:
                    raise RuntimeError(
                        "Gemini returned an empty response."
                    )

                return self._clean(text)

            except Exception as exc:

                last_error = exc

                if attempt < self.retries - 1:
                    time.sleep(2 ** attempt)

        raise RuntimeError(
            f"Gemini generation failed: {last_error}"
        )

    @staticmethod
    def _clean(text: str) -> str:

        text = text.strip()

        if text.startswith("```"):

            lines = text.splitlines()

            if lines:
                lines = lines[1:]

            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]

            text = "\n".join(lines)

        return text.strip()