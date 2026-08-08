from __future__ import annotations

import os
import time

from dotenv import load_dotenv



from openai import OpenAI

from scanner.language_learning.query_generator import BaseLLM

load_dotenv()
class NemotronLLM(BaseLLM):
    """
    NVIDIA Nemotron implementation.

    Uses NVIDIA API Catalog (OpenAI compatible API).

    Environment Variables

    NVIDIA_API_KEY
    LLM_MODEL
    LLM_TEMPERATURE
    LLM_MAX_RETRIES
    """

    DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b"

    BASE_URL = "https://integrate.api.nvidia.com/v1"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        retries: int | None = None,
    ):

        self.api_key = api_key or os.getenv("NVIDIA_API_KEY")

        if not self.api_key:
            raise RuntimeError(
                "NVIDIA_API_KEY environment variable is not set."
            )

        self.model = (
            model
            or os.getenv("LLM_MODEL")
            or self.DEFAULT_MODEL
        )

        self.temperature = float(
            temperature
            if temperature is not None
            else os.getenv("LLM_TEMPERATURE", 0.0)
        )

        self.retries = int(
            retries
            if retries is not None
            else os.getenv("LLM_MAX_RETRIES", 3)
        )

        self.client = OpenAI(
            base_url=self.BASE_URL,
            api_key=self.api_key,
        )

    # ----------------------------------------------------------

    def generate(
    self,
    prompt: str,
    system_prompt: str | None = None,
) -> str:

        last_error = None

        for attempt in range(self.retries):

            try:

                response = self.client.chat.completions.create(

                    model=self.model,

                    messages=[
    {
        "role": "system",
        "content": system_prompt or (
            "You are an expert Tree-sitter engineer.\n"
            "Return ONLY valid Tree-sitter query (.scm).\n"
            "Never use markdown.\n"
            "Never explain anything.\n"
            "Output only raw query text."
        ),
    },
    {
        "role": "user",
        "content": prompt,
    },
],

                    temperature=self.temperature,

                    max_tokens=16000,

                    extra_body={
                        "chat_template_kwargs": {
                            "enable_thinking": False
                        }
                    },
                )

                text = response.choices[0].message.content

                if not text:
                    raise RuntimeError(
                        "Nemotron returned an empty response."
                    )

                return self._clean(text)

            except Exception as exc:

                last_error = exc

                if attempt < self.retries - 1:

                    time.sleep(2 ** attempt)

        raise RuntimeError(
            f"Nemotron generation failed: {last_error}"
        )

    # ----------------------------------------------------------

    @staticmethod
    def _clean(
        text: str,
    ) -> str:

        text = text.strip()

        if text.startswith("```"):

            lines = text.splitlines()

            if lines:

                lines = lines[1:]

            if lines and lines[-1].startswith("```"):

                lines = lines[:-1]

            text = "\n".join(lines)

        return text.strip()