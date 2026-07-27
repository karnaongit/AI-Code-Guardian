import json
import logging
import os
from typing import Dict, List

from dotenv import load_dotenv
from openai import OpenAI

from prompts import SECURITY_ANALYST_PROMPT

logging.basicConfig(level=logging.INFO)

load_dotenv()


class SecurityLLM:
    """
    Handles interaction with the OpenAI model.
    """

    def __init__(self):

        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not found in .env"
            )

        self.client = OpenAI(
            api_key=api_key
        )

        self.model = os.getenv(
            "LLM_MODEL",
            "gpt-4.1-mini"
        )

    # --------------------------------------------------

    def _build_context(
        self,
        retrieved_docs: List[Dict]
    ) -> str:

        context = []

        for doc in retrieved_docs:

            context.append(
                f"""
Source:
{doc['source']}

Vulnerability:
{doc['vulnerability']}

Description:
{doc['description']}

Recommendation:
{doc['recommendation']}

Reference:
{doc['url']}
"""
            )

        return "\n\n".join(context)

    # --------------------------------------------------

    def generate(
        self,
        finding: Dict,
        retrieved_docs: List[Dict]
    ) -> Dict:

        context = self._build_context(
            retrieved_docs
        )

        prompt = SECURITY_ANALYST_PROMPT.format(
            context=context,
            category=finding["category"],
            severity=finding["severity"],
            language=finding.get("language", "Unknown"),
            snippet=finding["snippet"],
        )

        logging.info(
            "Generating AI explanation..."
        )

        response = self.client.chat.completions.create(
            model=self.model,
            response_format={
                "type": "json_object"
            },
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert Application "
                        "Security Engineer."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.2,
        )

        try:

            result = json.loads(
                response.choices[0].message.content
            )

        except Exception:

            logging.exception(
                "Failed to parse model output."
            )

            raise

        return result