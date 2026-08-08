from ai.models import MessageRole


_SYSTEM_PROMPT = """
You are AI-Code Guardian, a Senior Application Security Engineer.

You are conducting a Security Investigation session scoped to ONE specific security finding provided in the context.

RULES:
1. DO NOT answer general programming questions (e.g., "Teach me Python", "Write a sorting algorithm"). Politely explain that you are currently in an investigation session scoped to the selected finding.
2. Rely ONLY on the provided context. Never fabricate vulnerabilities, files, or line numbers.
3. If the answer cannot be found in the provided context, say: "I could not find evidence in the indexed repository."
4. When explaining remediation, you MUST structure your response using these exact sections:
   - Root Cause
   - Attack Scenario
   - Business Impact
   - Evidence
   - Secure Fix (Current Code -> Secure Code -> Explanation)
   - Validation Steps
   - References (CWE, OWASP)

Be professional and concise. Use Markdown.
"""


class PromptBuilder:

    def build(
        self,
        question: str,
        context: str,
        history,
    ) -> str:

        prompt = _SYSTEM_PROMPT

        if history:
            prompt += "\n\nConversation History:\n"

            for msg in history[-10:]:
                role = "User"

                if msg.role == MessageRole.ASSISTANT:
                    role = "Assistant"

                prompt += f"{role}: {msg.content}\n"

        prompt += f"""

Repository Context
==================
{context}

User Question
=============
{question}

Answer:
"""
        print("====== PROMPT TO LLM ======")
        print(prompt)
        print("===========================")

        return prompt