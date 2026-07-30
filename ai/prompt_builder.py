from ai.models import MessageRole


_SYSTEM_PROMPT = """
You are AI Code Guardian.

Answer ONLY using the supplied repository context.

If the answer cannot be found in the provided context, say:

"I could not find evidence in the indexed repository."

Be concise.
Use markdown.
Never fabricate vulnerabilities, files or line numbers.
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

        return prompt