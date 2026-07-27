from typing import Dict

from retriever import Retriever
from llm import SecurityLLM


class RAGPipeline:

    def __init__(self):

        self.retriever = Retriever()
        self.llm = SecurityLLM()

    # --------------------------------------------------

    def enhance(self, finding: Dict) -> Dict:

        query = (
            f"{finding['category']} "
            f"{finding['snippet']}"
        )

        retrieved_docs = self.retriever.search(query)

        ai_response = self.llm.generate(
            finding,
            retrieved_docs
        )

        enhanced_finding = {
            **finding,
            "why": ai_response["why"],
            "fix": ai_response["fix"],
            "references": [
                doc["url"]
                for doc in retrieved_docs
            ],
        }

        return enhanced_finding