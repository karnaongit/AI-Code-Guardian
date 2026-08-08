from rag.retriever import Retriever
from rag.llm import SecurityLLM

from ai.conversation_memory import ConversationMemory
from ai.prompt_builder import PromptBuilder
from ai.rag_pipeline import RAGPipeline


class AIAssistant:
    """
    High-level interface for the conversational AI assistant.
    """

    def __init__(self):
        self.memory = ConversationMemory()

        self.pipeline = RAGPipeline(
            retriever=Retriever(),
            llm=SecurityLLM(),
            prompt_builder=PromptBuilder(),
            memory=self.memory,
        )

    def attach_scan(
        self,
        scan_report: dict | None = None,
        repo_root: str | None = None,
    ) -> None:
        """
        Attach scan report and repository root so the assistant
        can answer using scan findings.
        """
        self.pipeline.attach_scan_context(
            scan_report=scan_report,
            repo_root=repo_root,
        )
        if repo_root:
            safe_repo_name = repo_root.replace("/", "_")
            self.pipeline.set_retriever_index(safe_repo_name)

    def ask(self, question: str, investigation_context: str | None = None):
        """
        Ask the assistant a question.
        """
        return self.pipeline.ask(question, investigation_context=investigation_context)

    def take_action(self, session, action, question=None, workspace_id=None):
        """
        Execute a structured prompt strategy.
        """
        return self.pipeline.take_action(session, action, question, workspace_id)

    def clear_history(self):
        """
        Clear conversation memory.
        """
        self.pipeline.clear_history()

    def get_retrieval_context(self, question: str, top_k: int = 5):
        """
        Debug helper.
        """
        return self.pipeline.get_retrieval_context(question, top_k)