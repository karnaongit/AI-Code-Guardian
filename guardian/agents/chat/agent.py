"""
Interactive Chat Agent
======================
Dynamically responds to user queries by interacting with the ToolRegistry
using native LangChain tool bindings via the OpenAI-compatible NVIDIA endpoint.
"""
from typing import Any, Callable, Dict, List

from langchain_core.messages import SystemMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
import asyncio
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception

from guardian.llm.config import LLMConfig
from guardian.orchestrator.events import EventBus
from guardian.orchestrator.state import AgentWorkflowState
from guardian.orchestrator.tools import ToolRegistry





_nim_semaphore = asyncio.Semaphore(2)

def _is_retryable_error(exception: Exception) -> bool:
    err_str = str(exception).lower()
    return "resourceexhausted" in err_str or "limit reached" in err_str or "connection" in err_str or "timeout" in err_str or "500" in err_str or "502" in err_str or "503" in err_str or "504" in err_str or "429" in err_str


class InteractiveChatAgent:
    """Conversational RAG agent interacting directly with the codebase."""
    
    def __init__(self, tool_registry: ToolRegistry, event_bus: EventBus) -> None:
        self.tool_registry = tool_registry
        self.event_bus = event_bus
        self.config = LLMConfig.from_env()
        
        # Instantiate standard LangChain client pointing to NVIDIA endpoint
        self.llm = ChatOpenAI(
            base_url=self.config.base_url,
            api_key=self.config.api_key,
            model=self.config.model,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            model_kwargs={"top_p": self.config.top_p}
        )
        
        self.tools = self._create_tools()
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        
        self.system_prompt = (
            "You are the universal AI Code Guardian assistant. Your objective is to help the user with any code or security queries.\n"
            "1. Determine if the user's question is about a specific security finding, patches, or general coding.\n"
            "2. If security-related, strictly use your tools (`get_scan_findings`, `get_scan_patches`, `semantic_search`, `repository_graph_query`) to query the codebase state and cite `[Evidence E1]` markers.\n"
            "3. If general coding, provide standard, helpful code assistant behaviors.\n"
            "You MUST NOT hallucinate answers about the repository architecture; always query the tools when you need information."
        )

    def _create_tools(self) -> List[Callable]:
        """Creates LangChain-compatible @tool functions, bound to this agent instance for state access."""
        @tool
        def semantic_search(query: str, limit: int = 5) -> Dict[str, Any]:
            """Performs vector-based semantic search across codebase documentation and standard frameworks."""
            return self.tool_registry.execute("semantic_search_tool", query=query, limit=limit)
            
        @tool
        def repository_graph_query(node_count: int = 0, rel_count: int = 0) -> Dict[str, Any]:
            """Queries structural repository topology, call trees, and import hierarchies."""
            return self.tool_registry.execute("repository_graph_tool", node_count=node_count, rel_count=rel_count)
            
        @tool
        def fetch_evidence(evidence_ids: List[str]) -> Dict[str, Any]:
            """Manages grounding evidence objects and proof chains."""
            return self.tool_registry.execute("evidence_tool", evidence=evidence_ids)
            
        @tool
        def get_scan_findings(severity: str = "") -> str:
            """Retrieves security findings and vulnerabilities discovered in the codebase. Use severity='CRITICAL' or 'HIGH' to filter."""
            findings = getattr(self, "_current_state", {}).get("findings", [])
            if not findings:
                return "No findings are currently present in the scan state."
            
            res = []
            for f in findings:
                if severity and f.get("severity", "").upper() != severity.upper():
                    continue
                res.append({
                    "id": f.get("finding_id"),
                    "rule": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "file": f.get("file_path"),
                    "line": f.get("line_number"),
                    "description": f.get("description")
                })
            import json
            return json.dumps(res, indent=2)

        @tool
        def get_scan_patches() -> str:
            """Retrieves proposed remediation patches for discovered findings."""
            patches = getattr(self, "_current_state", {}).get("patches", [])
            if not patches:
                return "No patches are currently proposed in the scan state."
            
            res = []
            for p in patches:
                res.append({
                    "id": p.get("patch_id"),
                    "finding_id": p.get("finding_id"),
                    "file": p.get("file_path"),
                    "description": p.get("description")
                })
            import json
            return json.dumps(res, indent=2)

        return [semantic_search, repository_graph_query, fetch_evidence, get_scan_findings, get_scan_patches]

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(15),
        retry=retry_if_exception(_is_retryable_error)
    )
    async def _safe_ainvoke(self, messages, config):
        async with _nim_semaphore:
            return await self.llm_with_tools.ainvoke(messages, config=config)

    async def run(self, state: AgentWorkflowState, config: Any = None) -> AgentWorkflowState:
        """Executes one turn of the chat loop."""
        self._current_state = state
        messages = state.get("messages", [])
        
        # Prepend system prompt if not present
        if not messages or not any(isinstance(m, SystemMessage) for m in messages):
            findings_count = len(state.get("findings", []))
            patches_count = len(state.get("patches", []))
            sys_prompt = self.system_prompt + f"\n\nCURRENT REPOSITORY SCAN RESULTS:\n- Total Findings: {findings_count}\n- Total Patches: {patches_count}\nUse the `get_scan_findings` and `get_scan_patches` tools to view them."
            messages = [SystemMessage(content=sys_prompt)] + messages
            
        response = await self._safe_ainvoke(messages, config)

        # V3 FIX: Validate any [Evidence Exx] markers the LLM cited exist in the
        # actual evidence store.  Flag fabricated IDs inline so they are visible
        # to users and auditable — not silently accepted as grounded claims.
        import re as _re
        response_text = getattr(response, "content", "") or ""
        cited_ids = _re.findall(r"\[Evidence\s+(E\d+)\]", response_text)
        if cited_ids:
            evidence_in_state = state.get("evidence", [])
            if isinstance(evidence_in_state, list) and evidence_in_state:
                if isinstance(evidence_in_state[0], dict):
                    known_ids = {e.get("id", e.get("evidence_id", "")) for e in evidence_in_state}
                else:
                    known_ids = {getattr(e, "id", "") for e in evidence_in_state}
            else:
                known_ids = set()

            unverified = [eid for eid in cited_ids if eid not in known_ids]
            if unverified and known_ids:
                # Append a grounding caveat to the response content
                caveat = (
                    f"\n\n> ⚠️ **Grounding Note**: Evidence ID(s) {unverified} cited above "
                    "could not be verified against the current scan evidence store. "
                    "Treat these claims as unverified suggestions."
                )
                from langchain_core.messages import AIMessage
                if hasattr(response, "content"):
                    response = AIMessage(
                        content=response_text + caveat,
                        tool_calls=getattr(response, "tool_calls", []),
                    )

        return {"messages": [response]}
