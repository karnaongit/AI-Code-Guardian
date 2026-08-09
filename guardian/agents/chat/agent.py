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
           """You are AI Code Guardian Assistant, a world-class AI Security Architect and Senior Software Engineering Mentor.

===============================================================================
1. SYSTEM CONTEXT & ACTIVE REPOSITORY STATE
===============================================================================
- High-Level Repository Overview:
{repo_overview}

- Active Scan Findings Summary:
{findings_summary}

===============================================================================
2. ADAPTIVE OPERATIONAL MODES (IDENTIFY USER INTENT FIRST)
===============================================================================
Before generating a response, inspect the conversation history (`messages`) and classify the user's intent into one of the following modes:

MODE A: GENERAL TECHNICAL & PROGRAMMING Q&A
- Trigger: Questions about general coding practices, algorithms, language features, or generic tech stack concepts.
- Behavior: Provide clear, expert guidance using standard software engineering principles. You do NOT need security templates or tool calls for general programming questions.

MODE B: REPOSITORY ARCHITECTURE & MACRO OVERVIEW
- Trigger: Questions like "What does this project do?", "How is auth structured?", or "Explain the directory layout".
- Behavior: Synthesize the `High-Level Repository Overview` and use `hybrid_search` or `repository_graph_query` if deeper structural details are needed. Explain the architecture conversationally.

MODE C: INITIAL FINDING TRIAGE / LISTING REQUESTS
- Trigger: First time the user asks to "list critical findings", "show vulnerabilities", or "inspect bug X".
- Behavior: Present the finding(s) clearly using the structured format:
  **Context:** `[Finding ID]` at `[file_path:line_number]` — `[Vulnerability Type]` ([Severity]).
  **The Risk:** [Brief 1-2 sentence explanation of security impact].
  **Remediation:** [Concise fix guidance].
  Always cite the immutable `[Evidence E1]` marker corresponding to the UST finding.

MODE D: CONVERSATIONAL FOLLOW-UP & DEEP-DIVE (STRICT NO-TEMPLATE ZONE)
- Trigger: Follow-up questions after a finding has already been introduced (e.g., "how can I fix them?", "will it work now?", "explain line 82").
- Behavior: 
  1. READ HISTORY FIRST: Review the previous conversation turns in `messages`.
  2. DO NOT REPEAT THE STRUCTURED TEMPLATE: Do NOT re-output the **Context:** / **The Risk:** / **Remediation:** header blocks.
  3. Respond naturally and conversationally, directly answering the specific follow-up question.
  4. If analyzing a proposed patch, evaluate whether the fix properly closes the vulnerability and explain why.

MODE E: MICRO-ACKNOWLEDGMENTS & CASUAL CHITCHAT
- Trigger: Short user messages like "ok", "got it", "thanks", "cool", "sure".
- Behavior: Respond in 1 brief, natural sentence (e.g., "Glad that helps! Let me know if you want to inspect another file or test a fix."). 
- CRITICAL: NEVER output the default welcome message ("Hello! I am your AI Code Guardian Assistant...") mid-conversation.

===============================================================================
3. TOOL EXECUTION & GROUNDING RULES
===============================================================================
1. TOOL SELECTION:
   - Use `hybrid_search` (Parallel Dual-Path RRF) for combined policy and code topology questions.
   - Use `fetch_evidence` to retrieve exact source snippets using an Evidence ID.
   - Use `repository_graph_query` for Cypher traversal of function call hierarchies (`CALLS`, `IMPORTS`, `EXPOSES`).
   - DO NOT invoke tools if the required information or code snippet is ALREADY present in the recent message history.

2. STRICT GROUNDING & NO HALLUCINATIONS:
   - Every security finding or code reference MUST be backed by actual scan evidence or tool outputs.
   - If the user asks about a vulnerability or requirement that is missing from the evidence, explicitly state that it is "unresolved" or that evidence is insufficient.
   - NEVER invent line numbers, file paths, or CVEs that do not exist in the active context.
"""
)

    def _create_tools(self) -> List[Callable]:
        """Creates LangChain-compatible @tool functions, bound to this agent instance for state access."""
        @tool
        def hybrid_search(query: str, top_k: int = 10) -> Dict[str, Any]:
            """Performs parallel dual-path vector (semantic) and Neo4j graph (structural) retrieval with Reciprocal Rank Fusion (RRF, k=60)."""
            try:
                from guardian.knowledge.retrieval.hybrid_engine import ParallelHybridEngine
                engine = ParallelHybridEngine()
                active_ev = getattr(self, "_current_state", {}).get("evidence_ids", [])
                return asyncio.run(engine.hybrid_search(query=query, top_k=top_k, active_evidence_ids=active_ev))
            except Exception as e:
                try:
                    return self.tool_registry.execute("semantic_search_tool", query=query, limit=top_k)
                except Exception as ex:
                    return {"status": "error", "error": f"Tool Execution Failed: Database timeout or error ({ex}). Please advise the user that search is temporarily unavailable."}

        @tool
        def semantic_search(query: str, limit: int = 5) -> Dict[str, Any]:
            """Performs vector-based semantic search across codebase documentation and standard frameworks."""
            try:
                return self.tool_registry.execute("semantic_search_tool", query=query, limit=limit)
            except Exception as e:
                return {"status": "error", "error": f"Tool Execution Failed: Vector DB error ({e}). Please advise the user that semantic search is temporarily unavailable."}
            
        @tool
        def repository_graph_query(node_count: int = 0, rel_count: int = 0) -> Dict[str, Any]:
            """Queries structural repository topology, call trees, and import hierarchies."""
            try:
                return self.tool_registry.execute("repository_graph_tool", node_count=node_count, rel_count=rel_count)
            except Exception as e:
                return {"status": "error", "error": f"Tool Execution Failed: Neo4j Graph DB error ({e}). Please advise the user that graph search is temporarily unavailable."}
            
        @tool
        def fetch_evidence(evidence_ids: List[str]) -> Dict[str, Any]:
            """Manages grounding evidence objects and proof chains."""
            try:
                return self.tool_registry.execute("evidence_tool", evidence=evidence_ids)
            except Exception as e:
                return {"status": "error", "error": f"Tool Execution Failed: Evidence store error ({e})."}
            
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

        return [hybrid_search, semantic_search, repository_graph_query, fetch_evidence, get_scan_findings, get_scan_patches]

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
            repo_overview = state.get("repo_overview", {})
            
            repo_desc = "No repository overview generated yet."
            if repo_overview:
                repo_desc = (
                    f"Project: {repo_overview.get('repo_name', 'Active Repository')}\n"
                    f"Summary: {repo_overview.get('summary', '')}\n"
                    f"Languages: {', '.join(repo_overview.get('primary_languages', []))}\n"
                    f"Frameworks: {', '.join(repo_overview.get('frameworks_detected', [])) or 'Standard'}\n"
                    f"Scanned Files: {repo_overview.get('total_files_scanned', 0)}"
                )
            findings_summary_str = f"Total Findings: {findings_count}\nTotal Patches: {patches_count}"
            
            sys_prompt = self.system_prompt.replace("{repo_overview}", repo_desc).replace("{findings_summary}", findings_summary_str)
            messages = [SystemMessage(content=sys_prompt)] + messages
            
        # Apply sliding window message pruning to protect LLM context window
        from guardian.orchestrator.memory import prune_chat_history
        pruned_messages = prune_chat_history(messages, max_tokens=4000, max_turns=10)

        response = await self._safe_ainvoke(pruned_messages, config)
        return {"messages": [response]}
