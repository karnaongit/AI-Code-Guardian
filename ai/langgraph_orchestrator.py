from typing import TypedDict, Optional, Any, Dict
from langgraph.graph import StateGraph, START, END
import logging
import json

from ai.models import InvestigationAction, InvestigationResult
from ai.strategies import StrategyFactory

logger = logging.getLogger(__name__)

class AgentState(TypedDict):
    workspace_id: Optional[str]
    action: InvestigationAction
    session: Any
    question: Optional[str]
    repo_name: str
    
    # Context
    evidence: str
    retrieved_context: str
    graph_context: str
    policy_decision: Optional[dict]
    
    # Final response
    response: Optional[InvestigationResult]
    error: Optional[str]

class LangGraphOrchestrator:
    def __init__(self, llm, retriever):
        self.llm = llm
        self.retriever = retriever
        
        # Build graph
        workflow = StateGraph(AgentState)
        
        workflow.add_node("evidence_node", self.evidence_node)
        workflow.add_node("semantic_search_node", self.semantic_search_node)
        workflow.add_node("graph_tool_node", self.graph_tool_node)
        workflow.add_node("reasoning_node", self.reasoning_node)
        
        workflow.add_node("policy_node", self.policy_node)
        
        # Add edges based on action routing
        workflow.add_conditional_edges(
            START,
            self.route_action,
        )
        
        # Nodes go to policy_node
        workflow.add_edge("evidence_node", "policy_node")
        workflow.add_edge("semantic_search_node", "policy_node")
        workflow.add_edge("graph_tool_node", "policy_node")
        
        # Policy node goes to reasoning node
        workflow.add_edge("policy_node", "reasoning_node")
        
        workflow.add_edge("reasoning_node", END)
        
        self.app = workflow.compile()
        
    def route_action(self, state: AgentState):
        action = state.get("action")
        # Route based on the action
        if action == InvestigationAction.GENERATE_FIX:
            # We want both evidence, semantic search, and graph context
            return ["evidence_node", "semantic_search_node", "graph_tool_node"]
        elif action == InvestigationAction.SHOW_EVIDENCE:
            return ["evidence_node"]
        elif action == InvestigationAction.VALIDATE_FIX:
            return ["evidence_node", "semantic_search_node"]
        elif action == InvestigationAction.EXPLAIN_FINDING:
            return ["evidence_node", "semantic_search_node"]
        else:
            return ["evidence_node"]
            
    def evidence_node(self, state: AgentState):
        logger.info("Executing evidence_node")
        session = state.get("session")
        evidence = ""
        if session and session.context:
            evidence = session.context.evidence or "No deterministic evidence found."
        return {"evidence": evidence}
        
    def semantic_search_node(self, state: AgentState):
        logger.info("Executing semantic_search_node")
        session = state.get("session")
        q = state.get("question")
        if not q and session and session.context:
            q = session.context.summary.title
            
        retrieved_context = ""
        if q and self.retriever:
            docs = self.retriever.search(q)
            # Handle list of dicts returning from RAG
            doc_texts = []
            for doc in docs:
                if isinstance(doc, dict):
                    doc_texts.append(doc.get("content", ""))
                else:
                    doc_texts.append(str(doc))
            retrieved_context = "\n".join(doc_texts)
        return {"retrieved_context": retrieved_context}
        
    def graph_tool_node(self, state: AgentState):
        logger.info("Executing graph_tool_node")
        # Use repo_name as the repository-scoped namespace (to be replaced by real workspace_id in future)
        repo_namespace = state.get("repo_name")
        if not repo_namespace:
            logger.error("repository namespace missing, cannot query Neo4j")
            return {"error": "repository namespace missing, cannot query Neo4j", "graph_context": ""}
            
        try:
            from scanner.intelligence.neo4j_adapter import Neo4jAdapter
            adapter = Neo4jAdapter()
            if not adapter.is_available():
                return {"error": "Neo4j driver unavailable", "graph_context": ""}
                
            session = state.get("session")
            finding_id = session.finding_id if session else None
            if not finding_id:
                return {"error": "finding_id missing, cannot query topology", "graph_context": ""}
                
            graph_context = adapter.get_topology(finding_id, repo_namespace)
            reachability_data = adapter.get_finding_reachability(repo_namespace, finding_id, max_depth=10)
            adapter.close()
            
            # Combine the two responses into graph_context as JSON-like text so the LLM can see both
            combined_context = (
                f"=== TOPOLOGY ===\n{graph_context}\n\n"
                f"=== DETERMINISTIC REACHABILITY ===\n"
                f"{json.dumps(reachability_data, indent=2)}"
            )
            
            return {"graph_context": combined_context}
        except Exception as e:
            logger.error(f"Error querying Neo4j: {e}")
            return {"error": "Neo4j query failed", "graph_context": ""}
            
    def policy_node(self, state: AgentState):
        logger.info("Executing policy_node")
        if state.get("error"):
            return {}
            
        session = state.get("session")
        if not session or not session.context or not session.context.summary:
            return {}
            
        severity = session.context.summary.severity
        graph_context = state.get("graph_context", "")
        
        reachable = False
        endpoint = None
        if "=== DETERMINISTIC REACHABILITY ===" in graph_context:
            try:
                parts = graph_context.split("=== DETERMINISTIC REACHABILITY ===")
                reachability_json = parts[1].strip()
                reachability_data = json.loads(reachability_json)
                reachable = bool(reachability_data.get("reachable", False))
                endpoint = reachability_data.get("endpoint")
            except Exception as e:
                logger.error(f"Failed to parse reachability: {e}")
                
        try:
            from ai.policy_engine import evaluate
            decision = evaluate(severity, reachable)
            decision_dict = decision.to_dict()
            if endpoint:
                decision_dict["endpoint"] = endpoint
            return {"policy_decision": decision_dict}
        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}")
            return {"error": f"Policy Validation Error: {e}"}
        
    def reasoning_node(self, state: AgentState):
        logger.info("Executing reasoning_node")
        
        # Check for errors from tools
        if state.get("error"):
            # Return a controlled error as the investigation result
            return {"response": InvestigationResult(summary=f"Controlled Application Error: {state.get('error')}")}
            
        action = state.get("action")
        session = state.get("session")
        question = state.get("question")
        
        # We reuse StrategyFactory to keep the prompt deterministic, injecting new context
        strategy = StrategyFactory.get_strategy(action)
        base_prompt = strategy.build_prompt(session, question)
        
        additional_context = ""
        if state.get("retrieved_context"):
            additional_context += f"\n\nSemantic Context:\n{state.get('retrieved_context')}"
        if state.get("graph_context"):
            additional_context += f"\n\nGraph Context:\n{state.get('graph_context')}"
        if state.get("policy_decision"):
            additional_context += f"\n\nDeterministic Policy Decision (DO NOT OVERRIDE):\n{json.dumps(state.get('policy_decision'), indent=2)}"
            
        full_prompt = base_prompt + additional_context + "\n\nRespond ONLY with valid JSON matching the requested InvestigationResult fields."
        
        raw_answer = self.llm.chat(full_prompt)
        
        try:
            if "```json" in raw_answer:
                json_str = raw_answer.split("```json")[1].split("```")[0].strip()
            else:
                json_str = raw_answer.strip()
                
            data = json.loads(json_str)
            result = InvestigationResult(
                summary=data.get("summary", ""),
                root_cause=data.get("root_cause", ""),
                attack_scenario=data.get("attack_scenario", ""),
                evidence=data.get("evidence", ""),
                business_impact=data.get("business_impact", ""),
                secure_fix=data.get("secure_fix", ""),
                secure_code=data.get("secure_code", ""),
                validation_steps=data.get("validation_steps", ""),
                references=data.get("references", "")
            )
        except Exception as e:
            logger.error(f"Failed to parse structured LLM output: {e}")
            result = InvestigationResult(summary=raw_answer)
            
        # PROVE LLM CANNOT OVERRIDE
        # Enforce deterministic policy authority in code
        if state.get("policy_decision"):
            result.policy_decision = state.get("policy_decision")
            
        return {"response": result}

    def invoke(self, state: dict) -> AgentState:
        return self.app.invoke(state)

