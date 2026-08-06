"""
AI Code Guardian v3 — LangGraph StateGraph Workflow
===================================================
Defines the LangGraph StateGraph workflow engine powering multi-agent transitions.
Phase 3 implements START -> Planner -> END with placeholder stubs for future agents.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from guardian.orchestrator.events import EventBus
from guardian.orchestrator.planner import PlannerAgent
from guardian.orchestrator.state import AgentWorkflowState
from guardian.orchestrator.tools import ToolRegistry

logger = logging.getLogger(__name__)

# Standard node identifier constants
NODE_PLANNER = "planner"
NODE_REPOSITORY = "repository"
NODE_BUSINESS = "business"
NODE_SECURITY = "security"
NODE_ARCHITECTURE = "architecture"
NODE_DEPENDENCY = "dependency"
NODE_THREAT_SIMULATION = "threat_simulation"
NODE_POLICY = "policy"
NODE_RISK_FUSION = "risk_fusion"
NODE_PATCH = "patch"
NODE_VALIDATION = "validation"


def create_placeholder_node(agent_name: str) -> Callable[[AgentWorkflowState], AgentWorkflowState]:
    """Factory creating lightweight placeholder nodes for future specialist agents."""
    def placeholder_node(state: AgentWorkflowState) -> AgentWorkflowState:
        new_state = dict(state)
        new_state["current_task"] = f"Placeholder for {agent_name} agent"
        return new_state
    return placeholder_node


def build_workflow_graph(
    planner_agent: Optional[PlannerAgent] = None,
    tool_registry: Optional[ToolRegistry] = None,
    event_bus: Optional[EventBus] = None,
    agent_registry: Optional[Any] = None,
    checkpointer: Optional[Any] = None
) -> Any:
    """
    Constructs and compiles the LangGraph StateGraph.
    Phase 4 layout:
      START -> Planner -> Repository -> Business -> Security -> Architecture -> Dependency -> END
    """
    planner = planner_agent or PlannerAgent(tool_registry=tool_registry, event_bus=event_bus, agent_registry=agent_registry)

    # Helper function to get agent runner node
    def get_agent_node(name: str):
        if agent_registry and hasattr(agent_registry, "get"):
            agent_instance = agent_registry.get(name)
            if agent_instance:
                if hasattr(agent_instance, "run"):
                    return lambda s: agent_instance.run(s)
                elif callable(agent_instance):
                    inst = agent_instance(tool_registry=tool_registry, event_bus=event_bus)
                    return lambda s: inst.run(s)
        return create_placeholder_node(name)

    def planner_node(state: AgentWorkflowState) -> AgentWorkflowState:
        return planner.run(state)

    def trim_messages_node(state: AgentWorkflowState) -> AgentWorkflowState:
        try:
            from langchain_core.messages import RemoveMessage
            messages = state.get("messages", [])
            if len(messages) > 10:
                # Remove oldest messages exceeding the limit of 10
                to_remove = messages[:-10]
                return {"messages": [RemoveMessage(id=m.id) for m in to_remove if hasattr(m, "id")]}
        except ImportError:
            pass
        return {}

    repo_node = get_agent_node(NODE_REPOSITORY)
    biz_node = get_agent_node(NODE_BUSINESS)
    sec_node = get_agent_node(NODE_SECURITY)
    arch_node = get_agent_node(NODE_ARCHITECTURE)
    dep_node = get_agent_node(NODE_DEPENDENCY)
    threat_node = get_agent_node(NODE_THREAT_SIMULATION)
    pol_node = get_agent_node(NODE_POLICY)
    risk_node = get_agent_node(NODE_RISK_FUSION)
    patch_node = get_agent_node(NODE_PATCH)
    val_node = get_agent_node(NODE_VALIDATION)

    try:
        from langgraph.graph import END, START, StateGraph
        from langgraph.prebuilt import ToolNode, tools_condition
        
        try:
            from guardian.agents.chat.agent import InteractiveChatAgent
            chat_agent = InteractiveChatAgent(tool_registry=tool_registry, event_bus=event_bus)
            tool_node = ToolNode(chat_agent.tools)
        except ImportError:
            chat_agent = None
            tool_node = None
            
        def route_workflow_start(state: AgentWorkflowState) -> str:
            return "chat_agent" if state.get("scan_mode") == "chat" else NODE_PLANNER

        builder = StateGraph(AgentWorkflowState)

        # 1. Register Nodes
        builder.add_node("trim_messages", trim_messages_node)
        if chat_agent:
            builder.add_node("chat_agent", chat_agent.run)
            builder.add_node("tools", tool_node)
            
        builder.add_node(NODE_PLANNER, planner_node)
        builder.add_node(NODE_REPOSITORY, repo_node)
        builder.add_node(NODE_BUSINESS, biz_node)
        builder.add_node(NODE_SECURITY, sec_node)
        builder.add_node(NODE_ARCHITECTURE, arch_node)
        builder.add_node(NODE_DEPENDENCY, dep_node)
        builder.add_node(NODE_THREAT_SIMULATION, threat_node)
        builder.add_node(NODE_POLICY, pol_node)
        builder.add_node(NODE_RISK_FUSION, risk_node)
        builder.add_node(NODE_PATCH, patch_node)
        builder.add_node(NODE_VALIDATION, val_node)

        # 2. Register Edges
        builder.add_edge(START, "trim_messages")
        
        if chat_agent:
            builder.add_conditional_edges("trim_messages", route_workflow_start, {NODE_PLANNER: NODE_PLANNER, "chat_agent": "chat_agent"})
            builder.add_conditional_edges("chat_agent", tools_condition, {"tools": "tools", "__end__": END})
            builder.add_edge("tools", "chat_agent")
        else:
            builder.add_edge("trim_messages", NODE_PLANNER)
            
        builder.add_edge(NODE_PLANNER, NODE_REPOSITORY)
        builder.add_edge(NODE_REPOSITORY, NODE_BUSINESS)
        builder.add_edge(NODE_BUSINESS, NODE_SECURITY)
        builder.add_edge(NODE_SECURITY, NODE_ARCHITECTURE)
        builder.add_edge(NODE_ARCHITECTURE, NODE_DEPENDENCY)
        builder.add_edge(NODE_DEPENDENCY, NODE_THREAT_SIMULATION)
        builder.add_edge(NODE_THREAT_SIMULATION, NODE_POLICY)
        builder.add_edge(NODE_POLICY, NODE_RISK_FUSION)
        builder.add_edge(NODE_RISK_FUSION, NODE_PATCH)
        builder.add_edge(NODE_PATCH, NODE_VALIDATION)
        builder.add_edge(NODE_VALIDATION, END)

        return builder.compile(checkpointer=checkpointer)

    except Exception as exc:
        logger.warning(f"Using fallback StateGraph runner due to: {exc}")

        # Fallback deterministic graph runner mimicking LangGraph interface
        class FallbackCompiledGraph:
            def __init__(self, nodes: List[Callable[[AgentWorkflowState], AgentWorkflowState]]) -> None:
                self.nodes = nodes

            def invoke(self, state: AgentWorkflowState) -> AgentWorkflowState:
                current_state = state
                for n_fn in self.nodes:
                    current_state = n_fn(current_state)
                return current_state

        return FallbackCompiledGraph([planner_node, repo_node, biz_node, sec_node, arch_node, dep_node, threat_node, pol_node, risk_node, patch_node, val_node])
