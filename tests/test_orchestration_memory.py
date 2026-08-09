"""
Unit Tests for Phase 4: Orchestration Memory, Message Pruning & Resilience
===========================================================================
Tests sliding window chat history pruning, tool-call request-response pairing,
checkpointer fallbacks, and resilient error handling during tool execution failures.
"""
import pytest
from unittest.mock import MagicMock, patch
from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from guardian.orchestrator.memory import prune_chat_history
from guardian.orchestrator.checkpointer import get_checkpointer
from guardian.orchestrator.tools import ToolRegistry
from guardian.orchestrator.events import EventBus
from guardian.agents.chat.agent import InteractiveChatAgent


def test_message_pruning_system_preservation_and_pairing():
    """Verifies that prune_chat_history retains SystemMessage and preserves AIMessage-ToolMessage pairs."""
    sys_msg = SystemMessage(content="You are AI Code Guardian.")
    
    messages = [sys_msg]
    # Build 10 turns of Human/AI + tool calls
    for i in range(1, 11):
        messages.append(HumanMessage(content=f"Question {i} asking about security vulnerability {i}"))
        tc_id = f"call_{i}"
        messages.append(AIMessage(content=f"Checking tool {i}", tool_calls=[{"name": "hybrid_search", "args": {"query": f"vulnerability {i}"}, "id": tc_id}]))
        messages.append(ToolMessage(content=f"Evidence result for call {i}", tool_call_id=tc_id))
        messages.append(AIMessage(content=f"Answer {i} for vulnerability {i}"))

    # Prune with max_turns=3
    pruned = prune_chat_history(messages, max_tokens=1000, max_turns=3)

    assert isinstance(pruned[0], SystemMessage)
    assert pruned[0].content == "You are AI Code Guardian."
    assert len(pruned) < len(messages)
    
    # Check that any ToolMessage in pruned has its corresponding AIMessage present
    tool_msg_ids = {m.tool_call_id for m in pruned if isinstance(m, ToolMessage)}
    ai_call_ids = set()
    for m in pruned:
        if isinstance(m, AIMessage):
            for tc in getattr(m, "tool_calls", []):
                ai_call_ids.add(tc.get("id"))

    assert tool_msg_ids.issubset(ai_call_ids)


def test_tool_failure_resilience():
    """Verifies that tool execution errors return a graceful error dict rather than raising unhandled 500 exceptions."""
    tool_registry = ToolRegistry()
    event_bus = EventBus()

    # Mock tool registry execute to raise TimeoutError
    tool_registry.execute = MagicMock(side_effect=TimeoutError("Neo4j database connection timed out"))

    with patch("guardian.agents.chat.agent.ChatOpenAI"):
        agent = InteractiveChatAgent(tool_registry=tool_registry, event_bus=event_bus)
        
        # Find semantic_search tool
        sem_tool = next(t for t in agent.tools if t.name == "semantic_search")
        res = sem_tool.invoke({"query": "SQL injection", "limit": 5})

        assert isinstance(res, dict)
        assert res.get("status") == "error"
        assert "Tool Execution Failed" in res.get("error", "")


def test_checkpointer_fallback():
    """Verifies get_checkpointer returns a valid checkpointer instance."""
    cp = get_checkpointer()
    assert cp is not None
