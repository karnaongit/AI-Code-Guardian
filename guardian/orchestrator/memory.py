"""
AI Code Guardian v3 — Orchestration Memory & Message Pruner
============================================================
Provides sliding-window chat history pruning to protect the LLM context window,
preserving system prompts and keeping tool-call requests paired with tool outputs.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

logger = logging.getLogger(__name__)


def _estimate_tokens(message: BaseMessage, chars_per_token: int = 4) -> int:
    content = str(getattr(message, "content", ""))
    return len(content) // chars_per_token + 1


def prune_chat_history(
    messages: List[BaseMessage],
    max_tokens: int = 4000,
    max_turns: int = 10,
    chars_per_token: int = 4
) -> List[BaseMessage]:
    """
    Trims chat messages to stay within max_tokens and max_turns.
    - Preserves SystemMessage (index 0) if present.
    - Never breaks AIMessage tool call requests from their ToolMessage responses.
    """
    if not messages:
        return []

    # Extract SystemMessage if first
    system_msg: Optional[BaseMessage] = None
    chat_messages: List[BaseMessage] = list(messages)

    if chat_messages and isinstance(chat_messages[0], SystemMessage):
        system_msg = chat_messages.pop(0)

    if not chat_messages:
        return [system_msg] if system_msg else []

    # Map ToolMessages to AIMessage tool_call_ids
    tool_call_pairs: Dict[str, str] = {}
    for idx, msg in enumerate(chat_messages):
        if isinstance(msg, AIMessage):
            tool_calls = getattr(msg, "tool_calls", []) or []
            for tc in tool_calls:
                tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None)
                if tc_id:
                    tool_call_pairs[tc_id] = str(idx)

    system_tokens = _estimate_tokens(system_msg, chars_per_token) if system_msg else 0
    available_tokens = max(500, max_tokens - system_tokens)

    # Collect messages from end (newest) working backwards
    kept_indices: Set[int] = set()
    current_tokens = 0
    turn_count = 0

    idx = len(chat_messages) - 1
    while idx >= 0:
        msg = chat_messages[idx]
        msg_tokens = _estimate_tokens(msg, chars_per_token)

        # Count turns on HumanMessage
        if isinstance(msg, HumanMessage):
            turn_count += 1

        if turn_count > max_turns or (current_tokens + msg_tokens > available_tokens and kept_indices):
            break

        kept_indices.add(idx)
        current_tokens += msg_tokens

        # Ensure tool call pairing: if we keep a ToolMessage, also keep its parent AIMessage
        if isinstance(msg, ToolMessage):
            t_id = getattr(msg, "tool_call_id", None)
            if t_id and t_id in tool_call_pairs:
                parent_idx = int(tool_call_pairs[t_id])
                if parent_idx not in kept_indices:
                    kept_indices.add(parent_idx)
                    current_tokens += _estimate_tokens(chat_messages[parent_idx], chars_per_token)

        idx -= 1

    # Reconstruct sorted list
    result_messages: List[BaseMessage] = []
    if system_msg:
        result_messages.append(system_msg)

    for idx in sorted(kept_indices):
        result_messages.append(chat_messages[idx])

    return result_messages
