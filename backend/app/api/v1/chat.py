"""
Chat & Reasoning API Endpoint
=============================
Provides interactive Nemotron AI completions grounded in scan evidence and RAG knowledge.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from guardian.llm.personas import SystemPersona, get_persona_prompt
from guardian.reasoning.tools import (
    NEMOTRON_TOOL_DEFINITIONS,
    query_security_knowledge,
    get_finding_detail,
    get_scan_funnel_summary,
    get_active_findings_context,
)

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatMessage(BaseModel):
    role: str = Field(..., description="Role: 'user', 'assistant', or 'system'")
    content: str = Field(..., description="Message content")


class ChatCompletionRequest(BaseModel):
    messages: List[ChatMessage]
    persona: str = Field("Developer", description="Persona: 'Executive', 'Developer', or 'Red Teamer'")
    temperature: float = Field(0.2, ge=0.0, le=1.0)


class ChatCompletionResponse(BaseModel):
    persona: str
    reply: str
    tools_used: List[str] = Field(default_factory=list)


GREETINGS = {"hi", "hello", "hey", "greetings", "good morning", "good afternoon", "good evening", "howdy", "sup"}


@router.post("/completions", response_model=ChatCompletionResponse)
async def chat_completion(request: ChatCompletionRequest):
    system_prompt = get_persona_prompt(request.persona)
    user_query = (request.messages[-1].content if request.messages else "").strip()
    query_lower = user_query.lower()

    tools_used = []
    tool_insights = []

    is_greeting = query_lower in GREETINGS or len(query_lower) <= 3

    if is_greeting:
        reply = (
            f"Hello! I am your AI Code Guardian Assistant ({request.persona} Persona).\n\n"
            f"I can help you analyze vulnerabilities, generate security fixes, explain CWE/OWASP risks, "
            f"or review active scan findings across your repository. How can I assist you today?"
        )
        return ChatCompletionResponse(persona=request.persona, reply=reply, tools_used=[])

    # 1. RAG Knowledge Retrieval — only when security terms are queried
    sec_keywords = ["cwe", "owasp", "fix", "vulnerability", "tls", "ssl", "sql", "secret", "crypto", "finding", "problem", "issue", "risk", "attack", "exploit", "code"]
    if any(kw in query_lower for kw in sec_keywords):
        knowledge_entries = query_security_knowledge(user_query)
        if knowledge_entries:
            tools_used.append("query_security_knowledge")
            snippets = []
            for k in knowledge_entries[:2]:
                title = k.get("title", "Security Standard")
                std = k.get("standard", "OWASP/CWE")
                content = k.get("content", "")
                snippets.append(f"### [{std}] {title}\n{content}")
            tool_insights.append("### Trusted Security Guidance:\n" + "\n\n".join(snippets))

    # 2. Active Scan Evidence Context
    findings_context = get_active_findings_context(limit=6)
    if findings_context and "No active" not in findings_context:
        tools_used.append("get_active_findings_context")
        tool_insights.append(f"### Active Repository Scan Evidence:\n{findings_context}")

    # 3. Funnel Summary Context (if requested)
    if any(kw in query_lower for kw in ["summary", "metric", "funnel", "report", "overall", "score"]):
        summary = get_scan_funnel_summary()
        tools_used.append("get_scan_funnel_summary")
        tool_insights.append(f"### Scan Triage Summary Metrics:\n{summary}")

    insight_str = "\n\n".join(tool_insights) if tool_insights else "No specific scan evidence attached."

    # Construct Grounded Context
    context_msg = (
        f"--- GROUNDED EVIDENCE CONTEXT ---\n"
        f"{insight_str}\n"
        f"---------------------------------\n\n"
        f"USER QUERY:\n{user_query}\n\n"
        f"DIRECTIVE:\n"
        f"1. Base your answer strictly on the provided evidence context above.\n"
        f"2. NEVER invent fake hardcoded secrets for standard UI keys (like key='sidebar_file_search').\n"
        f"3. Be concise, concrete, and directly answer the user's question without dumping raw system prompts."
    )

    llm_messages = [{"role": "system", "content": system_prompt}]
    for m in request.messages[:-1]:
        llm_messages.append({"role": m.role, "content": m.content})
    llm_messages.append({"role": "user", "content": context_msg})

    if not settings.NVIDIA_API_KEY:
        reply = (
            f"Based on your query: '{user_query}'\n\n"
            f"{insight_str}\n\n"
            f"Note: Configure `NVIDIA_API_KEY` in `.env` to enable full live LLM reasoning."
        )
    else:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post(
                    f"{settings.NVIDIA_BASE_URL.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.NVIDIA_API_KEY}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": settings.NVIDIA_MODEL,
                        "messages": llm_messages,
                        "temperature": request.temperature or settings.LLM_TEMPERATURE,
                        "max_tokens": settings.LLM_MAX_TOKENS,
                    }
                )
                res.raise_for_status()
                data = res.json()
                reply = data["choices"][0]["message"]["content"]
        except Exception as e:
            reply = f"Error communicating with AI service: {str(e)}"

    return ChatCompletionResponse(
        persona=request.persona,
        reply=reply,
        tools_used=tools_used
    )
