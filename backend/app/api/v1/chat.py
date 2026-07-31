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


@router.post("/completions", response_model=ChatCompletionResponse)
async def chat_completion(request: ChatCompletionRequest):
    system_prompt = get_persona_prompt(request.persona)
    user_query = request.messages[-1].content if request.messages else ""

    tools_used = []
    tool_insights = []

    # 1. Always-on RAG Knowledge Retrieval (OWASP / CWE / NIST standards)
    knowledge_entries = query_security_knowledge(user_query)
    if knowledge_entries:
        tools_used.append("query_security_knowledge")
        snippets = []
        for k in knowledge_entries:
            title = k.get("title", "Security Standard")
            std = k.get("standard", "OWASP/CWE")
            content = k.get("content", "")
            snippets.append(f"### [{std}] {title}\n{content}")
        tool_insights.append("### Trusted Security Knowledge (RAG Context):\n" + "\n\n".join(snippets))

    # 2. Active Repository Scan Evidence Context
    findings_context = get_active_findings_context(limit=6)
    if findings_context:
        tools_used.append("get_active_findings_context")
        tool_insights.append(f"### Active Repository Scan Evidence:\n{findings_context}")

    # 3. Funnel Summary Context (if requested or relevant)
    if any(kw in user_query.lower() for kw in ["summary", "metric", "funnel", "report", "overall", "score", "risk"]):
        summary = get_scan_funnel_summary()
        tools_used.append("get_scan_funnel_summary")
        tool_insights.append(f"### Scan Triage Summary Metrics:\n{summary}")

    insight_str = "\n\n".join(tool_insights) if tool_insights else "No active tool context triggered."

    # Construct Grounded LLM User Context
    context_msg = (
        f"--- GROUNDED EVIDENCE & RAG CONTEXT ---\n"
        f"{insight_str}\n"
        f"---------------------------------------\n\n"
        f"USER QUERY:\n{user_query}\n\n"
        f"Remember: Base your response ONLY on the grounded evidence and standards above."
    )

    llm_messages = [
        {"role": "system", "content": system_prompt},
    ]
    for m in request.messages[:-1]:
        llm_messages.append({"role": m.role, "content": m.content})
    llm_messages.append({"role": "user", "content": context_msg})

    if not settings.NVIDIA_API_KEY:
        reply = (
            f"[{request.persona} Persona Response]\n\n"
            f"Based on your query: '{user_query}'\n\n"
            f"{insight_str}\n\n"
            f"Recommendation:\nFor full model-guided reasoning, ensure `NVIDIA_API_KEY` is configured in `.env`."
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
        except httpx.HTTPStatusError as e:
            import logging
            logger = logging.getLogger("guardian.api")
            logger.error(f"HTTP error calling AI service: {e.response.text}", exc_info=True)
            reply = f"Error communicating with AI service (HTTP {e.response.status_code}): {e.response.text}"
        except Exception as e:
            import logging
            logger = logging.getLogger("guardian.api")
            logger.error("Error communicating with AI service", exc_info=True)
            reply = f"Error communicating with AI service: {str(e)}"

    return ChatCompletionResponse(
        persona=request.persona,
        reply=reply,
        tools_used=tools_used
    )
