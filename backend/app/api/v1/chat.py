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


import re

_GREETING_PATTERNS = [
    re.compile(r"^(hi|hello|hey|greetings|good\s+(morning|afternoon|evening)|hi\s+there|hello\s+there)\b[\!\?\. ]*$", re.I),
    re.compile(r"^(who\s+are\s+you|what\s+can\s+you\s+do|help|what\s+is\s+this)\b[\!\?\. ]*$", re.I),
    re.compile(r"^(thanks|thank\s+you|thx|awesome|great|cool)\b[\!\?\. ]*$", re.I),
    re.compile(r"^(bye|goodbye|cya|see\s+you)\b[\!\?\. ]*$", re.I),
]


def _check_greeting(query: str, persona: str) -> Optional[str]:
    q = query.strip()
    if not any(pat.match(q) for pat in _GREETING_PATTERNS):
        return None

    if re.search(r"thanks|thank|awesome|great|cool", q, re.I):
        return "You're welcome! Let me know if you have any questions about your repository scan findings or security policy."
    if re.search(r"bye|goodbye|cya|see\s+you", q, re.I):
        return "Goodbye! Have a great day."

    if persona == "Executive":
        return (
            "Hello! I am your AI Code Guardian Executive Advisor. "
            "How can I assist you with executive risk posture evaluation, compliance standards, or business impact metrics today?"
        )
    elif persona == "Red Teamer":
        return (
            "Greetings! I am your AI Code Guardian Red Team Specialist. "
            "Ask me about attack vectors, entry point reachability, or exploitability analysis for your scan findings."
        )
    else:
        return (
            "Hello! I am your AI Code Guardian Security Assistant tailored for the Developer persona. "
            "How can I assist you with analyzing code vulnerabilities, data flows, or safe remediation patches today?"
        )


@router.post("/completions", response_model=ChatCompletionResponse)
async def chat_completion(request: ChatCompletionRequest):
    system_prompt = get_persona_prompt(request.persona)
    user_query = request.messages[-1].content.strip() if request.messages else ""

    # Fast-path for conversational greetings
    greeting_reply = _check_greeting(user_query, request.persona)
    if greeting_reply:
        return ChatCompletionResponse(
            persona=request.persona,
            reply=greeting_reply,
            tools_used=[]
        )

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
    findings_context = get_active_findings_context(limit=10)
    if findings_context and findings_context != "No active repository scan findings currently registered.":
        tools_used.append("get_active_findings_context")
        tool_insights.append(f"### Active Repository Scan Evidence:\n{findings_context}")

    # 3. Funnel Summary Context & Walkthrough Keywords
    if any(kw in user_query.lower() for kw in ["summary", "metric", "funnel", "report", "overall", "score", "risk", "walkthrough", "walk through", "repository", "codebase", "overview", "explain"]):
        summary = get_scan_funnel_summary()
        tools_used.append("get_scan_funnel_summary")
        tool_insights.append(f"### Scan Triage Summary Metrics:\n{summary}")

    insight_str = "\n\n".join(tool_insights) if tool_insights else ""

    # Construct Grounded LLM User Context
    if insight_str:
        context_msg = (
            f"--- GROUNDED EVIDENCE & RAG CONTEXT ---\n"
            f"{insight_str}\n"
            f"---------------------------------------\n\n"
            f"USER QUERY:\n{user_query}\n\n"
            f"Remember: Base your response on the grounded evidence and standards above when applicable."
        )
    else:
        context_msg = user_query

    llm_messages = [
        {"role": "system", "content": system_prompt},
    ]
    for m in request.messages[:-1]:
        llm_messages.append({"role": m.role, "content": m.content})
    llm_messages.append({"role": "user", "content": context_msg})

    if not settings.NVIDIA_API_KEY:
        if insight_str:
            reply = (
                f"[{request.persona} Persona - Grounded Findings]\n\n"
                f"{insight_str}\n\n"
                f"*(Note: Configure `NVIDIA_API_KEY` in `.env` to enable interactive LLM chat reasoning.)*"
            )
        else:
            reply = (
                f"[{request.persona} Persona Response]\n\n"
                f"I could not find active scan findings or matched security standards for '{user_query}'.\n\n"
                f"Try asking about vulnerabilities, SQL injection, cryptography, or run a scan first. "
                f"*(Note: Configure `NVIDIA_API_KEY` in `.env` for full open-ended AI chat reasoning.)*"
            )
    else:
        try:
            timeout_config = httpx.Timeout(60.0, connect=10.0)
            async with httpx.AsyncClient(timeout=timeout_config) as client:
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
        except httpx.TimeoutException:
            import logging
            logger = logging.getLogger("guardian.api")
            logger.warning(f"Timeout calling AI service for query '{user_query}'")
            if insight_str:
                reply = (
                    f"[{request.persona} Persona - Grounded Findings]\n\n"
                    f"⚠️ **AI Service Timeout (>60s)**\n\n"
                    f"The upstream AI service timed out while generating detailed analysis. "
                    f"Here is the grounded evidence retrieved from your repository:\n\n"
                    f"{insight_str}"
                )
            else:
                reply = (
                    f"[{request.persona} Persona Response]\n\n"
                    f"⚠️ **AI Service Timeout (>60s)**\n\n"
                    f"The AI service took longer than 60 seconds to process your query '{user_query}'. "
                    f"Please try again or refine your question."
                )
        except httpx.HTTPStatusError as e:
            import logging
            logger = logging.getLogger("guardian.api")
            logger.error(f"HTTP error calling AI service: {e.response.text}", exc_info=True)
            reply = f"Error communicating with AI service (HTTP {e.response.status_code}): {e.response.text or str(e)}"
        except Exception as e:
            import logging
            logger = logging.getLogger("guardian.api")
            logger.error("Error communicating with AI service", exc_info=True)
            err_msg = str(e).strip() or f"{type(e).__name__}"
            reply = f"Error communicating with AI service: {err_msg}"

    return ChatCompletionResponse(
        persona=request.persona,
        reply=reply,
        tools_used=tools_used
    )
