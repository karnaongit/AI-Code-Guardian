"""
Chat & Reasoning API Endpoint
=============================
Provides interactive Nemotron AI completions grounded in scan evidence and RAG knowledge.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import json

from backend.app.core.config import settings
from guardian.copilot import synthesize_security_answer
from guardian.llm.personas import SystemPersona, get_persona_prompt
from guardian.reasoning.tools import (
    _ACTIVE_FINDINGS,
    query_security_knowledge,
    get_scan_funnel_summary,
    get_active_findings_context,
    get_repo_overview,
)

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatMessage(BaseModel):
    role: str = Field(..., description="Role: 'user', 'assistant', or 'system'")
    content: str = Field(..., description="Message content")


class ChatCompletionRequest(BaseModel):
    messages: List[ChatMessage]
    persona: str = Field("Developer", description="Persona: 'Executive', 'Developer', or 'Red Teamer'")
    temperature: float = Field(0.2, ge=0.0, le=1.0)
    thread_id: str = Field(..., description="Thread ID for conversation state")


class ChatCompletionResponse(BaseModel):
    persona: str
    reply: str
    tools_used: List[str] = Field(default_factory=list)


class ChatStreamRequest(BaseModel):
    message: str
    thread_id: str


GREETINGS = {"hi", "hello", "hey", "greetings", "good morning", "good afternoon", "good evening", "howdy", "sup"}


@router.post("/completions", response_model=ChatCompletionResponse)
async def chat_completion(request: ChatCompletionRequest):
    system_prompt = get_persona_prompt(request.persona)
    user_query = (request.messages[-1].content if request.messages else "").strip()
    query_lower = user_query.lower()

    tools_used = []
    tool_insights = []

    is_greeting = (query_lower in GREETINGS or len(query_lower) <= 3) and len(request.messages) <= 1

    if is_greeting:
        reply = (
            f"Hello! I am your AI Code Guardian Assistant ({request.persona} Persona).\n\n"
            f"I can help you analyze vulnerabilities, generate security fixes, explain CWE/OWASP risks, "
            f"or review active scan findings across your repository. How can I assist you today?"
        )
        return ChatCompletionResponse(persona=request.persona, reply=reply, tools_used=[])

    # 0. Repository Overview Context
    repo_overview = get_repo_overview()
    if repo_overview:
        tools_used.append("get_repo_overview")
        tool_insights.append(
            f"### Repository Overview:\n"
            f"- Project: `{repo_overview.get('repo_name', 'Active Repository')}`\n"
            f"- Summary: {repo_overview.get('summary', '')}\n"
            f"- Languages: {', '.join(repo_overview.get('primary_languages', []))}\n"
            f"- Frameworks: {', '.join(repo_overview.get('frameworks_detected', [])) or 'Standard'}\n"
            f"- Scanned Files: {repo_overview.get('total_files_scanned', 0)}"
        )

    # 1. RAG Knowledge Retrieval — query-aware, not a fixed answer.
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

    deterministic_reply, _ = synthesize_security_answer(
        user_query,
        list(_ACTIVE_FINDINGS.values()),
        persona=request.persona,
        conversation=[m.model_dump() for m in request.messages],
        knowledge=knowledge_entries,
    )

    if not settings.NVIDIA_API_KEY:
        if _ACTIVE_FINDINGS:
            reply = deterministic_reply
            tools_used.append("synthesize_security_answer")
        elif knowledge_entries:
            top = knowledge_entries[0]
            reply = (
                f"I do not see active repository scan findings loaded yet, but this guidance is relevant:\n\n"
                f"**Context:** {top.get('title', 'Security guidance')} ({top.get('standard', 'reference')}).\n\n"
                f"**The Risk:** {top.get('content', '')[:500]}\n\n"
                f"**Remediation:** Run a repository scan so I can connect this guidance to exact files, lines, and fixes."
            )
            tools_used.append("synthesize_security_answer")
        else:
            reply = deterministic_reply
            tools_used.append("synthesize_security_answer")
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
            print(f"LLM API Error: {e}")
            reply = deterministic_reply
            tools_used.append("synthesize_security_answer")

    return ChatCompletionResponse(
        persona=request.persona,
        reply=reply,
        tools_used=tools_used
    )


@router.post("/stream")
async def chat_stream(request: ChatStreamRequest):
    """Streams RAG Agent response using LangGraph Server-Sent Events."""
    from guardian.orchestrator.workflow import OrchestratorWorkflow
    
    workflow = OrchestratorWorkflow()
    
    async def event_generator():
        from langchain_core.messages import HumanMessage
        config = {"configurable": {"thread_id": request.thread_id}}
        inputs = {"scan_mode": "chat", "messages": [HumanMessage(content=request.message)]}
        
        try:
            # astream_events yields events dynamically
            async for event in workflow.compiled_graph.astream_events(inputs, config=config, version="v1"):
                kind = event["event"]
                if kind == "on_chat_model_stream":
                    chunk = event["data"]["chunk"]
                    if chunk.content:
                        yield f"data: {json.dumps({'content': chunk.content})}\n\n"
                        
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: [DONE]\n\n"
        
    return StreamingResponse(event_generator(), media_type="text/event-stream")

