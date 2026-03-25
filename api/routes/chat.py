"""
Hawkins Forensic Chat — API route  (/api/analysis/chat)
────────────────────────────────────────────────────────
Accepts a conversation history + rich component context and streams
the Groq response back as plain-text chunks using a FastAPI
StreamingResponse.  The GROQ_API_KEY never leaves this container.

POST /api/analysis/chat
  Body (JSON):
    {
      "context":       "<rich context string built by the dashboard widget>",
      "messages":      [{"role": "user"|"assistant", "content": "..."}],
      "component_key": "<unique widget identifier — used only for logging>"
    }

Stream format: raw UTF-8 text chunks, no envelope.
On error:      single JSON chunk  {"error": "..."}  with appropriate HTTP status.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Generator, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from groq import Groq
from pydantic import BaseModel
from api.deps import UserInDB, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Constants ──────────────────────────────────────────────────────────────────

_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
_MAX_TOKENS = 1024

# System prompt injected server-side — not visible or modifiable from the dashboard.
_SYSTEM_PROMPT = """\
You are Hawkins, a forensic analyst assistant inside the LOGIC Web Agent dashboard.

Rules:
- Answer only about the dashboard component and data provided in the context block.
- Be concise and technical. Assume the reader is a security analyst.
- Use Markdown formatting (bold, code, bullet lists) where it aids clarity.
- If the data contains suspicious patterns, call them out.
- Do NOT fabricate rule IDs, IP addresses, or log entries not present in the data.
- If context includes SELECTED_THREAT or RESPONSE_MODE detailed_forensic_report, provide:
    1) observation summary,
    2) likely attack path or behavior hypothesis,
    3) evidence from provided fields,
    4) confidence level (high/medium/low),
    5) prioritized next investigation actions.
"""


# ── Request model ──────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    context:       str             # Rich component context string from the widget
    messages:      List[dict]      # [{role: user|assistant, content: str}, ...]
    component_key: str = "unknown" # Identifier for logging only


# ── Streaming generator ────────────────────────────────────────────────────────

def _stream_groq(context: str, messages: List[dict]) -> Generator[str, None, None]:
    """
    Yields raw text chunks from Groq as they arrive.
    The context is prepended to the FIRST user message so the model always
    sees the component data without it polluting the visible chat history.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        yield json.dumps({"error": "GROQ_API_KEY is not configured on the server."})
        return

    client = Groq(api_key=api_key)

    # Build messages: system prompt → context-injected user turns
    groq_messages = [{"role": "system", "content": _SYSTEM_PROMPT}]

    # Prepend the component context to the very first user message.
    # For subsequent messages the context is already implicit in the system turn.
    context_injected = False
    for msg in messages:
        if msg["role"] == "user" and not context_injected:
            groq_messages.append({
                "role":    "user",
                "content": f"[COMPONENT CONTEXT]\n{context}\n\n[USER QUESTION]\n{msg['content']}",
            })
            context_injected = True
        else:
            groq_messages.append(msg)

    try:
        stream = client.chat.completions.create(
            model=_MODEL,
            max_tokens=_MAX_TOKENS,
            messages=groq_messages,
            temperature=0.3,
            stream=True,
        )
        for chunk in stream:
            delta = chunk.choices[0].delta
            text  = getattr(delta, "content", None) or ""
            if text:
                yield text
    except Exception as exc:
        logger.error("Groq streaming error: %s", exc)
        yield json.dumps({"error": str(exc)})


# ── Route ──────────────────────────────────────────────────────────────────────

@router.post("/chat")
async def hawkins_chat(req: ChatRequest, _user: UserInDB = Depends(get_current_user)) -> StreamingResponse:
    """
    Stream a Hawkins forensic chat response back to the Streamlit dashboard.
    Returns plain-text chunks (UTF-8).  Errors are returned as JSON chunks.
    """
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        raise HTTPException(
            status_code=503,
            detail="GROQ_API_KEY is not configured.  Set it in .env and rebuild the API container.",
        )

    if not req.messages:
        raise HTTPException(status_code=400, detail="messages list must not be empty.")

    logger.info("Hawkins chat — component=%s  turns=%d", req.component_key, len(req.messages))

    return StreamingResponse(
        _stream_groq(req.context, req.messages),
        media_type="text/plain; charset=utf-8",
        headers={
            # Prevent any proxy/CDN from buffering the stream
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-cache",
        },
    )
