from __future__ import annotations

import os
from urllib.parse import urlencode, urlsplit

from fastapi import Request

WINDOWS_NXLOG_INGEST_PATH = "/api/windows-agent/ingest"
LOGICX_INGEST_PATH = "/api/logicx/ingest"


def ingest_path_for_project_type(project_type: str) -> str:
    return WINDOWS_NXLOG_INGEST_PATH if (project_type or "").strip().lower() == "windows" else LOGICX_INGEST_PATH


def resolve_public_ingest_base(request: Request) -> str:
    """
    Resolve a public API base URL suitable for external agents.

    Priority:
    1) AGENT_INGEST_PUBLIC_BASE_URL env override
    2) Forwarded host/proto headers
    3) Origin header
    4) Referer header
    5) Request base URL

    If the resolved URL points to common frontend ports (3000/3001), it is
    rewritten to API port 4000 so agents bypass UI proxies.
    """
    explicit = (os.getenv("AGENT_INGEST_PUBLIC_BASE_URL") or "").strip()
    normalized_explicit = _normalize_base_url(explicit)
    if normalized_explicit:
        return normalized_explicit

    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",", 1)[0].strip()
    forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",", 1)[0].strip()

    candidates: list[str] = []
    if forwarded_proto and forwarded_host:
        candidates.append(f"{forwarded_proto}://{forwarded_host}")

    origin = (request.headers.get("origin") or "").strip()
    if origin:
        candidates.append(origin)

    referer = (request.headers.get("referer") or "").strip()
    if referer:
        candidates.append(referer)

    candidates.append(str(request.base_url).rstrip("/"))

    for candidate in candidates:
        normalized = _normalize_base_url(candidate)
        if normalized:
            return normalized

    # Safe fallback for local development.
    return "http://localhost:4000"


def build_ingest_url(base_url: str, ingest_path: str, project_id: str, api_key: str) -> str:
    query_api_key = api_key.strip() if api_key.strip() else "generate_api_key_from_projects_page"
    query = urlencode({"project_id": project_id, "api_key": query_api_key})
    return f"{base_url.rstrip('/')}{ingest_path}?{query}"


def _normalize_base_url(value: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    if not (value.startswith("http://") or value.startswith("https://")):
        return None

    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return None

    host = parsed.hostname
    if not host:
        return None

    port = parsed.port
    if port in {3000, 3001}:
        port = 4000

    if ":" in host and not host.startswith("["):
        host_display = f"[{host}]"
    else:
        host_display = host

    netloc = f"{host_display}:{port}" if port is not None else host_display
    return f"{parsed.scheme}://{netloc}".rstrip("/")
