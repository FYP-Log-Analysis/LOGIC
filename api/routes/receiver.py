from __future__ import annotations

import gzip
import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request

from api.deps import UserInDB, get_current_user, get_optional_current_user
from api.routes.projects import _normalize_project_id
from api.routes.upload import _ingest_and_normalise
from core.storage.sqlite_store import (
    get_project,
    get_project_by_api_key,
    get_uploads_for_project,
    init_db,
    insert_upload_status,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/receiver", tags=["Live Receiver"])

PROJECTS_DIR = Path(__file__).resolve().parents[2] / "data" / "projects"
_LIVE_UPLOAD_FILENAME = "live-stream.log"
_DEFAULT_SOURCE_FILE = "live-stream.log"
_PROJECT_PIPELINE_STATE: dict[str, dict[str, Any]] = {}
_STATE_GUARD = threading.Lock()
_PROJECT_MONITOR_STATE: dict[str, dict[str, Any]] = {}
_MONITOR_GUARD = threading.Lock()
_MAX_MONITOR_EVENTS = 100
_MAX_DECOMPRESSED_PAYLOAD_BYTES = 10 * 1024 * 1024
_MAX_RECORDS_PER_REQUEST = 5_000
_REQUIRED_AGENT_FIELDS = ("host", "file", "log", "date", "agent_version")


def _project_upload_dir(project_id: str, upload_id: str) -> Path:
    return PROJECTS_DIR / project_id / "uploads" / upload_id


def _get_monitor_state(project_id: str) -> dict[str, Any]:
    with _MONITOR_GUARD:
        state = _PROJECT_MONITOR_STATE.get(project_id)
        if state is None:
            state = {
                "started_at": None,
                "last_batch_at": None,
                "total_records": 0,
                "total_bytes": 0,
                "batch_count": 0,
                "last_upload_id": None,
                "last_host": None,
                "endpoint_usage": {},
                "validation_events": [],
                "processing_events": [],
            }
            _PROJECT_MONITOR_STATE[project_id] = state
        return state


def _push_monitor_event(events: list[dict[str, Any]], message: str) -> None:
    events.append({"timestamp": time.time(), "message": message})
    if len(events) > _MAX_MONITOR_EVENTS:
        del events[: len(events) - _MAX_MONITOR_EVENTS]


def _record_validation_error(project_id: str, message: str) -> None:
    state = _get_monitor_state(project_id)
    with _MONITOR_GUARD:
        _push_monitor_event(state["validation_events"], message)


def _record_processing_error(project_id: str, message: str) -> None:
    state = _get_monitor_state(project_id)
    with _MONITOR_GUARD:
        _push_monitor_event(state["processing_events"], message)


def _record_ingest_batch(
    project_id: str,
    upload_id: str,
    records: int,
    payload_bytes: int,
    host: str,
    endpoint_used: str,
) -> None:
    state = _get_monitor_state(project_id)
    now = time.time()
    with _MONITOR_GUARD:
        if state["started_at"] is None:
            state["started_at"] = now
        state["last_batch_at"] = now
        state["total_records"] += records
        state["total_bytes"] += payload_bytes
        state["batch_count"] += 1
        state["last_upload_id"] = upload_id
        state["last_host"] = host
        endpoint_usage = state.setdefault("endpoint_usage", {})
        endpoint_usage[endpoint_used] = int(endpoint_usage.get(endpoint_used, 0)) + 1


def get_live_monitor_snapshot(project_id: str) -> dict[str, Any]:
    state = _get_monitor_state(project_id)
    now = time.time()
    with _MONITOR_GUARD:
        started_at = state["started_at"]
        last_batch_at = state["last_batch_at"]
        has_traffic = bool(last_batch_at)
        uptime_seconds = int(now - started_at) if started_at else 0
        status = "active" if last_batch_at and (now - last_batch_at) <= 30 else "idle"
        seconds_since_last_batch = int(now - last_batch_at) if last_batch_at else None
        validation_errors = list(state["validation_events"][-20:])
        processing_errors = list(state["processing_events"][-20:])

        return {
            "project_id": project_id,
            "status": status,
            "has_traffic": has_traffic,
            "uptime_seconds": uptime_seconds,
            "last_batch_at": last_batch_at,
            "seconds_since_last_batch": seconds_since_last_batch,
            "batch_count": int(state["batch_count"]),
            "total_logs": int(state["total_records"]),
            "total_size_bytes": int(state["total_bytes"]),
            "last_upload_id": state["last_upload_id"],
            "last_host": state.get("last_host"),
            "endpoint_usage": dict(state.get("endpoint_usage", {})),
            "validation_errors": validation_errors,
            "processing_errors": processing_errors,
            "validation_error_count": len(validation_errors),
            "processing_error_count": len(processing_errors),
            "last_validation_error": validation_errors[-1] if validation_errors else None,
            "last_processing_error": processing_errors[-1] if processing_errors else None,
        }


def _get_pipeline_state(project_id: str) -> dict[str, Any]:
    with _STATE_GUARD:
        state = _PROJECT_PIPELINE_STATE.get(project_id)
        if state is None:
            state = {
                "lock": threading.Lock(),
                "dirty": threading.Event(),
            }
            _PROJECT_PIPELINE_STATE[project_id] = state
        return state


def _assert_project_access(project_id: str, user: UserInDB) -> dict:
    project_id = _normalize_project_id(project_id)
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project["owner_id"] != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Not your project")
    return project


def _latest_live_upload_id(project_id: str) -> str | None:
    for upload in get_uploads_for_project(project_id):
        filename = (upload.get("filename") or "").strip()
        if filename == _LIVE_UPLOAD_FILENAME and upload.get("status") != "error":
            return upload["upload_id"]
    return None


def _ensure_live_upload(project_id: str, rotate: bool) -> str:
    init_db()
    if not rotate:
        existing = _latest_live_upload_id(project_id)
        if existing:
            return existing

    upload_id = str(uuid.uuid4())
    raw_dir = _project_upload_dir(project_id, upload_id) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    insert_upload_status(upload_id, project_id=project_id, filename=_LIVE_UPLOAD_FILENAME)
    logger.info("Created live upload session upload_id=%s project_id=%s", upload_id, project_id)
    return upload_id


def _sanitize_source_name(value: str | None) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return _DEFAULT_SOURCE_FILE
    candidate = Path(candidate).name.replace("..", "_")
    if not candidate:
        return _DEFAULT_SOURCE_FILE
    suffix = Path(candidate).suffix.lower()
    if suffix not in {".log", ".txt", ".gz"}:
        candidate = f"{candidate}.log"
    return candidate


def _extract_source(record: dict[str, Any]) -> str:
    return _sanitize_source_name(
        record.get("file")
        or record.get("path")
        or record.get("source")
        or record.get("filename")
        or record.get("log_file")
    )


def _extract_raw_message(record: dict[str, Any]) -> str:
    for key in ("log", "message", "raw"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.rstrip("\n")
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"))


def _validate_agent_record_fields(record: dict[str, Any], line_number: int | None = None) -> None:
    missing = [
        field
        for field in _REQUIRED_AGENT_FIELDS
        if not isinstance(record.get(field), str) or not record.get(field, "").strip()
    ]
    if missing:
        location = f" at record {line_number}" if line_number is not None else ""
        raise HTTPException(
            status_code=400,
            detail=f"Invalid log record{location}: missing required fields {', '.join(missing)}",
        )


def _parse_json_body(payload: bytes, enforce_agent_schema: bool = False) -> list[tuple[str, str]]:
    if not payload.strip():
        return []

    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {exc}")

    if isinstance(decoded, dict):
        records: list[Any] = decoded.get("records") if isinstance(decoded.get("records"), list) else [decoded]
    elif isinstance(decoded, list):
        records = decoded
    else:
        raise HTTPException(status_code=400, detail="JSON payload must be an object or array")

    extracted: list[tuple[str, str]] = []
    for idx, record in enumerate(records, start=1):
        if isinstance(record, str):
            if enforce_agent_schema:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid log record at record {idx}: expected JSON object",
                )
            line = record.strip()
            if line:
                extracted.append((_DEFAULT_SOURCE_FILE, line))
            continue
        if not isinstance(record, dict):
            if enforce_agent_schema:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid log record at record {idx}: expected JSON object",
                )
            continue
        if enforce_agent_schema:
            _validate_agent_record_fields(record, idx)
        line = _extract_raw_message(record).strip()
        if not line:
            continue
        extracted.append((_extract_source(record), line))
    return extracted


def _parse_ndjson_body(payload: bytes, enforce_agent_schema: bool = False) -> list[tuple[str, str]]:
    extracted: list[tuple[str, str]] = []
    parse_errors = 0
    for line_number, raw_line in enumerate(payload.decode("utf-8", errors="replace").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        if isinstance(decoded, dict):
            if enforce_agent_schema:
                _validate_agent_record_fields(decoded, line_number)
            message = _extract_raw_message(decoded).strip()
            if message:
                extracted.append((_extract_source(decoded), message))
        elif isinstance(decoded, str) and decoded.strip():
            if enforce_agent_schema:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid log record at line {line_number}: expected JSON object",
                )
            extracted.append((_DEFAULT_SOURCE_FILE, decoded.strip()))

    if parse_errors:
        raise HTTPException(
            status_code=400,
            detail=f"Malformed NDJSON payload: {parse_errors} line(s) are not valid JSON",
        )
    return extracted


def _extract_records(
    payload: bytes,
    content_type: str | None,
    enforce_agent_schema: bool = False,
) -> list[tuple[str, str]]:
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype in {"application/json"}:
        return _parse_json_body(payload, enforce_agent_schema=enforce_agent_schema)
    if ctype in {"application/x-ndjson", "application/jsonl", "text/plain", ""}:
        return _parse_ndjson_body(payload, enforce_agent_schema=enforce_agent_schema)
    if ctype == "application/octet-stream":
        return _parse_ndjson_body(payload, enforce_agent_schema=enforce_agent_schema)
    raise HTTPException(status_code=415, detail=f"Unsupported content type '{ctype or 'unknown'}'")


def _append_records(project_id: str, upload_id: str, records: list[tuple[str, str]]) -> int:
    raw_dir = _project_upload_dir(project_id, upload_id) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    by_source: dict[str, list[str]] = {}
    for source, line in records:
        if not line:
            continue
        by_source.setdefault(source, []).append(line)
        written += 1

    for source, lines in by_source.items():
        with open(raw_dir / source, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.write("\n")
    return written


def _run_live_pipeline(upload_id: str, project_id: str) -> None:
    state = _get_pipeline_state(project_id)
    dirty: threading.Event = state["dirty"]
    lock: threading.Lock = state["lock"]
    dirty.set()

    if not lock.acquire(blocking=False):
        logger.debug("Live pipeline already running for project_id=%s; coalescing batch", project_id)
        return

    try:
        while True:
            dirty.clear()
            try:
                _ingest_and_normalise(upload_id, project_id)
            except Exception as exc:  # pragma: no cover - defensive runtime capture
                _record_processing_error(project_id, str(exc))
                raise
            if not dirty.is_set():
                break
    finally:
        lock.release()


def _extract_sender_host(payload: bytes, content_type: str | None, fallback: str = "unknown") -> str:
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype == "application/json":
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            return fallback

        candidates: list[Any]
        if isinstance(decoded, dict):
            if isinstance(decoded.get("records"), list):
                candidates = decoded["records"]
            else:
                candidates = [decoded]
        elif isinstance(decoded, list):
            candidates = decoded
        else:
            return fallback

        for item in candidates:
            if isinstance(item, dict):
                host = str(item.get("host") or "").strip()
                if host:
                    return host
        return fallback

    for raw_line in payload.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            host = str(decoded.get("host") or "").strip()
            if host:
                return host
    return fallback


def _validate_payload_limits(payload: bytes, records: list[tuple[str, str]]) -> None:
    if len(payload) > _MAX_DECOMPRESSED_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large after decompression (limit {_MAX_DECOMPRESSED_PAYLOAD_BYTES} bytes)",
        )

    if len(records) > _MAX_RECORDS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"Too many records in one request (limit {_MAX_RECORDS_PER_REQUEST})",
        )


async def _receive_live_ingest(
    request: Request,
    background_tasks: BackgroundTasks,
    project_id: str,
    rotate: bool,
    current_user: Optional[UserInDB],
    x_logic_api_key: Optional[str],
    endpoint_used: str,
) -> dict:
    # Resolve authentication.
    if x_logic_api_key:
        project = get_project_by_api_key(x_logic_api_key)
        if not project or project["id"] != project_id:
            raise HTTPException(status_code=401, detail="Invalid API key for this project")
    elif current_user:
        project = _assert_project_access(project_id, current_user)
    else:
        raise HTTPException(
            status_code=401,
            detail="Authentication required: provide an X-Logic-Api-Key header or Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = await request.body()
    if not payload:
        _record_validation_error(project_id, "Empty request body")
        raise HTTPException(status_code=400, detail="Request body is empty")

    # Decompress gzip-encoded payloads from the LOGIC agent.
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            payload = gzip.decompress(payload)
        except Exception as exc:
            _record_validation_error(project_id, f"gzip decompression failed: {exc}")
            raise HTTPException(status_code=400, detail=f"Failed to decompress gzip body: {exc}")

    try:
        records = _extract_records(
            payload,
            request.headers.get("content-type"),
            enforce_agent_schema=True,
        )
        _validate_payload_limits(payload, records)
    except HTTPException as exc:
        _record_validation_error(project_id, str(exc.detail))
        raise

    if not records:
        _record_validation_error(project_id, "No log records found in request body")
        raise HTTPException(status_code=400, detail="No log records found in request body")

    upload_id = _ensure_live_upload(project_id, rotate=rotate)
    written = _append_records(project_id, upload_id, records)
    sender_host = _extract_sender_host(
        payload,
        request.headers.get("content-type"),
        fallback=(request.client.host if request.client else "unknown"),
    )
    _record_ingest_batch(project_id, upload_id, written, len(payload), sender_host, endpoint_used)
    background_tasks.add_task(_run_live_pipeline, upload_id, project_id)

    logger.info(
        "LOGICX Receiver: %d logs received from %s (project %s, endpoint %s, payload_bytes %d)",
        written,
        sender_host,
        project_id,
        endpoint_used,
        len(payload),
    )

    return {
        "status": "accepted",
        "project_id": project_id,
        "upload_id": upload_id,
        "records_received": written,
        "message": "Live log batch queued for analysis.",
        "status_url": f"/api/upload/status/{upload_id}",
        "logs_url": f"/api/upload/logs/{upload_id}",
    }


@router.get("/monitor")
async def get_project_live_monitor(
    project_id: str = Query(..., description="Project to inspect live agent monitor data"),
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    _assert_project_access(project_id, current_user)
    return get_live_monitor_snapshot(project_id)