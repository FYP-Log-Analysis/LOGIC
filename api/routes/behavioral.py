"""
API routes for behavioral traffic analysis.

POST /api/analysis/behavioral          — run all 4 behavioral detections
GET  /api/analysis/behavioral/results  — return the latest behavioral_results.json
GET  /api/analysis/behavioral/alerts   — query SQLite behavioral_alerts table
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from api.deps import UserInDB, get_current_user
from api.routes.projects import _normalize_project_id

logger = logging.getLogger(__name__)
router = APIRouter()

_PROJECT_ROOT  = Path(__file__).resolve().parents[2]


def _results_path(project_id: str | None) -> Path | None:
    if project_id:
        project_id = _normalize_project_id(project_id)
        return _PROJECT_ROOT / "data" / "projects" / project_id / "detection_results" / "behavioral_results.json"
    return None


def _assert_project_type(project_id: str, required_type: str) -> dict:
    from core.storage.sqlite_store import get_project

    project_id = _normalize_project_id(project_id)
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")
    if project.get("project_type") != required_type:
        raise HTTPException(
            status_code=400,
            detail=(
                f"This endpoint is for {required_type.upper()} projects. "
                f"The project '{project_id}' is a {project.get('project_type', 'unknown').upper()} project."
            ),
        )
    return project


# ── Request schemas ────────────────────────────────────────────────────────────

class BehavioralRequest(BaseModel):
    rate_window_minutes:    int   = 1
    rate_threshold:         int   = 60
    enum_window_hours:      int   = 1
    enum_threshold:         int   = 50
    status_window_minutes:  int   = 5
    status_error_ratio:     float = 0.50
    visitor_zscore:         float = 2.0
    start_ts:               Optional[str] = None
    end_ts:                 Optional[str] = None
    project_id:             Optional[str] = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/behavioral")
def run_behavioral(req: BehavioralRequest, _user: UserInDB = Depends(get_current_user)):
    """Run all behavioral detections and persist results."""
    try:
        project_id = _normalize_project_id(req.project_id)
        _assert_project_type(project_id, "web")

        from core.behavioral.behavioral import run_behavioral_analysis
        result = run_behavioral_analysis(
            rate_window_minutes   = req.rate_window_minutes,
            rate_threshold        = req.rate_threshold,
            enum_window_hours     = req.enum_window_hours,
            enum_threshold        = req.enum_threshold,
            status_window_minutes = req.status_window_minutes,
            status_error_ratio    = req.status_error_ratio,
            visitor_zscore        = req.visitor_zscore,
            start_ts              = req.start_ts,
            end_ts                = req.end_ts,
            project_id            = project_id,
        )
        return {
            "status":  "complete",
            "summary": result.get("summary", {}),
            "generated_at": result.get("generated_at"),
        }
    except Exception as exc:
        logger.exception("Behavioral analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/behavioral/results")
def get_behavioral_results(
    project_id: Optional[str] = Query(None, description="Scope to a specific project"),
    _user: UserInDB = Depends(get_current_user),
):
    """Return the latest behavioral_results.json (project-scoped if project_id given)."""
    project_id = _normalize_project_id(project_id)
    _assert_project_type(project_id, "web")

    path = _results_path(project_id)
    if not path or not path.exists():
        detail = (
            f"No behavioral results found for project '{project_id}'. "
            "Run POST /api/analysis/behavioral first."
            if project_id
            else "No behavioral results found. Run POST /api/analysis/behavioral first."
        )
        raise HTTPException(status_code=404, detail=detail)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read results: {exc}")


@router.get("/behavioral/alerts")
def get_behavioral_alerts_route(
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    client_ip:  Optional[str] = Query(None, description="Filter by client IP"),
    project_id: Optional[str] = Query(None, description="Scope to a specific project"),
    start_ts:   Optional[str] = Query(None, description="Earliest timestamp (ISO 8601)"),
    end_ts:     Optional[str] = Query(None, description="Latest timestamp (ISO 8601)"),
    limit:      int           = Query(500,  ge=1, le=5000),
    offset:     int           = Query(0,    ge=0),
    _user:      UserInDB      = Depends(get_current_user),
):
    """Query behavioral alerts from behavioral_results.json files."""
    try:
        if project_id:
            _assert_project_type(project_id, "web")

        from core.storage.sqlite_store import get_behavioral_alerts as _get
        return {"alerts": _get(
            alert_type=alert_type, client_ip=client_ip,
            project_id=project_id, start_ts=start_ts, end_ts=end_ts,
            limit=limit, offset=offset,
        )}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Windows Behavioral (ML) Endpoints ──────────────────────────────────────────

class WindowsBehavioralRequest(BaseModel):
    window_minutes: int = 5
    project_id: Optional[str] = None
    upload_id: Optional[str] = None
    start_ts: Optional[str] = None
    end_ts: Optional[str] = None


@router.post("/windows/behavioral")
def run_windows_behavioral(
    req: WindowsBehavioralRequest,
    _user: UserInDB = Depends(get_current_user),
):
    """Run Windows ML (Isolation Forest) anomaly detection."""
    try:
        project_id = _normalize_project_id(req.project_id)
        _assert_project_type(project_id, "windows")

        resolved_upload_id = req.upload_id
        if not resolved_upload_id:
            from core.storage.sqlite_store import get_uploads_for_project

            uploads = get_uploads_for_project(project_id)
            for upload in uploads:
                if upload.get("status") == "complete":
                    resolved_upload_id = upload["upload_id"]
                    break

        if not resolved_upload_id:
            raise HTTPException(
                status_code=404,
                detail=f"No uploads found for project '{project_id}'. Upload logs first.",
            )

        from core.behavioral.windows_ml import run_windows_ml_analysis
        
        result = run_windows_ml_analysis(
            project_id=project_id,
            upload_id=resolved_upload_id,
            window_minutes=req.window_minutes,
            start_ts=req.start_ts,
            end_ts=req.end_ts,
        )
        return {
            "status": "complete",
            "total_windows": result.get("total_windows", 0),
            "anomalous_windows": result.get("anomalous_windows", 0),
            "detection_status": result.get("status", "unknown"),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Windows behavioral analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/windows/behavioral/results")
def get_windows_behavioral_results(
    project_id: Optional[str] = Query(None, description="Scope to a specific project"),
    upload_id: Optional[str] = Query(None, description="Target a specific upload"),
    _user: UserInDB = Depends(get_current_user),
):
    """Get Windows ML anomaly detection results."""
    from pathlib import Path
    
    project_id = _normalize_project_id(project_id)
    _assert_project_type(project_id, "windows")
    
    projects_dir = _PROJECT_ROOT / "data" / "projects"
    
    # Resolve upload_id
    if not upload_id:
        from core.storage.sqlite_store import get_uploads_for_project
        uploads = get_uploads_for_project(project_id)
        for u in uploads:
            if u.get("status") == "complete":
                upload_id = u["upload_id"]
                break
    
    if not upload_id:
        raise HTTPException(status_code=404, detail=f"No uploads found for project '{project_id}'.")
    
    results_path = projects_dir / project_id / "uploads" / upload_id / "windows_ml_anomalies.json"
    
    if not results_path.exists():
        raise HTTPException(status_code=404, detail="No Windows behavioral results found. Run analysis first.")
    
    try:
        with open(results_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read results: {exc}")


def _parse_iso_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


@router.get("/windows/behavioral/window-events")
def get_windows_behavioral_window_events(
    project_id: Optional[str] = Query(None, description="Scope to a specific project"),
    upload_id: Optional[str] = Query(None, description="Target a specific upload"),
    window_start: Optional[str] = Query(None, description="Window start (ISO 8601)"),
    start_ts: Optional[str] = Query(None, description="Backward-compatible alias for window_start"),
    window_minutes: int = Query(5, ge=1, le=180, description="Window size in minutes"),
    limit: int = Query(200, ge=1, le=2000, description="Max matching events returned"),
    _user: UserInDB = Depends(get_current_user),
):
    """Return normalized Windows events for a selected behavioral analysis time window."""
    import ijson

    project_id = _normalize_project_id(project_id)
    _assert_project_type(project_id, "windows")

    selected_start_raw = window_start or start_ts
    selected_start = _parse_iso_utc(selected_start_raw)
    if not selected_start:
        raise HTTPException(status_code=400, detail="window_start (or start_ts) must be a valid ISO 8601 timestamp.")

    if not upload_id:
        from core.storage.sqlite_store import get_uploads_for_project

        uploads = get_uploads_for_project(project_id)
        for upload in uploads:
            if upload.get("status") == "complete":
                upload_id = upload["upload_id"]
                break

    if not upload_id:
        raise HTTPException(status_code=404, detail=f"No uploads found for project '{project_id}'.")

    projects_dir = _PROJECT_ROOT / "data" / "projects"
    normalized_path = projects_dir / project_id / "uploads" / upload_id / "normalized.json"
    if not normalized_path.exists():
        raise HTTPException(status_code=404, detail="No normalized Windows log data found for selected upload.")

    selected_end = selected_start + timedelta(minutes=window_minutes)
    sampled_events = []
    total_events = 0

    try:
        with open(normalized_path, "rb") as fh:
            for entry in ijson.items(fh, "item"):
                if entry.get("server_type") != "windows_event":
                    continue

                event_ts = _parse_iso_utc(entry.get("timestamp"))
                if not event_ts:
                    continue
                if not (selected_start <= event_ts < selected_end):
                    continue

                total_events += 1
                if len(sampled_events) < limit:
                    sampled_events.append(
                        {
                            "timestamp": entry.get("timestamp"),
                            "computer": entry.get("computer"),
                            "channel": entry.get("channel"),
                            "event_id": entry.get("event_id"),
                            "auth_user": entry.get("auth_user"),
                            "client_ip": entry.get("client_ip"),
                            "level": entry.get("level"),
                            "message": entry.get("message"),
                            "entry": entry,
                        }
                    )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to read window events for project=%s upload=%s", project_id, upload_id)
        raise HTTPException(status_code=500, detail=f"Could not extract window events: {exc}")

    return {
        "project_id": project_id,
        "upload_id": upload_id,
        "window_start": selected_start.isoformat(),
        "window_end": selected_end.isoformat(),
        "window_minutes": window_minutes,
        "total_events": total_events,
        "events": sampled_events,
    }
