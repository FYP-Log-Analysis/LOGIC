from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Any, Dict, Optional
from api.deps import UserInDB, get_current_user
from api.routes.projects import _normalize_project_id
from api.services.llm_service import async_analyse_windows_event
import json
import logging
import uuid
import threading
from pathlib import Path
from datetime import datetime, timezone
import yaml

logger = logging.getLogger(__name__)
router = APIRouter()

PROJECTS_DIR = Path(__file__).resolve().parents[2] / "data" / "projects"
SIGMA_RULES_DIR = Path(__file__).resolve().parents[2] / "data" / "sigma_rules"


def _iter_sigma_rule_files(root: Path) -> list[Path]:
    """Return all YAML Sigma rule files under the sigma root."""
    if not root.exists() or not root.is_dir():
        return []

    files = [
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
    ]
    files.sort(key=lambda p: str(p.relative_to(root)).replace("\\", "/").lower())
    return files


def _read_sigma_rule_metadata(rule_file: Path) -> dict[str, Any]:
    """Extract lightweight Sigma metadata from YAML; fall back to filename when needed."""
    try:
        relative_path = str(rule_file.resolve().relative_to(SIGMA_RULES_DIR.resolve())).replace("\\", "/")
    except Exception:
        relative_path = rule_file.name

    metadata: dict[str, Any] = {
        "rule_path": relative_path,
        "id": rule_file.stem,
        "title": rule_file.stem,
        "level": "medium",
        "description": "",
        "logsource": {},
        "tags": [],
    }

    try:
        parsed = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        if isinstance(parsed, dict):
            metadata["id"] = str(parsed.get("id", "")).strip() or rule_file.stem
            metadata["title"] = str(parsed.get("title", "")).strip() or rule_file.stem
            metadata["level"] = str(parsed.get("level", "medium")).lower()
            metadata["description"] = str(parsed.get("description", "")).strip()
            metadata["logsource"] = parsed.get("logsource") if isinstance(parsed.get("logsource"), dict) else {}
            metadata["tags"] = parsed.get("tags") if isinstance(parsed.get("tags"), list) else []
    except Exception:
        # Keep fallback metadata so broken YAML can still be listed and opened.
        pass

    return metadata


def _latest_upload_id(project_id: str) -> str | None:
    """Return the most-recent completed upload_id for a project, or None."""
    from core.storage.sqlite_store import get_uploads_for_project
    uploads = get_uploads_for_project(project_id)
    for u in uploads:
        if u.get("status") == "complete":
            return u["upload_id"]
    return None


def _windows_project_paths(project_id: str | None, upload_id: str | None = None) -> tuple[Path, Path, str]:
    """Return (normalized_path, results_path, resolved_upload_id) for Windows project."""
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id is required.")
    
    project_id = _normalize_project_id(project_id)
    
    # Validate project type is Windows
    from core.storage.sqlite_store import get_project
    proj = get_project(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found.")
    if proj.get("project_type") != "windows":
        raise HTTPException(
            status_code=400,
            detail=f"This endpoint is for WINDOWS projects. Project '{project_id}' is a {proj.get('project_type', 'unknown').upper()} project.",
        )
    
    resolved_upload = upload_id or _latest_upload_id(project_id)
    if not resolved_upload:
        raise HTTPException(
            status_code=404,
            detail=f"No uploads found for Windows project '{project_id}'.",
        )
    
    base = PROJECTS_DIR / project_id / "uploads" / resolved_upload
    return (
        base / "normalized.json",
        base / "windows_sigma_matches.json",
        resolved_upload,
    )


def _filter_by_time_range(items: list, start_ts: str | None, end_ts: str | None, timestamp_field: str = "timestamp") -> list:
    """Filter a list of items by timestamp range (ISO 8601 format)."""
    if not start_ts and not end_ts:
        return items
    
    filtered = []
    try:
        start_dt = datetime.fromisoformat(start_ts.replace("Z", "+00:00")) if start_ts else None
        end_dt = datetime.fromisoformat(end_ts.replace("Z", "+00:00")) if end_ts else None
        if start_dt and start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
        if end_dt and end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return items
    
    for item in items:
        ts_str = item.get(timestamp_field)
        if not ts_str:
            continue
        try:
            item_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if item_dt.tzinfo is None:
                item_dt = item_dt.replace(tzinfo=timezone.utc)
            if start_dt and item_dt < start_dt:
                continue
            if end_dt and item_dt > end_dt:
                continue
            filtered.append(item)
        except (ValueError, AttributeError, TypeError):
            continue
    
    return filtered


def _severity_rank(value: str | None) -> int:
    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    return severity_order.get(str(value or "").lower(), 0)


def _sort_windows_matches(matches: list[dict], sort_expr: str) -> list[dict]:
    """Sort matches by allowed keys. Prefix with '-' for descending order."""
    expr = (sort_expr or "-timestamp").strip()
    descending = expr.startswith("-")
    sort_key = expr[1:] if descending else expr
    allowed = {"timestamp", "severity", "rule_title", "computer", "event_id", "channel"}
    if sort_key not in allowed:
        sort_key = "timestamp"
        descending = True

    def _key(item: dict):
        if sort_key == "severity":
            return _severity_rank(item.get("severity"))
        value = item.get(sort_key)
        if value is None:
            return ""
        if sort_key == "event_id":
            try:
                return int(value)
            except Exception:
                return str(value)
        return str(value)

    return sorted(matches, key=_key, reverse=descending)


def _project_windows_match_fields(matches: list[dict], fields_expr: str | None, include_entry: bool) -> list[dict]:
    """Return matches with optional field projection while preserving key display fields."""
    if not fields_expr and include_entry:
        return matches

    keep_fields = {
        "rule_id",
        "rule_title",
        "severity",
        "timestamp",
        "computer",
        "event_id",
        "channel",
        "mitre_techniques",
    }
    if fields_expr:
        requested = {f.strip() for f in fields_expr.split(",") if f.strip()}
        keep_fields.update(requested)
    if include_entry:
        keep_fields.add("entry")

    projected: list[dict] = []
    for match in matches:
        row = {k: v for k, v in match.items() if k in keep_fields}
        projected.append(row)
    return projected


class WindowsAnalysisRequest(BaseModel):
    mode: str = "auto"
    start_ts: Optional[str] = None
    end_ts: Optional[str] = None
    project_id: Optional[str] = None
    upload_id: Optional[str] = None


class WindowsEventExplainRequest(BaseModel):
    event: Dict[str, Any]
    project_id: Optional[str] = None


# In-memory run tracking
_windows_runs: dict = {}
_windows_cancel_requested: set[str] = set()
_windows_run_lock = threading.Lock()


@router.post("/windows/explain-event")
async def explain_windows_event(
    request: WindowsEventExplainRequest,
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Explain one Windows event record using Groq LLM."""
    if request.project_id:
        project_id = _normalize_project_id(request.project_id)
        from core.storage.sqlite_store import get_project

        project = get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found.")
        if project.get("project_type") != "windows":
            raise HTTPException(status_code=400, detail="This endpoint is for WINDOWS projects only.")

    if not isinstance(request.event, dict) or not request.event:
        raise HTTPException(status_code=400, detail="event payload is required.")

    result = await async_analyse_windows_event(request.event)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message") or "Event explanation failed")

    return {
        "status": "success",
        **result,
    }


@router.post("/windows/run-sigma")
async def run_windows_sigma(
    request: WindowsAnalysisRequest,
    background_tasks: BackgroundTasks,
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Run Sigma rule detection on Windows EVTX logs."""
    normalised_path, results_path, resolved_upload_id = _windows_project_paths(
        request.project_id,
        request.upload_id,
    )
    
    if not normalised_path.exists():
        raise HTTPException(status_code=400, detail="No normalised log data found. Upload logs first.")
    
    run_id = str(uuid.uuid4())
    with _windows_run_lock:
        _windows_runs[run_id] = {
            "run_id": run_id,
            "mode": request.mode,
            "project_id": request.project_id,
            "upload_id": resolved_upload_id,
            "status": "pending",
            "analysis_type": "windows_sigma",
            "cancel_requested": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    
    def _run_windows_sigma_task():
        """Background task to run Windows Sigma detection."""
        def _should_cancel() -> bool:
            with _windows_run_lock:
                return run_id in _windows_cancel_requested

        try:
            from core.detection.windows_sigma import run_sigma_pipeline

            with _windows_run_lock:
                record = _windows_runs.get(run_id)
                if not record:
                    return
                if run_id in _windows_cancel_requested:
                    record["status"] = "cancelled"
                    record["cancelled_at"] = datetime.now(timezone.utc).isoformat()
                    _windows_cancel_requested.discard(run_id)
                    return
                record["status"] = "running"
                record["started_at"] = datetime.now(timezone.utc).isoformat()
            
            # Load Windows events from normalized.json
            windows_events = []
            with open(normalised_path, "r", encoding="utf-8") as fh:
                import ijson
                for index, entry in enumerate(ijson.items(fh, "item")):
                    if index % 500 == 0 and _should_cancel():
                        with _windows_run_lock:
                            record = _windows_runs.get(run_id)
                            if record:
                                record["status"] = "cancelled"
                                record["cancelled_at"] = datetime.now(timezone.utc).isoformat()
                                record["cancelled_at_step"] = "loading_events"
                                record["total_events"] = len(windows_events)
                            _windows_cancel_requested.discard(run_id)
                        return

                    if entry.get("server_type") == "windows_event":
                        windows_events.append(entry)
            
            if request.start_ts or request.end_ts:
                windows_events = _filter_by_time_range(
                    windows_events,
                    request.start_ts,
                    request.end_ts,
                    "timestamp",
                )
            
            if not windows_events:
                empty_result = {
                    "matches": [],
                    "matched_rules": [],
                    "total_matches": 0,
                    "sigma_matches": 0,
                }
                with open(results_path, "w", encoding="utf-8") as fh:
                    json.dump(empty_result, fh, indent=2)
                with _windows_run_lock:
                    record = _windows_runs.get(run_id)
                    if record:
                        record["status"] = "complete"
                        record["total_events"] = 0
                        record["total_matches"] = 0
                        record["completed_at"] = datetime.now(timezone.utc).isoformat()
                    _windows_cancel_requested.discard(run_id)
                return

            # Run Sigma pipeline
            result = run_sigma_pipeline(windows_events, str(SIGMA_RULES_DIR), should_cancel=_should_cancel)

            if result.get("cancelled") or _should_cancel():
                with _windows_run_lock:
                    record = _windows_runs.get(run_id)
                    if record:
                        record["status"] = "cancelled"
                        record["cancelled_at"] = datetime.now(timezone.utc).isoformat()
                        record["total_events"] = result.get("processed_events", len(windows_events))
                        record["total_matches"] = result.get("total_matches", 0)
                    _windows_cancel_requested.discard(run_id)
                return

            # Persist results
            results_path.parent.mkdir(parents=True, exist_ok=True)
            with open(results_path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)

            with _windows_run_lock:
                record = _windows_runs.get(run_id)
                if record:
                    record["status"] = "complete"
                    record["total_events"] = len(windows_events)
                    record["total_matches"] = result.get("total_matches", 0)
                    record["unique_rules"] = len(result.get("matched_rules", []))
                    record["completed_at"] = datetime.now(timezone.utc).isoformat()
                _windows_cancel_requested.discard(run_id)

        except Exception as exc:
            logger.error(f"Windows Sigma task {run_id} failed: {exc}", exc_info=True)
            with _windows_run_lock:
                record = _windows_runs.get(run_id)
                if not record:
                    return
                if run_id in _windows_cancel_requested:
                    record["status"] = "cancelled"
                    record["cancelled_at"] = datetime.now(timezone.utc).isoformat()
                    _windows_cancel_requested.discard(run_id)
                    return
                record["status"] = "failed"
                record["error"] = str(exc)[:500]
                record["failed_at"] = datetime.now(timezone.utc).isoformat()
                _windows_cancel_requested.discard(run_id)
    
    background_tasks.add_task(_run_windows_sigma_task)
    return {
        "status": "accepted",
        "run_id": run_id,
        "message": "Windows Sigma analysis started.",
    }


@router.get("/windows/results")
async def get_windows_sigma_results(
    project_id: Optional[str] = Query(None, description="Scope to a specific project"),
    upload_id: Optional[str] = Query(None, description="Target a specific upload"),
    start_ts: Optional[str] = Query(None, description="Filter start time (ISO 8601)"),
    end_ts: Optional[str] = Query(None, description="Filter end time (ISO 8601)"),
    limit: Optional[int] = Query(None, ge=1, le=5000, description="Maximum matches returned"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    sort: str = Query("-timestamp", description="Sort key, prefix with '-' for descending"),
    fields: Optional[str] = Query(None, description="Comma-separated list of top-level match fields"),
    include_entry: bool = Query(True, description="Include raw event entry payload"),
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Get Windows Sigma detection results with optional time filtering."""
    _, results_path, _ = _windows_project_paths(project_id, upload_id)
    
    if not results_path.exists():
        return {
            "matches": [],
            "matched_rules": [],
            "total_matches": 0,
            "sigma_matches": 0,
        }
    
    with open(results_path, "r", encoding="utf-8") as fh:
        results = json.load(fh)
    
    matches = results.get("matches", [])

    # Apply time range filter if requested.
    if start_ts or end_ts:
        matches = _filter_by_time_range(matches, start_ts, end_ts, "timestamp")
        results["filtered_by_time"] = True
        results["time_range"] = {"start": start_ts, "end": end_ts}

    # Sort and optionally project fields.
    matches = _sort_windows_matches(matches, sort)
    matches = _project_windows_match_fields(matches, fields, include_entry)

    total_count = len(matches)
    if limit is not None:
        paginated_matches = matches[offset: offset + limit]
        has_more = offset + len(paginated_matches) < total_count
    else:
        paginated_matches = matches[offset:] if offset else matches
        has_more = False

    results["matches"] = paginated_matches
    results["count"] = total_count
    results["total_matches"] = total_count
    results["sigma_matches"] = total_count
    results["offset"] = offset
    results["limit"] = limit
    results["returned_matches"] = len(paginated_matches)
    results["has_more"] = has_more
    results["sort"] = sort
    
    return results


@router.get("/windows/sigma-rules")
async def list_windows_sigma_rules(_user: UserInDB = Depends(get_current_user)) -> Dict:
    """List available Windows Sigma rules with metadata for browsing."""
    indexed_rules = [_read_sigma_rule_metadata(rule_file) for rule_file in _iter_sigma_rule_files(SIGMA_RULES_DIR)]

    indexed_rules.sort(key=lambda item: (item.get("rule_path", "").lower(), item.get("title", "").lower()))
    return {
        "rules": indexed_rules,
        "count": len(indexed_rules),
    }


@router.get("/windows/sigma-rules/view")
async def view_windows_sigma_rule(
    rule_path: str = Query(..., description="Rule path relative to data/sigma_rules"),
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Return one Sigma rule's YAML content and metadata."""
    normalized = (rule_path or "").strip().lstrip("/")
    if not normalized:
        raise HTTPException(status_code=400, detail="rule_path is required.")
    
    target = (SIGMA_RULES_DIR / normalized).resolve()
    sigma_root = SIGMA_RULES_DIR.resolve()
    if not str(target).startswith(str(sigma_root)):
        raise HTTPException(status_code=400, detail="Invalid rule_path.")
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Sigma rule file not found.")

    try:
        yaml_content = target.read_text(encoding="utf-8")
    except Exception as exc:
        logger.exception("Failed reading sigma rule file %s: %s", target, exc)
        raise HTTPException(status_code=500, detail="Failed to read sigma rule file.") from exc

    rule_metadata = _read_sigma_rule_metadata(target)
    
    return {
        "rule": {
            "rule_path": normalized.replace("\\", "/"),
            "id": str(rule_metadata.get("id", "")).strip() or target.stem,
            "title": str(rule_metadata.get("title", target.stem)),
            "level": str(rule_metadata.get("level", "medium")).lower(),
            "description": str(rule_metadata.get("description", "")).strip(),
            "logsource": rule_metadata.get("logsource", {}),
            "tags": rule_metadata.get("tags", []),
        },
        "yaml": yaml_content,
    }


@router.get("/windows/run/{run_id}")
async def get_windows_run_status(
    run_id: str,
    _user: UserInDB = Depends(get_current_user)
) -> Dict:
    """Get status of a Windows Sigma analysis run."""
    with _windows_run_lock:
        record = _windows_runs.get(run_id)
        is_cancel_requested = run_id in _windows_cancel_requested
    if not record:
        raise HTTPException(status_code=404, detail=f"No Windows analysis run found with id '{run_id}'")
    payload = dict(record)
    payload["cancel_requested"] = bool(payload.get("cancel_requested") or is_cancel_requested)
    payload["can_cancel"] = payload.get("status") in {"pending", "running", "cancelling"}
    return payload


@router.post("/windows/run/{run_id}/cancel")
async def cancel_windows_run(
    run_id: str,
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Request cooperative cancellation for a running Windows Sigma analysis."""
    with _windows_run_lock:
        record = _windows_runs.get(run_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"No Windows analysis run found with id '{run_id}'")

        status = str(record.get("status", "")).lower()
        if status in {"complete", "failed", "cancelled"}:
            return {
                "status": "ignored",
                "run_id": run_id,
                "run_status": status,
                "message": "Run already finished.",
            }

        _windows_cancel_requested.add(run_id)
        record["cancel_requested"] = True
        record["cancel_requested_at"] = datetime.now(timezone.utc).isoformat()
        if status in {"pending", "running"}:
            record["status"] = "cancelling"

    return {
        "status": "accepted",
        "run_id": run_id,
        "run_status": "cancelling",
        "message": "Cancellation requested.",
    }


@router.get("/windows/iocs")
async def get_windows_iocs(
    project_id: Optional[str] = Query(None, description="Scope to a specific project"),
    upload_id: Optional[str] = Query(None, description="Target a specific upload"),
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Extract IOCs from Windows Sigma matches."""
    _, results_path, _ = _windows_project_paths(project_id, upload_id)
    
    if not results_path.exists():
        return {
            "ips": [],
            "domains": [],
            "hashes": {"md5": [], "sha1": [], "sha256": []},
            "file_paths": [],
            "users": [],
            "processes": [],
            "total_iocs": 0,
        }
    
    with open(results_path, "r", encoding="utf-8") as fh:
        results = json.load(fh)
    
    from core.detection.ioc_extractor import extract_iocs_from_sigma_matches
    matches = results.get("matches", [])
    
    iocs = extract_iocs_from_sigma_matches(matches)
    return iocs


@router.get("/windows/export/sigma-csv")
async def export_sigma_matches_csv(
    project_id: Optional[str] = Query(None),
    upload_id: Optional[str] = Query(None),
    _user: UserInDB = Depends(get_current_user),
):
    """Export Sigma matches to CSV."""
    from fastapi.responses import StreamingResponse
    from core.export.windows_export import export_sigma_matches_csv as export_csv
    
    _, results_path, _ = _windows_project_paths(project_id, upload_id)
    if not results_path.exists():
        raise HTTPException(status_code=404, detail="No Sigma results found")
    
    with open(results_path, "r", encoding="utf-8") as fh:
        results = json.load(fh)
    
    csv_content = export_csv(results.get("matches", []))
    
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sigma_matches_{project_id}.csv"}
    )


@router.get("/windows/export/behavioral-csv")
async def export_behavioral_windows_csv(
    project_id: Optional[str] = Query(None),
    upload_id: Optional[str] = Query(None),
    _user: UserInDB = Depends(get_current_user),
):
    """Export behavioral analysis windows to CSV."""
    from fastapi.responses import StreamingResponse
    from core.export.windows_export import export_behavioral_windows_csv as export_csv
    from core.storage.sqlite_store import get_project
    
    project_id = _normalize_project_id(project_id)
    resolved_upload = upload_id or _latest_upload_id(project_id)
    
    base = PROJECTS_DIR / project_id / "uploads" / resolved_upload
    results_path = base / "windows_ml_anomalies.json"
    
    if not results_path.exists():
        raise HTTPException(status_code=404, detail="No behavioral results found")
    
    with open(results_path, "r", encoding="utf-8") as fh:
        results = json.load(fh)
    
    csv_content = export_csv(results.get("windows", []))
    
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=behavioral_windows_{project_id}.csv"}
    )


@router.get("/windows/export/report")
async def export_forensic_report(
    project_id: Optional[str] = Query(None),
    upload_id: Optional[str] = Query(None),
    _user: UserInDB = Depends(get_current_user),
):
    """Export comprehensive forensic report."""
    from fastapi.responses import StreamingResponse
    from core.export.windows_export import generate_forensic_report
    from core.storage.sqlite_store import get_project
    
    project_id = _normalize_project_id(project_id)
    proj = get_project(project_id)
    project_name = proj.get("name", "Unknown") if proj else "Unknown"
    
    resolved_upload = upload_id or _latest_upload_id(project_id)
    base = PROJECTS_DIR / project_id / "uploads" / resolved_upload
    
    # Load Sigma results
    sigma_path = base / "windows_sigma_matches.json"
    sigma_results = {}
    if sigma_path.exists():
        with open(sigma_path, "r", encoding="utf-8") as fh:
            sigma_results = json.load(fh)
    
    # Load behavioral results
    behavioral_path = base / "windows_ml_anomalies.json"
    behavioral_results = None
    if behavioral_path.exists():
        with open(behavioral_path, "r", encoding="utf-8") as fh:
            behavioral_results = json.load(fh)
    
    # Extract IOCs
    from core.detection.ioc_extractor import extract_iocs_from_sigma_matches
    iocs = extract_iocs_from_sigma_matches(sigma_results.get("matches", []))
    
    report_content = generate_forensic_report(project_name, sigma_results, behavioral_results, iocs)
    
    return StreamingResponse(
        iter([report_content]),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=forensic_report_{project_id}.txt"}
    )


@router.get("/windows/correlation")
async def get_event_correlations(
    project_id: Optional[str] = Query(None),
    upload_id: Optional[str] = Query(None),
    time_window_minutes: int = Query(60, description="Time window for correlation in minutes"),
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Get correlated event chains (attack chains) from Sigma matches."""
    _, results_path, _ = _windows_project_paths(project_id, upload_id)
    
    if not results_path.exists():
        return {
            "chains": [],
            "patterns": [],
            "total_chains": 0,
        }
    
    with open(results_path, "r", encoding="utf-8") as fh:
        results = json.load(fh)
    
    from core.detection.event_correlation import EventCorrelator, detect_attack_patterns
    
    correlator = EventCorrelator(time_window_minutes=time_window_minutes)
    chains = correlator.correlate_matches(results.get("matches", []))
    patterns = detect_attack_patterns(results.get("matches", []))
    
    return {
        "chains": chains,
        "patterns": patterns,
        "total_chains": len(chains),
        "time_window_minutes": time_window_minutes,
    }



