from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Any, Dict, Optional
from api.services.llm_service import async_analyse_detection_results, async_analyse_specific_match
from api.deps import UserInDB, get_current_user
from api.routes.projects import _normalize_project_id
import json
import logging
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
router = APIRouter()

PROJECTS_DIR = Path(__file__).resolve().parents[2] / "data" / "projects"
SIGMA_RULES_DIR = Path(__file__).resolve().parents[2] / "data" / "sigma_rules"


def _latest_upload_id(project_id: str) -> str | None:
    """Return the most-recent completed upload_id for a project, or None."""
    from core.storage.sqlite_store import get_uploads_for_project
    uploads = get_uploads_for_project(project_id)
    for u in uploads:  # already ordered newest-first
        if u.get("status") == "complete":
            return u["upload_id"]
    return None


def _project_paths(project_id: str | None, upload_id: str | None = None, required_type: str | None = None) -> tuple[Path, Path, str]:
    """Return (normalised_path, results_file, resolved_upload_id) scoped to a specific upload.
    Validates project type if required_type is specified."""
    if not project_id:
        raise HTTPException(
            status_code=400,
            detail="project_id is required for analysis.",
        )

    project_id = _normalize_project_id(project_id)

    # Validate project type if specified
    if required_type:
        from core.storage.sqlite_store import get_project
        proj = get_project(project_id)
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found.")
        if proj.get("project_type") != required_type:
            raise HTTPException(
                status_code=400,
                detail=f"This endpoint is for {required_type.upper()} projects. The project '{project_id}' is a {proj.get('project_type', 'unknown').upper()} project.",
            )

    resolved_upload = upload_id or _latest_upload_id(project_id)
    if not resolved_upload:
        raise HTTPException(
            status_code=404,
            detail=f"No uploads found for project '{project_id}'. Upload logs first.",
        )

    base = PROJECTS_DIR / project_id / "uploads" / resolved_upload
    return (
        base / "normalized.json",
        base / "rule_matches.json",
        resolved_upload,
    )


def _load_results(path: Path) -> Dict:
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail="No detection results found. Run analysis first.",
        )
    with open(path, "r") as fh:
        return json.load(fh)


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
        return items  # invalid format, return all
    
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


@router.post("/threat-insights")
async def get_threat_insights(
    project_id: Optional[str] = None,
    upload_id:  Optional[str] = None,
    start_ts: Optional[str] = Query(None, description="Start time (ISO 8601)"),
    end_ts: Optional[str] = Query(None, description="End time (ISO 8601)"),
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    _, results_file, _ = _project_paths(project_id, upload_id, required_type="web")
    detection_data = _load_results(results_file)
    
    # Apply time range filter if provided
    if start_ts or end_ts:
        matches = detection_data.get("matches", [])
        filtered_matches = _filter_by_time_range(matches, start_ts, end_ts, "timestamp")
        detection_data["matches"] = filtered_matches
        detection_data["filtered_by_time"] = True
        detection_data["time_range"] = {"start": start_ts, "end": end_ts}
    
    result = await async_analyse_detection_results(detection_data)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message"))
    return {"status": "success", **result}


@router.post("/threat-insights/{rule_id}")
async def analyse_rule_match(
    rule_id:    str,
    project_id: Optional[str] = None,
    upload_id:  Optional[str] = None,
    _user:      UserInDB = Depends(get_current_user),
) -> Dict:
    _, results_file, _ = _project_paths(project_id, upload_id, required_type="web")
    detection_data = _load_results(results_file)
    matches = detection_data.get("matches", [])
    match = next((m for m in matches if m.get("rule_id") == rule_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"No match found for rule id '{rule_id}'")
    result = await async_analyse_specific_match(match)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message"))
    return {"status": "success", **result, "match_details": match}


@router.get("/threat-insights/status")
async def insights_status(
    project_id: Optional[str] = None,
    upload_id:  Optional[str] = None,
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    groq_key_set = bool(os.getenv("GROQ_API_KEY"))
    try:
        _, results_file, _ = _project_paths(project_id, upload_id, required_type="web")
    except HTTPException as exc:
        return {"status": "no_data", "message": exc.detail, "groq_key_set": groq_key_set}
    if results_file.exists():
        try:
            with open(results_file) as fh:
                data = json.load(fh)
            return {
                "status":        "available",
                "total_matches": data.get("total_matches", 0),
                "unique_rules":  len(data.get("matched_rules", [])),
                "groq_key_set":  groq_key_set,
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc), "groq_key_set": groq_key_set}
    return {"status": "no_data", "message": "Run analysis pipeline first.", "groq_key_set": groq_key_set}


class AnalysisRequest(BaseModel):
    mode:          str = "auto"   # "auto" | "manual"
    start_ts:      Optional[str] = None
    end_ts:        Optional[str] = None
    project_id:    Optional[str] = None  # scope analysis to a specific project
    upload_id:     Optional[str] = None  # target a specific upload; latest used if omitted


# In-memory run tracking (keyed by run_id)
_analysis_runs: dict = {}


def _run_file_path(project_id: str | None, upload_id: str | None) -> Path | None:
    """Return the path to the persisted analysis_run.json for a project/upload."""
    if not project_id or not upload_id:
        return None
    return PROJECTS_DIR / project_id / "uploads" / upload_id / "analysis_run.json"


def _persist_run(run_id: str, record: dict) -> None:
    """Write a completed/failed run record to disk so it survives backend restarts."""
    try:
        path = _run_file_path(record.get("project_id"), record.get("upload_id"))
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(record, fh)
    except Exception as exc:
        logger.warning(f"Failed to persist analysis run {run_id}: {exc}")


def _load_persisted_run(project_id: str | None, upload_id: str | None) -> dict | None:
    """Load the most recent persisted run record from disk, or None."""
    path = _run_file_path(project_id, upload_id)
    if not path or not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _run_analysis_task(
    run_id:        str,
    start_ts:      str | None,
    end_ts:        str | None,
    analysis_type: str = "crs",
    project_id:    str | None = None,
    upload_id:     str | None = None,
) -> None:
    """Background task: run CRS detection with optional time filter."""
    from core.detection.rule_pipeline import run_rule_pipeline_from_file
    import time

    try:
        normalised_path, _, resolved_upload_id = _project_paths(project_id, upload_id)
    except HTTPException as exc:
        _analysis_runs[run_id].update({"status": "failed", "error_msg": exc.detail, "error": exc.detail})
        return

    _analysis_runs[run_id]["status"] = "running"
    steps = []

    try:
        t0 = time.time()
        _analysis_runs[run_id]["current_step"] = "rule_detection"
        rule_result = run_rule_pipeline_from_file(
            normalised_path,
            start_ts=start_ts, end_ts=end_ts,
            project_id=project_id, upload_id=resolved_upload_id,
        )
        from core.storage.sqlite_store import get_overview_stats
        overview = get_overview_stats(
            project_id=project_id,
            upload_id=resolved_upload_id,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        severity_breakdown = overview.get("severity_breakdown", {})
        elapsed_s = round(time.time() - t0, 1)
        steps.append({
            "step":          "rule_detection",
            "status":        "complete",
            "elapsed_s":     elapsed_s,
            "total_matches": rule_result.get("total_matches", 0),
            "unique_rules":  len(rule_result.get("matched_rules", [])),
            "crs_matches":   rule_result.get("crs_matches", 0),
            "detector":      rule_result.get("detector", "crs"),
            "detector_status": rule_result.get("detector_status", "unknown"),
            "warning":       rule_result.get("warning"),
        })

        completed = {
            "status":       "complete",
            "steps":        steps,
            "current_step": None,
            "upload_id":    resolved_upload_id,
            "detector":     rule_result.get("detector", "crs"),
            "detector_status": rule_result.get("detector_status", "unknown"),
            "warning_msg":  rule_result.get("warning"),
            "stats": {
                "total_logs": overview.get("total_logs", 0),
                # flagged_logs = unique log entries that triggered at least one rule
                # rule_matches = total rule-hit count (can legitimately exceed total_logs)
                "flagged_logs": overview.get("unique_flagged_entries", overview.get("total_detections", 0)),
                "rule_matches": overview.get("total_detections", 0),
                "critical_count": severity_breakdown.get("critical", 0),
                "high_count": severity_breakdown.get("high", 0),
                "medium_count": severity_breakdown.get("medium", 0),
                "low_count": severity_breakdown.get("low", 0),
                "unique_ips": overview.get("unique_ips", 0),
                "unique_rules": overview.get("unique_rules", 0),
                "analysis_duration_seconds": elapsed_s,
            },
            "top_threats": [
                {
                    "rule": row.get("rule_title") or row.get("rule_id"),
                    "count": row.get("hit_count", 0),
                    "severity": row.get("severity", "unknown"),
                }
                for row in overview.get("top_rules", [])[:10]
            ],
        }
        _analysis_runs[run_id].update(completed)
        _persist_run(run_id, {**_analysis_runs[run_id], **completed})

    except Exception as exc:
        logger.error(f"Analysis task {run_id} failed: {exc}", exc_info=True)
        failed = {
            "status":    "failed",
            "error_msg": str(exc)[:500],
            "error":     str(exc)[:500],
            "steps":     steps,
        }
        _analysis_runs[run_id].update(failed)
        _persist_run(run_id, {**_analysis_runs[run_id], **failed})


@router.post("/run")
async def run_analysis(
    request:          AnalysisRequest,
    background_tasks: BackgroundTasks,
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """
    Kick off a background CRS analysis task (WEB LOGS ONLY).
    Returns 202 with run_id for polling.
    """
    normalised_path, _, resolved_upload_id = _project_paths(request.project_id, request.upload_id, required_type="web")
    if not normalised_path.exists():
        raise HTTPException(
            status_code=400,
            detail="No normalised log data found. Upload and ingest logs first.",
        )

    start_ts = request.start_ts if request.mode == "manual" else None
    end_ts   = request.end_ts   if request.mode == "manual" else None

    run_id = str(uuid.uuid4())
    _analysis_runs[run_id] = {
        "run_id":        run_id,
        "mode":          request.mode,
        "project_id":    request.project_id,
        "upload_id":     resolved_upload_id,
        "start_ts":      start_ts,
        "end_ts":        end_ts,
        "status":        "pending",
        "current_step":  None,
        "steps":         [],
        "error_msg":     None,
        "error":         None,
    }

    background_tasks.add_task(
        _run_analysis_task, run_id, start_ts, end_ts,
        "crs", request.project_id, resolved_upload_id,
    )

    return {
        "status":  "accepted",
        "run_id":  run_id,
        "message": f"Analysis started. Poll GET /api/analysis/run/{run_id} for status.",
    }


@router.get("/latest")
async def get_latest_analysis_run(
    project_id: Optional[str] = None,
    upload_id:  Optional[str] = None,
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Return the most recent persisted analysis run for a project/upload."""
    # Try resolved upload first, then fall back to latest completed upload
    resolved = upload_id or _latest_upload_id(project_id) if project_id else None
    record = _load_persisted_run(project_id, resolved)
    if not record:
        raise HTTPException(status_code=404, detail="No persisted analysis run found.")
    # Re-hydrate into in-memory cache so /run/{run_id} also works
    run_id = record.get("run_id")
    if run_id and run_id not in _analysis_runs:
        _analysis_runs[run_id] = record
    return record


@router.get("/run/{run_id}")
async def get_analysis_run(run_id: str, _user: UserInDB = Depends(get_current_user)) -> Dict:
    record = _analysis_runs.get(run_id)
    if not record:
        # Try to restore from disk (e.g. after backend restart)
        # We do a best-effort scan across all projects/uploads
        raise HTTPException(status_code=404, detail=f"No analysis run found with id '{run_id}'")
    return record


# ── Windows Analysis Endpoints ─────────────────────────────────────────────────

def _windows_results_path(project_id: str | None, upload_id: str | None = None) -> tuple[Path, str]:
    """Return the Windows Sigma results file path and resolved_upload_id. Validates project is Windows type."""
    project_id = _normalize_project_id(project_id)
    
    # Validate project type is Windows
    from core.storage.sqlite_store import get_project
    proj = get_project(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found.")
    if proj.get("project_type") != "windows":
        raise HTTPException(
            status_code=400,
            detail=f"This endpoint is for WINDOWS projects. The project '{project_id}' is a {proj.get('project_type', 'unknown').upper()} project.",
        )
    
    resolved_upload = upload_id or _latest_upload_id(project_id)
    if not resolved_upload:
        raise HTTPException(status_code=404, detail=f"No uploads found for Windows project '{project_id}'.")
    
    base = PROJECTS_DIR / project_id / "uploads" / resolved_upload
    return base / "windows_sigma_matches.json", resolved_upload


def _load_sigma_rule_index() -> list[dict[str, Any]]:
    from core.detection.windows_sigma import load_sigma_rules

    indexed_rules: list[dict[str, Any]] = []
    for rule in load_sigma_rules(str(SIGMA_RULES_DIR)):
        source_file = Path(str(rule.get("source_file", "")))
        try:
            relative_path = source_file.resolve().relative_to(SIGMA_RULES_DIR.resolve())
        except Exception:
            continue

        indexed_rules.append(
            {
                "rule_path": str(relative_path).replace("\\", "/"),
                "id": str(rule.get("id", "")).strip() or source_file.stem,
                "title": str(rule.get("title", "Unnamed Rule")),
                "level": str(rule.get("level", "medium")).lower(),
                "description": str(rule.get("description", "")).strip(),
                "logsource": rule.get("logsource") if isinstance(rule.get("logsource"), dict) else {},
            }
        )

    indexed_rules.sort(key=lambda item: (item.get("title", "").lower(), item.get("rule_path", "")))
    return indexed_rules


@router.get("/windows/sigma-rules")
async def list_windows_sigma_rules(_user: UserInDB = Depends(get_current_user)) -> Dict:
    """List available Windows Sigma rules with metadata for browsing."""
    rules = _load_sigma_rule_index()
    return {
        "rules": rules,
        "count": len(rules),
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

    indexed = next((r for r in _load_sigma_rule_index() if r["rule_path"] == normalized.replace("\\", "/")), None)
    if not indexed:
        raise HTTPException(status_code=404, detail="Sigma rule metadata not found.")

    try:
        yaml_content = target.read_text(encoding="utf-8")
    except Exception as exc:
        logger.exception("Failed reading sigma rule file %s: %s", target, exc)
        raise HTTPException(status_code=500, detail="Failed to read sigma rule file.") from exc

    return {
        "rule": indexed,
        "yaml": yaml_content,
    }


@router.post("/windows/run-sigma")
async def run_windows_sigma(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Run Sigma rule detection on Windows EVTX logs."""
    normalised_path, _, resolved_upload_id = _project_paths(
        request.project_id,
        request.upload_id,
        required_type="windows",
    )
    if not normalised_path.exists():
        raise HTTPException(status_code=400, detail="No normalised log data found.")

    run_id = str(uuid.uuid4())
    _analysis_runs[run_id] = {
        "run_id": run_id,
        "mode": request.mode,
        "project_id": request.project_id,
        "upload_id": resolved_upload_id,
        "status": "pending",
        "analysis_type": "windows_sigma",
    }

    def _run_windows_sigma_task():
        """Background task to run Windows Sigma detection."""
        try:
            from core.detection.windows_sigma import run_sigma_pipeline
            import json
            
            _analysis_runs[run_id]["status"] = "running"
            
            # Load Windows events from normalized.json
            windows_events = []
            with open(normalised_path, "r", encoding="utf-8") as fh:
                import ijson
                for entry in ijson.items(fh, "item"):
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
                _analysis_runs[run_id]["status"] = "complete"
                _analysis_runs[run_id]["total_events"] = 0
                _analysis_runs[run_id]["matches"] = []
                _analysis_runs[run_id]["matched_rules"] = []
                return
            
            # Run Sigma pipeline
            rules_folder = Path(__file__).resolve().parents[2] / "data" / "sigma_rules"
            result = run_sigma_pipeline(windows_events, str(rules_folder))
            
            # Persist results
            results_path, _ = _windows_results_path(request.project_id, resolved_upload_id)
            results_path.parent.mkdir(parents=True, exist_ok=True)
            with open(results_path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            
            _analysis_runs[run_id]["status"] = "complete"
            _analysis_runs[run_id]["total_events"] = len(windows_events)
            _analysis_runs[run_id]["total_matches"] = result.get("total_matches", 0)
            _analysis_runs[run_id]["unique_rules"] = len(result.get("matched_rules", []))
            _analysis_runs[run_id]["matches"] = result.get("matches", [])
            
        except Exception as exc:
            logger.error(f"Windows Sigma task {run_id} failed: {exc}", exc_info=True)
            _analysis_runs[run_id]["status"] = "failed"
            _analysis_runs[run_id]["error"] = str(exc)[:500]

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
    _user: UserInDB = Depends(get_current_user),
) -> Dict:
    """Get Windows Sigma detection results."""
    results_path, _ = _windows_results_path(project_id, upload_id)
    if not results_path.exists():
        raise HTTPException(status_code=404, detail="No Windows Sigma results found. Run analysis first.")
    
    with open(results_path, "r", encoding="utf-8") as fh:
        return json.load(fh)
