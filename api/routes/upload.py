import os
import shutil
import tarfile
import tempfile
import uuid
import zipfile
import logging
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile

from core.storage.sqlite_store import (
    init_db,
    insert_upload_status,
    update_upload_status,
    get_upload_status,
    get_log_time_range,
    query_logs,
    get_project,
    get_uploads_for_project,
    get_log_statistics as _get_log_statistics,
)
from api.deps import UserInDB, get_current_user
from api.routes.projects import _normalize_project_id

logger = logging.getLogger(__name__)
router = APIRouter()

# ── Per-upload pipeline log accumulator ────────────────────────────────────────
# Stores log lines emitted during background processing so the frontend can
# poll them and display a live terminal view.
_upload_logs: dict[str, list[str]] = {}
_MAX_LOG_LINES = 200  # max lines kept per upload
_MAX_UPLOAD_LOGS = 20  # max number of upload IDs to keep


def _log(upload_id: str, msg: str) -> None:
    """Append a timestamped message to the upload's log buffer."""
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    buf = _upload_logs.setdefault(upload_id, [])
    buf.append(line)
    # Trim old lines for this upload
    if len(buf) > _MAX_LOG_LINES:
        _upload_logs[upload_id] = buf[-_MAX_LOG_LINES:]
    # Evict oldest upload buffers when too many accumulate
    if len(_upload_logs) > _MAX_UPLOAD_LOGS:
        oldest = list(_upload_logs.keys())[: len(_upload_logs) - _MAX_UPLOAD_LOGS]
        for k in oldest:
            _upload_logs.pop(k, None)
    logger.info("upload=%s %s", upload_id, msg)

ALLOWED_EXT  = {".zip", ".tar", ".gz", ".tgz", ".log", ".txt", ".evtx", ".xml"}
PROJECTS_DIR = Path(__file__).resolve().parents[2] / "data" / "projects"


def _upload_raw_dir(project_id: str, upload_id: str) -> Path:
    """Return the raw-files directory for a specific upload."""
    return PROJECTS_DIR / project_id / "uploads" / upload_id / "raw"


def _safe_extract_zip(zip_path: str, dest: Path) -> None:
    dest = dest.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            target = (dest / member).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"Unsafe path in archive: {member}")
        zf.extractall(dest)


def _safe_extract_tar(tar_path: str, dest: Path) -> None:
    dest = dest.resolve()
    with tarfile.open(tar_path) as tf:
        for member in tf.getmembers():
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"Unsafe path in archive: {member.name}")
        tf.extractall(dest)


def _ingest_and_normalise(
    upload_id: str,
    project_id: str,
    time_from: str | None = None,
    time_to: str | None = None,
) -> None:
    from core.ingestion.ingest_logs import ingest_all
    from core.processor.process_logs import process_all

    try:
        # Stage 1 — Parsing (ingestion reads raw files → per-upload intermediate.json)
        update_upload_status(upload_id, stage="parsing", status="running")
        _log(upload_id, "Starting log ingestion…")
        entries = ingest_all(project_id=project_id, upload_id=upload_id)
        _log(upload_id, f"Ingested {len(entries):,} raw log lines")
        if time_from or time_to:
            _log(upload_id, f"Applying time-range filter: {time_from} → {time_to}")
        update_upload_status(upload_id, stage="parsing", status="complete")

        # Stage 2 — Normalisation (process_logs → per-upload normalized.json + SQLite aggregations)
        update_upload_status(upload_id, stage="normalizing", status="running")
        _log(upload_id, "Parsing & normalizing entries…")
        entry_count = process_all(
            upload_id=upload_id,
            project_id=project_id,
            time_from=time_from,
            time_to=time_to,
        )
        _log(upload_id, f"Normalized {entry_count:,} entries → stored behavioral aggregations")
        update_upload_status(upload_id, stage="normalizing", status="complete", entry_count=entry_count)

        _log(upload_id, "Detection and ML stages are manual and were not executed during upload")
        _log(upload_id, f"Pipeline complete — {entry_count:,} entries parsed and normalized")
        update_upload_status(
            upload_id,
            stage="saved",
            status="complete",
            entry_count=entry_count,
        )

    except Exception as exc:
        logger.error(f"Upload background task failed: {exc}", exc_info=True)
        _log(upload_id, f"ERROR: {exc}")
        update_upload_status(
            upload_id,
            stage="error",
            status="error",
            error_msg=str(exc)[:500],
        )


@router.post("/upload", status_code=202)
async def upload_logs(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_id: str = Form(...),
    time_from: str | None = Form(None),
    time_to: str | None = Form(None),
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """
    Upload web server log files (.log / .txt / .gz / .zip / .tar / .tgz).
    Files are saved under data/projects/{project_id}/uploads/{upload_id}/raw/
    and ingestion + normalisation run in the background.
    Returns 202 Accepted with an upload_id.
    Poll GET /api/upload/status/{upload_id} for progress.
    """
    suffix = Path(file.filename or "unknown").suffix.lower()
    if suffix not in ALLOWED_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: {sorted(ALLOWED_EXT)}",
        )
    
    project_id = _normalize_project_id(project_id)

    # Validate project exists and is type "web"
    proj = get_project(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if proj.get("project_type") != "web":
        raise HTTPException(status_code=400, detail="This endpoint is for web projects. Use /api/upload/windows for Windows EVTX files.")
    if proj["owner_id"] != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not your project")



    upload_id = str(uuid.uuid4())
    dest_dir  = _upload_raw_dir(project_id, upload_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp()

    try:
        tmp_file = os.path.join(tmp, file.filename)
        with open(tmp_file, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        if suffix == ".zip":
            _safe_extract_zip(tmp_file, dest_dir)
            saved_name = file.filename
        elif suffix in {".tar", ".tgz"}:
            _safe_extract_tar(tmp_file, dest_dir)
            saved_name = file.filename
        else:
            dest = dest_dir / file.filename
            shutil.copy(tmp_file, dest)
            saved_name = file.filename

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"File processing failed: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    init_db()
    insert_upload_status(upload_id, project_id=project_id, filename=saved_name, time_from=time_from, time_to=time_to)
    background_tasks.add_task(_ingest_and_normalise, upload_id, project_id, time_from, time_to)

    return {
        "status":     "accepted",
        "upload_id":  upload_id,
        "filename":   saved_name,
        "project_id": project_id,
        "log_type":   "web",
        "message":    "Ingestion started. Poll GET /api/upload/status/{upload_id} for progress.",
    }


@router.post("/upload/windows", status_code=202)
async def upload_windows_logs(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_id: str = Form(...),
    time_from: str | None = Form(None),
    time_to: str | None = Form(None),
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """
    Upload Windows EVTX event log files (.evtx / .xml).
    Files are saved under data/projects/{project_id}/uploads/{upload_id}/raw/
    and ingestion + normalization + Sigma rules + ML analysis run in the background.
    Returns 202 Accepted with an upload_id.
    Poll GET /api/upload/status/{upload_id} for progress.
    """
    suffix = Path(file.filename or "unknown").suffix.lower()
    if suffix not in {".evtx", ".xml"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Windows endpoint accepts: .evtx, .xml",
        )

    project_id = _normalize_project_id(project_id)

    # Validate project exists and is type "windows"
    proj = get_project(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if proj.get("project_type") != "windows":
        raise HTTPException(status_code=400, detail="This endpoint is for Windows EVTX projects. Use /api/upload for web server logs.")
    if proj["owner_id"] != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not your project")

    upload_id = str(uuid.uuid4())
    dest_dir  = _upload_raw_dir(project_id, upload_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp()

    try:
        tmp_file = os.path.join(tmp, file.filename)
        with open(tmp_file, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        # For Windows, we handle .evtx and .xml files
        if suffix == ".evtx" or suffix == ".xml":
            dest = dest_dir / file.filename
            shutil.copy(tmp_file, dest)
            saved_name = file.filename
        else:
            raise ValueError(f"Unexpected file type: {suffix}")

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"File processing failed: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    init_db()
    insert_upload_status(upload_id, project_id=project_id, filename=saved_name, time_from=time_from, time_to=time_to)
    background_tasks.add_task(_ingest_and_normalise, upload_id, project_id, time_from, time_to)

    return {
        "status":     "accepted",
        "upload_id":  upload_id,
        "filename":   saved_name,
        "project_id": project_id,
        "log_type":   "windows",
        "message":    "Windows EVTX processing started. Poll GET /api/upload/status/{upload_id} for progress.",
    }


@router.get("/upload/status/{upload_id}")
async def get_upload_progress(
    upload_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    record = get_upload_status(upload_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"No upload found with id '{upload_id}'")
    return record


@router.get("/upload/logs/{upload_id}")
async def get_upload_logs(
    upload_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """Return the accumulated pipeline log lines for an upload."""
    lines = _upload_logs.get(upload_id, [])
    return {"upload_id": upload_id, "lines": lines}


@router.get("/logs/time-range")
async def log_time_range(
    project_id: str | None = Query(None, description="Scope to a specific project"),
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    return get_log_time_range(project_id=project_id)


@router.get("/logs/entries")
async def get_log_entries(
    limit:      int        = Query(5000, le=10000, description="Max rows to return"),
    project_id: str | None = Query(None, description="Scope to a specific project"),
    upload_id:  str | None = Query(None, description="Return entries for a specific upload"),
    live_only: bool        = Query(False, description="Only return live agent stream logs"),
    exclude_windows: bool  = Query(False, description="Exclude Windows event log entries"),
    _user:      UserInDB   = Depends(get_current_user),
) -> list:
    """Return normalised log entries for a specific upload."""
    return query_logs(
        limit=limit,
        project_id=project_id,
        upload_id=upload_id,
        live_only=live_only,
        exclude_windows=exclude_windows,
    )


@router.get("/logs/statistics")
async def get_log_stats(
    project_id: str | None = Query(None, description="Scope to a specific project"),
    upload_id:  str | None = Query(None, description="Scope to a specific upload"),
    _user:      UserInDB   = Depends(get_current_user),
) -> dict:
    """Return pre-computed log statistics from compact aggregation tables."""
    return _get_log_statistics(project_id=project_id, upload_id=upload_id)

