"""
api/routes/projects.py — Project CRUD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
POST   /api/projects              — create project (authenticated)
GET    /api/projects              — list own projects
GET    /api/projects/{id}         — get one project (owner or admin)
DELETE /api/projects/{id}         — delete project + all files (owner or admin)
GET    /api/projects/{id}/stats   — log/detection counts for a project
"""

from __future__ import annotations

import logging
import secrets
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from core.storage.sqlite_store import (
    create_project,
    delete_upload_for_project,
    delete_project,
    get_project,
    get_project_stats,
    get_upload_status,
    list_projects_for_user,
    get_uploads_for_project,
    set_project_api_key,
    get_project_agent_log_paths,
    set_project_agent_log_paths,
    get_project_by_api_key,
)
from api.deps import UserInDB, get_current_user, require_analyst

logger = logging.getLogger(__name__)
router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_DIR = PROJECT_ROOT / "data" / "projects"
WINDOWS_DEFAULT_PATHS = [
    "C:/inetpub/logs/LogFiles/**/*.log",
    "C:/Windows/System32/LogFiles/Firewall/pfirewall.log",
]
UNIX_DEFAULT_PATHS = [
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
]


def _project_dir(project_id: str) -> Path:
    return PROJECTS_DIR / project_id


# ── Request models ─────────────────────────────────────────────────────────────

class CreateProjectRequest(BaseModel):
    name:         str
    description:  str = ""
    project_type: str = "web"  # "web" or "windows"


class AgentConfigRequest(BaseModel):
    log_paths: list[str]


def _sanitize_log_paths(values: list[str]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        path = value.strip()
        if not path:
            continue
        if len(path) > 512:
            raise HTTPException(400, "Log path entries must be 512 characters or fewer.")
        if path not in cleaned:
            cleaned.append(path)

    if len(cleaned) > 32:
        raise HTTPException(400, "A project can have at most 32 configured log paths.")
    return cleaned


def _default_paths_for_platform(platform: str | None) -> list[str]:
    p = (platform or "").strip().lower()
    if p in {"windows", "win", "win32"}:
        return WINDOWS_DEFAULT_PATHS
    return UNIX_DEFAULT_PATHS


def _resolve_public_api_base(request: Request) -> str:
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",", 1)[0].strip()
    forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",", 1)[0].strip()

    if forwarded_proto and forwarded_host:
        return f"{forwarded_proto}://{forwarded_host}".rstrip("/")

    return str(request.base_url).rstrip("/")


def _render_nxlog_conf(
    api_base_url: str,
    project_id: str,
    api_key: str,
    file_log_paths: list[str],
    include_windows_eventlog: bool,
) -> str:
    ingest_url = f"{api_base_url.rstrip('/')}/api/logicx/ingest?project_id={project_id}"
    header_api_key = api_key.strip() if api_key.strip() else "<generate-api-key-from-projects-page>"

    file_inputs: list[str] = []
    file_input_names: list[str] = []
    for idx, path in enumerate(file_log_paths, start=1):
        input_name = f"in_file_{idx}"
        file_input_names.append(input_name)
        normalized_path = path.replace("\r", "").replace("\n", "").strip()
        file_inputs.append(
            "\n".join(
                [
                    f"<Input {input_name}>",
                    "    Module      im_file",
                    f"    File        \"{normalized_path}\"",
                    "    SavePos     TRUE",
                    "    ReadFromLast TRUE",
                    "    Exec        $host = hostname();",
                    f"    Exec        $file = \"{normalized_path}\";",
                    "    Exec        $log = $raw_event;",
                    "    Exec        $date = strftime(now(), \"%Y-%m-%dT%H:%M:%SZ\");",
                    "    Exec        $agent_version = \"nxlog-1.0\";",
                    "    Exec        to_json();",
                    f"</Input>",
                ]
            )
        )

    route_sources = [*(["in_windows_events"] if include_windows_eventlog else []), *file_input_names]
    route_path = f"{route_sources[0]} => out_logicx" if len(route_sources) == 1 else f"{', '.join(route_sources)} => out_logicx"

    parts: list[str] = [
        "Panic Soft",
        "#NoFreeOnExit TRUE",
        "",
        "define ROOT     C:\\Program Files\\nxlog",
        "define CERTDIR  %ROOT%\\cert",
        "define CONFDIR  %ROOT%\\conf\\nxlog.d",
        "define LOGDIR   %ROOT%\\data",
        "",
        "include %CONFDIR%\\\\*.conf",
        "define LOGFILE  %LOGDIR%\\nxlog.log",
        "LogFile %LOGFILE%",
        "",
        "Moduledir %ROOT%\\modules",
        "CacheDir  %ROOT%\\data",
        "Pidfile   %ROOT%\\data\\nxlog.pid",
        "SpoolDir  %ROOT%\\data",
        "",
        "<Extension _syslog>",
        "    Module      xm_syslog",
        "</Extension>",
        "",
        "<Extension _charconv>",
        "    Module      xm_charconv",
        "    AutodetectCharsets iso8859-2, utf-8, utf-16, utf-32",
        "</Extension>",
        "",
        "<Extension _exec>",
        "    Module      xm_exec",
        "</Extension>",
        "",
        "<Extension _fileop>",
        "    Module      xm_fileop",
        "",
        "    # Check the size of our log file hourly, rotate if larger than 5MB",
        "    <Schedule>",
        "        Every   1 hour",
        "        Exec    if (file_exists('%LOGFILE%') and \\",
        "                   (file_size('%LOGFILE%') >= 5M)) \\",
        "                    file_cycle('%LOGFILE%', 8);",
        "    </Schedule>",
        "",
        "    # Rotate our log file every week on Sunday at midnight",
        "    <Schedule>",
        "        When    @weekly",
        "        Exec    if file_exists('%LOGFILE%') file_cycle('%LOGFILE%', 8);",
        "    </Schedule>",
        "</Extension>",
        "",
        "# LOGIC additions for NXLog forwarding",
        "<Extension _json>",
        "    Module      xm_json",
        "</Extension>",
        "",
        *(
            [
                "<Input in_windows_events>",
                "    Module      im_msvistalog",
                "    <QueryXML>",
                "        <QueryList>",
                "            <Query Id='0'>",
                "                <Select Path='Security'>*</Select>",
                "                <Select Path='System'>*</Select>",
                "                <Select Path='Application'>*</Select>",
                "            </Query>",
                "        </QueryList>",
                "    </QueryXML>",
                "    Exec        to_json();",
                "    Exec        $log = $raw_event;",
                "    Exec        $host = hostname();",
                "    Exec        $file = \"windows_eventlog\";",
                "    Exec        $date = strftime(now(), \"%Y-%m-%dT%H:%M:%SZ\");",
                "    Exec        $agent_version = \"nxlog-1.0\";",
                "    Exec        to_json();",
                "</Input>",
                "",
            ]
            if include_windows_eventlog
            else []
        ),
        *file_inputs,
        *( [""] if file_inputs else [] ),
        "<Output out_logicx>",
        "    Module      om_http",
        f"    URL         {ingest_url}",
        "    HTTPSAllowUntrusted TRUE",
        "    ContentType application/x-ndjson",
        f"    AddHeader   X-Logic-Api-Key {header_api_key}",
        "</Output>",
        "",
        "<Route r_logicx>",
        f"    Path        {route_path}",
        "</Route>",
        "",
    ]
    return "\n".join(parts)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _assert_access(project: dict, user: UserInDB) -> None:
    """Raise 403 if the caller does not own the project and is not an admin."""
    if project["owner_id"] != user.id and user.role != "admin":
        raise HTTPException(403, "You do not have access to this project.")


def _normalize_project_id(project_id: str | None) -> str:
    if project_id is None:
        raise HTTPException(400, "project_id is required.")

    candidate = project_id.strip()
    if not candidate:
        raise HTTPException(400, "project_id is required.")

    try:
        return str(uuid.UUID(candidate))
    except ValueError as exc:
        raise HTTPException(400, "project_id must be a valid UUID.") from exc


def _assert_exists(project_id: str) -> dict:
    project_id = _normalize_project_id(project_id)
    project = get_project(project_id)
    if not project:
        raise HTTPException(404, f"Project '{project_id}' not found.")
    return project


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/projects", status_code=201)
async def create_new_project(
    req:          CreateProjectRequest,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """
    Create a new project (web or windows).
    Initialises the active per-project directory structure under data/projects/{id}/.
    """
    name = req.name.strip()
    if not name:
        raise HTTPException(400, "Project name cannot be empty.")
    
    project_type = req.project_type.strip().lower()
    if project_type not in ("web", "windows"):
        raise HTTPException(400, "project_type must be 'web' or 'windows'.")

    project_id = str(uuid.uuid4())

    # Create only directories used by the current upload and analysis pipeline.
    base = _project_dir(project_id)
    for subdir in ["uploads", "detection_results"]:
        (base / subdir).mkdir(parents=True, exist_ok=True)

    project = create_project(
        project_id   = project_id,
        name         = name,
        description  = req.description.strip(),
        owner_id     = current_user.id,
        project_type = project_type,
    )
    logger.info("Project created: %s ('%s', type=%s) by user %s", project_id, name, project_type, current_user.username)
    return project


@router.get("/projects")
async def list_projects(
    current_user: UserInDB = Depends(get_current_user),
    project_type: str | None = Query(None, description="Filter by type: 'web' or 'windows'"),
) -> dict:
    """Return projects owned by the current user, optionally filtered by type."""
    projects = list_projects_for_user(current_user.id, project_type=project_type)
    return {
        "projects": projects,
        "filter": project_type,
        "count": len(projects),
    }


@router.get("/projects/{project_id}")
async def get_one_project(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    project = _assert_exists(project_id)
    _assert_access(project, current_user)
    return project


@router.get("/projects/{project_id}/stats")
async def project_stats(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    project = _assert_exists(project_id)
    _assert_access(project, current_user)
    stats = get_project_stats(project_id)
    return {"project_id": project_id, **stats}


@router.get("/projects/{project_id}/uploads")
async def project_uploads(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> list:
    """Return all upload records for a project, newest first."""
    project = _assert_exists(project_id)
    _assert_access(project, current_user)
    return get_uploads_for_project(project_id)


@router.delete("/projects/{project_id}/uploads/{upload_id}", status_code=204)
async def remove_project_upload(
    project_id: str,
    upload_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> None:
    """Delete one uploaded log bundle for a project (DB row + upload directory)."""
    project = _assert_exists(project_id)
    _assert_access(project, current_user)

    upload = get_upload_status(upload_id)
    if not upload or upload.get("project_id") != project_id:
        raise HTTPException(404, f"Upload '{upload_id}' not found for this project.")

    upload_dir = _project_dir(project_id) / "uploads" / upload_id
    if upload_dir.exists():
        try:
            shutil.rmtree(upload_dir)
        except Exception as exc:
            logger.exception(
                "Failed deleting upload directory for project=%s upload=%s by user=%s: %s",
                project_id,
                upload_id,
                current_user.username,
                exc,
            )
            raise HTTPException(
                500,
                "Could not delete upload files. Ensure no process is using these files and retry.",
            ) from exc

    deleted_rows = delete_upload_for_project(project_id, upload_id)
    if deleted_rows == 0:
        raise HTTPException(404, f"Upload '{upload_id}' no longer exists for this project.")

    logger.info(
        "Project upload deleted: project=%s upload=%s by user=%s",
        project_id,
        upload_id,
        current_user.username,
    )


@router.delete("/projects/{project_id}", status_code=204)
async def remove_project(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> None:
    """
    Delete a project, all its database rows, and its file tree on disk.
    Only the owner or an admin may delete a project.
    """
    project = _assert_exists(project_id)
    _assert_access(project, current_user)

    # Delete project data files first so a filesystem failure does not leave DB state diverged.
    base = _project_dir(project_id)
    if base.exists():
        try:
            shutil.rmtree(base)
        except Exception as exc:
            logger.exception(
                "Failed deleting project directory for project=%s by user=%s: %s",
                project_id,
                current_user.username,
                exc,
            )
            raise HTTPException(
                500,
                "Could not delete project files. Ensure no process is using this project and retry.",
            ) from exc

    try:
        delete_project(project_id)
    except Exception as exc:
        logger.exception(
            "Failed deleting project DB rows for project=%s by user=%s: %s",
            project_id,
            current_user.username,
            exc,
        )
        raise HTTPException(500, "Could not delete project metadata. Retry the operation.") from exc

    logger.info("Project deleted: %s by user %s", project_id, current_user.username)


# ── Agent API key management ───────────────────────────────────────────────────

@router.post("/projects/{project_id}/api-key", status_code=201)
async def generate_api_key(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """
    Generate (or rotate) the agent API key for a project.
    The key is returned once — store it securely.
    Only the project owner or an admin may generate a key.
    """
    project = _assert_exists(project_id)
    _assert_access(project, current_user)

    api_key = f"lak_{secrets.token_hex(32)}"
    set_project_api_key(project_id, api_key)
    logger.info("API key generated for project %s by user %s", project_id, current_user.username)
    return {"project_id": project_id, "api_key": api_key}


@router.get("/projects/{project_id}/api-key")
async def get_api_key(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """
    Return the current agent API key for a project, or null if none has been generated.
    Only the project owner or an admin may view the key.
    """
    project = _assert_exists(project_id)
    _assert_access(project, current_user)
    return {"project_id": project_id, "api_key": project.get("api_key")}


@router.get("/projects/{project_id}/agent-config")
async def get_agent_config_for_project(
    project_id: str,
    platform: str | None = Query(None, description="Optional platform hint: windows|linux|macos"),
    current_user: UserInDB = Depends(require_analyst),
) -> dict:
    """Return agent config for a project (analyst-only dashboard access)."""
    project = _assert_exists(project_id)
    _assert_access(project, current_user)

    configured = get_project_agent_log_paths(project_id)
    effective = configured if configured else _default_paths_for_platform(platform)

    return {
        "project_id": project_id,
        "log_paths": configured,
        "effective_log_paths": effective,
        "source": "custom" if configured else "default",
        "updated_at": project.get("agent_config_updated_at"),
    }


@router.post("/projects/{project_id}/agent-config")
async def save_agent_config_for_project(
    project_id: str,
    req: AgentConfigRequest,
    current_user: UserInDB = Depends(require_analyst),
) -> dict:
    """Persist per-project agent log paths (analyst-only)."""
    project = _assert_exists(project_id)
    _assert_access(project, current_user)

    cleaned = _sanitize_log_paths(req.log_paths)
    set_project_agent_log_paths(project_id, cleaned)
    updated = get_project(project_id) or project

    logger.info("Agent config updated for project %s by user %s", project_id, current_user.username)
    return {
        "project_id": project_id,
        "log_paths": cleaned,
        "effective_log_paths": cleaned if cleaned else _default_paths_for_platform(None),
        "source": "custom" if cleaned else "default",
        "updated_at": updated.get("agent_config_updated_at"),
    }


@router.get("/logicx/config")
async def get_agent_runtime_config(
    project_id: str = Query(..., description="Project UUID used by the running agent"),
    platform: str | None = Query(None, description="Optional platform hint: windows|linux|macos"),
    x_logic_api_key: str | None = Header(None),
) -> dict:
    """Runtime bootstrap config for LOGIC agents authenticated by project API key."""
    if not x_logic_api_key:
        raise HTTPException(401, "Missing X-Logic-Api-Key header")

    project = get_project_by_api_key(x_logic_api_key)
    if not project or project.get("id") != project_id:
        raise HTTPException(401, "Invalid API key for this project")

    configured = get_project_agent_log_paths(project_id)
    effective = configured if configured else _default_paths_for_platform(platform)

    return {
        "project_id": project_id,
        "log_paths": effective,
        "source": "custom" if configured else "default",
        "updated_at": project.get("agent_config_updated_at"),
        "flush_interval": 2,
        "batch_size": 200,
        "ingest_path": "/api/logicx/ingest",
    }


@router.get("/projects/{project_id}/agent-config/nxlog", response_class=PlainTextResponse)
async def get_project_nxlog_conf(
    request: Request,
    project_id: str,
    current_user: UserInDB = Depends(require_analyst),
) -> PlainTextResponse:
    """Return a copy/paste-ready NXLog config for web/windows log shipping to LOGIC."""
    project = _assert_exists(project_id)
    _assert_access(project, current_user)

    api_key = str(project.get("api_key") or "").strip()
    configured = get_project_agent_log_paths(project_id)
    project_type = str(project.get("project_type") or "web").lower()
    default_platform = "windows" if project_type == "windows" else None
    effective_paths = configured if configured else _default_paths_for_platform(default_platform)

    conf_text = _render_nxlog_conf(
        api_base_url=_resolve_public_api_base(request),
        project_id=project_id,
        api_key=api_key,
        file_log_paths=effective_paths,
        include_windows_eventlog=project_type == "windows",
    )
    return PlainTextResponse(conf_text)
