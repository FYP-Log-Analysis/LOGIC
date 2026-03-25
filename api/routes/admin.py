"""
api/routes/admin.py — Admin-only management endpoints
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
All routes require role='admin' (enforced by require_admin dependency).

GET    /api/admin/users                       — list all users
POST   /api/admin/users/{user_id}/deactivate  — disable a user
POST   /api/admin/users/{user_id}/activate    — re-enable a user
POST   /api/admin/users/{user_id}/promote     — promote to admin
POST   /api/admin/users/{user_id}/demote      — demote to user
GET    /api/admin/projects                    — list all projects (any owner)
DELETE /api/admin/projects/{project_id}       — force-delete any project
GET    /api/admin/stats                       — platform-level summary counts
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.storage.sqlite_store import (
    DB_PATH,
    cleanup_mixed_project_artifacts,
    delete_project,
    delete_user,
    get_project,
    get_user_by_id,
    list_all_projects,
    list_users,
    set_user_active,
    set_user_role,
)
from api.deps import UserInDB, require_admin

logger = logging.getLogger(__name__)
router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_DIR = PROJECT_ROOT / "data" / "projects"


class CleanupMixedRequest(BaseModel):
    project_id: str | None = None
    dry_run: bool = True
    archive: bool = True


# ── Users ──────────────────────────────────────────────────────────────────────

@router.get("/users")
async def admin_list_users(_admin: UserInDB = Depends(require_admin)) -> list:
    """Return every user account (id, username, email, role, is_active, created_at)."""
    return list_users()


@router.post("/users/{user_id}/deactivate")
async def admin_deactivate_user(
    user_id: int,
    _admin:  UserInDB = Depends(require_admin),
) -> dict:
    """Disable a user account. The user can no longer log in."""
    if _admin.id == user_id:
        raise HTTPException(400, "You cannot deactivate your own account.")
    _assert_user_exists(user_id)
    set_user_active(user_id, 0)
    logger.info("Admin %s deactivated user %d", _admin.username, user_id)
    return {"message": f"User {user_id} deactivated."}


@router.post("/users/{user_id}/activate")
async def admin_activate_user(
    user_id: int,
    _admin:  UserInDB = Depends(require_admin),
) -> dict:
    """Re-enable a previously deactivated user account."""
    _assert_user_exists(user_id)
    set_user_active(user_id, 1)
    logger.info("Admin %s activated user %d", _admin.username, user_id)
    return {"message": f"User {user_id} activated."}


@router.post("/users/{user_id}/promote")
async def admin_promote_user(
    user_id: int,
    _admin:  UserInDB = Depends(require_admin),
) -> dict:
    """Grant admin role to a user."""
    _assert_user_exists(user_id)
    set_user_role(user_id, "admin")
    logger.info("Admin %s promoted user %d to admin", _admin.username, user_id)
    return {"message": f"User {user_id} promoted to admin."}


@router.post("/users/{user_id}/demote")
async def admin_demote_user(
    user_id: int,
    _admin:  UserInDB = Depends(require_admin),
) -> dict:
    """Remove admin role from a user (set to 'analyst')."""
    if _admin.id == user_id:
        raise HTTPException(400, "You cannot demote yourself.")
    _assert_user_exists(user_id)
    set_user_role(user_id, "analyst")
    logger.info("Admin %s demoted user %d", _admin.username, user_id)
    return {"message": f"User {user_id} demoted to analyst."}


@router.delete("/users/{user_id}", status_code=204)
async def admin_delete_user(
    user_id: int,
    _admin:  UserInDB = Depends(require_admin),
) -> None:
    """Permanently delete a user account."""
    if _admin.id == user_id:
        raise HTTPException(400, "You cannot delete your own account.")
    _assert_user_exists(user_id)
    delete_user(user_id)
    logger.info("Admin %s deleted user %d", _admin.username, user_id)


# ── Projects ───────────────────────────────────────────────────────────────────

@router.get("/projects")
async def admin_list_projects(_admin: UserInDB = Depends(require_admin)) -> list:
    """Return all projects across all users, including owner_username."""
    return list_all_projects()


@router.post("/projects/cleanup-mixed")
async def admin_cleanup_mixed_artifacts(
    req: CleanupMixedRequest,
    _admin: UserInDB = Depends(require_admin),
) -> dict:
    """Scan or clean mixed web/windows artifacts left by historical runs."""
    result = cleanup_mixed_project_artifacts(
        project_id=req.project_id,
        dry_run=req.dry_run,
        archive=req.archive,
    )
    logger.info(
        "Admin %s ran mixed-artifact cleanup (dry_run=%s, archive=%s, project_id=%s)",
        _admin.username,
        req.dry_run,
        req.archive,
        req.project_id,
    )
    return result


@router.delete("/projects/{project_id}", status_code=204)
async def admin_delete_project(
    project_id: str,
    _admin:     UserInDB = Depends(require_admin),
) -> None:
    """Force-delete any project regardless of owner."""
    project = get_project(project_id)
    if not project:
        raise HTTPException(404, f"Project '{project_id}' not found.")

    base = PROJECTS_DIR / project_id
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)

    delete_project(project_id)
    logger.info("Admin %s force-deleted project %s", _admin.username, project_id)


# ── Stats ──────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def admin_stats(_admin: UserInDB = Depends(require_admin)) -> dict:
    """Platform-level counts: total users, projects, logs, and detections."""
    from core.storage.sqlite_store import get_log_count, get_project_stats
    with sqlite3.connect(DB_PATH) as conn:
        user_count    = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        project_count = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        project_ids   = [r[0] for r in conn.execute("SELECT id FROM projects").fetchall()]
    log_count = get_log_count()
    det_count = sum(get_project_stats(pid)["detections"] for pid in project_ids)
    return {
        "total_users":       user_count,
        "total_projects":    project_count,
        "total_log_entries": log_count,
        "total_detections":  det_count,
    }


# ── Private helpers ────────────────────────────────────────────────────────────

def _assert_user_exists(user_id: int) -> dict:
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(404, f"User {user_id} not found.")
    return user
