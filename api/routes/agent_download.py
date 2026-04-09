import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

router = APIRouter(tags=["logicx-agent"])
logger = logging.getLogger(__name__)


@router.get("/logicx/script", response_class=PlainTextResponse, summary="Legacy Python script endpoint (removed)")
def download_script():
    """Legacy endpoint kept for compatibility after NXLog-only agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Python script distribution was removed. Use /api/projects/{project_id}/agent-config/nxlog instead.",
    )


@router.get("/logicx/install/windows", response_class=PlainTextResponse, summary="Download the Logicx installer (Windows)")
def download_install_windows():
    """Legacy endpoint kept for compatibility after NXLog-only agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Windows installer was removed. Use /api/projects/{project_id}/agent-config/nxlog.",
    )


@router.get("/logicx/service/windows", response_class=PlainTextResponse, summary="Download the Logicx service helper script (Windows)")
def download_service_windows():
    """Legacy endpoint kept for compatibility after NXLog-only agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Service helper was removed. Use /api/projects/{project_id}/agent-config/nxlog.",
    )


@router.get("/logicx/exe/windows", summary="Download the Logicx executable (Windows)")
def download_windows_executable():
    """Legacy endpoint kept for compatibility after NXLog-only agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Windows executable distribution was removed. Use /api/projects/{project_id}/agent-config/nxlog.",
    )


@router.get("/logicx/exe/windows/sha256", response_class=PlainTextResponse, summary="Download SHA256 checksum for Logicx Windows executable")
def download_windows_executable_sha256():
    """Legacy endpoint kept for compatibility after single-script agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Windows executable checksum is not available because executable distribution was removed.",
    )
