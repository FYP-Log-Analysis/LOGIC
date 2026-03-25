import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

router = APIRouter(tags=["logicx-agent"])
logger = logging.getLogger(__name__)

# Agent files live in agent/ at the project root.
from pathlib import Path

_AGENT_DIR = Path(__file__).resolve().parent.parent.parent / "agent"


def _serve(filename: str) -> PlainTextResponse:
    path = _AGENT_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Agent file not found: {filename}")
    try:
        return PlainTextResponse(path.read_text(encoding="utf-8"))
    except OSError as exc:
        logger.exception("Failed to read agent text file %s", path)
        raise HTTPException(status_code=500, detail="Failed to read requested agent file") from exc


@router.get("/logicx/script", response_class=PlainTextResponse, summary="Download the Logicx agent Python script")
def download_script():
    """Returns log_sender.py as plain text."""
    return _serve("log_sender.py")


@router.get("/logicx/install/windows", response_class=PlainTextResponse, summary="Download the Logicx installer (Windows)")
def download_install_windows():
    """Legacy endpoint kept for compatibility after single-script agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Windows installer was removed. Use /api/logicx/script and run log_sender.py directly.",
    )


@router.get("/logicx/service/windows", response_class=PlainTextResponse, summary="Download the Logicx service helper script (Windows)")
def download_service_windows():
    """Legacy endpoint kept for compatibility after single-script agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Service helper was removed. Run log_sender.py directly in foreground mode.",
    )


@router.get("/logicx/exe/windows", summary="Download the Logicx executable (Windows)")
def download_windows_executable():
    """Legacy endpoint kept for compatibility after single-script agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Windows executable distribution was removed. Use /api/logicx/script.",
    )


@router.get("/logicx/exe/windows/sha256", response_class=PlainTextResponse, summary="Download SHA256 checksum for Logicx Windows executable")
def download_windows_executable_sha256():
    """Legacy endpoint kept for compatibility after single-script agent migration."""
    raise HTTPException(
        status_code=410,
        detail="Windows executable checksum is not available because executable distribution was removed.",
    )
