from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, Query, Request

from api.deps import UserInDB, get_optional_current_user
from api.routes.receiver import _receive_live_ingest

router = APIRouter(prefix="/logicx", tags=["LOGICX Receiver"])


@router.post("/ingest", status_code=202)
async def ingest_logicx_logs(
    request: Request,
    background_tasks: BackgroundTasks,
    project_id: str = Query(..., description="Project that owns this live stream"),
    rotate: bool = Query(False, description="Create a fresh live upload session"),
    current_user: Optional[UserInDB] = Depends(get_optional_current_user),
    x_logic_api_key: Optional[str] = Header(None),
) -> dict:
    """Native LOGICX log ingestion endpoint for LOGIC agents."""
    return await _receive_live_ingest(
        request=request,
        background_tasks=background_tasks,
        project_id=project_id,
        rotate=rotate,
        current_user=current_user,
        x_logic_api_key=x_logic_api_key,
        endpoint_used="logicx/ingest",
    )
