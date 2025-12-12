from fastapi import APIRouter
from services.logs_service import load_all_logs, load_logs_by_type

router = APIRouter()

# GET /api/logs
@router.get("/")
def get_all_logs():
    return load_all_logs()

# GET /api/logs/System or /api/logs/Application
@router.get("/{log_type}")
def get_logs_by_type(log_type: str):
    return load_logs_by_type(log_type)
