import logging
import os

import bcrypt
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import upload, analysis
from api.routes.search import router as search_router
from api.routes.behavioral import router as behavioral_router
from api.routes.chat import router as chat_router
from api.routes.auth import router as auth_router
from api.routes.projects import router as projects_router
from api.routes.admin import router as admin_router
from api.routes.receiver import router as receiver_router
from api.routes.logicx import router as logicx_router
from api.routes.windows_agent import router as windows_agent_router
from api.routes.agent_download import router as agent_download_router
from api.routes.windows_analysis import router as windows_analysis_router
from core.storage.sqlite_store import (
    init_db,
    get_user_by_username,
    create_user,
    set_user_active,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="LOGIC Web Agent API",
    description="Web server log forensics — ingest, analyse, and interpret access/error logs",
    version="2.0",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Set ALLOWED_ORIGINS env var as a comma-separated list for production.
# Example: ALLOWED_ORIGINS=https://tool.company.com,http://localhost:8501
_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure the SQLite schema exists and seed demo accounts on first run
@app.on_event("startup")
def on_startup() -> None:
    init_db()

    # Seed demo accounts if they don't exist yet.
    # Re-activate them if they were accidentally deactivated via the admin panel.
    _SEEDS = [
        {"username": "admin",   "email": "admin@logic.local",   "password": "admin123",   "role": "admin"},
        {"username": "analyst", "email": "analyst@logic.local", "password": "analyst123", "role": "analyst"},
    ]
    for s in _SEEDS:
        existing = get_user_by_username(s["username"])
        if not existing:
            hashed = bcrypt.hashpw(s["password"].encode(), bcrypt.gensalt()).decode()
            create_user(username=s["username"], email=s["email"], hashed_password=hashed, role=s["role"])
            logger.info("Seeded demo account: %s (role=%s)", s["username"], s["role"])
        elif not existing.get("is_active"):
            set_user_active(existing["id"], 1)
            logger.warning("Re-activated deactivated demo account: %s", s["username"])

app.include_router(upload.router,       prefix="/api")
app.include_router(analysis.router,     prefix="/api/analysis")
app.include_router(windows_analysis_router, prefix="/api/analysis")
app.include_router(behavioral_router,   prefix="/api/analysis")
app.include_router(chat_router,         prefix="/api/analysis")
app.include_router(auth_router,         prefix="/api/auth")
app.include_router(projects_router,     prefix="/api")
app.include_router(admin_router,        prefix="/api/admin")
app.include_router(receiver_router,     prefix="/api")
app.include_router(logicx_router,       prefix="/api")
app.include_router(windows_agent_router, prefix="/api")
app.include_router(agent_download_router, prefix="/api")
app.include_router(search_router,       prefix="/api")


@app.get("/")
def root():
    return {"message": "LOGIC Web Agent API", "status": "running", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=4000)
