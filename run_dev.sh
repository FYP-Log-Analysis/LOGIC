#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run_dev.sh — LOGIC Web Agent local dev launcher (no Docker required)
#
# Usage:
#   chmod +x run_dev.sh
#   ./run_dev.sh
#
# What it does:
#   1. Creates a .venv if it doesn't exist
#   2. Installs all Python dependencies
#   3. Sources .env variables into the shell
#   4. Starts FastAPI (port 4000) and Next.js frontend (port 3000) concurrently
#   5. Waits — Ctrl+C kills both
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${CYAN}[dev]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC}  $*"; }
warn() { echo -e "${YELLOW}[!!]${NC}  $*"; }

# ── 1. Virtual env ────────────────────────────────────────────────────────────
VENV=".venv"
if [ ! -d "$VENV" ]; then
    log "Creating virtual environment at .venv …"
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"
ok "Virtual environment active: $(which python)"

# ── 2. Install dependencies ────────────────────────────────────────────────────
log "Installing / upgrading dependencies …"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
pip install --quiet -r api/requirements.txt
ok "Dependencies installed"

# ── 3. Source .env ────────────────────────────────────────────────────────────
if [ -f ".env" ]; then
    log "Loading .env …"
    # Export each non-comment, non-blank line
    set -o allexport
    # shellcheck disable=SC1091
    source .env
    set +o allexport
    ok ".env loaded"
else
    echo -e "${RED}[FATAL]${NC} .env file not found. Create .env in the project root before running dev."
    exit 1
fi

# ── 4. Ensure active data directories exist ──────────────────────────────────
mkdir -p data/crs_audit data/crs_rules data/projects

# ── 5. CRS URL (external optional service, no Docker orchestration here) ─────
export CRS_SERVICE_URL="${CRS_SERVICE_URL:-http://localhost:8080}"
warn "Assuming CRS service at ${CRS_SERVICE_URL}. Start it separately if needed."

# ── 6. Set PYTHONPATH so both api/ and root modules are importable ─────────────
export PYTHONPATH="$SCRIPT_DIR"
export API_BASE_URL="${API_BASE_URL:-http://localhost:4000}"
export DATA_ROOT="${DATA_ROOT:-$SCRIPT_DIR/data}"
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:3000,http://127.0.0.1:3000}"

# ── 7. JWT secret — generate and persist if missing ───────────────────────────
if [ -z "${JWT_SECRET_KEY:-}" ]; then
    warn "JWT_SECRET_KEY not set in .env — generating a stable dev key and saving it."
    NEW_KEY="dev-$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    echo "" >> .env
    echo "# Auto-generated dev secret — replace before production" >> .env
    echo "JWT_SECRET_KEY=${NEW_KEY}" >> .env
    export JWT_SECRET_KEY="$NEW_KEY"
    ok "JWT_SECRET_KEY written to .env"
fi

# ── 8. Launch FastAPI ─────────────────────────────────────────────────────────
log "Starting FastAPI on http://localhost:4000 …"
uvicorn api.main:app --reload --host 0.0.0.0 --port 4000 \
    --log-level info &
API_PID=$!

# Give the API a moment to bind
sleep 2

# ── 9. Launch Next.js frontend (dev mode with hot-reload) ────────────────────
if [ -d "frontend" ]; then
    log "Installing frontend dependencies …"
    (cd frontend && npm install --silent)
    log "Starting Next.js on http://localhost:3000 …"
    (cd frontend && npm run dev) &
    DASH_PID=$!
else
    warn "frontend/ directory not found — skipping Next.js"
    DASH_PID=""
fi

# ── 10. Print summary ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  LOGIC Web Agent — running locally${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Dashboard : ${CYAN}http://localhost:3000${NC}"
echo -e "  API       : ${CYAN}http://localhost:4000${NC}"
echo -e "  API docs  : ${CYAN}http://localhost:4000/docs${NC}"
echo -e ""
echo -e "  Press ${RED}Ctrl+C${NC} to stop both services"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── 11. Wait and clean up ─────────────────────────────────────────────────────
trap '
    echo ""
    log "Stopping services …"
    kill $API_PID ${DASH_PID:-} 2>/dev/null
    wait 2>/dev/null
    ok "Done."
' INT TERM
wait
