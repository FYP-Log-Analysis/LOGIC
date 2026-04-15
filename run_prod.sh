#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run_prod.sh — LOGIC Web Agent production launcher (no Docker)
#
# Usage:
#   chmod +x run_prod.sh
#   ./run_prod.sh
#
# Prerequisites:
#   • Ensure .env exists and fill in required values (JWT_SECRET_KEY, GROQ_API_KEY …)
#   • Python 3.11+ and pip available in PATH
#   • (Optional) Run behind Nginx for HTTPS — see README.md production section
#
# What it does:
#   1. Validates required env vars are set
#   2. Activates .venv (creates and installs deps if missing)
#   3. Starts FastAPI with uvicorn (2 workers, no --reload)
#   4. Starts Next.js frontend (production build)
#   5. Traps Ctrl+C / SIGTERM to cleanly stop both
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${CYAN}[prod]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC}   $*"; }
warn() { echo -e "${YELLOW}[!!]${NC}   $*"; }
die()  { echo -e "${RED}[FATAL]${NC} $*"; exit 1; }

port_in_use() {
    local port="$1"
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

# ── 1. Load .env ──────────────────────────────────────────────────────────────
if [ -f ".env" ]; then
    log "Loading .env …"
    set -o allexport
    # shellcheck disable=SC1091
    source .env
    set +o allexport
    ok ".env loaded"
else
    die ".env file not found. Create .env in the project root and fill in all required values."
fi

# ── 2. Validate required env vars ─────────────────────────────────────────────
[[ -z "${JWT_SECRET_KEY:-}" ]]  && die "JWT_SECRET_KEY is not set in .env"
[[ "${JWT_SECRET_KEY}" == "CHANGE-ME-"* ]] && die "JWT_SECRET_KEY still has the placeholder value. Generate a real key."
[[ -z "${GROQ_API_KEY:-}" ]]   && warn "GROQ_API_KEY is not set — AI features will be disabled."

ok "Environment validated."

# ── 3. Virtual env ────────────────────────────────────────────────────────────
VENV=".venv"
if [ ! -d "$VENV" ]; then
    log "Creating virtual environment …"
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

log "Installing / upgrading dependencies …"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
pip install --quiet -r api/requirements.txt
ok "Dependencies ready."

# ── 4. Ensure active data directories exist ──────────────────────────────────
mkdir -p data/crs_audit data/crs_rules data/projects

# ── 5. Export runtime env vars ────────────────────────────────────────────────
export PYTHONPATH="$SCRIPT_DIR"
export API_BASE_URL="${API_BASE_URL:-http://localhost:4000}"
export DATA_ROOT="${DATA_ROOT:-$SCRIPT_DIR/data}"
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:3000}"

# macOS does not support `hostname -I`; derive a best-effort host IP portably.
if command -v ipconfig >/dev/null 2>&1; then
    HOST_IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo localhost)"
else
    HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    HOST_IP="${HOST_IP:-localhost}"
fi

# ── 6. Preflight port checks ─────────────────────────────────────────────────
port_in_use 4000 && die "Port 4000 is already in use. Stop the existing process before running production."
if [ -d "frontend" ]; then
    port_in_use 3000 && die "Port 3000 is already in use. Stop the existing process before running production."
fi

# ── 7. Start FastAPI (production mode — 2 workers, no hot-reload) ─────────────
log "Starting FastAPI on :4000 (2 workers) …"
uvicorn api.main:app \
    --host 0.0.0.0 \
    --port 4000 \
    --workers 2 \
    --log-level warning \
    --access-log &
API_PID=$!

sleep 2
kill -0 "$API_PID" 2>/dev/null || die "FastAPI failed to start. Check logs and try again."

# ── 8. Build and start Next.js frontend (production) ────────────────────────
if [ -d "frontend" ]; then
    log "Building Next.js frontend …"
    (cd frontend && env -u NODE_OPTIONS npm install --silent && env -u NODE_OPTIONS npm run build)
    log "Starting Next.js standalone server on :3000 …"
    if [ -f "frontend/.next/standalone/server.js" ]; then
        (cd frontend && env -u NODE_OPTIONS HOSTNAME=0.0.0.0 PORT=3000 node .next/standalone/server.js) &
    else
        warn "Standalone output missing; falling back to next start"
        (cd frontend && env -u NODE_OPTIONS npm run start -- --port 3000) &
    fi
    DASH_PID=$!
    sleep 2
    kill -0 "$DASH_PID" 2>/dev/null || die "Next.js failed to start. Check frontend logs and try again."
else
    warn "frontend/ directory not found — skipping Next.js"
    DASH_PID=""
fi

# ── 9. Print summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  LOGIC Web Agent — PRODUCTION${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Dashboard  : ${CYAN}http://${HOST_IP}:3000${NC}"
echo -e "  API        : ${CYAN}http://${HOST_IP}:4000${NC}"
echo -e "  API docs   : ${CYAN}http://${HOST_IP}:4000/docs${NC}"
echo -e ""
echo -e "  API PID    : ${API_PID}"
echo -e "  Dash PID   : ${DASH_PID:-N/A}"
echo -e ""
echo -e "  Press ${RED}Ctrl+C${NC} or send SIGTERM to stop both services"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── 10. Wait and clean up ─────────────────────────────────────────────────────
cleanup() {
    echo ""
    log "Received shutdown signal — stopping services …"
    kill "$API_PID" ${DASH_PID:-} 2>/dev/null || true
    wait "$API_PID" ${DASH_PID:-} 2>/dev/null || true
    ok "Services stopped. Goodbye."
}
trap cleanup INT TERM

wait
