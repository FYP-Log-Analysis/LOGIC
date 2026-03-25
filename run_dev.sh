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
    warn ".env not found — using defaults. Copy .env.example if available."
fi

# ── 4. Ensure active data directories exist ──────────────────────────────────
mkdir -p data/crs_audit data/crs_rules data/projects

# ── 5. Start CRS detection container (requires Docker) ───────────────────────
CRS_PID=""
if command -v docker &>/dev/null; then
    log "Starting CRS detector container (logic-crs-detector) …"
    crs_started=0
    expected_audit_mount="$SCRIPT_DIR/data/crs_audit"
    expected_rules_mount="$SCRIPT_DIR/data/crs_rules"

    # Reuse the existing named container when it already exists.
    if docker container inspect logic-crs-detector >/dev/null 2>&1; then
        audit_mount_source="$(docker inspect logic-crs-detector --format '{{range .Mounts}}{{if eq .Destination "/var/log/modsec"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
        rules_mount_source="$(docker inspect logic-crs-detector --format '{{range .Mounts}}{{if eq .Destination "/etc/modsecurity.d/owasp-crs/rules/z_custom-rules"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"

        if [ "$audit_mount_source" != "$expected_audit_mount" ] || [ "$rules_mount_source" != "$expected_rules_mount" ]; then
            warn "Existing logic-crs-detector container has stale mount paths; recreating for this workspace."
            docker rm -f logic-crs-detector >/dev/null 2>&1 || true
            compose_err=""
            if compose_err=$(docker compose up -d crs-detector 2>&1); then
                crs_started=1
            elif compose_err=$(docker-compose up -d crs-detector 2>&1); then
                crs_started=1
            else
                warn "Could not recreate CRS detector."
                warn "Docker error: ${compose_err}"
            fi
        elif docker start logic-crs-detector >/dev/null 2>&1 || docker ps --format '{{.Names}}' | grep -q '^logic-crs-detector$'; then
            crs_started=1
        fi
    else
        compose_err=""
        if compose_err=$(docker compose up -d crs-detector 2>&1); then
            crs_started=1
        elif compose_err=$(docker-compose up -d crs-detector 2>&1); then
            crs_started=1
        else
            warn "Could not start CRS detector."
            warn "Docker error: ${compose_err}"
        fi
    fi

    if [ "$crs_started" -eq 1 ]; then
        crs_reachable=0
        # Wait for nginx inside the container to become ready
        for i in 1 2 3 4 5; do
            code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 1 http://localhost:8080/ || true)"
            if [ "$code" != "000" ]; then
                crs_reachable=1
                break
            fi
            sleep 1
        done
        if [ "$crs_reachable" -eq 1 ]; then
            ok "CRS detector reachable at http://localhost:8080 (HTTP ${code})"
            export CRS_SERVICE_URL="${CRS_SERVICE_URL:-http://localhost:8080}"
        else
            warn "CRS container started but is not reachable at http://localhost:8080"
        fi
    fi
else
    warn "Docker not found — CRS detection is unavailable in local dev."
fi

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
    if command -v docker &>/dev/null; then
        log "Stopping CRS detector container …"
        docker compose stop crs-detector 2>/dev/null || docker-compose stop crs-detector 2>/dev/null
    fi
    ok "Done."
' INT TERM
wait
