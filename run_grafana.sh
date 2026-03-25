#!/usr/bin/env bash
# Local Grafana launcher for LOGIC (no Docker).
# Requires grafana-server (or grafana) installed on host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${CYAN}[grafana]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC}      $*"; }
die()  { echo -e "${RED}[FATAL]${NC}   $*"; exit 1; }

if [ -f ".env" ]; then
    set -o allexport
    # shellcheck disable=SC1091
    source .env
    set +o allexport
fi

if command -v grafana-server >/dev/null 2>&1; then
    GRAFANA_SERVER_BIN="grafana-server"
elif command -v grafana >/dev/null 2>&1; then
    GRAFANA_SERVER_BIN="grafana"
else
    die "Grafana is not installed. Install it first (e.g. brew install grafana)."
fi

if command -v grafana-cli >/dev/null 2>&1; then
    GRAFANA_CLI_BIN="grafana-cli"
elif command -v grafana >/dev/null 2>&1; then
    GRAFANA_CLI_BIN="grafana"
else
    GRAFANA_CLI_BIN=""
fi

mkdir -p data/grafana data/grafana/log data/grafana/plugins

export LOGIC_API_URL="${LOGIC_API_URL:-http://localhost:4000}"
export GF_SECURITY_ADMIN_USER="${GRAFANA_USER:-admin}"
export GF_SECURITY_ADMIN_PASSWORD="${GRAFANA_PASSWORD:-logic1234}"
export GF_PATHS_DATA="$SCRIPT_DIR/data/grafana"
export GF_PATHS_LOGS="$SCRIPT_DIR/data/grafana/log"
export GF_PATHS_PLUGINS="$SCRIPT_DIR/data/grafana/plugins"
export GF_PATHS_PROVISIONING="$SCRIPT_DIR/grafana/provisioning"

if [ -n "$GRAFANA_CLI_BIN" ]; then
    log "Ensuring Infinity datasource plugin is installed ..."
    if [ "$GRAFANA_CLI_BIN" = "grafana" ]; then
        grafana cli --pluginsDir "$GF_PATHS_PLUGINS" plugins install yesoreyeram-infinity-datasource >/dev/null 2>&1 || true
    else
        grafana-cli --pluginsDir "$GF_PATHS_PLUGINS" plugins install yesoreyeram-infinity-datasource >/dev/null 2>&1 || true
    fi
fi

ok "Starting Grafana on http://localhost:3002"
log "Using API URL: $LOGIC_API_URL"

if [ "$GRAFANA_SERVER_BIN" = "grafana" ]; then
    exec grafana server --config "$SCRIPT_DIR/grafana/grafana.ini"
else
    exec grafana-server --config "$SCRIPT_DIR/grafana/grafana.ini"
fi