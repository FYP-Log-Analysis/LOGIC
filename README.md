# LOGIC Web Agent

LOGIC Web Agent is a local-first log forensics platform for web and Windows telemetry.
It includes:

- FastAPI backend for ingestion, detection, search, auth, and admin operations
- Next.js frontend dashboard for analysts
- SQLite-backed project storage under `data/`
- Rule-based detection pipelines (CRS + Sigma + behavioral)

## Project Layout

- `api/`: API routes, auth dependencies, and LLM service integration
- `core/`: ingestion, normalization, detection, enrichment, and storage logic
- `frontend/`: Next.js dashboard and API proxy
- `agent/`: downloadable log sender script
- `data/`: runtime data, project files, rule bundles, and SQLite DB
- `grafana/`: provisioning for Grafana dashboards/datasources

## Local Development

### Prerequisites

- Python 3.11+
- Node.js 20+
- npm
- Optional: Docker (for CRS detector in dev)

### Start

1. Copy environment template:
   - `cp .env.example .env`
2. Update at least `JWT_SECRET_KEY` in `.env`
3. Run:
   - `./run_dev.sh`

Services:

- Frontend: `http://localhost:3000`
- API: `http://localhost:4000`
- API docs: `http://localhost:4000/docs`

## Production (No Docker)

1. Copy env template:
   - `cp .env.example .env`
2. Set strong secrets (`JWT_SECRET_KEY`, `GRAFANA_PASSWORD`) and production origins (`ALLOWED_ORIGINS`)
3. Run:
   - `./run_prod.sh`

`run_prod.sh` runs FastAPI with 2 workers and Next.js in production mode.

## Production (Docker Compose)

Run:

- `docker compose up -d --build`

Default ports:

- API: `4000`
- Frontend: `3001`
- CRS detector: `8080`
- Grafana: `3000`

## Cleanup Policy

This repository keeps runtime data and rule assets under `data/`.
Do not delete the following in routine cleanup:

- `data/projects/`
- `data/crs_audit/`
- `data/crs_rules/`
- `data/sigma_rules/`
- `data/logic.db`

Safe cleanup targets:

- Python cache folders (`__pycache__/`)
- local virtual env (`.venv/`) when recreating environment
- frontend build cache (`frontend/.next/`)

## Notes On API Cleanup

A conservative route audit was performed before cleanup.
All routers mounted in `api/main.py` are active, and no endpoint files were removed in this pass.
Only low-risk hygiene changes were applied.
