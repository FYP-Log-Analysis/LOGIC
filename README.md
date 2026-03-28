# LOGIC

LOGIC is a local-first detection and investigation platform for two telemetry modes:

1. Web server logs (Apache/Nginx style)
2. Windows event logs (EVTX/XML)

It combines ingestion, normalization, rule matching, behavioral analytics, and analyst workflows in one stack.

## What This Repository Contains

1. FastAPI backend for ingest, search, auth, project management, and analytics endpoints
2. Next.js dashboard for analysts and admins
3. Local SQLite state and per-project JSON artifacts under data
4. Detection content for both domains:
   - CRS-oriented web detection
   - Sigma-oriented Windows detection
   - Behavioral anomaly views
5. A lightweight log sender agent used for live ingestion

## Core Directory Map

1. api
   - Route handlers, auth dependencies, and service wiring
2. core
   - Ingestion, normalization, detection, enrichment, and storage helpers
3. frontend
   - Next.js app router pages, components, API proxy layer, and client store
4. agent
   - Downloadable sender script used by live stream workflows
5. data
   - Runtime data, rules, uploads, detection outputs, and logic.db

## Runtime Model

LOGIC stores data per project. A project has uploads, and each upload has intermediate and normalized artifacts.

Typical flow:

1. Upload or stream raw logs
2. Ingest raw files into intermediate structured records
3. Normalize records by log type
4. Run detection and analytics
5. Serve results through API and dashboard

Important: data/projects is the source of truth for project-scoped artifacts.

## Requirements

1. Python 3.11+
2. Node.js 20+
3. npm
4. Optional: Docker and Docker Compose (for containerized runtime)

## Quick Start (Local Dev)

1. Create environment file at repository root:
   - .env
2. Set minimum required values:
   - JWT_SECRET_KEY
3. Start development stack:
   - ./run_dev.sh

Default local endpoints:

1. Frontend: http://localhost:3000
2. API: http://localhost:4000
3. API OpenAPI docs: http://localhost:4000/docs

## Production (Host Processes, No Docker)

1. Configure .env with production-safe values:
   - JWT_SECRET_KEY
   - ALLOWED_ORIGINS
2. Start production script:
   - ./run_prod.sh

Current behavior:

1. FastAPI starts with multiple workers
2. Next.js runs in production mode

## Production (Docker Compose)

Start full container stack:

1. docker compose up -d --build

Container defaults:

1. API: 4000
2. Frontend: 3001
3. CRS detector: 8080

## Data and Cleanup Safety

Do not remove these during normal cleanup:

1. data/projects
2. data/crs_audit
3. data/crs_rules
4. data/sigma_rules
5. data/logic.db

Usually safe to remove:

1. Python caches (__pycache__)
2. Recreated virtual environments (.venv)
3. Frontend build cache (frontend/.next)

If you wipe data/projects or data/logic.db, you are deleting investigation history.

## Log Type Notes

Web projects:

1. Focus on HTTP request behavior, status patterns, and web detection workflows
2. Agents page incoming logs is intended for live web stream visibility

Windows projects:

1. Focus on Sigma matches and Windows behavioral windows
2. Sigma catalog is sourced from data/sigma_rules/windows and includes nested folders

## Operational Checks After Startup

1. Confirm API health by loading /docs
2. Log in to frontend and verify project list loads
3. In a web project, verify incoming live logs are visible only when the agent streams data
4. In a windows project, verify Sigma rules appear in overview grouped by folder structure

## Troubleshooting

API does not start:

1. Check missing .env values
2. Confirm Python dependencies are installed
3. Check for port conflicts on 4000

Frontend build or lint errors:

1. Run npm install in frontend
2. Re-run npm run lint and inspect file-specific hook/type violations

No logs shown in project views:

1. Confirm active project selection
2. Confirm upload status reached complete
3. Confirm correct endpoint used for project type (web upload vs windows upload)

## Security and Access

1. Auth is token-based; project access is owner-scoped unless admin role is used
2. Keep JWT secret private and rotate for production environments
3. Restrict ALLOWED_ORIGINS to trusted domains in production

## Development Notes

1. Keep route behavior explicit per project type to avoid cross-type leakage
2. Treat data/sigma_rules and data/crs_rules as controlled detection content
3. Prefer additive migrations in SQLite helpers to avoid destructive resets
