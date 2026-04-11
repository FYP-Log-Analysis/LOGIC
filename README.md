# LOGIC

LOGIC is a local-first detection and investigation platform for two telemetry domains: web server logs and Windows event logs. The platform combines ingestion, normalization, correlation, detection, behavioral analytics, and analyst workflows in a single operational stack.

## 1. System Overview

The repository contains the following major components.

1. API service built with FastAPI for authentication, project lifecycle, ingestion, analysis, search, and administration.
2. Web console built with Next.js for analyst and administrator workflows.
3. Core processing modules for parsing, normalization, detection logic, enrichment, and storage.
4. Runtime data store based on SQLite and project-scoped artifact files under the data directory.
5. Agent-facing ingest endpoints for live stream submission.

The platform supports two project types.

1. Web projects: optimized for Apache or Nginx style traffic and CRS-oriented detection.
2. Windows projects: optimized for EVTX or XML telemetry and Sigma-oriented detection.

## 2. Repository Structure

The top-level directories are organized as follows.

1. api: FastAPI application, route modules, and service wiring.
2. core: processing pipelines for ingestion, normalization, detection, enrichment, and export.
3. frontend: Next.js application, dashboard views, and client-side state logic.
4. agent: lightweight sender artifacts for ingestion workflows.
5. data: runtime state, uploaded content, detection outputs, and rule catalogs.

## 3. Execution Model

All data is project scoped. Each project can contain multiple uploads. Upload processing produces intermediate and normalized artifacts, followed by analysis outputs.

Standard processing sequence.

1. Receive logs from upload endpoints or agent ingest endpoints.
2. Parse and normalize records by telemetry type.
3. Execute detection and behavioral analytics.
4. Persist generated results under the project data path.
5. Serve outputs to the dashboard and API consumers.

## 4. Prerequisites

1. Python 3.11 or later.
2. Node.js 20 or later.
3. npm.
4. Docker and Docker Compose for containerized deployment (optional).

## 5. Local Development

Create a repository-level .env file with, at minimum, JWT_SECRET_KEY set.

Start the development stack.

```bash
./run_dev.sh
```

Default development endpoints.

1. Frontend: http://localhost:3000
2. API: http://localhost:4000
3. OpenAPI UI: http://localhost:4000/docs

The development launcher will create a local virtual environment when needed, install dependencies, and start API and frontend processes.

## 6. Production Execution (Host Processes)

Set production-safe environment values in .env, including JWT_SECRET_KEY and ALLOWED_ORIGINS.

Start production processes.

```bash
./run_prod.sh
```

The production launcher starts FastAPI with multiple workers and starts the Next.js frontend in production mode.

## 7. Container Deployment

Start all containers.

```bash
docker compose up -d --build
```

Default container ports.

1. API: 4000
2. Frontend: 3001
3. CRS detector: 8080

## 8. Data Management Policy

The following paths contain operational history and should be treated as persistent runtime data.

1. data/projects
2. data/crs_audit
3. data/crs_rules
4. data/sigma_rules
5. data/logic.db

Deleting data/projects or data/logic.db removes investigation history and analysis outputs.

## 9. Security and Access Control

1. Authentication is token based.
2. Access is owner scoped for standard users and elevated for administrators.
3. JWT secret material must be managed securely and rotated in production environments.
4. CORS origins should be explicitly restricted in production through ALLOWED_ORIGINS.

## 10. Documentation Set

Primary API documentation is available in two forms.

1. OpenAPI UI served by FastAPI at /docs.
2. Static API reference in api/README.md.

## 11. Operational Validation Checklist

After startup, confirm the following.

1. API responds and OpenAPI page loads.
2. Frontend authentication flow succeeds.
3. Project list and project detail pages load expected data.
4. Web analysis and Windows analysis endpoints return results for their respective project types.

## 12. Troubleshooting Summary

If API startup fails.

1. Validate .env values.
2. Verify dependencies were installed for root and api requirements.
3. Check for host port conflicts.

If frontend startup fails.

1. Reinstall frontend dependencies.
2. Rebuild and review lint or type errors.

If analysis output is missing.

1. Verify project type and endpoint alignment.
2. Verify upload status reached completion.
3. Verify project-scoped filters are set correctly.
