# LOGIC API Documentation

## 1. Purpose

This document defines the HTTP API contract for the LOGIC backend service. It is intended for frontend engineers, integration developers, and operations teams.

The API is implemented with FastAPI and exposes authentication, project management, ingestion, search, analysis, administration, and export capabilities.

## 2. Service Metadata

1. API name: LOGIC Web Agent API
2. Framework: FastAPI
3. Default local base URL: http://localhost:4000
4. OpenAPI UI: /docs
5. OpenAPI JSON: /openapi.json

## 3. Authentication and Authorization

Two authentication modes are used.

1. Bearer token authentication (JWT)
2. Project API key authentication (for agent ingestion and config workflows)

### 3.1 Bearer Token

Obtain a token from POST /api/auth/login and provide it in the Authorization header.

Authorization header format:

```text
Authorization: Bearer <access_token>
```

### 3.2 Project API Key

Project keys are generated per project and are used by agent workflows.

Supported transport:

1. X-Logic-Api-Key request header
2. api_key query parameter

### 3.3 Role Model

1. analyst: standard authenticated user with project-scoped access
2. admin: elevated access for platform-wide administration

## 4. Runtime and Security Notes

1. CORS is controlled by ALLOWED_ORIGINS.
2. JWT secret is controlled by JWT_SECRET_KEY.
3. JWT algorithm is HS256.
4. Token expiration uses JWT_EXPIRE_MINUTES (default 480).
5. On startup, demo users may be seeded if missing:
   1. admin / admin123
   2. analyst / analyst123

## 5. API Conventions

1. Asynchronous operations return 202 Accepted with a run_id or upload_id.
2. Status endpoints are provided for long-running tasks.
3. Most read endpoints support project_id filtering.
4. Timestamps are ISO 8601 where applicable.
5. Error responses follow standard HTTP status semantics.

## 6. Endpoint Reference

### 6.1 Health

| Method | Path | Authentication | Description |
|---|---|---|---|
| GET | / | None | Service health and documentation pointer. |
| GET | /api/windows-agent/health | None | Windows agent ingest health check. |

### 6.2 Authentication

| Method | Path | Authentication | Description |
|---|---|---|---|
| POST | /api/auth/register | None | Register a new user account. |
| POST | /api/auth/login | None | Authenticate user and return JWT token. |
| GET | /api/auth/me | Bearer token | Return authenticated user profile. |

### 6.3 Projects

| Method | Path | Authentication | Description |
|---|---|---|---|
| POST | /api/projects | Bearer token | Create a project (web or windows). |
| GET | /api/projects | Bearer token | List projects visible to current user. |
| GET | /api/projects/{project_id} | Bearer token | Get project metadata. |
| GET | /api/projects/{project_id}/stats | Bearer token | Get project-level operational statistics. |
| GET | /api/projects/{project_id}/uploads | Bearer token | List project uploads. |
| DELETE | /api/projects/{project_id}/uploads/{upload_id} | Bearer token | Delete a specific upload and associated artifacts. |
| DELETE | /api/projects/{project_id} | Bearer token | Delete a project and associated artifacts. |
| POST | /api/projects/{project_id}/api-key | Bearer token | Generate or rotate project API key. |
| GET | /api/projects/{project_id}/api-key | Bearer token | Retrieve project API key. |
| GET | /api/projects/{project_id}/agent-config | Bearer token | Retrieve configured agent path settings. |
| POST | /api/projects/{project_id}/agent-config | Bearer token | Update configured agent path settings. |
| GET | /api/projects/{project_id}/agent-config/nxlog | Bearer token | Download generated NXLog configuration text. |
| GET | /api/logicx/config | Project API key | Retrieve agent runtime configuration. |

### 6.4 Upload and Log Access

| Method | Path | Authentication | Description |
|---|---|---|---|
| POST | /api/upload | Bearer token | Upload web log file for asynchronous processing. |
| POST | /api/upload/windows | Bearer token | Upload Windows EVTX or XML file for asynchronous processing. |
| GET | /api/upload/status/{upload_id} | Bearer token | Get ingest status for an upload. |
| GET | /api/upload/logs/{upload_id} | Bearer token | Get processing log lines for an upload. |
| GET | /api/logs/time-range | Bearer token | Get min and max timestamps in normalized log data. |
| GET | /api/logs/entries | Bearer token | Query normalized log entries. |
| GET | /api/logs/statistics | Bearer token | Get aggregated log statistics. |

### 6.5 Web Analysis

| Method | Path | Authentication | Description |
|---|---|---|---|
| POST | /api/analysis/run | Bearer token | Start CRS-oriented web analysis run. |
| GET | /api/analysis/latest | Bearer token | Retrieve most recent analysis run output. |
| GET | /api/analysis/run/{run_id} | Bearer token | Get status and output of a specific analysis run. |
| POST | /api/analysis/threat-insights | Bearer token | Generate LLM-based threat insights for rule matches. |
| POST | /api/analysis/threat-insights/{rule_id} | Bearer token | Generate LLM-based threat insight for one rule. |
| GET | /api/analysis/threat-insights/status | Bearer token | Check threat insight service and dataset availability. |

### 6.6 Behavioral Analysis

| Method | Path | Authentication | Description |
|---|---|---|---|
| POST | /api/analysis/behavioral | Bearer token | Run behavioral analytics for web telemetry. |
| GET | /api/analysis/behavioral/results | Bearer token | Retrieve persisted behavioral analysis output. |
| GET | /api/analysis/behavioral/alerts | Bearer token | Query behavioral alert records. |
| POST | /api/analysis/windows/behavioral | Bearer token | Run Windows behavioral analytics workflow. |
| GET | /api/analysis/windows/behavioral/results | Bearer token | Retrieve persisted Windows behavioral output. |

### 6.7 Windows Analysis

| Method | Path | Authentication | Description |
|---|---|---|---|
| POST | /api/analysis/windows/explain-event | Bearer token | Generate LLM explanation for a Windows event. |
| POST | /api/analysis/windows/run-sigma | Bearer token | Start asynchronous Sigma detection run. |
| GET | /api/analysis/windows/results | Bearer token | Retrieve Sigma match output. |
| GET | /api/analysis/windows/sigma-rules | Bearer token | List available Sigma rules with metadata. |
| GET | /api/analysis/windows/sigma-rules/view | Bearer token | Retrieve Sigma rule YAML and normalized metadata. |
| GET | /api/analysis/windows/run/{run_id} | Bearer token | Get status and output for a Sigma run. |
| GET | /api/analysis/windows/iocs | Bearer token | Extract indicators of compromise from analysis output. |
| GET | /api/analysis/windows/export/sigma-csv | Bearer token | Export Sigma results as CSV file. |
| GET | /api/analysis/windows/export/behavioral-csv | Bearer token | Export behavioral results as CSV file. |
| GET | /api/analysis/windows/export/report | Bearer token | Export consolidated text report. |
| GET | /api/analysis/windows/correlation | Bearer token | Return correlated event-chain analysis output. |

### 6.8 Search and Dashboard Query

| Method | Path | Authentication | Description |
|---|---|---|---|
| GET | /api/search/detections | Bearer token | Query detections with filters and pagination. |
| GET | /api/search/stats | Bearer token | Get detection summary statistics. |
| GET | /api/search/ip-summary/{client_ip} | Bearer token | Get detailed summary for a client IP. |
| GET | /api/search/overview | Bearer token | Get dashboard-level overview payload. |
| GET | /api/search/detection-aggregations | Bearer token | Get aggregated detection metrics. |

### 6.9 Live Receiver and Agent Ingest

| Method | Path | Authentication | Description |
|---|---|---|---|
| POST | /api/logicx/ingest | Bearer token or Project API key | Ingest live LOGICX agent records. |
| POST | /api/windows-agent/ingest | Bearer token or Project API key | Ingest live Windows agent or NXLog records. |
| GET | /api/receiver/monitor | Bearer token | Retrieve receiver runtime monitoring snapshot. |

Payload guidance for ingest endpoints.

1. Supported content types: application/x-ndjson, application/json, application/octet-stream
2. UTF-8 payload expected
3. Gzip content supported through Content-Encoding header
4. Per-record required fields: host, file, log, date, agent_version

### 6.10 Hawkins Chat

| Method | Path | Authentication | Description |
|---|---|---|---|
| POST | /api/analysis/chat | Bearer token | Stream forensic assistant response for chat context. |

### 6.11 Administration

All endpoints in this section require admin role.

| Method | Path | Authentication | Description |
|---|---|---|---|
| GET | /api/admin/users | Admin bearer token | List users. |
| POST | /api/admin/users/{user_id}/activate | Admin bearer token | Activate user account. |
| POST | /api/admin/users/{user_id}/deactivate | Admin bearer token | Deactivate user account. |
| POST | /api/admin/users/{user_id}/promote | Admin bearer token | Promote user to admin role. |
| POST | /api/admin/users/{user_id}/demote | Admin bearer token | Demote admin to analyst role. |
| DELETE | /api/admin/users/{user_id} | Admin bearer token | Delete user account. |
| GET | /api/admin/projects | Admin bearer token | List projects across all owners. |
| POST | /api/admin/projects/cleanup-mixed | Admin bearer token | Clean mixed artifacts in project storage. |
| DELETE | /api/admin/projects/{project_id} | Admin bearer token | Force-delete project. |
| GET | /api/admin/stats | Admin bearer token | Retrieve platform-level metrics. |

### 6.12 Legacy Agent Download Endpoints

The following endpoints are retained for compatibility but currently return 410 Gone.

1. GET /api/logicx/script
2. GET /api/logicx/install/windows
3. GET /api/logicx/service/windows
4. GET /api/logicx/exe/windows
5. GET /api/logicx/exe/windows/sha256

## 7. Typical Integration Flows

### 7.1 Standard User Flow

1. Register or log in.
2. Create a project.
3. Upload data or configure live ingest.
4. Poll status endpoints until processing completes.
5. Query search, analysis, and export endpoints.

### 7.2 Agent Ingest Flow

1. Generate project API key.
2. Retrieve runtime config from /api/logicx/config.
3. Send records to ingest endpoint using API key.
4. Monitor receiver and upload status endpoints.

### 7.3 Administrative Flow

1. Authenticate as admin.
2. Review users, projects, and platform stats.
3. Apply account actions and maintenance operations.

## 8. Response and Error Expectations

Common status patterns.

1. 200 OK for successful read operations.
2. 201 Created for resource creation.
3. 202 Accepted for asynchronous task start.
4. 204 No Content for successful deletion.
5. 400 Bad Request for validation or domain mismatch.
6. 401 Unauthorized for missing or invalid authentication.
7. 403 Forbidden for insufficient permissions.
8. 404 Not Found for missing resource identifiers.
9. 410 Gone for retired legacy endpoints.

## 9. Change Management Guidance

1. Keep this document aligned with route changes in api/routes and include_router mappings in api/main.py.
2. For precise request and response schemas, treat FastAPI OpenAPI output as the contract source of truth.
3. Update this document in the same pull request as endpoint additions, deletions, path changes, or auth changes.
