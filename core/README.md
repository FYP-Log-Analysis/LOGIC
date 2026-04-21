# LOGIC Core Modules: Detection and Analytics Implementation Guide

This document explains how the important security modules are implemented in this project, how they are applied during analysis, and what artifacts they produce.

## 1) Core Pipeline in This Repository

The end-to-end processing flow is project-scoped (`web` or `windows`) and upload-scoped.

1. Ingestion reads raw files and creates `intermediate.json`.
   - Module: `core/ingestion/ingest_logs.py`
2. Processing parses and normalizes to `normalized.json`.
   - Module: `core/processor/process_logs.py`
   - Windows events are normalized as `server_type = windows_event`.
3. Detection runs by project type.
   - Web projects: OWASP CRS replay and match extraction.
   - Windows projects: Sigma matching.
   - Module: `core/detection/rule_pipeline.py`
4. Behavioral analytics runs separately.
   - Web traffic behavior: `core/behavioral/behavioral.py`
   - Windows ML anomaly detection (Isolation Forest): `core/behavioral/windows_ml.py`
5. API routes expose execution and results.
   - Web analysis: `api/routes/analysis.py`
   - Windows rule analysis: `api/routes/windows_analysis.py`
   - Behavioral routes: `api/routes/behavioral.py`

## 2) CRS Detection: How It Is Implemented and Applied

### 2.1 What CRS does in this project

CRS detection is used for web logs only. The system replays normalized HTTP-like events to a ModSecurity CRS container running in DetectionOnly mode, then parses the CRS audit log to recover rule hits.

Main module: `core/detection/crs_processor.py`

### 2.2 Runtime wiring

- Container service is defined in `docker-compose.yml` as `crs-detector` using image `owasp/modsecurity-crs:nginx-alpine`.
- API side environment variables:
  - `CRS_SERVICE_URL` (default `http://crs-detector:8080`)
  - `CRS_AUDIT_LOG` (default under `data/crs_audit/audit.log`)
  - `CRS_BATCH_SIZE`, `CRS_FLUSH_WAIT`, `CRS_TIMEOUT`, `CRS_WORKERS`
- Audit log volume is shared (`./data/crs_audit:/var/log/modsec`) so Python can parse ModSecurity output.

### 2.3 Replay and matching pipeline

`run_crs_detection(...)` in `core/detection/crs_processor.py` performs:

1. Service reachability check with fallback URL resolution.
   - If configured host is `crs-detector`, it also tries localhost/127.0.0.1 combinations.
2. Stream-read of `normalized.json` via `ijson`.
3. Time-range filtering (`start_ts`, `end_ts`) if provided.
4. Batch replay of candidate entries using a pooled `requests.Session` + thread pool.
   - Each replay request gets a unique transaction id in header `X-Logic-TxId`.
5. Wait for audit flush (`CRS_FLUSH_WAIT`).
6. Parse NDJSON audit records and match them back to replayed requests using `X-Logic-TxId`.
7. Extract per-message details (rule id, message, tags, severity, anomaly score, paranoia level).

### 2.4 CRS severity mapping in this codebase

`core/detection/rule_pipeline.py` applies two severity concepts for CRS hits:

- Legacy severity: based mainly on anomaly score.
- Active v2 severity: risk-aware mapping in `_crs_severity_v2(...)`.

v2 mapping includes:

1. Base severity from CRS severity string when available, else score fallback.
2. Forced high severity for high anomaly score (`>= 5`).
3. Paranoia-level adjustment (`PL >= 3` and score `>= 2` can upgrade to high).
4. Tag/message risk token upgrade for high-risk patterns (SQLi, RCE, XSS, etc).
5. Scanner/bot-only signals are capped at medium unless stronger attack signals exist.

### 2.5 Where CRS is invoked

- Web analysis endpoint starts background run:
  - `POST /api/analysis/run`
  - Route module: `api/routes/analysis.py`
- Background task calls:
  - `core/detection/rule_pipeline.py -> run_rule_pipeline_from_file(...)`
- Strict project separation:
  - `web` projects run CRS only
  - `windows` projects run Sigma only

### 2.6 CRS output artifact

- Primary output file: `data/projects/<project_id>/uploads/<upload_id>/rule_matches.json`
- Output includes:
  - `matches[]` with normalized unified match shape
  - `crs_matches`, `sigma_matches`, `detector`, `detector_status`
  - severity fields: `severity`, `severity_legacy`, `severity_v2`, `severity_mapping_version`

## 3) Sigma Rule Sets: How They Are Implemented and Applied

### 3.1 Rule set location and structure

- Root folder: `data/sigma_rules`
- Main Windows EVTX hierarchy: `data/sigma_rules/windows/evtx/...`
- Current local EVTX rules in repo: 324 YAML rules.
- Coverage note is tracked in `data/sigma_rules/SIGMA_GAP_REPORT.md`.

### 3.2 Rule loading

`load_sigma_rules(...)` in `core/detection/windows_sigma.py`:

1. Recursively scans `.yml` and `.yaml` files.
2. Parses each rule with `yaml.safe_load`.
3. Stores `source_file` path in each loaded rule.

### 3.3 Sigma matching engine behavior

Main matching function: `check_if_event_matches_rule(...)` in `core/detection/windows_sigma.py`.

Implemented capabilities include:

1. Field mapping support (for example `EventID -> event_id`, `Channel -> channel`).
2. Access to normalized event fields and nested `event_data` keys.
3. Operators/modifiers:
   - equality
   - `|contains`, `|startswith`, `|endswith`, `|re`
   - `|all` semantics for text operators
4. Selection forms:
   - dictionary selection (all fields must match)
   - list selection (any item match)
5. Condition expression handling:
   - boolean `and` / `or` / `not`
   - `1 of pattern*` and `all of pattern*` style expansion

### 3.4 Sigma severity and risk mapping

`_sigma_severity_v2(...)` in `core/detection/windows_sigma.py` applies:

1. Base from Sigma `level` (`critical/high/medium/low`, fallback medium).
2. Risk-token upgrade of medium to high when tags/title indicate high-risk behavior.
   - Tokens include execution, persistence, credential access, lateral movement, PowerShell, ransomware, exploit patterns, etc.

### 3.5 MITRE ATT&CK enrichment

Module: `core/detection/mitre_mapping.py`

For each Sigma match:

1. Extract techniques from Sigma tags (for example `attack.t1059`).
2. If tags do not map, infer from event content + event ids + keyword mapping.
3. Add `mitre_techniques` and `mitre_tactics` to the match when available.

### 3.6 Where Sigma is invoked

Windows Sigma execution route:

- `POST /api/analysis/windows/run-sigma`
- Route module: `api/routes/windows_analysis.py`
- Internally loads Windows events from `normalized.json`, optionally time-filters, then calls:
  - `core/detection/windows_sigma.py -> run_sigma_pipeline(...)`
- Result is saved to:
  - `data/projects/<project_id>/uploads/<upload_id>/windows_sigma_matches.json`

Auxiliary Sigma endpoints include:

- List indexed rules: `GET /api/analysis/windows/sigma-rules`
- View rule YAML: `GET /api/analysis/windows/sigma-rules/view`
- Fetch results: `GET /api/analysis/windows/results`

## 4) Isolation Forest (Windows Behavioral ML): How It Is Implemented and Applied

### 4.1 Purpose

Isolation Forest is used to detect anomalous Windows activity windows (time buckets), not single events. It identifies periods with unusual event distribution patterns.

Main module: `core/behavioral/windows_ml.py`

### 4.2 Input and windowing

`run_windows_ml_analysis(...)` does the following:

1. Reads `normalized.json` with `ijson`.
2. Keeps only `server_type == windows_event`.
3. Applies optional `start_ts`/`end_ts` filter.
4. Buckets events into fixed windows (`window_minutes`, default 5).

### 4.3 Features used for the model

For each window, `_extract_features(...)` computes:

1. `event_count`
2. `unique_event_ids`
3. `security_events`
4. `system_events`
5. `powershell_events`
6. `unique_computers`
7. `unique_users`
8. `unique_source_ips`

### 4.4 Model behavior and fallback logic

- If scikit-learn is unavailable, or fewer than 20 windows exist:
  - No anomaly labeling is applied.
  - `anomaly_score = null`, `is_anomalous = false`, `anomaly_severity = low`.
  - Status indicates baseline/model limitation (`ok:insufficient_baseline` or `ok:sklearn_unavailable`).

- Otherwise:
  1. Features are standardized (`StandardScaler`).
  2. `IsolationForest(n_estimators=100, contamination=<validated>, random_state=42)` is trained.
  3. `decision_function` score + `predict` label are produced per window.
  4. Severity is assigned from score bands for anomalous windows.

Contamination is validated to `(0, 0.5)`, defaulting to `0.1` if out of range.

### 4.5 Where Isolation Forest is invoked

- Run endpoint:
  - `POST /api/analysis/windows/behavioral`
  - Route module: `api/routes/behavioral.py`
- Read results endpoint:
  - `GET /api/analysis/windows/behavioral/results`
- Correlated drill-down endpoints for selected windows:
  - `GET /api/analysis/windows/behavioral/window-events`
  - `GET /api/analysis/windows/behavioral/window-findings`

### 4.6 Isolation Forest output artifact

- File: `data/projects/<project_id>/uploads/<upload_id>/windows_ml_anomalies.json`
- Contains:
  - model metadata (`type`, contamination, scaling, min windows)
  - `windows[]` rows with anomaly score, anomaly flag, severity
  - totals: `total_windows`, `anomalous_windows`, `status`

## 5) Supporting Detection Modules in Windows Investigations

These modules enrich and operationalize Sigma and behavioral outputs:

1. IOC extraction
   - Module: `core/detection/ioc_extractor.py`
   - Extracts IPs, domains, hashes, suspicious file paths, users, and processes.
   - API endpoint: `GET /api/analysis/windows/iocs`

2. Event correlation and attack chain detection
   - Module: `core/detection/event_correlation.py`
   - Correlates matches using time window and shared attributes (computer, user, IP, process lineage).
   - Detects pattern classes like lateral movement, credential access, PowerShell chains, log clearing.
   - API endpoint: `GET /api/analysis/windows/correlation`

3. Export for reporting
   - Module: `core/export/windows_export.py`
   - Exports Sigma CSV, behavioral CSV, and forensic report text.

## 6) Project-Type Separation Rules (Important)

This project enforces strict detector separation in `core/detection/rule_pipeline.py`:

1. Web project:
   - CRS only
   - Writes unified `rule_matches.json`
2. Windows project:
   - Sigma only
   - Writes `windows_sigma_matches.json`
3. Windows behavioral ML is separate and writes `windows_ml_anomalies.json`

This separation prevents mixing detector logic across incompatible telemetry types.

## 7) Practical Notes for Extending These Implementations

1. CRS extension points
   - Add custom CRS rules under `data/crs_rules` (mounted into container).
   - Tune replay/concurrency using CRS env vars.

2. Sigma extension points
   - Add new YAML rules under `data/sigma_rules/...`.
   - For advanced Sigma constructs not currently handled, extend matcher logic in `core/detection/windows_sigma.py`.

3. Isolation Forest extension points
   - Add richer features (for example process entropy, rare event family counts).
   - Make contamination adaptive by upload size or baseline profile.
   - Add persisted baseline model training if long-term profiling is desired.

## 8) Key Artifacts Produced Per Upload

1. `intermediate.json` (raw parsed entries)
2. `normalized.json` (normalized records)
3. `rule_matches.json` (web/CRS unified matches)
4. `windows_sigma_matches.json` (windows/Sigma matches)
5. `windows_ml_anomalies.json` (windows Isolation Forest windows)
6. `behavioral_results.json` (web behavioral analysis, project-level output path)

This is the implementation state reflected in the current codebase as of 2026-04-16.
