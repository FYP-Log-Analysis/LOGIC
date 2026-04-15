# CHAPTER 4: TESTING AND ANALYSIS

## 4.1 TEST PLAN

The updated LOGIC testing strategy validates both implementation correctness and full workflow reliability across all major platform tools. Testing is split into two levels:

1. Unit testing to verify individual modules, functions, and API behaviors in isolation.
2. System testing to validate end-to-end user and platform workflows in an integrated environment.

The test environment uses local development execution with FastAPI backend, Next.js frontend, SQLite storage, project-scoped runtime data, and optional containerized deployment.

Practical distinction used in this report:

1. Unit testing: validates one function, class, or route contract in isolation using mocks/fixtures and controlled inputs.
2. System testing: validates a complete business workflow across multiple real components (UI, API, async processing, storage, and output artifacts).
3. Unit test failures usually point to a local implementation defect; system test failures usually point to integration, orchestration, data-flow, or environment defects.

Main coverage areas in this plan:

1. Authentication and authorization flows.
2. Project lifecycle and data isolation controls.
3. Web and Windows ingestion paths.
4. Normalization pipelines (Apache, EVTX/XML).
5. Detection engines (CRS and Sigma).
6. Event correlation and IOC extraction.
7. Behavioral analysis modules.
8. Search, overview, and timeline data retrieval.
9. Export and reporting routes.
10. Agent download and receiver ingest workflows.
11. LLM-assisted analysis/chat services.
12. Persistence and recovery behavior.
13. Error handling and resilience paths.
14. Deployment smoke validation.

## 4.1.1 UNIT TESTING, TEST PLAN

Unit testing focuses on deterministic validation of module-level logic and route-level behavior with mocks, fixtures, and controlled sample payloads.

Planned unit test objectives:

1. Verify ingestion, parsing, and normalization behavior for both telemetry domains.
2. Verify detection, correlation, IOC extraction, and behavioral analytics outputs.
3. Verify API schema validation, auth rules, and route response contracts.
4. Verify service dependencies (storage and LLM service) under success and failure conditions.

Unit test entry criteria:

1. Modules are implemented and importable.
2. Representative sample data is available for web logs and Windows events.
3. Required environment variables are configured.
4. Test fixtures and dependency mocks are prepared.

Unit test exit criteria:

1. Minimum 14 planned unit tests are implemented and executed.
2. Critical-path modules have no unresolved blocking defect.
3. API contract assertions pass for required route-level tests.

## 4.1.2 SYSTEM TESTING, TEST PLAN

System testing validates complete user-visible and operator-visible workflows from login to investigation output, including runtime resilience.
Unlike unit tests, system tests run integrated service paths without module-level mocking and verify cross-component behavior.

Planned system test objectives:

1. Validate role-aware user journeys across frontend navigation, API authorization, and persisted session state.
2. Validate asynchronous ingest-to-analysis workflows for web and Windows telemetry across upload, queue/status polling, normalization, and persistence.
3. Validate analyst investigation workflows (overview, search, detail inspection, timeline, and export) using generated project data.
4. Validate operational reliability behaviors including invalid-input containment, restart recovery, and agent-assisted ingestion.

System test entry criteria:

1. API and frontend services are running.
2. Test users and at least one web and one Windows project are available.
3. Sample uploads, rulesets, and agent credentials are accessible.
4. Background processing paths are enabled (task polling/worker behavior reachable in current runtime mode).
5. Optional docker compose environment is available for deployment smoke testing.

System test exit criteria:

1. Minimum 12 planned system tests are executed.
2. End-to-end critical workflows pass without blocking defect.
3. No unresolved high-severity issue remains in authentication, analysis, data isolation, or recovery paths.
4. Each executed workflow has reproducible evidence (API responses, persisted output checks, and/or UI verification artifacts).

## 4.2 UNIT TESTING

The following updated 14 unit test cases cover all major backend tools and core processing modules.

| Test ID | Module / Component | Test Scenario | Expected Result | Status |
|---|---|---|---|---|
| UT-01 | core.processor.apache_norm | Normalize Apache access log line with optional fields | Structured schema fields are mapped correctly with stable defaults | Planned |
| UT-02 | core.processor.evtx_norm | Normalize EVTX/XML record with nested event data | Event ID, channel, host, user, and process fields map to normalized schema | Planned |
| UT-03 | core.processor.process_logs | Process malformed web lines mixed with valid lines | Invalid records are skipped/flagged and pipeline continues without crash | Planned |
| UT-04 | core.ingestion.ingest_logs | Route file type to correct parser by project type | Correct ingest path is selected and unsupported type returns validation error | Planned |
| UT-05 | core.detection.rule_pipeline | Apply CRS rules to representative suspicious request set | Rule hits include rule id, severity, confidence, and source event linkage | Planned |
| UT-06 | core.detection.windows_sigma | Execute Sigma matching on normalized Windows events | Matching rules return expected metadata and mapped severity | Planned |
| UT-07 | core.detection.ioc_extractor | Extract IOC values from mixed detections | IP, domain, URL, and hash indicators are deduplicated and typed correctly | Planned |
| UT-08 | core.detection.event_correlation | Build attack chains within configured time window | Related events are grouped with correlation reasons and chain severity | Planned |
| UT-09 | core.behavioral.windows_ml | Score anomaly windows from baseline event distribution | Outlier windows cross threshold and include contributing features | Planned |
| UT-10 | core.storage.sqlite_store | Persist, query, and update project-scoped analysis output | CRUD operations are consistent and project scoping is enforced | Planned |
| UT-11 | services.llm_service | Handle provider timeout or invalid model response | Service returns safe fallback/error envelope without API crash | Planned |
| UT-12 | api.routes.auth | Login token issuance and invalid credential rejection | Valid login returns token; invalid login returns expected auth error | Planned |
| UT-13 | api.routes.upload | Upload request validation and async status contract | Valid upload returns task metadata; invalid payload returns 4xx schema error | Planned |
| UT-14 | api.routes.search | Multi-filter detection search with pagination | Filtered subset and counts are correct and deterministic across pages | Planned |

Unit testing outcome summary:

1. Total planned unit test cases: 14
2. Coverage target: all critical modules listed in Section 4.1
3. Execution status: planned for current validation cycle
4. Acceptance target: 100% pass on critical-path cases

## 4.3 SYSTEM TESTING

The following updated 12 system test cases validate integrated workflows across backend, frontend, storage, agent tooling, and deployment.
Each case is defined as a full workflow traversal, not as a single-module behavior check.

| Test ID | End-to-End Workflow | Integration Boundary Traversed | Test Scenario | Expected Result | Status |
|---|---|---|---|---|---|
| ST-01 | Platform startup and health | Frontend runtime -> API service -> route registry/docs | Start API and frontend, then validate root and docs endpoints | Services are reachable and operational health is confirmed | Planned |
| ST-02 | Authenticated analyst login | Login UI -> auth route -> token/session -> protected dashboard API | Login from UI and access protected dashboard route | Session is established and protected pages load with authorized data | Planned |
| ST-03 | Authorization enforcement | Analyst token -> admin route guard -> HTTP error handling | Analyst account invokes admin-only endpoint | Access is denied with correct authorization response and no privilege escalation | Planned |
| ST-04 | Multi-project isolation workflow | User/project identity context -> API queries -> dashboard rendering | Create two projects under different user identities and open project detail pages | Projects render correctly and cross-project data leakage does not occur | Planned |
| ST-05 | Web telemetry ingest to query | Upload UI/API -> ingest route -> normalization -> storage -> search endpoint | Upload Apache/Nginx logs and poll processing status until completion | Upload completes and normalized web events are queryable from investigation views | Planned |
| ST-06 | Windows telemetry ingest to query | Upload UI/API -> EVTX/XML parsing -> normalization -> storage -> analysis route | Upload EVTX/XML telemetry and poll processing status until completion | Windows records ingest and persist without blocking errors and are available for analysis | Planned |
| ST-07 | Web detection investigation | Analysis trigger -> CRS engine -> persisted detections -> dashboard/timeline widgets | Run web analysis and open detections view | Detections, severity buckets, and timeline widgets are populated consistently | Planned |
| ST-08 | Windows detection and chaining | Analysis trigger -> Sigma matching -> correlation engine -> detail panel schema | Run Sigma analysis and inspect correlated output | Sigma matches and correlated chains are returned with expected fields and severities | Planned |
| ST-09 | Analyst filtering workflow | UI filters -> search/overview routes -> pagination/state synchronization | Apply filters and time ranges in overview/search pages | Counts, tables, and detail panels remain consistent across navigation and pagination | Planned |
| ST-10 | Export artifact workflow | Investigation selections -> export route -> file generation -> download path | Trigger CSV/report export for investigation artifacts | Export files are generated, downloadable, and non-empty with expected columns | Planned |
| ST-11 | LLM-assisted triage workflow | Chat UI -> analysis route -> LLM service wrapper -> response rendering | Submit analyst question via analysis chat interface | Insight response returns without API failure and includes project-relevant context | Planned |
| ST-12 | Agent ingestion with recovery | Agent download route -> receiver ingest -> persistence -> restart -> re-ingest | Download agent artifact, submit ingest payload with API key, then re-run after service restart | Failed/invalid ingest is contained and subsequent valid ingest succeeds after recovery | Planned |

System testing outcome summary:

1. Total planned system test cases: 12
2. Coverage target: authentication, authorization, ingestion pipelines, analytics, exports, agent tooling, isolation, and resilience
3. Execution status: planned for integrated validation cycle
4. Acceptance target: no high-severity blocker in end-to-end workflows
5. Evidence target: each case includes at least one integration proof point (UI state, API contract, and stored-result verification)

## 4.4 CRITICAL ANALYSIS

The updated testing scope indicates that LOGIC has broad and balanced verification coverage for core detection and investigation workflows across web and Windows telemetry processing.

Key strengths identified:

1. Clear project-scoped workflow design reduced cross-project data leakage risk.
2. Asynchronous processing model improved reliability for long-running analysis tasks.
3. Separation of concerns across ingestion, normalization, detection, and export modules improved testability.
4. API contract coverage is broad, enabling predictable integration with frontend and agents.

Observed limitations and risks:

1. Runtime storage on SQLite is suitable for local-first operation but can become a bottleneck under high concurrency.
2. LLM-dependent features (for example threat insights and event explanations) can vary by model availability and response latency.
3. Rule quality (CRS/Sigma) directly impacts detection precision and may require continuous tuning.
4. Test evidence currently emphasizes functional behavior; non-functional testing (load, stress, long-duration soak, and security hardening) should be expanded.

Recommended improvements:

1. Add automated CI pipelines for unit and API integration tests with coverage thresholds.
2. Introduce performance and load testing for upload, search, and analysis endpoints.
3. Expand negative and adversarial test datasets for parser robustness and rule validation.
4. Add formal regression test packs for each release cycle, especially for route changes and detection logic updates.

Conclusion:

The updated Chapter 4 test plan defines a minimum validation baseline of 14 unit tests and 12 system tests, covering all primary project tools and workflows. This provides a dependable foundation for controlled execution, regression safety, and future scaling and security hardening.

## 4.5 HOW EVENTS ARE CORRELATED IN LOGIC PROJECTS (WINDOWS AND WEB SERVER LOGS)

### A. Windows log event correlation

In Windows projects, LOGIC performs explicit attack-chain correlation from Sigma detection matches.

Correlation flow:

1. Sigma matches are loaded and sorted by event timestamp.
2. Events are compared inside a configurable time window (default 60 minutes).
3. Two events are considered related when at least two linkage signals match.

Linkage signals used:

1. Same computer host.
2. Same authenticated user.
3. Same source IP address.
4. Process lineage relation (for example parent-child process ID link).
5. Same process ID across events.

If related events are found within the time window, they are grouped into one chain with:

1. Chain start and end time.
2. Event count and duration.
3. Involved computers and users.
4. Correlation reasons.
5. Chain severity (upgraded to the highest severity found in that chain).

In addition to chain building, LOGIC tags higher-level Windows attack patterns such as:

1. Lateral movement (RDP plus SMB combinations).
2. Credential access patterns (for example LSASS or credential-dumping indicators).
3. PowerShell execution chains.
4. Audit log tampering or clearing behavior.

### B. Web server log event correlation

In web projects, LOGIC does not use the same explicit chain-building model used for Windows Sigma events. Instead, it correlates activity through behavioral and detection aggregations across time, source IP, and request attributes.

Web correlation flow:

1. CRS detections are aggregated by severity, rule, source IP, path, method, status class, and hourly timeline.
2. A unique flagged web event is identified using the tuple: timestamp + client_ip + method + path.
3. Behavioral analysis merges per-upload statistical buckets and detects anomaly patterns.

Behavioral linkage dimensions:

1. Request-rate spikes by client IP in minute windows.
2. URL enumeration by client IP in hour windows (many distinct paths).
3. Status-code anomaly windows (high 4xx/5xx error ratio).
4. Visitor-rate anomalies (z-score based hourly deviation).

Interpretation:

1. Windows correlation is chain-based and relationship-driven (entity and process links).
2. Web correlation is aggregation-based and behavior-driven (traffic and anomaly patterns).
3. Together, this dual model gives LOGIC both forensic sequencing for Windows attacks and campaign-level behavioral detection for web traffic attacks.
