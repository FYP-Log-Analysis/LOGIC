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

Unit testing validates the correctness of individual backend modules and functions in complete isolation. Each unit test runs against a single module with all external dependencies (database, LLM service, file I/O, and other modules) replaced by mocks or controlled fixtures. No running services or UI are required.

Unit testing scope boundary:

- **In scope**: Individual parsing functions, normalization logic, detection rule processors, IOC extractors, behavioral scoring, storage CRUD operations, and LLM service error handling — each tested independently.
- **Out of scope**: Multi-component workflows, UI interactions, end-to-end data flows, and any test requiring a live API or running database. Those belong to System Testing.

Unit test objectives:

1. Verify correct field mapping for Apache and EVTX/XML log normalization functions.
2. Verify CRS rule matching and Sigma detection logic against controlled sample inputs.
3. Verify IOC extraction deduplication and type tagging from mock detection sets.
4. Verify event correlation chain building within a configured time window using mock events.
5. Verify behavioural anomaly scoring module against a synthesised baseline event distribution.
6. Verify SQLite storage CRUD and project-scoped query isolation using a test database.
7. Verify LLM service fallback envelope when the provider returns a timeout or invalid response.

Unit test entry criteria:

1. Modules are implemented and importable without starting any service.
2. Representative sample data is available as static fixtures for web logs and Windows events.
3. All external dependencies are mockable and fixtures are prepared.

Unit test exit criteria:

1. Minimum 10 unit test cases are executed.
2. All critical-path modules pass with no unresolved blocking defect.
3. No unit test case requires a live service, running database, or browser.

## 4.1.2 SYSTEM TESTING, TEST PLAN

System testing validates complete, observable user workflows from the frontend UI through the API, async processing, storage, and output artifacts. All real services are active and no module-level mocking is applied. Each system test begins from a user action in the browser or a real HTTP client and ends with a verifiable output in the UI, the database, or a downloaded file.

System testing scope boundary:

- **In scope**: Login-to-dashboard navigation, file upload and async processing polling, analysis triggering, investigation views, filtering, export downloads, LLM chat interactions, agent ingestion, and multi-user data isolation — all verified through the running system.
- **Out of scope**: Internal function logic, data structure correctness, and module-level error handling. Those belong to Unit Testing.

System test objectives:

1. Validate that the platform is reachable and both the UI and API surfaces are operational.
2. Validate the full analyst login and session lifecycle through the browser UI.
3. Validate role-based access control by confirming rejection of unauthorized routes in the live system.
4. Validate that two separate user accounts cannot access each other's project data.
5. Validate the complete web log upload → async processing → investigation view workflow.
6. Validate the complete Windows EVTX upload → normalization → analysis view workflow.
7. Validate that web CRS detections and timeline widgets are populated correctly after analysis.
8. Validate that Windows Sigma detections and correlated chains appear correctly in the UI.
9. Validate the CSV export download workflow from investigation selections.
10. Validate the LLM-assisted analysis chat session from prompt submission to rendered response.

System test entry criteria:

1. API and frontend services are fully running (local dev or Docker Compose).
2. At least one analyst and one admin test account exist.
3. Sample web log file and EVTX file are available for upload.
4. Background processing is active and reachable.

System test exit criteria:

1. Minimum 10 system test cases are executed.
2. All end-to-end critical workflows pass without a blocking defect.
3. No unresolved high-severity issue remains in authentication, data isolation, or analysis paths.
4. Each test has concrete evidence: a UI screenshot, HTTP response, or downloaded output file.

## 4.2 UNIT TESTING

The following 10 unit test cases have been executed. All tests run against individual modules in isolation using static fixtures and mocked dependencies. No live service, database connection, or browser is involved at this level.

| Test ID | Module Under Test | What Is Isolated | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-01 | `core.processor.apache_norm` | All I/O mocked; only normalization logic tested | Single raw Apache access log line string with optional fields absent | All schema fields present with correct types and stable defaults for missing optionals | Schema dictionary returned with correct field mapping and `None` defaults for absent fields | Pass |
| UT-02 | `core.processor.evtx_norm` | XML parsing and field extraction tested without file I/O | Raw EVTX/XML record string with nested EventData block | EventID, channel, hostname, username, and process fields extracted to normalized schema | All target fields correctly extracted from nested XML into flat normalized dictionary | Pass |
| UT-03 | `core.processor.process_logs` | File reader mocked; error-handling logic isolated | Mixed list of 5 valid and 3 malformed log line strings | Malformed lines skipped; 5 valid records returned; no exception raised | Function returned exactly 5 valid records and logged 3 skip events without crashing | Pass |
| UT-04 | `core.detection.rule_pipeline` | CRS rule loader mocked with 3 representative rules | 4 normalized web events; 2 match CRS patterns | Returned hits contain rule ID, severity, confidence, and reference to source event | 2 hits returned with correct rule metadata; unmatched events produced no output | Pass |
| UT-05 | `core.detection.windows_sigma` | Sigma rule set mocked; no live rule loader | 3 normalized Windows events; 1 matches mocked Sigma rule | Rule match returned with rule title, severity, and mapped event reference | Match object returned with correct title and severity; 2 non-matching events omitted | Pass |
| UT-06 | `core.detection.ioc_extractor` | No external calls; pure extraction logic | List of 6 mock detection objects containing IPs, a domain, and a file hash | IOC list with unique entries, correct type tags (IP, domain, hash), no duplicates | 4 unique IOCs returned with correct types; duplicate IP correctly collapsed | Pass |
| UT-07 | `core.detection.event_correlation` | No storage calls; chain builder logic only | 4 mock Sigma match events within a 60-minute window sharing host and user fields | Events grouped into one chain with start/end time, event count, and highest severity | Single chain object returned with correct duration, severity escalation, and 2 correlation reasons | Pass |
| UT-08 | `core.behavioral.windows_ml` | No storage or model calls; scoring logic only | Synthesised event count time series with 1 outlier window exceeding z-score threshold | Outlier window flagged with threshold exceeded flag and contributing feature names | Anomaly window correctly identified; baseline windows not flagged | Pass |
| UT-09 | `core.storage.sqlite_store` | Uses in-memory SQLite test database; no shared state | Sequential insert, query by project ID, update, and delete operations | CRUD operations succeed; query returns only records scoped to the correct project ID | All four operations completed correctly; records from a second project ID were invisible in scoped query | Pass |
| UT-10 | `services.llm_service` | HTTP client mocked to simulate provider timeout and invalid JSON body | Two calls: first simulates timeout, second simulates malformed response | Both calls return a structured error envelope; no exception propagates to the caller | Safe error dictionaries returned for both failure modes; caller-level exception not raised | Pass |

Unit testing outcome summary:

1. Total executed unit test cases: 10
2. Layer boundary enforced: every test operates on one module with mocked dependencies — no live service or UI was used.
3. Execution status: Completed — all 10 cases passed.
4. Acceptance outcome: All critical backend modules verified at the function level.

## 4.3 SYSTEM TESTING

The following 10 system test cases validate complete, observable user workflows across the live LOGIC platform. All real services are active during execution (FastAPI backend, Next.js frontend, SQLite storage). Each test begins from a user action — browser navigation or a real HTTP request — and ends with a verifiable output in the UI, the database, or a downloaded file. No module-level mocking is applied.

> **How this differs from Unit Testing:** Unit tests verify that individual functions produce correct outputs from controlled inputs in isolation. System tests verify that a real user can complete a real workflow using the fully integrated running platform — they test the joins between components, not the components themselves.

| Test ID | Workflow Being Tested | User Actions Performed | Expected System Outcome | Actual Observed Outcome | Status |
|---|---|---|---|---|---|
| ST-01 | Platform startup and availability | Navigate to `localhost:3000` (UI) and `localhost:8000/docs` (API) in browser. | Both UI dashboard and API documentation pages load without errors. | UI dashboard rendered correctly; FastAPI docs page loaded and all routes were listed. | Pass |
| ST-02 | Analyst login and protected dashboard access | Enter analyst credentials in the login form and submit. Observe redirect and dashboard load. | Session established; analyst dashboard loads with project list visible. | Login succeeded; JWT session cookie set; dashboard rendered with correct project data. | Pass |
| ST-03 | Role-based access control enforcement | While logged in as Analyst, navigate directly to an admin-only URL (`/admin`). | System denies access and returns an authorization error to the user. | HTTP 403 returned; UI displayed access-denied message; no admin data was exposed. | Pass |
| ST-04 | Cross-user project data isolation | Log in as User A then as User B. Attempt to access User A's project via its direct URL as User B. | User B is denied access; User A's project data is not visible or loadable. | Project detail page returned empty state; API enforced ownership check; no data leaked. | Pass |
| ST-05 | Web log upload through to investigation view | Log in, create a web project, upload an Apache log file via the Upload & Process modal, wait for status completion, then open the Detections page. | Uploaded file is processed; CRS detections appear in the Detections table with severity labels. | Log file processed successfully; Detections table populated with flagged entries and severity buckets. | Pass |
| ST-06 | Windows EVTX upload through to analysis view | Log in, create a Windows project, upload an EVTX file, wait for completion, then open the Analysis page. | EVTX records are processed; normalized events and Sigma detections appear in the Analysis view. | EVTX file parsed correctly; Windows events appeared in the Analysis view with rule match labels. | Pass |
| ST-07 | Detection timeline and overview consistency | After web analysis (ST-05), open the Overview page and the Timeline widget, then switch between severity filters. | Timeline chart and overview metrics update correctly and remain consistent with filter selection. | Overview counts matched detection table; timeline chart updated correctly on filter change. | Pass |
| ST-08 | Investigation filtering and search | On the Detections page, apply a time range filter and a severity filter simultaneously. Check that results update and pagination works. | Only detections within the selected time range and severity appear; page navigation is consistent. | Results correctly narrowed to selected range and severity; pagination returned correct subsets. | Pass |
| ST-09 | CSV export download | On the Detections page, select investigation results and click Export to CSV. | A CSV file is downloaded to the browser with the expected columns and non-empty rows. | CSV file downloaded successfully; file contained correct column headers and populated rows. | Pass |
| ST-10 | LLM analysis chat session | On the Analysis page, type a question into the chat widget (e.g., "Summarise the top threats") and submit. | The chat interface displays a relevant insight response without errors or timeouts. | LLM response streamed successfully to the chat UI; response referenced project-relevant detection context. | Pass |

System testing outcome summary:

1. Total executed system test cases: 10
2. Layer boundary enforced: every test was performed against the real running system through the browser or live HTTP client — no mocking was applied.
3. Coverage attained: platform availability, authentication, role-based access control, data isolation, web and Windows ingestion pipelines, detection views, filtering, CSV export, and LLM chat.
4. Execution status: Completed — all 10 cases passed.
5. Evidence: Each test verified by observable UI state, live API HTTP response, or downloaded output file.

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

Chapter 4 defines a two-level testing baseline of 10 unit tests and 10 system tests, with a strict layer boundary between them. Unit tests validate individual module correctness in isolation; system tests validate observable end-to-end user workflows on the live platform. This separation ensures that defects are localised accurately — a unit test failure indicates a module-level bug, while a system test failure indicates an integration, workflow, or environment issue. Together they provide a dependable foundation for regression safety and future scalability.

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
