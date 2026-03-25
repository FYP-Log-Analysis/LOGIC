import { apiGet, apiPost, apiDelete, apiUpload } from "./api";

export type ProjectType = "web" | "windows";

// ── Shared scope options ──────────────────────────────────────────────────────
export interface ScopeOpts {
  projectId?: string;
  uploadId?:  string;
  startTs?:   string;
  endTs?:     string;
}

function buildQuery(base: string, opts?: ScopeOpts & { limit?: number }): string {
  const params = new URLSearchParams();
  // Preserve existing query from base
  const [path, existing] = base.split("?");
  if (existing) new URLSearchParams(existing).forEach((v, k) => params.set(k, v));
  if (opts?.limit    != null)  params.set("limit",      String(opts.limit));
  if (opts?.projectId)          params.set("project_id", opts.projectId);
  if (opts?.uploadId)           params.set("upload_id",  opts.uploadId);
  if (opts?.startTs)            params.set("start_ts",   opts.startTs);
  if (opts?.endTs)              params.set("end_ts",     opts.endTs);
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

// ── Data (rule matches, normalized logs, CRS) ─────────────────────────────────

// ── Server-side aggregated endpoints (no client-side truncation) ──────────────

export interface OverviewData {
  total_logs: number;
  min_timestamp: string | null;
  max_timestamp: string | null;
  unique_ips: number;
  total_detections: number;
  unique_rules: number;
  severity_breakdown: Record<string, number>;
  top_ips: Array<{ client_ip: string; hit_count: number }>;
  top_rules: Array<{ rule_id: string; rule_title: string; severity: string; hit_count: number }>;
  hourly_timeline: Record<string, Record<string, number>>;
  attack_success_rate: number;
  recent_alerts: Array<{
    id: number; rule_id: string; rule_title: string; severity: string;
    client_ip: string; timestamp: string; method: string; path: string; status_code: number;
  }>;
}

export async function getOverviewData(opts?: ScopeOpts): Promise<OverviewData> {
  return apiGet<OverviewData>(buildQuery("api/search/overview", opts));
}

export interface DetectionAggregations {
  total_detections: number;
  severity_breakdown: Record<string, number>;
  top_rules: Array<{ rule_id: string; rule_title: string; severity: string; hit_count: number }>;
  top_ips: Array<{ client_ip: string; hit_count: number }>;
  top_paths: Array<{ path: string; hit_count: number }>;
  method_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  hourly_timeline: Record<string, Record<string, number>>;
}

export async function getDetectionAggregations(opts?: ScopeOpts): Promise<DetectionAggregations> {
  return apiGet<DetectionAggregations>(buildQuery("api/search/detection-aggregations", opts));
}

export interface LogStatistics {
  total_entries: number;
  unique_ips: number;
  hourly_heatmap: Record<string, number>;
  top_ips: Array<{ client_ip: string; request_count: number }>;
  top_paths: Array<{ request_path: string; count: number }>;
  top_user_agents: Array<{ user_agent: string; count: number }>;
  status_classes: Record<string, number>;
  bot_count: number;
  human_count: number;
}

export async function getLogStatistics(opts?: Pick<ScopeOpts, "projectId" | "uploadId">): Promise<LogStatistics> {
  return apiGet<LogStatistics>(buildQuery("api/logs/statistics", opts));
}

export async function getRuleMatches(opts?: ScopeOpts) {
  const data = await apiGet<{
    count: number;
    results: Array<{
      id?: number;
      rule_id?: string;
      rule_title?: string;
      severity?: string;
      client_ip?: string;
      method?: string;
      path?: string;
      status_code?: number;
      timestamp?: string;
      user_agent?: string;
    }>;
  }>(buildQuery("api/search/detections", { ...opts, limit: 50000 }));
  const results = data.results ?? [];
  return {
    total_matches: data.count,
    matched_rules: [...new Set(results.map((r) => r.rule_id).filter(Boolean))] as string[],
    matches: results.map((r) => ({
      rule_id: r.rule_id,
      rule_title: r.rule_title,
      severity: r.severity,
      client_ip: r.client_ip,
      method: r.method,
      path: r.path,
      status_code: r.status_code,
      timestamp: r.timestamp,
      tags: [] as string[],
    })),
  };
}

export interface GeoCountrySummary {
  country_code: string;
  country_name: string;
  detection_count: number;
  unique_ips: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export async function getGeoSummary(limit = 10, opts?: Pick<ScopeOpts, "projectId">) {
  return apiGet<{
    countries_impacted: number;
    total_detections: number;
    geolocated_detections: number;
    unknown_detections: number;
    coverage_pct: number;
    backfilled_ip_count: number;
    top_source_country: GeoCountrySummary | null;
    countries: GeoCountrySummary[];
    top_countries: GeoCountrySummary[];
  }>(buildQuery(`api/search/geography/summary`, { projectId: opts?.projectId, limit }));
}

// ── Analysis ─────────────────────────────────────────────────────────────────

export async function runAnalysis(params?: {
  mode?: string;
  project_id?: string;
  upload_id?: string;
  start_ts?: string;
  end_ts?: string;
}) {
  const mode = params?.mode ?? (params?.start_ts || params?.end_ts ? "manual" : "auto");
  return apiPost<{ run_id?: string; status?: string; [key: string]: unknown }>(
    "api/analysis/run",
    { ...params, mode },
  );
}

export async function getAnalysisRun(runId: string) {
  return apiGet<{ status?: string; [key: string]: unknown }>(
    `api/analysis/run/${runId}`,
  );
}

export async function getLatestAnalysisRun(projectId?: string, uploadId?: string) {
  return apiGet<{ status?: string; run_id?: string; [key: string]: unknown }>(
    buildQuery("api/analysis/latest", { projectId, uploadId }),
  );
}

export async function getLogTimeRange(projectId?: string) {
  return apiGet<{ min_timestamp?: string; max_timestamp?: string; total_logs?: number }>(
    buildQuery("api/logs/time-range", { projectId }),
  );
}

export async function getThreatInsights(projectId?: string) {
  return apiPost<{
    insights?: string;
    status?: string;
    [key: string]: unknown;
  }>(buildQuery("api/analysis/threat-insights", { projectId }));
}

export async function getInsightsStatus(projectId?: string) {
  return apiGet<{ status?: string; insights?: string; [key: string]: unknown }>(
    buildQuery("api/analysis/threat-insights/status", { projectId }),
  );
}

// ── Behavioral Analysis ───────────────────────────────────────────────────────

export interface BehavioralParams {
  rate_window_minutes?: number;
  rate_threshold?: number;
  enum_window_hours?: number;
  enum_threshold?: number;
  status_window_minutes?: number;
  status_error_ratio?: number;
  visitor_zscore?: number;
  start_ts?: string;
  end_ts?: string;
  project_id?: string;
}

export async function runBehavioralAnalysis(params?: BehavioralParams) {
  return apiPost<unknown>("api/analysis/behavioral", params ?? {});
}

export async function getBehavioralResults(opts?: Pick<ScopeOpts, "projectId">) {
  return apiGet<{
    request_rate_spikes?: unknown[];
    url_enumeration?: unknown[];
    status_code_spikes?: unknown[];
    visitor_rates?: unknown[];
    thresholds?: Record<string, number>;
  }>(buildQuery("api/analysis/behavioral/results", opts));
}

export async function getIpSummary(clientIp: string) {
  return apiGet<{
    client_ip: string;
    country_code: string | null;
    country_name: string;
    request_count: number;
    unique_paths: number;
    first_seen: string | null;
    last_seen: string | null;
    user_agents: Array<{ user_agent: string; count: number }>;
    status_distribution: Record<string, number>;
    top_paths: Array<{ request_path: string; count: number }>;
  }>(`api/search/ip-summary/${encodeURIComponent(clientIp)}`);
}

// ── Projects ─────────────────────────────────────────────────────────────────

export async function getProjects() {
  const result = await apiGet<
    | Array<{ id: string; name?: string; description?: string; status?: string; last_run_at?: string; project_type?: ProjectType }>
    | { projects: Array<{ id: string; name?: string; description?: string; status?: string; last_run_at?: string; project_type?: ProjectType }> }
  >("api/projects");
  const raw = Array.isArray(result)
    ? result
    : (result as unknown as { projects: Array<{ id: string; name?: string; description?: string; status?: string; last_run_at?: string; project_type?: ProjectType }> }).projects ?? [];

  return raw.map((project) => ({
    ...project,
    project_type: project.project_type === "windows" ? "windows" : "web",
  }));
}

export async function createProject(name: string, description = "", projectType: ProjectType = "web") {
  return apiPost<{ id?: string; project_id?: string; name?: string }>(
    "api/projects",
    { name, description, project_type: projectType },
  );
}

export async function deleteProject(projectId: string) {
  return apiDelete(`api/projects/${projectId}`);
}

export async function getProjectStats(projectId: string) {
  return apiGet<{ project_id: string; log_entries: number; detections: number }>(
    `api/projects/${projectId}/stats`,
  );
}

export async function getProjectUploads(projectId: string) {
  return apiGet<Array<{
    upload_id: string;
    filename?: string;
    stage?: string;
    status?: string;
    entry_count?: number;
    started_at?: string;
    updated_at?: string;
  }>>(`api/projects/${projectId}/uploads`);
}

export async function deleteProjectUpload(projectId: string, uploadId: string) {
  return apiDelete(`api/projects/${projectId}/uploads/${uploadId}`);
}

export async function generateProjectApiKey(projectId: string) {
  return apiPost<{ project_id: string; api_key: string }>(
    `api/projects/${projectId}/api-key`,
    {},
  );
}

export async function getProjectApiKey(projectId: string) {
  return apiGet<{ project_id: string; api_key: string | null }>(
    `api/projects/${projectId}/api-key`,
  );
}

export interface ProjectAgentConfig {
  project_id: string;
  log_paths: string[];
  effective_log_paths: string[];
  source: "custom" | "default";
  updated_at: string | null;
}

export async function getProjectAgentConfig(projectId: string, platform?: "windows" | "linux" | "macos") {
  const params = new URLSearchParams();
  if (platform) params.set("platform", platform);
  const qs = params.toString();
  const path = `api/projects/${projectId}/agent-config${qs ? `?${qs}` : ""}`;
  return apiGet<ProjectAgentConfig>(path);
}

export async function saveProjectAgentConfig(projectId: string, logPaths: string[]) {
  return apiPost<ProjectAgentConfig>(`api/projects/${projectId}/agent-config`, {
    log_paths: logPaths,
  });
}

export interface LiveAgentMonitorEvent {
  timestamp: number;
  message: string;
}

export interface LiveAgentMonitorData {
  project_id: string;
  status: "active" | "idle";
  uptime_seconds: number;
  last_batch_at: number | null;
  batch_count: number;
  total_logs: number;
  total_size_bytes: number;
  last_upload_id: string | null;
  validation_errors: LiveAgentMonitorEvent[];
  processing_errors: LiveAgentMonitorEvent[];
}

export async function getLiveAgentMonitor(projectId: string) {
  return apiGet<LiveAgentMonitorData>(`api/receiver/monitor?project_id=${encodeURIComponent(projectId)}`);
}

// ── Raw Logs ──────────────────────────────────────────────────────────────────

export interface RawLogEntry {
  timestamp?: string;
  client_ip?: string;
  http_method?: string;
  request_path?: string;
  query_string?: string;
  status_code?: number;
  response_size?: number;
  user_agent?: string;
  source?: string;
  [key: string]: unknown;
}

export async function getRawLogs(opts?: Pick<ScopeOpts, "projectId" | "uploadId"> & { limit?: number }): Promise<RawLogEntry[]> {
  return apiGet<RawLogEntry[]>(buildQuery("api/logs/entries", opts));
}

// ── Upload ────────────────────────────────────────────────────────────────────

export async function uploadFile(
  file: File,
  projectId: string,
  projectType: ProjectType,
  timeFrom?: string,
  timeTo?: string,
): Promise<{ upload_id: string; [key: string]: unknown }> {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("project_id", projectId);
  if (timeFrom) fd.append("time_from", timeFrom);
  if (timeTo)   fd.append("time_to",   timeTo);
  const endpoint = projectType === "windows" ? "api/upload/windows" : "api/upload";
  return apiUpload(endpoint, fd);
}

export async function getUploadStatus(uploadId: string) {
  return apiGet<{
    stage?: string;
    status?: string;
    entry_count?: number;
    error?: string;
  }>(`api/upload/status/${uploadId}`);
}

export async function getUploadLogs(uploadId: string) {
  return apiGet<{
    upload_id: string;
    lines: string[];
  }>(`api/upload/logs/${uploadId}`);
}

// ── Windows Analysis (Sigma + ML) ────────────────────────────────────────────

export async function runWindowsSigmaAnalysis(params?: {
  project_id?: string;
  upload_id?: string;
  start_ts?: string;
  end_ts?: string;
}) {
  return apiPost<{ run_id?: string; status?: string; [key: string]: unknown }>(
    "api/analysis/windows/run-sigma",
    { mode: "auto", ...params },
  );
}

export async function getWindowsSigmaResults(opts?: Pick<ScopeOpts, "projectId" | "uploadId">) {
  return apiGet<{
    matches: Array<{
      rule_id: string;
      rule_title: string;
      severity: string;
      computer: string;
      event_id: number | string;
      channel: string;
      timestamp: string;
      entry: Record<string, unknown>;
    }>;
    matched_rules: string[];
    total_matches: number;
    sigma_matches: number;
  }>(buildQuery("api/analysis/windows/results", opts));
}

export interface WindowsSigmaRuleSummary {
  rule_path: string;
  id: string;
  title: string;
  level: string;
  description: string;
  logsource: Record<string, unknown>;
}

export async function getWindowsSigmaRules() {
  return apiGet<{ rules: WindowsSigmaRuleSummary[]; count: number }>(
    "api/analysis/windows/sigma-rules",
  );
}

export async function getWindowsSigmaRuleDetail(rulePath: string) {
  return apiGet<{ rule: WindowsSigmaRuleSummary; yaml: string }>(
    `api/analysis/windows/sigma-rules/view?rule_path=${encodeURIComponent(rulePath)}`,
  );
}

export interface WindowsBehavioralResult {
  project_id: string;
  upload_id: string;
  window_minutes: number;
  total_windows: number;
  anomalous_windows: number;
  windows: Array<{
    window_start: string;
    event_count: number;
    unique_event_ids: number;
    security_events: number;
    system_events: number;
    powershell_events: number;
    unique_computers: number;
    unique_users: number;
    unique_source_ips: number;
    anomaly_score: number | null;
    is_anomalous: boolean;
  }>;
  status: string;
}

export async function runWindowsBehavioralAnalysis(params?: {
  window_minutes?: number;
  project_id?: string;
  upload_id?: string;
  start_ts?: string;
  end_ts?: string;
}) {
  return apiPost<{ status?: string; total_windows?: number; anomalous_windows?: number; [key: string]: unknown }>(
    "api/analysis/windows/behavioral",
    { window_minutes: 5, ...params },
  );
}

export async function getWindowsBehavioralResults(
  opts?: Pick<ScopeOpts, "projectId" | "uploadId">,
): Promise<WindowsBehavioralResult> {
  return apiGet<WindowsBehavioralResult>(buildQuery("api/analysis/windows/behavioral/results", opts));
}

// ── Admin ─────────────────────────────────────────────────────────────────────

export async function adminStats() {
  return apiGet<{
    total_users: number;
    total_projects: number;
    total_log_entries?: number;
    total_detections?: number;
  }>("api/admin/stats");
}

export async function adminListUsers() {
  return apiGet<
    Array<{
      id: number;
      username: string;
      role: string;
      is_active: boolean | number;
      email?: string;
    }>
  >("api/admin/users");
}

export async function adminCreateAnalyst(username: string, password: string) {
  return apiPost("api/auth/register", {
    username,
    password,
    email: `${username}@logic.local`,
  });
}

export async function adminSetUserActive(userId: number, isActive: boolean) {
  const action = isActive ? "activate" : "deactivate";
  return apiPost(`api/admin/users/${userId}/${action}`, {});
}

export async function adminDeleteUser(userId: number) {
  return apiDelete(`api/admin/users/${userId}`);
}
