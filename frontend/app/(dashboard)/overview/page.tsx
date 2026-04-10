"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import {
  getLogStatistics,
  getLiveAgentMonitor,
  getRawLogs,
  getWindowsSigmaRuleDetail,
  getWindowsSigmaRules,
  type LiveAgentMonitorData,
  type LogStatistics,
  type RawLogEntry,
  type WindowsSigmaRuleSummary,
} from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { SectionHeader, MetricCard, Divider, Spinner, Btn } from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import PieChart from "@/components/charts/pie-chart";

function heatColor(count: number, maxCount: number): string {
  if (maxCount === 0 || count === 0) return "#111";
  const ratio = count / maxCount;
  if (ratio > 0.75) return "#7c2020";
  if (ratio > 0.5) return "#5a3010";
  if (ratio > 0.25) return "#3a3010";
  return "#1a2a18";
}

function formatUptime(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${h}h ${m}m ${s}s`;
}

export default function OverviewPage() {
  const [stats, setStats] = useState<LogStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [monitor, setMonitor] = useState<LiveAgentMonitorData | null>(null);
  const [rawLogs, setRawLogs] = useState<RawLogEntry[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [logFilter, setLogFilter] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [sigmaRuleCatalog, setSigmaRuleCatalog] = useState<WindowsSigmaRuleSummary[]>([]);
  const [sigmaRuleLoading, setSigmaRuleLoading] = useState(false);
  const [sigmaRuleError, setSigmaRuleError] = useState<string | null>(null);
  const [ruleViewLoading, setRuleViewLoading] = useState(false);
  const [selectedRule, setSelectedRule] = useState<{ rule: WindowsSigmaRuleSummary; yaml: string } | null>(null);
  const { activeProject } = useAuthStore();
  const isWindowsProject = activeProject?.project_type === "windows";
  const PAGE_SIZE = 50;

  const loadData = useCallback(() => {
    if (!activeProject?.id) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    getLogStatistics({ projectId: activeProject.id })
      .then((d) => setStats(d))
      .catch((e) => {
        setStats(null);
        setError(e instanceof Error ? e.message : "Failed to load log statistics.");
      })
      .finally(() => setLoading(false));
  }, [activeProject]);

  const loadSigmaRules = useCallback(() => {
    if (!isWindowsProject) {
      setSigmaRuleCatalog([]);
      setSigmaRuleLoading(false);
      setSigmaRuleError(null);
      return;
    }

    setSigmaRuleLoading(true);
    setSigmaRuleError(null);
    getWindowsSigmaRules()
      .then((catalog) => setSigmaRuleCatalog(catalog.rules || []))
      .catch((e) => {
        setSigmaRuleCatalog([]);
        setSigmaRuleError(e instanceof Error ? e.message : "Failed to load Sigma rules.");
      })
      .finally(() => setSigmaRuleLoading(false));
  }, [isWindowsProject]);

  const loadLiveWindow = useCallback(async (silent = false) => {
    if (!activeProject?.id) {
      setMonitor(null);
      setRawLogs([]);
      return;
    }

    if (!silent) {
      setLogsLoading(true);
      setLiveError(null);
    }

    try {
      const logsPromise = isWindowsProject
        ? getRawLogs({ projectId: activeProject.id, limit: 500, liveOnly: true })
        : getRawLogs({ projectId: activeProject.id, limit: 500, liveOnly: true, excludeWindows: true });

      const [monitorData, logs] = await Promise.all([
        getLiveAgentMonitor(activeProject.id),
        logsPromise,
      ]);

      setMonitor(monitorData);
      if (isWindowsProject) {
        const windowsOnly = logs.filter((entry) => {
          const serverType = String(entry.server_type ?? "").toLowerCase();
          return serverType === "windows_event" || serverType.includes("windows");
        });
        setRawLogs(windowsOnly.length > 0 ? windowsOnly : logs);
      } else {
        setRawLogs(
          logs.filter((entry) => {
            const serverType = String(entry.server_type ?? "").toLowerCase();
            return !(serverType === "windows_event" || serverType.includes("windows"));
          }),
        );
      }
      setLiveError(null);
    } catch (e) {
      if (!silent) {
        setRawLogs([]);
      }
      setLiveError(e instanceof Error ? e.message : "Failed to load live agent telemetry.");
    } finally {
      if (!silent) {
        setLogsLoading(false);
      }
    }
  }, [activeProject?.id, isWindowsProject]);

  const openRuleView = useCallback(async (rulePath: string) => {
    setRuleViewLoading(true);
    try {
      const detail = await getWindowsSigmaRuleDetail(rulePath);
      setSelectedRule(detail);
    } catch (e) {
      setSigmaRuleError(e instanceof Error ? e.message : "Failed to load Sigma rule details.");
    } finally {
      setRuleViewLoading(false);
    }
  }, []);

  const sigmaRulesByFolder = useMemo(() => {
    const grouped = new Map<string, WindowsSigmaRuleSummary[]>();
    for (const rule of sigmaRuleCatalog) {
      const rawPath = (rule.rule_path || "").replace(/\\/g, "/").replace(/^\/+/, "");
      const lastSlash = rawPath.lastIndexOf("/");
      const folder = lastSlash > -1 ? rawPath.slice(0, lastSlash) : "(root)";
      const bucket = grouped.get(folder) ?? [];
      bucket.push(rule);
      grouped.set(folder, bucket);
    }

    return Array.from(grouped.entries())
      .map(([folder, rules]) => ({
        folder,
        rules: [...rules].sort((a, b) => (a.rule_path || "").localeCompare(b.rule_path || "")),
      }))
      .sort((a, b) => a.folder.localeCompare(b.folder));
  }, [sigmaRuleCatalog]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      loadData();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadData]);

  useEffect(() => {
    loadSigmaRules();
  }, [loadSigmaRules]);

  useEffect(() => {
    if (!activeProject?.id) return;

    let cancelled = false;
    loadLiveWindow(false);

    const id = window.setInterval(async () => {
      if (cancelled) return;
      await loadLiveWindow(true);
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [activeProject?.id, loadLiveWindow]);

  const filteredLogs = useMemo(() => {
    if (!logFilter.trim()) return rawLogs;
    const q = logFilter.toLowerCase();
    if (isWindowsProject) {
      return rawLogs.filter((l) => {
        const eventId = String((l as Record<string, unknown>).event_id ?? "");
        const channel = String((l as Record<string, unknown>).channel ?? "").toLowerCase();
        const computer = String((l as Record<string, unknown>).computer ?? "").toLowerCase();
        const user = String((l as Record<string, unknown>).auth_user ?? "").toLowerCase();
        const raw = String((l as Record<string, unknown>).raw ?? "").toLowerCase();
        return (
          (l.client_ip ?? "").toLowerCase().includes(q) ||
          eventId.includes(q) ||
          channel.includes(q) ||
          computer.includes(q) ||
          user.includes(q) ||
          raw.includes(q)
        );
      });
    }
    return rawLogs.filter((l) =>
      (l.client_ip ?? "").toLowerCase().includes(q) ||
      (l.request_path ?? "").toLowerCase().includes(q) ||
      (l.http_method ?? "").toLowerCase().includes(q) ||
      String(l.status_code ?? "").includes(q) ||
      (l.user_agent ?? "").toLowerCase().includes(q),
    );
  }, [rawLogs, logFilter, isWindowsProject]);

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / PAGE_SIZE));
  const pageStart = (currentPage - 1) * PAGE_SIZE;
  const pagedLogs = filteredLogs.slice(pageStart, pageStart + PAGE_SIZE);

  useEffect(() => {
    setCurrentPage(1);
  }, [activeProject?.id, logFilter]);

  useEffect(() => {
    if (currentPage > totalPages) setCurrentPage(totalPages);
  }, [currentPage, totalPages]);

  const refreshOverview = useCallback(() => {
    loadData();
    void loadLiveWindow(false);
  }, [loadData, loadLiveWindow]);

  const liveSection = (
    <>
      <div className="section-block">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
            gap: 12,
          }}
        >
          <MetricCard
            label="Agent Status"
            value={(monitor?.status ?? "idle").toUpperCase()}
            accent={monitor?.status === "active" ? "#70d08c" : "#c5b27b"}
          />
          <MetricCard
            label="Uptime"
            value={formatUptime(monitor?.uptime_seconds ?? 0)}
            sub={monitor?.last_batch_at ? `Last batch ${new Date(monitor.last_batch_at * 1000).toLocaleString()}` : "No batches yet"}
          />
          <MetricCard label="Total Live Logs" value={(monitor?.total_logs ?? 0).toLocaleString()} />
          <MetricCard label="Last Host" value={monitor?.last_host || "—"} />
        </div>
      </div>

      <div className="section-block">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
          <div style={{ fontSize: 11, letterSpacing: 1.2, textTransform: "uppercase", color: "#888" }}>
            Incoming Raw Logs
            {rawLogs.length > 0 && (
              <span style={{ color: "#444", marginLeft: 8 }}>
                showing {Math.min(pageStart + PAGE_SIZE, filteredLogs.length).toLocaleString()} of {filteredLogs.length.toLocaleString()} filtered ({rawLogs.length.toLocaleString()} total)
              </span>
            )}
          </div>
          <Btn onClick={() => void loadLiveWindow(false)} style={{ marginLeft: "auto" }}>Refresh Live Logs</Btn>
          {rawLogs.length > 0 && (
            <input
              type="text"
              placeholder={isWindowsProject ? "Filter by event id, channel, computer, user, IP..." : "Filter by IP, path, method, status, user-agent..."}
              value={logFilter}
              onChange={(e) => setLogFilter(e.target.value)}
              style={{
                background: "#0d0d0d",
                border: "1px solid #2a2a2a",
                borderRadius: 4,
                color: "#ccc",
                fontSize: 11,
                fontFamily: "monospace",
                padding: "5px 10px",
                outline: "none",
                width: 320,
              }}
            />
          )}
        </div>

        {liveError && (
          <div style={{ color: "#ff8a80", fontSize: 12, marginBottom: 10 }}>
            {liveError}
          </div>
        )}

        {logsLoading ? (
          <div style={{ textAlign: "center", padding: 24 }}><Spinner size={18} /></div>
        ) : rawLogs.length === 0 ? (
          <div style={{ color: "#444", fontSize: 12, border: "1px dashed #1e1e1e", borderRadius: 4, padding: 20 }}>
            No log entries available. Upload logs or connect the agent to populate this view.
          </div>
        ) : filteredLogs.length === 0 ? (
          <div style={{ color: "#444", fontSize: 12, border: "1px dashed #1e1e1e", borderRadius: 4, padding: 20 }}>
            No entries match the current filter.
          </div>
        ) : (
          <>
            <div style={{ overflowX: "auto", border: "1px solid #1e1e1e", borderRadius: 4 }}>
              {isWindowsProject ? (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "monospace" }}>
                  <thead>
                    <tr style={{ background: "#0d0d0d" }}>
                      {["#", "Time", "Event ID", "Channel", "Computer", "User", "IP"].map((col) => (
                        <th
                          key={col}
                          style={{
                            textAlign: "left",
                            padding: "8px 12px",
                            borderBottom: "1px solid #1e1e1e",
                            color: "#555",
                            fontWeight: 600,
                            letterSpacing: 0.8,
                            whiteSpace: "nowrap",
                          }}
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {pagedLogs.map((entry, idx) => {
                      const absoluteIdx = pageStart + idx;
                      const eventId = (entry as Record<string, unknown>).event_id;
                      const channel = (entry as Record<string, unknown>).channel;
                      const computer = (entry as Record<string, unknown>).computer;
                      const authUser = (entry as Record<string, unknown>).auth_user;
                      return (
                        <tr
                          key={`${entry.timestamp ?? ""}-${absoluteIdx}`}
                          style={{ borderBottom: "1px solid #141414", background: idx % 2 === 0 ? "transparent" : "#0a0a0a" }}
                        >
                          <td style={{ padding: "6px 12px", color: "#333", minWidth: 40 }}>{absoluteIdx + 1}</td>
                          <td style={{ padding: "6px 12px", color: "#555", whiteSpace: "nowrap" }}>
                            {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#f0c040", whiteSpace: "nowrap" }}>
                            {eventId != null ? String(eventId) : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#8fb9ff", whiteSpace: "nowrap" }}>
                            {channel != null && String(channel) ? String(channel) : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#e8e8e8", whiteSpace: "nowrap" }}>
                            {computer != null && String(computer) ? String(computer) : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#6ecb9e", whiteSpace: "nowrap" }}>
                            {authUser != null && String(authUser) ? String(authUser) : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#60a5fa", whiteSpace: "nowrap" }}>
                            {entry.client_ip ?? "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "monospace" }}>
                  <thead>
                    <tr style={{ background: "#0d0d0d" }}>
                      {["#", "Time", "Method", "Path", "Status", "IP", "User-Agent"].map((col) => (
                        <th
                          key={col}
                          style={{
                            textAlign: "left",
                            padding: "8px 12px",
                            borderBottom: "1px solid #1e1e1e",
                            color: "#555",
                            fontWeight: 600,
                            letterSpacing: 0.8,
                            whiteSpace: "nowrap",
                          }}
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {pagedLogs.map((entry, idx) => {
                      const absoluteIdx = pageStart + idx;
                      const sc = entry.status_code ?? 0;
                      const statusColor =
                        sc >= 500 ? "#ff4444" :
                        sc >= 400 ? "#ff8800" :
                        sc >= 300 ? "#f0c040" :
                        sc >= 200 ? "#4caf50" : "#666";
                      const path = entry.request_path ?? "";
                      const ua = entry.user_agent ?? "";
                      return (
                        <tr
                          key={`${entry.timestamp ?? ""}-${absoluteIdx}`}
                          style={{ borderBottom: "1px solid #141414", background: idx % 2 === 0 ? "transparent" : "#0a0a0a" }}
                        >
                          <td style={{ padding: "6px 12px", color: "#333", minWidth: 40 }}>{absoluteIdx + 1}</td>
                          <td style={{ padding: "6px 12px", color: "#555", whiteSpace: "nowrap" }}>
                            {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#a78bfa", whiteSpace: "nowrap" }}>
                            {entry.http_method ?? "—"}
                          </td>
                          <td
                            style={{
                              padding: "6px 12px",
                              color: "#e8e8e8",
                              maxWidth: 320,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                            title={path}
                          >
                            {path || "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: statusColor, whiteSpace: "nowrap" }}>
                            {sc || "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#60a5fa", whiteSpace: "nowrap" }}>
                            {entry.client_ip ?? "—"}
                          </td>
                          <td
                            style={{
                              padding: "6px 12px",
                              color: "#555",
                              maxWidth: 260,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                            title={ua}
                          >
                            {ua || "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 10 }}>
              <div style={{ color: "#555", fontSize: 11 }}>
                Page {currentPage} of {totalPages}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <Btn variant="ghost" onClick={() => setCurrentPage((p) => Math.max(1, p - 1))} disabled={currentPage <= 1}>
                  PREVIOUS 50
                </Btn>
                <Btn variant="ghost" onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))} disabled={currentPage >= totalPages}>
                  NEXT 50
                </Btn>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );

  if (!activeProject?.id) {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
        Select a project from the sidebar to view this page.
      </div>
    );
  }

  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: 60 }}>
        <Spinner size={28} />
      </div>
    );
  }

  const hasStats = !!stats && (
    stats.total_entries > 0 ||
    stats.unique_ips > 0 ||
    stats.top_ips.length > 0 ||
    stats.top_paths.length > 0 ||
    Object.values(stats.status_classes).some((count) => count > 0) ||
    Object.values(stats.hourly_heatmap).some((count) => count > 0)
  );

  if (!hasStats || !stats) {
    return (
      <div>
        <SectionHeader title="Overview" subtitle="Operational log baseline and request behavior snapshot" />
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <Btn onClick={refreshOverview} style={{ marginLeft: "auto" }}>Refresh</Btn>
        </div>
        <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
          {error ?? "No log statistics are available for this project yet."}
        </div>
        <Divider />
        {liveSection}
      </div>
    );
  }

  const {
    total_entries,
    unique_ips,
    hourly_heatmap,
    top_ips,
    top_paths,
    status_classes,
    bot_count,
    human_count,
  } = stats;

  const hourCounts = Array.from({ length: 24 }, (_, h) => hourly_heatmap[h] ?? hourly_heatmap[String(h)] ?? 0);
  const maxHour = Math.max(...hourCounts, 1);
  const hasTimestamps = hourCounts.some((c) => c > 0);

  const statusColors: Record<string, string> = {
    "2xx": "#4caf50",
    "3xx": "#4488ff",
    "4xx": "#f0c040",
    "5xx": "#ff4444",
    other: "#555",
  };

  const statusFiltered = (["2xx", "3xx", "4xx", "5xx", "other"] as const)
    .filter((k) => (status_classes[k] ?? 0) > 0);

  const peakHour = hourCounts.reduce(
    (best, count, hour) => (count > best.count ? { hour, count } : best),
    { hour: 0, count: 0 },
  );
  const activeHours = hourCounts.filter((count) => count > 0).length;
  const topPathCount = top_paths[0]?.count ?? 0;

  return (
    <div className="page-shell">
      <SectionHeader title="Overview" subtitle="Operational log baseline and request behavior snapshot" />

      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 28 }}>
        <div style={{ color: "#666", fontSize: 12, letterSpacing: 0.6 }}>
          Peak hour {peakHour.hour.toString().padStart(2, "0")}:00 UTC · {peakHour.count.toLocaleString()} requests · {activeHours}/24 active hours
        </div>
        <Btn onClick={refreshOverview} disabled={loading} style={{ marginLeft: "auto" }}>Refresh</Btn>
      </div>

      {liveSection}

      <Divider />

      {isWindowsProject && (
        <div className="section-block">
          <div className="surface-panel" style={{ minHeight: 0, overflow: "auto" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px", marginBottom: "10px" }}>
              <h3 style={{ margin: 0, color: "#7cb342", fontSize: "12px", fontWeight: "bold", textTransform: "uppercase", letterSpacing: "0.8px" }}>
                Sigma Rule Library
              </h3>
              <div style={{ color: "#6f6f6f", fontSize: "11px" }}>{sigmaRuleCatalog.length} rules</div>
            </div>

            {sigmaRuleLoading && (
              <div style={{ color: "#666", fontSize: "11px", padding: "8px 0" }}>Loading Sigma rules...</div>
            )}

            {!sigmaRuleLoading && sigmaRuleError && (
              <div style={{ color: "#ff8a80", fontSize: "11px", padding: "8px 0" }}>{sigmaRuleError}</div>
            )}

            {!sigmaRuleLoading && !sigmaRuleError && sigmaRuleCatalog.length === 0 && (
              <div style={{ color: "#666", fontSize: "11px", padding: "8px 0" }}>No Sigma rules found.</div>
            )}

            {!sigmaRuleLoading && sigmaRuleCatalog.length > 0 && (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "320px", overflowY: "auto" }}>
                {sigmaRulesByFolder.map((group) => (
                  <div key={group.folder} style={{ border: "1px solid #1f1f1f", borderRadius: "4px", background: "#090909", padding: "8px" }}>
                    <div style={{ color: "#7cb342", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: "8px", fontFamily: "monospace" }}>
                      data/sigma_rules/{group.folder === "(root)" ? "" : group.folder} · {group.rules.length} file{group.rules.length === 1 ? "" : "s"}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {group.rules.map((rule) => (
                        <div
                          key={rule.rule_path}
                          style={{
                            border: "1px solid #1f1f1f",
                            borderRadius: "4px",
                            background: "#0b0b0b",
                            padding: "10px",
                            display: "flex",
                            alignItems: "center",
                            gap: "10px",
                          }}
                        >
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ color: "#d0d0d0", fontSize: "12px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontFamily: "monospace" }}>
                              {rule.rule_path.split("/").pop() || rule.rule_path}
                            </div>
                            <div style={{ color: "#707070", fontSize: "11px", marginTop: "3px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontFamily: "monospace" }}>
                              {rule.rule_path}
                            </div>
                            <div style={{ color: "#707070", fontSize: "11px", marginTop: "2px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              {rule.id} · {rule.level} · {rule.title}
                            </div>
                          </div>
                          <button
                            onClick={() => openRuleView(rule.rule_path)}
                            disabled={ruleViewLoading}
                            style={{
                              border: "1px solid #355a3b",
                              color: "#7cb342",
                              background: "#101a10",
                              fontSize: "11px",
                              borderRadius: "4px",
                              padding: "6px 10px",
                              cursor: ruleViewLoading ? "not-allowed" : "pointer",
                            }}
                          >
                            VIEW
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="section-block">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: isWindowsProject ? "repeat(2, minmax(0, 1fr))" : "repeat(4, minmax(0, 1fr))",
            gap: 18,
          }}
        >
          <MetricCard label="Total Entries" value={total_entries.toLocaleString()} />
          {!isWindowsProject && <MetricCard label="Unique IPs" value={unique_ips.toLocaleString()} />}
          {!isWindowsProject && <MetricCard label="Bot Requests" value={bot_count.toLocaleString()} accent="#f0c040" />}
          {!isWindowsProject && <MetricCard label="Human Requests" value={human_count.toLocaleString()} accent="#4488ff" />}
          {isWindowsProject && <MetricCard label="Top Path Hits" value={topPathCount.toLocaleString()} sub="Most requested endpoint volume" accent="#7cb342" />}
        </div>

        {hasTimestamps && (
          <div className="surface-panel">
            <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 18 }}>
              Hourly Traffic Distribution (UTC)
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(24, 1fr)", gap: 4 }}>
              {hourCounts.map((count, h) => (
                <div key={h} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
                  <div
                    title={`${h.toString().padStart(2, "0")}:00 - ${count.toLocaleString()} requests`}
                    style={{
                      width: "100%",
                      height: 52,
                      background: heatColor(count, maxHour),
                      borderRadius: 3,
                      border: "1px solid #1a1a1a",
                      cursor: "default",
                    }}
                  />
                  <span style={{ fontSize: 10, color: "#444", letterSpacing: 0 }}>{h.toString().padStart(2, "0")}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="section-block">
        <div style={{ display: "grid", gridTemplateColumns: !isWindowsProject ? "1fr 1fr" : "1fr", gap: 20 }}>
          {statusFiltered.length > 0 && (
            <PieChart
              title="Status Code Classes"
              labels={statusFiltered.map((k) => k === "2xx" ? "2xx Success" : k === "3xx" ? "3xx Redirect" : k === "4xx" ? "4xx Client Error" : k === "5xx" ? "5xx Server Error" : "Other")}
              values={statusFiltered.map((k) => status_classes[k])}
              colors={statusFiltered.map((k) => statusColors[k] ?? "#555")}
            />
          )}
          {!isWindowsProject && (
            <PieChart
              title="Bot vs Human"
              labels={["Human", "Bot"]}
              values={[human_count, bot_count]}
              colors={["#4488ff", "#f0c040"]}
              height={210}
            />
          )}
        </div>
      </div>

      <Divider />

      <div className="section-block">
        {top_paths.length > 0 && (
          <BarChart
            title="Top Requested Paths"
            labels={top_paths.map((p) => p.request_path.length > 48 ? p.request_path.slice(0, 48) + "..." : p.request_path)}
            values={top_paths.map((p) => p.count)}
            color="#606060"
            horizontal
          />
        )}

        {!isWindowsProject && top_ips.length > 0 && (
          <BarChart
            title="Top Source IPs"
            labels={top_ips.map((p) => p.client_ip)}
            values={top_ips.map((p) => p.request_count)}
            color="#484848"
            horizontal
          />
        )}
      </div>

      {selectedRule && (
        <div
          onClick={() => setSelectedRule(null)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.72)",
            zIndex: 1300,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "18px",
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: "min(900px, 96vw)",
              maxHeight: "88vh",
              overflowY: "auto",
              borderRadius: "6px",
              border: "1px solid #254226",
              background: "#090d09",
              padding: "14px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px", marginBottom: "10px" }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ color: "#7cb342", fontSize: "13px", fontWeight: "bold" }}>{selectedRule.rule.title}</div>
                <div style={{ color: "#79907d", fontSize: "11px", marginTop: "2px" }}>
                  {selectedRule.rule.id} · {selectedRule.rule.level} · {selectedRule.rule.rule_path}
                </div>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                style={{ border: "1px solid #355a3b", color: "#7cb342", background: "#101a10", fontSize: "11px", borderRadius: "2px", padding: "5px 9px", cursor: "pointer" }}
              >
                CLOSE
              </button>
            </div>

            {selectedRule.rule.description && (
              <p style={{ margin: "0 0 10px", color: "#98a398", fontSize: "11px" }}>{selectedRule.rule.description}</p>
            )}

            <pre
              style={{
                margin: 0,
                background: "#060806",
                border: "1px solid #1b2a1c",
                borderRadius: "4px",
                padding: "10px",
                color: "#d3dfd3",
                fontSize: "11px",
                lineHeight: 1.45,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {selectedRule.yaml}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
