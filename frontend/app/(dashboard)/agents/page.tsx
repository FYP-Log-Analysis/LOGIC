"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuthStore } from "@/lib/store";
import {
  getProjects,
  getProjectApiKey,
  getProjectAgentConfig,
  getProjectNxlogConfig,
  getLiveAgentMonitor,
  type LiveAgentMonitorData,
  getRawLogs,
  type RawLogEntry,
} from "@/lib/client";
import {
  AlertBanner,
  Badge,
  Btn,
  Divider,
  MetricCard,
  SectionHeader,
  Spinner,
} from "@/components/ui-primitives";

type ProjectOption = {
  id: string;
  name?: string;
  project_type?: "web" | "windows";
};

function formatUptime(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${h}h ${m}m ${s}s`;
}

export default function AgentsPage() {
  const { user, activeProject } = useAuthStore();
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("");
  const [apiKeys, setApiKeys] = useState<Record<string, string | null>>({});
  const [logPaths, setLogPaths] = useState<string[]>([
    "C:/inetpub/logs/LogFiles/**/*.log",
  ]);
  const [nxlogConf, setNxlogConf] = useState("");
  const [copied, setCopied] = useState<"key" | "nxlog" | null>(null);
  const [monitor, setMonitor] = useState<LiveAgentMonitorData | null>(null);
  const [rawLogs, setRawLogs] = useState<RawLogEntry[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [logFilter, setLogFilter] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const PAGE_SIZE = 50;

  const selectedProject = useMemo(
    () => projects.find((p) => p.id === selectedProjectId) ?? null,
    [projects, selectedProjectId],
  );

  const loadProjects = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const list = await getProjects();
      setProjects(list);
      const preferred = activeProject?.id && list.some((p) => p.id === activeProject.id)
        ? activeProject.id
        : list[0]?.id ?? "";
      setSelectedProjectId((prev) => prev || preferred);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [activeProject?.id]);

  const loadProjectRuntime = useCallback(async (projectId: string, projectType?: "web" | "windows") => {
    setError("");
    setLogsLoading(true);
    try {
      const platform = projectType === "windows" ? "windows" : undefined;
      const logsPromise = projectType === "windows"
        ? Promise.resolve([] as RawLogEntry[])
        : getRawLogs({ projectId, limit: 500, liveOnly: true, excludeWindows: true });

      const nxlogPromise = getProjectNxlogConfig(projectId);

      const [mon, keyData, logs, cfg, generatedNxlogConf] = await Promise.all([
        getLiveAgentMonitor(projectId),
        getProjectApiKey(projectId),
        logsPromise,
        getProjectAgentConfig(projectId, platform),
        nxlogPromise,
      ]);
      setMonitor(mon);
      setApiKeys((prev) => ({ ...prev, [projectId]: keyData.api_key ?? null }));
      setLogPaths(cfg.effective_log_paths?.length ? cfg.effective_log_paths : ["C:/inetpub/logs/LogFiles/**/*.log"]);
      setNxlogConf(generatedNxlogConf);
      setRawLogs(
        logs.filter((entry) => {
          const serverType = String(entry.server_type ?? "").toLowerCase();
          return !(serverType === "windows_event" || serverType.includes("windows"));
        }),
      );
    } catch (e) {
      setError(String(e));
      setRawLogs([]);
      setNxlogConf("");
    } finally {
      setLogsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProjects();
  }, [loadProjects]);

  useEffect(() => {
    if (!selectedProjectId) return;
    loadProjectRuntime(selectedProjectId, selectedProject?.project_type);

    let cancelled = false;
    const id = window.setInterval(async () => {
      try {
        const data = await getLiveAgentMonitor(selectedProjectId);
        if (!cancelled) setMonitor(data);
      } catch {}
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [selectedProjectId, selectedProject?.project_type, loadProjectRuntime]);

  const selectedApiKey = selectedProjectId ? apiKeys[selectedProjectId] ?? null : null;
  const filteredLogs = useMemo(() => {
    if (!logFilter.trim()) return rawLogs;
    const q = logFilter.toLowerCase();
    return rawLogs.filter((l) =>
      (l.client_ip ?? "").toLowerCase().includes(q) ||
      (l.request_path ?? "").toLowerCase().includes(q) ||
      (l.http_method ?? "").toLowerCase().includes(q) ||
      String(l.status_code ?? "").includes(q) ||
      (l.user_agent ?? "").toLowerCase().includes(q),
    );
  }, [rawLogs, logFilter]);
  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / PAGE_SIZE));
  const pageStart = (currentPage - 1) * PAGE_SIZE;
  const pagedLogs = filteredLogs.slice(pageStart, pageStart + PAGE_SIZE);

  useEffect(() => {
    setCurrentPage(1);
  }, [selectedProjectId, logFilter]);

  useEffect(() => {
    if (currentPage > totalPages) setCurrentPage(totalPages);
  }, [currentPage, totalPages]);

  const copyKey = () => {
    navigator.clipboard.writeText(selectedApiKey ?? "").then(() => {
      setCopied("key");
      setTimeout(() => setCopied(null), 2000);
    });
  };

  const copyNxlog = () => {
    navigator.clipboard.writeText(nxlogConf).then(() => {
      setCopied("nxlog");
      setTimeout(() => setCopied(null), 2000);
    });
  };

  if (user?.role === "admin") {
    return (
      <div style={{ maxWidth: 720 }}>
        <SectionHeader
          title="Agents"
          subtitle="Dedicated dashboard for LOGIX agent runtime configuration"
        />
        <AlertBanner type="warning" message="Agents dashboard is available for analyst accounts only." />
      </div>
    );
  }

  return (
    <div>
      <SectionHeader
        title="Agents"
        subtitle="NXLog agent operations dashboard with runtime monitoring and incoming logs"
      />

      {error && <AlertBanner type="error" message={error} />}

      {loading ? (
        <div style={{ textAlign: "center", padding: 40 }}><Spinner size={22} /></div>
      ) : projects.length === 0 ? (
        <AlertBanner type="info" message="No projects available. Create a project first." />
      ) : (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
            <div style={{ color: "#666", fontSize: 11, letterSpacing: 1, textTransform: "uppercase" }}>Project</div>
            <select
              value={selectedProjectId}
              onChange={(e) => setSelectedProjectId(e.target.value)}
              style={{
                background: "#111",
                border: "1px solid #2a2a2a",
                color: "#c0c0c0",
                padding: "7px 10px",
                borderRadius: 3,
                fontSize: 12,
                minWidth: 320,
              }}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>{p.name ?? p.id}</option>
              ))}
            </select>
            {selectedProject && <Badge color="#7fa8bf">{selectedProject.name ?? selectedProject.id}</Badge>}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
            <MetricCard label="API Key" value={selectedApiKey ? "AVAILABLE" : "MISSING"} accent={selectedApiKey ? "#70d08c" : "#d56a6a"} />
            <MetricCard label="Configured Paths" value={logPaths.length} />
            <MetricCard label="Agent Status" value={(monitor?.status ?? "idle").toUpperCase()} accent={monitor?.status === "active" ? "#70d08c" : "#c5b27b"} />
            <MetricCard label="Uptime" value={formatUptime(monitor?.uptime_seconds ?? 0)} sub={monitor?.last_batch_at ? `Last batch ${new Date(monitor.last_batch_at * 1000).toLocaleString()}` : "No batches yet"} />
          </div>

          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 14 }}>
            <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
              NXLog Agent Configuration
            </div>

            {logPaths.length === 0 ? (
              <div style={{ color: "#555", fontSize: 12, marginBottom: 10 }}>
                No log paths configured for this project.
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 10 }}>
                {logPaths.map((p) => (
                  <div
                    key={p}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      background: "#090909",
                      border: "1px solid #1a1a1a",
                      borderRadius: 3,
                      padding: "8px 10px",
                    }}
                  >
                    <div style={{ flex: 1, color: "#a7d97a", fontFamily: "monospace", fontSize: 11, wordBreak: "break-all" }}>{p}</div>
                  </div>
                ))}
              </div>
            )}

            <div style={{ fontSize: 10, color: "#6e8796", marginBottom: 4 }}>Copy-ready API key command</div>
            <div style={{ fontFamily: "monospace", fontSize: 11, color: "#9fd4ff", marginBottom: 10, whiteSpace: "pre-wrap", wordBreak: "break-all", background: "#090909", border: "1px solid #1a1a1a", borderRadius: 3, padding: "8px 10px" }}>
              {`Write-Output "${selectedApiKey ?? "<generate-api-key-from-projects-page>"}" | Set-Clipboard`}
            </div>

            <div style={{ display: "flex", gap: 8 }}>
              <Btn variant="ghost" onClick={copyKey} disabled={!selectedProjectId || !selectedApiKey}>
                {copied === "key" ? "COPIED!" : "COPY API KEY"}
              </Btn>
              <Btn
                variant="ghost"
                onClick={() => selectedProjectId && loadProjectRuntime(selectedProjectId, selectedProject?.project_type)}
                disabled={!selectedProjectId}
              >
                REFRESH
              </Btn>
            </div>

            <Divider />
            <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>
              Generated NXLog Configuration
            </div>
            <div style={{ fontSize: 11, color: "#777", marginBottom: 8 }}>
              Copy this full file into nxlog.conf and restart the NXLog service.
            </div>
            <pre
              style={{
                margin: 0,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                fontFamily: "monospace",
                fontSize: 11,
                color: "#a7d97a",
                background: "#090909",
                border: "1px solid #1a1a1a",
                borderRadius: 3,
                padding: "10px",
                maxHeight: 340,
                overflowY: "auto",
              }}
            >
              {nxlogConf || "NXLog config is not available yet. Click REFRESH to regenerate."}
            </pre>
            <div style={{ display: "flex", marginTop: 10 }}>
              <Btn variant="default" onClick={copyNxlog} disabled={!nxlogConf}>
                {copied === "nxlog" ? "COPIED!" : "COPY NXLOG CONF"}
              </Btn>
            </div>
          </div>

          <Divider />

          <div style={{ marginBottom: 24 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
              <div style={{ fontSize: 11, letterSpacing: 1.5, textTransform: "uppercase", color: "#888" }}>
                Incoming Raw Logs
                {rawLogs.length > 0 && (
                  <span style={{ color: "#444", marginLeft: 8 }}>
                    — showing {Math.min(pageStart + PAGE_SIZE, filteredLogs.length).toLocaleString()} of {filteredLogs.length.toLocaleString()} filtered ({rawLogs.length.toLocaleString()} total)
                  </span>
                )}
              </div>
              {rawLogs.length > 0 && (
                <input
                  type="text"
                  placeholder="Filter by IP, path, method, status, user-agent…"
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                  style={{
                    marginLeft: "auto",
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

            {logsLoading ? (
              <div style={{ textAlign: "center", padding: 24 }}><Spinner size={18} /></div>
            ) : selectedProject?.project_type === "windows" ? (
              <div style={{ color: "#444", fontSize: 12, border: "1px dashed #1e1e1e", borderRadius: 4, padding: 20 }}>
                Incoming Raw Logs is available for web-agent streams only. Windows project logs are intentionally hidden here.
              </div>
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
      )}

      <Divider />

      <div style={{ color: "#666", fontSize: 12, lineHeight: 1.5 }}>
        API key generation is intentionally managed from the Projects page. Rotate-key controls were removed from this dashboard.
      </div>
    </div>
  );
}
