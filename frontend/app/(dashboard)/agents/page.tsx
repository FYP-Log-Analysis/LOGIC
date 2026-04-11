"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuthStore } from "@/lib/store";
import {
  getProjects,
  getProjectApiKey,
  getProjectAgentConfig,
  getProjectNxlogConfig,
  getLiveAgentMonitor,
  sendAgentIngestTest,
  type LiveAgentMonitorData,
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
  const [testRunning, setTestRunning] = useState(false);
  const [testMessage, setTestMessage] = useState("");
  const [testError, setTestError] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const selectedProject = useMemo(
    () => projects.find((p) => p.id === selectedProjectId) ?? null,
    [projects, selectedProjectId],
  );
  const currentMode = selectedProject?.project_type ?? activeProject?.project_type ?? "web";
  const pageTitle = currentMode === "windows" ? "Windows Agents" : "Agents";
  const pageSubtitle =
    currentMode === "windows"
      ? "NXLog dashboard for Windows event collection and agent runtime monitoring"
      : "NXLog agent operations dashboard with runtime monitoring";

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
    try {
      const platform = projectType === "windows" ? "windows" : undefined;
      const fallbackPaths =
        projectType === "windows"
          ? ["C:/Windows/System32/winevt/Logs/Security.evtx"]
          : ["C:/inetpub/logs/LogFiles/**/*.log"];
      const nxlogPromise = getProjectNxlogConfig(projectId);

      const [mon, keyData, cfg, generatedNxlogConf] = await Promise.all([
        getLiveAgentMonitor(projectId),
        getProjectApiKey(projectId),
        getProjectAgentConfig(projectId, platform),
        nxlogPromise,
      ]);
      setMonitor(mon);
      setApiKeys((prev) => ({ ...prev, [projectId]: keyData.api_key ?? null }));
      setLogPaths(cfg.effective_log_paths?.length ? cfg.effective_log_paths : fallbackPaths);
      setNxlogConf(generatedNxlogConf);
    } catch (e) {
      setError(String(e));
      setNxlogConf("");
    }
  }, []);

  useEffect(() => {
    loadProjects();
  }, [loadProjects]);

  useEffect(() => {
    if (!selectedProjectId) return;
    setTestMessage("");
    setTestError("");
    loadProjectRuntime(selectedProjectId, selectedProject?.project_type);

    let cancelled = false;

    const refreshMonitor = async () => {
      try {
        const monitorData = await getLiveAgentMonitor(selectedProjectId);

        if (cancelled) return;
        setMonitor(monitorData);
      } catch {
        // Silent refresh failure: keep last known telemetry.
      }
    };

    const id = window.setInterval(async () => {
      await refreshMonitor();
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [selectedProjectId, selectedProject?.project_type, loadProjectRuntime]);

  const selectedApiKey = selectedProjectId ? apiKeys[selectedProjectId] ?? null : null;

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

  const runConnectivityTest = async () => {
    if (!selectedProjectId || !selectedApiKey) return;
    setTestRunning(true);
    setTestError("");
    setTestMessage("");
    try {
      const result = await sendAgentIngestTest(
        selectedProjectId,
        selectedApiKey,
        selectedProject?.project_type === "windows" ? "windows" : "web",
      );
      setTestMessage(`Test ingest accepted (upload ${result.upload_id.slice(0, 8)}..., records ${result.records_received}).`);
      await loadProjectRuntime(selectedProjectId, selectedProject?.project_type);
    } catch (e) {
      setTestError(String(e));
    } finally {
      setTestRunning(false);
    }
  };

  if (user?.role === "admin") {
    return (
      <div style={{ maxWidth: 720 }}>
        <SectionHeader
          title={pageTitle}
          subtitle="Dedicated dashboard for LOGIX agent runtime configuration"
        />
        <AlertBanner type="warning" message="Agents dashboard is available for analyst accounts only." />
      </div>
    );
  }

  return (
    <div>
      <SectionHeader
        title={pageTitle}
        subtitle={pageSubtitle}
      />

      {error && <AlertBanner type="error" message={error} />}
      {testMessage && <AlertBanner type="success" message={testMessage} />}
      {testError && <AlertBanner type="error" message={testError} />}

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
                    <div style={{ flex: 1, color: "#a7d97a", fontFamily: "var(--font-mono-stack)", fontSize: 11, wordBreak: "break-all" }}>{p}</div>
                  </div>
                ))}
              </div>
            )}

            <div style={{ fontSize: 10, color: "#6e8796", marginBottom: 4 }}>Copy-ready API key command</div>
            <div style={{ fontFamily: "var(--font-mono-stack)", fontSize: 11, color: "#9fd4ff", marginBottom: 10, whiteSpace: "pre-wrap", wordBreak: "break-all", background: "#090909", border: "1px solid #1a1a1a", borderRadius: 3, padding: "8px 10px" }}>
              {`Write-Output "${selectedApiKey ?? "<generate-api-key-from-projects-page>"}" | Set-Clipboard`}
            </div>

            <div style={{ display: "flex", gap: 8 }}>
              <Btn variant="ghost" onClick={copyKey} disabled={!selectedProjectId || !selectedApiKey}>
                {copied === "key" ? "COPIED!" : "COPY API KEY"}
              </Btn>
              <Btn
                variant="ghost"
                onClick={runConnectivityTest}
                disabled={!selectedProjectId || !selectedApiKey || testRunning}
              >
                {testRunning ? "TESTING..." : "RUN CONNECTIVITY TEST"}
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
                fontFamily: "var(--font-mono-stack)",
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

          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 14, marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
              Agent Telemetry
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 10 }}>
              <MetricCard label="Last Host" value={monitor?.last_host || "—"} />
              <MetricCard label="Batches" value={(monitor?.batch_count ?? 0).toLocaleString()} />
              <MetricCard label="Validation Errors" value={(monitor?.validation_error_count ?? monitor?.validation_errors?.length ?? 0).toLocaleString()} accent={(monitor?.validation_error_count ?? monitor?.validation_errors?.length ?? 0) > 0 ? "#d56a6a" : "#70d08c"} />
              <MetricCard label="Processing Errors" value={(monitor?.processing_error_count ?? monitor?.processing_errors?.length ?? 0).toLocaleString()} accent={(monitor?.processing_error_count ?? monitor?.processing_errors?.length ?? 0) > 0 ? "#d56a6a" : "#70d08c"} />
            </div>

            {selectedProject?.project_type === "windows" && !monitor?.has_traffic && (
              <div style={{ color: "#888", fontSize: 12, border: "1px dashed #1e1e1e", borderRadius: 4, padding: 12, marginBottom: 10 }}>
                No Windows agent traffic observed yet. Use "RUN CONNECTIVITY TEST" to verify project ID/API key/path wiring, then check the NXLog service status and connectivity from the Windows host.
              </div>
            )}

            {(monitor?.validation_errors?.length ?? 0) > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 10, color: "#aa6b6b", marginBottom: 4, letterSpacing: 0.8, textTransform: "uppercase" }}>
                  Recent Validation Errors
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {monitor!.validation_errors.slice(-5).reverse().map((evt, idx) => (
                    <div key={`val-${idx}-${evt.timestamp}`} style={{ color: "#cc8888", fontSize: 11, fontFamily: "var(--font-mono-stack)", background: "#120909", border: "1px solid #2a1515", borderRadius: 3, padding: "6px 8px" }}>
                      [{new Date(evt.timestamp * 1000).toLocaleString()}] {evt.message}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {(monitor?.processing_errors?.length ?? 0) > 0 && (
              <div>
                <div style={{ fontSize: 10, color: "#aa6b6b", marginBottom: 4, letterSpacing: 0.8, textTransform: "uppercase" }}>
                  Recent Processing Errors
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {monitor!.processing_errors.slice(-5).reverse().map((evt, idx) => (
                    <div key={`proc-${idx}-${evt.timestamp}`} style={{ color: "#cc8888", fontSize: 11, fontFamily: "var(--font-mono-stack)", background: "#120909", border: "1px solid #2a1515", borderRadius: 3, padding: "6px 8px" }}>
                      [{new Date(evt.timestamp * 1000).toLocaleString()}] {evt.message}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div style={{ color: "#555", fontSize: 12, marginBottom: 24 }}>
            Incoming raw logs were moved to the Overview page, where live status and stream activity are now displayed together.
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
