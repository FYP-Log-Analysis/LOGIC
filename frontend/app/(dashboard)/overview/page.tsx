"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  explainWindowsEvent,
  getOverviewData,
  getLogStatistics,
  getLiveAgentMonitor,
  getRawLogs,
  getWindowsSigmaResults,
  getWindowsSigmaRules,
  type LiveAgentMonitorData,
  type LogStatistics,
  type RawLogEntry,
} from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { SectionHeader, MetricCard, Divider, Spinner, Btn } from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import PieChart from "@/components/charts/pie-chart";
import { EventDetailModal } from "@/components/event-detail-modal";

function heatColor(count: number, maxCount: number): string {
  if (maxCount === 0 || count === 0) return "#111";
  const ratio = count / maxCount;
  if (ratio > 0.75) return "#315b8f";
  if (ratio > 0.5) return "#2a4c74";
  if (ratio > 0.25) return "#1f3a59";
  return "#16283c";
}

function formatUptime(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${h}h ${m}m ${s}s`;
}

const LOGON_TYPE_LABELS: Record<string, string> = {
  "2": "2 Interactive",
  "3": "3 Network",
  "4": "4 Batch",
  "5": "5 Service",
  "7": "7 Unlock",
  "8": "8 NetworkCleartext",
  "9": "9 NewCredentials",
  "10": "10 RemoteInteractive",
  "11": "11 CachedInteractive",
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function eventDataOf(entry: RawLogEntry): Record<string, unknown> {
  return asRecord((entry as Record<string, unknown>).event_data);
}

function isSecurityEvtxEntry(entry: RawLogEntry): boolean {
  const row = asRecord(entry);
  const channel = String(row.channel ?? "").toLowerCase();
  const source = String(row.source ?? "").toLowerCase();
  return channel.includes("security") || source.endsWith("security.evtx") || source.includes("/security.evtx");
}

function getSecurityLogonType(entry: RawLogEntry): string {
  if (!isSecurityEvtxEntry(entry)) return "-";
  const data = eventDataOf(entry);
  const raw = data.LogonType ?? data.logon_type ?? data.logonType;
  if (raw == null) return "-";
  const key = String(raw).trim();
  return LOGON_TYPE_LABELS[key] ?? key;
}

function getSecurityOutcome(entry: RawLogEntry): "Success" | "Failure" | "Unknown" {
  if (!isSecurityEvtxEntry(entry)) return "Unknown";

  const data = eventDataOf(entry);
  const rawStatus = data.Status ?? data.status;
  if (rawStatus != null) {
    const txt = String(rawStatus).trim().toLowerCase();
    if (txt === "success") return "Success";
    if (txt === "failure" || txt === "failed") return "Failure";
    if (txt.startsWith("0x")) {
      const parsed = Number.parseInt(txt.slice(2), 16);
      if (!Number.isNaN(parsed)) return parsed === 0 ? "Success" : "Failure";
    }
    const parsed = Number(txt);
    if (!Number.isNaN(parsed)) return parsed === 0 ? "Success" : "Failure";
  }

  const eventId = Number((entry as Record<string, unknown>).event_id ?? Number.NaN);
  if (eventId === 4624) return "Success";
  if (eventId === 4625) return "Failure";
  return "Unknown";
}

interface MicroTileProps {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}

function MicroTile({ label, value, sub, accent = "#4a7c59" }: MicroTileProps) {
  return (
    <div
      style={{
        border: "1px solid #262626",
        borderLeft: `2px solid ${accent}`,
        background: "#111",
        borderRadius: 4,
        padding: "10px 12px",
        minHeight: 72,
      }}
    >
      <div style={{ fontSize: 10, letterSpacing: 0.9, textTransform: "uppercase", color: "#6e8796", marginBottom: 8 }}>
        {label}
      </div>
      <div style={{ fontSize: 22, lineHeight: 1.1, color: "#d0d0d0", fontWeight: 300 }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      {sub && <div style={{ marginTop: 6, fontSize: 11, color: "#666" }}>{sub}</div>}
    </div>
  );
}

interface WorkflowStepProps {
  idx: number;
  text: string;
}

function WorkflowStep({ idx, text }: WorkflowStepProps) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "20px 1fr",
        gap: 8,
        alignItems: "start",
      }}
    >
      <div
        style={{
          width: 20,
          height: 20,
          borderRadius: 999,
          border: "1px solid #315b8f",
          background: "#0d1a3d",
          color: "#7fa8bf",
          fontSize: 10,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          lineHeight: 1,
        }}
      >
        {idx}
      </div>
      <div style={{ fontSize: 12, color: "#c8c8c8", lineHeight: 1.45 }}>{text}</div>
    </div>
  );
}

interface NavActionButtonProps {
  label: string;
  onClick: () => void;
}

function NavActionButton({ label, onClick }: NavActionButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        border: "1px solid #315b8f",
        background: "#0d1a3d",
        color: "#7fa8bf",
        borderRadius: 2,
        fontSize: 11,
        letterSpacing: 0.8,
        textTransform: "uppercase",
        padding: "8px 12px",
        cursor: "pointer",
        fontFamily: "inherit",
        transition: "border-color 0.15s ease, background 0.15s ease",
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLButtonElement).style.borderColor = "#4a7c59";
        (e.currentTarget as HTMLButtonElement).style.background = "#1a3d2a";
        (e.currentTarget as HTMLButtonElement).style.color = "#7cb342";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLButtonElement).style.borderColor = "#315b8f";
        (e.currentTarget as HTMLButtonElement).style.background = "#0d1a3d";
        (e.currentTarget as HTMLButtonElement).style.color = "#7fa8bf";
      }}
    >
      {label}
    </button>
  );
}

export default function OverviewPage() {
  const router = useRouter();
  const [stats, setStats] = useState<LogStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [monitor, setMonitor] = useState<LiveAgentMonitorData | null>(null);
  const [rawLogs, setRawLogs] = useState<RawLogEntry[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [logFilter, setLogFilter] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedEvent, setSelectedEvent] = useState<RawLogEntry | null>(null);
  const [eventExplanation, setEventExplanation] = useState<string>("");
  const [eventExplainLoading, setEventExplainLoading] = useState(false);
  const [eventExplainError, setEventExplainError] = useState<string | null>(null);
  const [sigmaRulesCount, setSigmaRulesCount] = useState<number | null>(null);
  const [sigmaMatchesCount, setSigmaMatchesCount] = useState<number | null>(null);
  const [webDetectionsCount, setWebDetectionsCount] = useState<number | null>(null);
  const [webUniqueRulesCount, setWebUniqueRulesCount] = useState<number | null>(null);
  const [sigmaSummaryLoading, setSigmaSummaryLoading] = useState(false);
  const [sigmaSummaryError, setSigmaSummaryError] = useState<string | null>(null);
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

  useEffect(() => {
    const timer = window.setTimeout(() => {
      loadData();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadData]);

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

  useEffect(() => {
    if (!activeProject?.id) {
      setSigmaRulesCount(null);
      setSigmaMatchesCount(null);
      setWebDetectionsCount(null);
      setWebUniqueRulesCount(null);
      setSigmaSummaryError(null);
      setSigmaSummaryLoading(false);
      return;
    }

    let cancelled = false;

    const loadDetectionSummary = async () => {
      setSigmaSummaryLoading(true);
      setSigmaSummaryError(null);
      try {
        if (isWindowsProject) {
          setWebDetectionsCount(null);
          setWebUniqueRulesCount(null);

          const rulesCatalog = await getWindowsSigmaRules();
          if (cancelled) return;

          const ruleCount =
            typeof rulesCatalog.count === "number"
              ? rulesCatalog.count
              : Array.isArray(rulesCatalog.rules)
                ? rulesCatalog.rules.length
                : 0;
          setSigmaRulesCount(ruleCount);

          try {
            const matches = await getWindowsSigmaResults({ projectId: activeProject.id, limit: 1, offset: 0 });
            if (cancelled) return;
            const total =
              typeof matches.total_matches === "number"
                ? matches.total_matches
                : typeof matches.count === "number"
                  ? matches.count
                  : Array.isArray(matches.matches)
                    ? matches.matches.length
                    : 0;
            setSigmaMatchesCount(total);
          } catch {
            if (cancelled) return;
            setSigmaMatchesCount(null);
          }
        } else {
          setSigmaRulesCount(null);
          setSigmaMatchesCount(null);

          const webOverview = await getOverviewData({ projectId: activeProject.id });
          if (cancelled) return;

          setWebDetectionsCount(
            typeof webOverview.total_detections === "number" ? webOverview.total_detections : 0,
          );
          setWebUniqueRulesCount(
            typeof webOverview.unique_rules === "number" ? webOverview.unique_rules : 0,
          );
        }
      } catch (e) {
        if (cancelled) return;
        setSigmaRulesCount(null);
        setSigmaMatchesCount(null);
        setWebDetectionsCount(null);
        setWebUniqueRulesCount(null);
        setSigmaSummaryError(e instanceof Error ? e.message : "Failed to load detection summary.");
      } finally {
        if (!cancelled) setSigmaSummaryLoading(false);
      }
    };

    void loadDetectionSummary();

    return () => {
      cancelled = true;
    };
  }, [activeProject?.id, isWindowsProject]);

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
        const logonType = getSecurityLogonType(l).toLowerCase();
        const outcome = getSecurityOutcome(l).toLowerCase();
        return (
          (l.client_ip ?? "").toLowerCase().includes(q) ||
          eventId.includes(q) ||
          channel.includes(q) ||
          computer.includes(q) ||
          user.includes(q) ||
          raw.includes(q) ||
          logonType.includes(q) ||
          outcome.includes(q)
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

  const summaryModeText = isWindowsProject ? ".EVTX -> SIGMA" : "HTTP -> WAF RULES";
  const summaryLeftPrimary =
    sigmaSummaryLoading
      ? "..."
      : isWindowsProject
        ? (sigmaRulesCount ?? "—").toString()
        : (webDetectionsCount ?? "—").toString();

  const summaryLeftSecondary =
    sigmaSummaryLoading
      ? "..."
      : isWindowsProject
        ? (sigmaMatchesCount ?? "—").toString()
        : (webUniqueRulesCount ?? "—").toString();

  const workflowSteps = isWindowsProject
    ? [
        "Ingest raw telemetry (.evtx or web logs).",
        "Normalize records into consistent event fields.",
        "Evaluate Sigma conditions against each event.",
        "Store matches and queue analyst triage.",
      ]
    : [
        "Ingest raw HTTP access and request logs.",
        "Normalize request, status, and source fields.",
        "Evaluate CRS/WAF rules against each request.",
        "Store rule matches and queue analyst triage.",
      ];

  const detectionSummarySection = (
    <div className="section-block">
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.3fr) minmax(0, 1fr)",
          gap: 14,
        }}
      >
        <div
          style={{
            borderLeft: "1px solid #1e1e1e",
            borderRight: "1px solid #1e1e1e",
            borderBottom: "1px solid #1e1e1e",
            borderTop: "2px solid #2f4a38",
            borderRadius: 6,
            background: "linear-gradient(180deg, #111611 0%, #0d0d0d 100%)",
            padding: 12,
          }}
        >
          <div style={{ fontSize: 10, letterSpacing: 1, textTransform: "uppercase", color: "#6e8796", marginBottom: 10 }}>
            Detection Snapshot
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 10 }}>
            <MicroTile
              label={isWindowsProject ? "Sigma Rules" : "Rule Matches"}
              value={summaryLeftPrimary}
              sub={isWindowsProject ? "Loaded rule catalog" : "CRS/WAF detections"}
              accent="#4a7c59"
            />
            <MicroTile
              label={isWindowsProject ? "Rule Matches" : "Unique Rules"}
              value={summaryLeftSecondary}
              sub={isWindowsProject ? "Current project results" : "Triggered in current scope"}
              accent="#315b8f"
            />
            <MicroTile label="Mode" value={summaryModeText} sub="Detection mapping" accent="#4a4a4a" />
            <MicroTile label="Project Type" value={isWindowsProject ? "WINDOWS" : "WEB"} sub="Active scope" accent="#4a4a4a" />
            <MicroTile
              label="Agent Status"
              value={(monitor?.status ?? "idle").toUpperCase()}
              sub="Live collector state"
              accent={monitor?.status === "active" ? "#4a7c59" : "#3a3a3a"}
            />
            <MicroTile label="Uptime" value={formatUptime(monitor?.uptime_seconds ?? 0)} sub="Collector runtime" accent="#315b8f" />
          </div>
        </div>

        <div
          style={{
            borderLeft: "1px solid #1e1e1e",
            borderRight: "1px solid #1e1e1e",
            borderBottom: "1px solid #1e1e1e",
            borderTop: "2px solid #2e4566",
            borderRadius: 6,
            background: "linear-gradient(180deg, #101725 0%, #0d0d0d 100%)",
            padding: 12,
          }}
        >
          <div style={{ fontSize: 10, letterSpacing: 1, textTransform: "uppercase", color: "#7fa8bf", marginBottom: 10 }}>
            Detection Workflow
          </div>
          <div style={{ display: "grid", gap: 8 }}>
            {workflowSteps.map((step, idx) => (
              <WorkflowStep key={step} idx={idx + 1} text={step} />
            ))}
          </div>

          <div style={{ display: "flex", gap: 10, marginTop: 12, flexWrap: "wrap" }}>
            {isWindowsProject ? (
              <>
                <NavActionButton label="Go To Rule Based Detection" onClick={() => router.push("/windows-analysis")} />
                <NavActionButton label="View Sigma Rules" onClick={() => router.push("/rules-setup")} />
                <NavActionButton label="View Anomalous Windows" onClick={() => router.push("/windows-behavioral")} />
              </>
            ) : (
              <>
                <NavActionButton label="Go To Web Analysis" onClick={() => router.push("/analysis")} />
                <NavActionButton label="View Web Detections" onClick={() => router.push("/detections")} />
                <NavActionButton label="View Web Behavioral" onClick={() => router.push("/behavioral")} />
              </>
            )}
          </div>
        </div>
      </div>

      <div
        style={{
          marginTop: 10,
          borderLeft: "1px solid #1e1e1e",
          borderRight: "1px solid #1e1e1e",
          borderBottom: "1px solid #1e1e1e",
          borderTop: "2px solid #2f4a38",
          borderRadius: 4,
          background: "linear-gradient(180deg, #101410 0%, #0d0d0d 100%)",
          padding: "10px 12px",
        }}
      >
        <div style={{ fontSize: 10, letterSpacing: 1, textTransform: "uppercase", color: "#7fa8bf", marginBottom: 6 }}>
          Threat Detection Guide
        </div>
        <div style={{ fontSize: 12, color: "#c8c8c8", lineHeight: 1.6, maxWidth: 920 }}>
          {isWindowsProject ? (
            <>
              1. .evtx logs are normalized into structured events.
              <br />
              2. Sigma conditions are evaluated against each event.
              <br />
              3. Matched rules are stored as rule-based detections for analyst triage.
            </>
          ) : (
            <>
              1. Web access logs are normalized into HTTP event records.
              <br />
              2. CRS/WAF rules are evaluated against each request.
              <br />
              3. Matched web detections are stored for analyst triage.
            </>
          )}
        </div>
        {sigmaSummaryError && (
          <div style={{ marginTop: 10, fontSize: 11, color: "#8a8a8a" }}>
            Detection summary unavailable: {sigmaSummaryError}
          </div>
        )}
      </div>
    </div>
  );

  const openEventDetail = useCallback((entry: RawLogEntry) => {
    setSelectedEvent(entry);
    setEventExplanation("");
    setEventExplainError(null);
    setEventExplainLoading(false);
  }, []);

  const explainSelectedEvent = useCallback(async () => {
    if (!selectedEvent || !activeProject?.id) return;

    setEventExplainLoading(true);
    setEventExplainError(null);
    try {
      const response = await explainWindowsEvent(selectedEvent as Record<string, unknown>, activeProject.id);
      setEventExplanation(response.analysis || "No explanation returned by Groq.");
    } catch (e) {
      setEventExplainError(e instanceof Error ? e.message : "Failed to explain event.");
    } finally {
      setEventExplainLoading(false);
    }
  }, [selectedEvent, activeProject?.id]);

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
            accent={monitor?.status === "active" ? "#d4d4d4" : "#9a9a9a"}
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
                fontFamily: "var(--font-mono-stack)",
                padding: "5px 10px",
                outline: "none",
                width: 320,
              }}
            />
          )}
        </div>

        {liveError && (
          <div style={{ color: "#b8b8b8", fontSize: 12, marginBottom: 10 }}>
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
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "var(--font-mono-stack)" }}>
                  <thead>
                    <tr style={{ background: "#0d0d0d" }}>
                      {["#", "Time", "Event ID", "Channel", "Logon Type", "Status", "Computer", "User", "IP"].map((col) => (
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
                      const securityEntry = isSecurityEvtxEntry(entry);
                      const logonType = getSecurityLogonType(entry);
                      const eventStatus = getSecurityOutcome(entry);
                      const statusColor =
                        eventStatus === "Success" ? "#d8d8d8" :
                        eventStatus === "Failure" ? "#a6a6a6" : "#7d7d7d";
                      return (
                        <tr
                          key={`${entry.timestamp ?? ""}-${absoluteIdx}`}
                          style={{ borderBottom: "1px solid #141414", background: idx % 2 === 0 ? "transparent" : "#0a0a0a", cursor: "pointer" }}
                          title="Click to inspect full event JSON and request a Groq explanation"
                          onClick={() => openEventDetail(entry)}
                        >
                          <td style={{ padding: "6px 12px", color: "#333", minWidth: 40 }}>{absoluteIdx + 1}</td>
                          <td style={{ padding: "6px 12px", color: "#555", whiteSpace: "nowrap" }}>
                            {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#c7c7c7", whiteSpace: "nowrap" }}>
                            {eventId != null ? String(eventId) : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#a8a8a8", whiteSpace: "nowrap" }}>
                            {channel != null && String(channel) ? String(channel) : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: securityEntry ? "#b9b9b9" : "#444", whiteSpace: "nowrap" }}>
                            {securityEntry ? logonType : "-"}
                          </td>
                          <td style={{ padding: "6px 12px", color: securityEntry ? statusColor : "#444", whiteSpace: "nowrap", fontWeight: 600 }}>
                            {securityEntry ? eventStatus : "-"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#e8e8e8", whiteSpace: "nowrap" }}>
                            {computer != null && String(computer) ? String(computer) : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#bdbdbd", whiteSpace: "nowrap" }}>
                            {authUser != null && String(authUser) ? String(authUser) : "—"}
                          </td>
                          <td style={{ padding: "6px 12px", color: "#a6a6a6", whiteSpace: "nowrap" }}>
                            {entry.client_ip ?? "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "var(--font-mono-stack)" }}>
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
                        sc >= 500 ? "#9a9a9a" :
                        sc >= 400 ? "#adadad" :
                        sc >= 300 ? "#c0c0c0" :
                        sc >= 200 ? "#d8d8d8" : "#666";
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
                          <td style={{ padding: "6px 12px", color: "#b6b6b6", whiteSpace: "nowrap" }}>
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
                          <td style={{ padding: "6px 12px", color: "#a6a6a6", whiteSpace: "nowrap" }}>
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
        {detectionSummarySection}
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
    other: "#666",
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

      {detectionSummarySection}

      {liveSection}

      <Divider />

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
          {!isWindowsProject && <MetricCard label="Bot Requests" value={bot_count.toLocaleString()} accent="#ff8800" />}
          {!isWindowsProject && <MetricCard label="Human Requests" value={human_count.toLocaleString()} accent="#42a5f5" />}
          {isWindowsProject && <MetricCard label="Top Path Hits" value={topPathCount.toLocaleString()} sub="Most requested endpoint volume" accent="#707070" />}
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
              colors={["#42a5f5", "#ff8800"]}
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
            color="#4a7a4a"
            horizontal
          />
        )}

        {!isWindowsProject && top_ips.length > 0 && (
          <BarChart
            title="Top Source IPs"
            labels={top_ips.map((p) => p.client_ip)}
            values={top_ips.map((p) => p.request_count)}
            color="#5a7a9a"
            horizontal
          />
        )}
      </div>

      {selectedEvent && (
        <EventDetailModal
          title={`Windows Event ${String((selectedEvent as Record<string, unknown>).event_id ?? "") || "Unknown"}`}
          subtitle={`Channel: ${String((selectedEvent as Record<string, unknown>).channel ?? "unknown")}`}
          payload={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          actions={(
            <>
              <div style={{ color: "#7f7f7f", fontSize: 11 }}>
                Full raw JSON is shown below. Use Groq for quick analyst guidance.
              </div>
              <Btn variant="ghost" onClick={explainSelectedEvent} disabled={eventExplainLoading}>
                {eventExplainLoading ? "Explaining..." : "Explain With Groq"}
              </Btn>
            </>
          )}
        >
          <div style={{ fontSize: 10, color: "#777", letterSpacing: 0.8, textTransform: "uppercase", marginBottom: 8 }}>
            Groq Explanation
          </div>
          {eventExplainError && (
            <div style={{ color: "#b8b8b8", fontSize: 12, marginBottom: 8 }}>
              {eventExplainError}
            </div>
          )}
          {!eventExplainError && !eventExplanation && (
            <div style={{ color: "#777", fontSize: 12 }}>
              Click &quot;Explain With Groq&quot; to generate a concise security interpretation.
            </div>
          )}
          {eventExplanation && (
            <div style={{ color: "#d0d0d0", fontSize: 12, lineHeight: 1.5, whiteSpace: "pre-wrap" }}>
              {eventExplanation}
            </div>
          )}
        </EventDetailModal>
      )}
    </div>
  );
}
