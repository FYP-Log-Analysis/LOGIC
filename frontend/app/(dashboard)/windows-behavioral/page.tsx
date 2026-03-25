"use client";

import { useCallback, useEffect, useState } from "react";
import { runWindowsBehavioralAnalysis, getWindowsBehavioralResults } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import {
  SectionHeader,
  MetricCard,
  Btn,
  Spinner,
  AlertBanner,
  Divider,
} from "@/components/ui-primitives";
import LineChart from "@/components/charts/line-chart";
import HawkinsChat from "@/components/hawkins-chat";

interface WindowsBehavioralResult {
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

export default function WindowsBehavioralPage() {
  const { activeProject } = useAuthStore();
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<WindowsBehavioralResult | null>(null);
  const [error, setError] = useState("");
  const [windowMinutes, setWindowMinutes] = useState(5);
  const [startTs, setStartTs] = useState("");
  const [endTs, setEndTs] = useState("");

  const toIsoOrUndefined = (value: string): string | undefined => {
    if (!value) return undefined;
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return undefined;
    return dt.toISOString();
  };

  const loadLatest = useCallback(async (projectId: string) => {
    setLoading(true);
    setError("");
    try {
      const r = await getWindowsBehavioralResults({ projectId });
      setResult(r);
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!activeProject?.id) {
      setLoading(false);
      return;
    }
    loadLatest(activeProject.id);
  }, [activeProject?.id, loadLatest]);

  const handleRun = async () => {
    setRunning(true);
    setError("");
    try {
      await runWindowsBehavioralAnalysis({
        project_id: activeProject?.id,
        window_minutes: windowMinutes,
        start_ts: toIsoOrUndefined(startTs),
        end_ts: toIsoOrUndefined(endTs),
      });
      await new Promise((res) => setTimeout(res, 1000));
      await loadLatest(activeProject.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    setRunning(false);
  };

  if (!activeProject?.id) {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
        Select a project from the sidebar to view this page.
      </div>
    );
  }

  if (activeProject.project_type === "web") {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#ffa726" }}>
        <h2 style={{ margin: 0, color: "#ffa726" }}>Windows Projects Only</h2>
        <p style={{ color: "#999", marginTop: 12 }}>
          This page is for Windows EVTX projects.
        </p>
      </div>
    );
  }

  // Timeline data for chart
  const timelineWindows = (result?.windows || []).filter((w) => w.anomaly_score !== null);
  const timelineLabels = timelineWindows.map((w) => new Date(w.window_start).toLocaleTimeString());
  const timelineDatasets = [
    {
      label: "Anomaly Score",
      data: timelineWindows.map((w) => parseFloat((w.anomaly_score! * 100).toFixed(1))),
      color: "#ff8800",
      fill: false,
    },
    {
      label: "Event Count",
      data: timelineWindows.map((w) => w.event_count),
      color: "#4488ff",
      fill: false,
    },
  ];

  return (
    <div>
      <SectionHeader
        title="Anomalous Windows"
        subtitle="ML-based (Isolation Forest) anomaly detection for Windows events"
      />

      {/* Run controls */}
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
        <label style={{ color: "#777", fontSize: 11, textTransform: "uppercase", letterSpacing: 0.8 }}>Window (min)</label>
        <input
          type="number"
          min={1}
          max={60}
          value={windowMinutes}
          onChange={(e) => setWindowMinutes(Math.max(1, Math.min(60, Number(e.target.value) || 5)))}
          style={{ width: 80, background: "#111", border: "1px solid #2a2a2a", color: "#ccc", padding: "6px 8px", borderRadius: 3, fontSize: 12 }}
        />
        <label style={{ color: "#777", fontSize: 11, textTransform: "uppercase", letterSpacing: 0.8 }}>From</label>
        <input
          type="datetime-local"
          value={startTs}
          onChange={(e) => setStartTs(e.target.value)}
          style={{ background: "#111", border: "1px solid #2a2a2a", color: "#ccc", padding: "6px 8px", borderRadius: 3, fontSize: 12 }}
        />
        <label style={{ color: "#777", fontSize: 11, textTransform: "uppercase", letterSpacing: 0.8 }}>To</label>
        <input
          type="datetime-local"
          value={endTs}
          onChange={(e) => setEndTs(e.target.value)}
          style={{ background: "#111", border: "1px solid #2a2a2a", color: "#ccc", padding: "6px 8px", borderRadius: 3, fontSize: 12 }}
        />
        <Btn onClick={handleRun} disabled={running}>
          {running ? <><Spinner size={12} />&nbsp;&nbsp;RUNNING</> : "RUN ML ANALYSIS"}
        </Btn>
        <Btn onClick={() => loadLatest(activeProject.id)} disabled={loading || running} style={{ marginLeft: "auto" }}>
          REFRESH
        </Btn>
      </div>

      {error && <AlertBanner type="error" message={error} />}

      {loading && (
        <div style={{ textAlign: "center", padding: 24 }}>
          <Spinner size={18} />
        </div>
      )}

      {/* Results */}
      {result && (
        <>
          <Divider />
          <div style={{ marginBottom: 18 }}>
            <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>
              Run Summary
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
              <MetricCard label="Total Windows" value={(result.total_windows ?? 0).toLocaleString()} />
              <MetricCard label="Anomalous Windows" value={(result.anomalous_windows ?? 0).toLocaleString()} accent="#ff8800" />
              <MetricCard label="Window Size" value={`${result.window_minutes} min`} />
            </div>
          </div>

          {/* Anomaly Timeline Chart */}
          {timelineLabels.length > 0 && (
            <>
              <Divider />
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Anomaly Score Timeline
              </div>
              <div style={{ background: "#0a0a0a", borderRadius: 4, padding: 16, marginBottom: 20 }}>
                <LineChart
                  labels={timelineLabels}
                  datasets={timelineDatasets}
                  yLabel="Value"
                />
              </div>
            </>
          )}

          {/* Anomalies Summary */}
          {(result?.windows || []).length > 0 && (
            <>
              <Divider />
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Anomalies by Time Window
              </div>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1e1e1e", background: "#0a0a0a" }}>
                    {["Time Window", "Events", "Computers", "Users", "Anomaly Score", "Status"].map((h) => (
                      <th key={h} style={{ textAlign: "left", color: "#444", padding: "6px 10px", fontSize: 9, letterSpacing: 0.8, textTransform: "uppercase" }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(result.windows || [])
                    .filter((w) => w.is_anomalous)
                    .slice(0, 15)
                    .map((w, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid #111" }}>
                        <td style={{ padding: "6px 10px", color: "#c0c0c0", fontSize: 10 }}>
                          {new Date(w.window_start).toLocaleString()}
                        </td>
                        <td style={{ padding: "6px 10px", color: "#808080" }}>{w.event_count}</td>
                        <td style={{ padding: "6px 10px", color: "#808080" }}>{w.unique_computers}</td>
                        <td style={{ padding: "6px 10px", color: "#808080" }}>{w.unique_users}</td>
                        <td style={{ padding: "6px 10px", color: "#ff8800", fontWeight: "bold" }}>
                          {(w.anomaly_score ? (w.anomaly_score * 100).toFixed(1) : "N/A")}%
                        </td>
                        <td style={{ padding: "6px 10px" }}>
                          <span style={{ background: "#ff8800", color: "#000", padding: "2px 6px", borderRadius: 2, fontSize: 8, fontWeight: "bold", textTransform: "uppercase" }}>
                            Anomalous
                          </span>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </>
          )}

          {/* Status message */}
          {result?.status && (
            <div style={{ marginTop: 20, fontSize: 11, color: result.status === "ok" ? "#4caf50" : "#f0c040" }}>
              Status: {result.status.toUpperCase()}
              {result.status.includes("insufficient") && " — Not enough data for ML model"}
              {result.status.includes("unavailable") && " — scikit-learn not available"}
            </div>
          )}
        </>
      )}

      <div style={{ marginTop: 40 }}>
        <HawkinsChat
          title="Hawkins — Anomalous Windows"
          description="Ask about anomalies and behavioral patterns"
          dataSummary={result ? `${result.anomalous_windows} anomalies in ${result.total_windows} windows` : "No analysis run yet"}
          componentKey="windows-behavioral"
          helpGuide="Try: 'What time windows had the highest anomaly scores?' or 'Which computers are most anomalous?'"
        />
      </div>
    </div>
  );
}
