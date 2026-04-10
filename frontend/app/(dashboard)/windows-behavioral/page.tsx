"use client";

import { useCallback, useEffect, useState } from "react";
import { runWindowsBehavioralAnalysis, getWindowsBehavioralResults } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import LineChart from "@/components/charts/line-chart";
import {
  WindowsSectionHeader,
  WindowsMetricCard,
  WindowsDataPanel,
  WindowsStatGrid,
  WindowsFilterControls,
  FilterInput,
  WindowsButton,
  WindowsEventTable,
  WindowsLoadingSkeleton,
  WindowsEmptyState,
  WindowsDivider,
} from "@/components/windows-ui";

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
      <WindowsEmptyState
        title="No Project Selected"
        message="Select a Windows project from the sidebar to view behavioral analysis"
      />
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

  const anomalousWindows = (result?.windows || []).filter((w) => w.is_anomalous);
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

  const topAnomalousComputers = (() => {
    const computerCounts = new Map<string, number>();
    anomalousWindows.forEach((w) => {
      const count = computerCounts.get(w.window_start) || 0;
      computerCounts.set(w.window_start, count + w.unique_computers);
    });
    return Array.from(computerCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  })();

  const avgAnomalyScore = anomalousWindows.length > 0
    ? (anomalousWindows.reduce((sum, w) => sum + (w.anomaly_score || 0), 0) / anomalousWindows.length * 100).toFixed(1)
    : "0.0";

  const tableData = anomalousWindows.slice(0, 20).map((w) => ({
    time: new Date(w.window_start).toLocaleString(),
    events: w.event_count.toLocaleString(),
    computers: w.unique_computers,
    users: w.unique_users,
    ips: w.unique_source_ips,
    score: w.anomaly_score ? `${(w.anomaly_score * 100).toFixed(1)}%` : "N/A",
  }));

  return (
    <main className="page-shell">
      <WindowsSectionHeader
        title="Anomalous Windows"
        subtitle={`${activeProject?.name} — ML-based (Isolation Forest) anomaly detection for Windows events`}
        actions={
          <WindowsButton onClick={() => loadLatest(activeProject.id)} disabled={loading || running}>
            {loading ? "LOADING..." : "REFRESH"}
          </WindowsButton>
        }
      />

      {/* Run Controls */}
      <WindowsFilterControls>
        <FilterInput
          label="Window (min)"
          type="number"
          min={1}
          max={60}
          value={windowMinutes}
          onChange={(e) => setWindowMinutes(Math.max(1, Math.min(60, Number(e.target.value) || 5)))}
          style={{ width: "100px" }}
        />
        <FilterInput
          label="From"
          type="datetime-local"
          value={startTs}
          onChange={(e) => setStartTs(e.target.value)}
        />
        <FilterInput
          label="To"
          type="datetime-local"
          value={endTs}
          onChange={(e) => setEndTs(e.target.value)}
        />
        <WindowsButton onClick={handleRun} disabled={running} style={{ marginLeft: "auto" }}>
          {running ? "RUNNING..." : "RUN ML ANALYSIS"}
        </WindowsButton>
      </WindowsFilterControls>

      {error && (
        <div style={{ padding: "12px", background: "#3d1a1a", border: "1px solid #8b3d3d", borderRadius: "4px", color: "#ff6b6b", fontSize: "11px" }}>
          {error}
        </div>
      )}

      {loading && <WindowsLoadingSkeleton count={3} height={100} />}

      {/* Results */}
      {!loading && result && (
        <>
          {/* Summary Metrics */}
          <WindowsStatGrid columns={4}>
            <WindowsMetricCard
              label="Total Windows"
              value={(result.total_windows ?? 0).toLocaleString()}
            />
            <WindowsMetricCard
              label="Anomalous Windows"
              value={(result.anomalous_windows ?? 0).toLocaleString()}
              sublabel={`${result.total_windows > 0 ? ((result.anomalous_windows / result.total_windows) * 100).toFixed(1) : 0}% of total`}
            />
            <WindowsMetricCard
              label="Window Size"
              value={`${result.window_minutes} min`}
            />
            <WindowsMetricCard
              label="Avg Anomaly Score"
              value={`${avgAnomalyScore}%`}
            />
          </WindowsStatGrid>

          <WindowsDivider />

          {/* Anomaly Timeline Chart */}
          {timelineLabels.length > 0 && (
            <WindowsDataPanel title="Anomaly Score Timeline" accent="#ff8800">
              <div style={{ background: "#0a0a0a", borderRadius: 4, padding: 16 }}>
                <LineChart
                  labels={timelineLabels}
                  datasets={timelineDatasets}
                  yLabel="Value"
                />
              </div>
            </WindowsDataPanel>
          )}

          {timelineLabels.length > 0 && <WindowsDivider />}

          {/* Anomalous Windows Table */}
          {anomalousWindows.length > 0 ? (
            <WindowsDataPanel title="Anomalous Time Windows" accent="#ff8800">
              <WindowsEventTable
                columns={[
                  { key: "time", label: "Time Window", width: "25%" },
                  { key: "events", label: "Events", width: "12%" },
                  { key: "computers", label: "Computers", width: "12%" },
                  { key: "users", label: "Users", width: "12%" },
                  { key: "ips", label: "IPs", width: "12%" },
                  { key: "score", label: "Anomaly Score", width: "15%" },
                ]}
                data={tableData}
                emptyMessage="No anomalous windows detected"
              />
            </WindowsDataPanel>
          ) : (
            <WindowsEmptyState
              title="No Anomalies Detected"
              message="All time windows appear to have normal behavioral patterns"
            />
          )}

          {/* Status Info */}
          {result?.status && result.status !== "ok" && (
            <div style={{ marginTop: 20, padding: "12px", background: "#2a2410", border: "1px solid #5a5020", borderRadius: "4px", fontSize: "11px", color: "#f0c040" }}>
              Status: {result.status.toUpperCase().replace(/_/g, " ")}
              {result.status.includes("insufficient") && " — Not enough data for ML model (need ≥5 windows)"}
              {result.status.includes("unavailable") && " — scikit-learn not available"}
            </div>
          )}
        </>
      )}

      {!loading && !result && !error && (
        <WindowsEmptyState
          title="No Analysis Results"
          message="Behavioral analysis has not been run yet for this project"
          action={
            <WindowsButton onClick={handleRun}>
              RUN ML ANALYSIS
            </WindowsButton>
          }
        />
      )}
    </main>
  );
}
