"use client";

import { useCallback, useEffect, useState } from "react";
import {
  runWindowsBehavioralAnalysis,
  getWindowsBehavioralResults,
  getWindowsBehavioralWindowEvents,
} from "@/lib/client";
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

type DetailBlockKey =
  | "timeline"
  | "allWindows"
  | "anomalousWindows"
  | "selectedWindow";

export default function WindowsBehavioralPage() {
  const { activeProject } = useAuthStore();
  const isCompact = true;
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<WindowsBehavioralResult | null>(null);
  const [error, setError] = useState("");
  const [windowMinutes, setWindowMinutes] = useState(5);
  const [startTs, setStartTs] = useState("");
  const [endTs, setEndTs] = useState("");
  const [selectedWindowStart, setSelectedWindowStart] = useState<string | null>(null);
  const [selectedWindowEvents, setSelectedWindowEvents] = useState<Array<Record<string, unknown>>>([]);
  const [selectedWindowTotal, setSelectedWindowTotal] = useState(0);
  const [selectedWindowLoading, setSelectedWindowLoading] = useState(false);
  const [selectedWindowError, setSelectedWindowError] = useState("");
  const [expandedDetails, setExpandedDetails] = useState<Record<DetailBlockKey, boolean>>({
    timeline: false,
    allWindows: false,
    anomalousWindows: false,
    selectedWindow: false,
  });

  const detailsBoxStyle: React.CSSProperties = {
    marginBottom: 10,
    padding: "8px 10px",
    background: "#10151a",
    border: "1px solid #233241",
    borderRadius: 4,
    color: "#9ab7d3",
    fontSize: 11,
    lineHeight: 1.55,
  };

  const renderDetailsButton = (key: DetailBlockKey, label: string) => (
    <button
      type="button"
      onClick={() => setExpandedDetails((prev) => ({ ...prev, [key]: !prev[key] }))}
      aria-label={`Toggle details for ${label}`}
      style={{
        border: "1px solid #2a3948",
        background: expandedDetails[key] ? "#1f3346" : "#11161b",
        color: expandedDetails[key] ? "#d6e7f8" : "#9bb5cc",
        borderRadius: 3,
        padding: "4px 8px",
        fontSize: 10,
        letterSpacing: 0.4,
        textTransform: "uppercase",
        cursor: "pointer",
      }}
    >
      {expandedDetails[key] ? "Hide Details" : "Details"}
    </button>
  );

  const toIsoOrUndefined = (value: string): string | undefined => {
    if (!value) return undefined;
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return undefined;
    return dt.toISOString();
  };

  const selectedUploadId = result?.upload_id;
  const selectedWindowMinutes = result?.window_minutes;

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

  useEffect(() => {
    const windows = result?.windows || [];
    if (windows.length === 0) {
      setSelectedWindowStart(null);
      return;
    }
    setSelectedWindowStart((prev) => {
      if (prev && windows.some((w) => w.window_start === prev)) return prev;
      return windows[0].window_start;
    });
  }, [result?.windows]);

  useEffect(() => {
    if (!activeProject?.id || !selectedUploadId || !selectedWindowMinutes || !selectedWindowStart) return;

    let cancelled = false;
    setSelectedWindowLoading(true);
    setSelectedWindowError("");

    getWindowsBehavioralWindowEvents({
      projectId: activeProject.id,
      uploadId: selectedUploadId,
      windowStart: selectedWindowStart,
      windowMinutes: selectedWindowMinutes,
      limit: 250,
    })
      .then((payload) => {
        if (cancelled) return;
        setSelectedWindowEvents((payload.events ?? []) as Array<Record<string, unknown>>);
        setSelectedWindowTotal(payload.total_events ?? 0);
      })
      .catch((e) => {
        if (cancelled) return;
        setSelectedWindowEvents([]);
        setSelectedWindowTotal(0);
        setSelectedWindowError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!cancelled) setSelectedWindowLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeProject?.id, selectedUploadId, selectedWindowMinutes, selectedWindowStart]);

  const handleRun = async () => {
    if (!activeProject?.id) return;

    setRunning(true);
    setError("");
    try {
      await runWindowsBehavioralAnalysis({
        project_id: activeProject.id,
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

  const allWindows = result?.windows || [];
  const anomalousWindows = allWindows.filter((w) => w.is_anomalous);
  const timelineWindows = allWindows.filter((w) => w.anomaly_score !== null);
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

  const avgAnomalyScore = anomalousWindows.length > 0
    ? (anomalousWindows.reduce((sum, w) => sum + (w.anomaly_score || 0), 0) / anomalousWindows.length * 100).toFixed(1)
    : "0.0";

  const allWindowsTableData = allWindows.map((w) => ({
    time: new Date(w.window_start).toLocaleString(),
    events: w.event_count.toLocaleString(),
    computers: w.unique_computers,
    users: w.unique_users,
    ips: w.unique_source_ips,
    score: w.anomaly_score !== null ? `${(w.anomaly_score * 100).toFixed(1)}%` : "N/A",
    anomaly: w.is_anomalous ? "YES" : "NO",
  }));

  const anomalousTableData = anomalousWindows.slice(0, 50).map((w) => ({
    time: new Date(w.window_start).toLocaleString(),
    events: w.event_count.toLocaleString(),
    computers: w.unique_computers,
    users: w.unique_users,
    ips: w.unique_source_ips,
    score: w.anomaly_score !== null ? `${(w.anomaly_score * 100).toFixed(1)}%` : "N/A",
  }));

  const selectedWindow = selectedWindowStart
    ? allWindows.find((w) => w.window_start === selectedWindowStart) || null
    : null;
  const selectedWindowRowIndex = selectedWindowStart
    ? allWindows.findIndex((w) => w.window_start === selectedWindowStart)
    : -1;

  const selectedWindowEventsTable = selectedWindowEvents.map((evt) => ({
    timestamp: evt.timestamp ? new Date(String(evt.timestamp)).toLocaleString() : "—",
    event_id: evt.event_id ?? "—",
    channel: evt.channel ?? "—",
    computer: evt.computer ?? "—",
    user: evt.auth_user ?? "—",
    ip: evt.client_ip ?? "—",
  }));

  return (
    <main className="page-shell">
      <WindowsSectionHeader
        title="Anomalous Windows"
        subtitle={`${activeProject?.name} — ML-based (Isolation Forest) anomaly detection for Windows events`}
        actions={
          <div style={{ display: "flex", gap: 10 }}>
            <WindowsButton onClick={() => loadLatest(activeProject.id)} disabled={loading || running}>
              {loading ? "LOADING..." : "REFRESH"}
            </WindowsButton>
          </div>
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
          style={{ width: isCompact ? "86px" : "100px" }}
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
          <div style={{ marginBottom: 10, color: "#8a8a8a", fontSize: 11 }}>
            Windows {result.total_windows.toLocaleString()} • Anomalous {result.anomalous_windows.toLocaleString()} • Window {result.window_minutes} min • Avg {avgAnomalyScore}%
          </div>

          <WindowsDivider />

          {/* Anomaly Timeline Chart */}
          {timelineLabels.length > 0 && (
            <WindowsDataPanel
              title="Anomaly Score Timeline"
              accent="#6f6f6f"
              actions={renderDetailsButton("timeline", "Anomaly Score Timeline")}
            >
              {expandedDetails.timeline && (
                <div style={detailsBoxStyle}>
                  Orange line shows anomaly score trend, blue line shows event volume per time window. When score drops while event count jumps, that window is a priority for investigation.
                </div>
              )}
              <div style={{ background: "#0a0a0a", borderRadius: 4, padding: isCompact ? 8 : 16 }}>
                <LineChart
                  labels={timelineLabels}
                  datasets={timelineDatasets}
                  yLabel="Value"
                />
              </div>
            </WindowsDataPanel>
          )}

          {timelineLabels.length > 0 && <WindowsDivider />}

          <WindowsDataPanel
            title="All Time Windows (Select To Inspect)"
            actions={renderDetailsButton("allWindows", "All Time Windows")}
          >
            {expandedDetails.allWindows && (
              <div style={detailsBoxStyle}>
                Every row is one analysis window. Click any row to load the exact raw events for that period in the Selected Window block below.
              </div>
            )}
            <div style={{ fontSize: "11px", color: "#888", marginBottom: "8px" }}>
              Click a window row to view the exact events inside that time window.
            </div>
            <WindowsEventTable
              columns={[
                { key: "time", label: "Time Window", width: "24%" },
                { key: "events", label: "Events", width: "11%" },
                { key: "computers", label: "Computers", width: "11%" },
                { key: "users", label: "Users", width: "11%" },
                { key: "ips", label: "IPs", width: "11%" },
                { key: "score", label: "Anomaly Score", width: "14%" },
                { key: "anomaly", label: "Anomalous", width: "10%" },
              ]}
              data={allWindowsTableData}
              onRowClick={(_, idx) => setSelectedWindowStart(allWindows[idx]?.window_start ?? null)}
              selectedRowIndex={selectedWindowRowIndex}
              emptyMessage="No time windows available"
              density={isCompact ? "compact" : "comfortable"}
              maxHeight={isCompact ? 360 : undefined}
            />
          </WindowsDataPanel>

          <WindowsDivider />

          {/* Anomalous Windows Table */}
          {anomalousWindows.length > 0 ? (
            <WindowsDataPanel
              title="Anomalous Time Windows"
              accent="#ff8800"
              actions={renderDetailsButton("anomalousWindows", "Anomalous Time Windows")}
            >
              {expandedDetails.anomalousWindows && (
                <div style={detailsBoxStyle}>
                  This is a filtered view of only flagged windows (highest risk first in your workflow). Use it to jump quickly to suspicious periods without scanning the full table.
                </div>
              )}
              <WindowsEventTable
                columns={[
                  { key: "time", label: "Time Window", width: "25%" },
                  { key: "events", label: "Events", width: "12%" },
                  { key: "computers", label: "Computers", width: "12%" },
                  { key: "users", label: "Users", width: "12%" },
                  { key: "ips", label: "IPs", width: "12%" },
                  { key: "score", label: "Anomaly Score", width: "15%" },
                ]}
                data={anomalousTableData}
                onRowClick={(_, idx) => setSelectedWindowStart(anomalousWindows[idx]?.window_start ?? null)}
                emptyMessage="No anomalous windows detected"
                density={isCompact ? "compact" : "comfortable"}
                maxHeight={isCompact ? 320 : undefined}
              />
            </WindowsDataPanel>
          ) : (
            <WindowsEmptyState
              title="No Anomalies Detected"
              message="All time windows appear to have normal behavioral patterns"
            />
          )}

          {selectedWindow && (
            <>
              <WindowsDivider />
              <WindowsDataPanel
                title={`Selected Window: ${new Date(selectedWindow.window_start).toLocaleString()}`}
                accent="#4488ff"
                actions={renderDetailsButton("selectedWindow", "Selected Window")}
              >
                {expandedDetails.selectedWindow && (
                  <div style={detailsBoxStyle}>
                    This block is the drill-down view for one chosen window. Top metrics summarize that window, and the table lists sampled raw events so you can validate why the model flagged it.
                  </div>
                )}
                <WindowsStatGrid columns={4}>
                  <WindowsMetricCard label="Events In Window" value={selectedWindow.event_count.toLocaleString()} />
                  <WindowsMetricCard label="Unique Event IDs" value={selectedWindow.unique_event_ids.toLocaleString()} />
                  <WindowsMetricCard
                    label="Anomaly Score"
                    value={selectedWindow.anomaly_score !== null ? `${(selectedWindow.anomaly_score * 100).toFixed(1)}%` : "N/A"}
                    sublabel={selectedWindow.anomaly_score !== null && selectedWindow.anomaly_score < 0 ? "Below zero: anomalous tendency" : "Near/above zero: normal tendency"}
                  />
                  <WindowsMetricCard
                    label="Anomaly Flag"
                    value={selectedWindow.is_anomalous ? "YES" : "NO"}
                  />
                </WindowsStatGrid>

                {selectedWindowError && (
                  <div style={{ padding: "12px", background: "#3d1a1a", border: "1px solid #8b3d3d", borderRadius: "4px", color: "#ff6b6b", fontSize: "11px" }}>
                    {selectedWindowError}
                  </div>
                )}

                {selectedWindowLoading ? (
                  <WindowsLoadingSkeleton count={2} height={60} />
                ) : (
                  <>
                    <div style={{ fontSize: "11px", color: "#888", marginBottom: "6px" }}>
                      Showing {selectedWindowEventsTable.length.toLocaleString()} of {selectedWindowTotal.toLocaleString()} events in this window.
                    </div>
                    <WindowsEventTable
                      columns={[
                        { key: "timestamp", label: "Timestamp", width: "22%" },
                        { key: "event_id", label: "Event ID", width: "10%" },
                        { key: "channel", label: "Channel", width: "20%" },
                        { key: "computer", label: "Computer", width: "16%" },
                        { key: "user", label: "User", width: "16%" },
                        { key: "ip", label: "Source IP", width: "16%" },
                      ]}
                      data={selectedWindowEventsTable}
                      emptyMessage="No events found for selected time window"
                      density="compact"
                      maxHeight={isCompact ? 360 : undefined}
                    />
                  </>
                )}
              </WindowsDataPanel>
            </>
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
