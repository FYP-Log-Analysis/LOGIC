"use client";

import { useCallback, useEffect, useState } from "react";
import {
  runWindowsBehavioralAnalysis,
  getWindowsBehavioralResults,
  getWindowsBehavioralWindowFindings,
  getWindowsBehavioralWindowEvents,
} from "@/lib/client";
import { useRouter } from "next/navigation";
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
  | "anomalousWindows"
  | "selectedWindow"
  | "sigmaFindings";

type WindowFindings = Awaited<ReturnType<typeof getWindowsBehavioralWindowFindings>>;

export default function WindowsBehavioralPage() {
  const router = useRouter();
  const { activeProject, setAssistantFocus, clearAssistantFocus } = useAuthStore();
  const isCompact = true;
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<WindowsBehavioralResult | null>(null);
  const [error, setError] = useState("");
  const [windowMinutes, setWindowMinutes] = useState(5);
  const [startTs, setStartTs] = useState("");
  const [endTs, setEndTs] = useState("");
  const [selectedWindowStart, setSelectedWindowStart] = useState<string | null>(null);
  const [selectedWindowFindings, setSelectedWindowFindings] = useState<WindowFindings | null>(null);
  const [selectedWindowLoading, setSelectedWindowLoading] = useState(false);
  const [selectedWindowError, setSelectedWindowError] = useState("");
  const [expandedDetails, setExpandedDetails] = useState<Record<DetailBlockKey, boolean>>({
    timeline: false,
    anomalousWindows: false,
    selectedWindow: false,
    sigmaFindings: false,
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
      return windows.find((w) => w.is_anomalous)?.window_start ?? windows[0].window_start;
    });
  }, [result?.windows]);

  useEffect(() => {
    if (!activeProject?.id || !selectedUploadId || !selectedWindowMinutes || !selectedWindowStart) return;

    let cancelled = false;
    setSelectedWindowLoading(true);
    setSelectedWindowError("");
    setSelectedWindowFindings(null);

    const fallbackWindow = (result?.windows || []).find((w) => w.window_start === selectedWindowStart) || null;

    getWindowsBehavioralWindowFindings({
      projectId: activeProject.id,
      uploadId: selectedUploadId,
      windowStart: selectedWindowStart,
      windowMinutes: selectedWindowMinutes,
      eventLimit: 500,
      sigmaLimit: 250,
      includeSigma: true,
      includeSigmaEntry: true,
    })
      .then((payload) => {
        if (cancelled) return;
        setSelectedWindowFindings(payload);
      })
      .catch(async () => {
        if (cancelled) return;

        // Keep the page usable if cross-detection enrichment is unavailable.
        try {
          const fallbackPayload = await getWindowsBehavioralWindowEvents({
            projectId: activeProject.id,
            uploadId: selectedUploadId,
            windowStart: selectedWindowStart,
            windowMinutes: selectedWindowMinutes,
            limit: 500,
          });
          if (cancelled) return;

          setSelectedWindowFindings({
            project_id: fallbackPayload.project_id,
            upload_id: fallbackPayload.upload_id,
            window_start: fallbackPayload.window_start,
            window_end: fallbackPayload.window_end,
            window_minutes: fallbackPayload.window_minutes,
            behavioral_window: fallbackWindow,
            total_events: fallbackPayload.total_events,
            events: fallbackPayload.events,
            sigma_matches: [],
            sigma_summary: {
              total_matches: 0,
              returned_matches: 0,
              unique_rules: 0,
              highest_severity: "none",
              severity_breakdown: {
                high: 0,
                medium: 0,
                low: 0,
              },
            },
            cross_detection: {
              is_anomalous_window: Boolean(fallbackWindow?.is_anomalous),
              has_sigma_matches: false,
              has_both: false,
            },
          });
          setSelectedWindowError("Cross-detection context is unavailable. Showing window events only.");
        } catch (fallbackError) {
          if (cancelled) return;
          setSelectedWindowFindings(null);
          setSelectedWindowError(fallbackError instanceof Error ? fallbackError.message : String(fallbackError));
        }
      })
      .finally(() => {
        if (!cancelled) setSelectedWindowLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeProject?.id, selectedUploadId, selectedWindowMinutes, selectedWindowStart, result?.windows]);

  useEffect(() => {
    if (!selectedWindowStart || !result) {
      clearAssistantFocus();
      return;
    }

    const windowRecord = (result.windows || []).find((w) => w.window_start === selectedWindowStart);
    if (!windowRecord) {
      clearAssistantFocus();
      return;
    }

    setAssistantFocus({
      id: `${result.upload_id}:${selectedWindowStart}`,
      kind: "windows_behavioral_window",
      sourcePage: "/windows-behavioral",
      title: `Behavioral Window ${new Date(selectedWindowStart).toLocaleString()}`,
      subtitle: `ANOMALY ${windowRecord.anomaly_score !== null ? `${(windowRecord.anomaly_score * 100).toFixed(1)}%` : "N/A"}`,
      severity: windowRecord.is_anomalous ? "high" : "low",
      timestamp: selectedWindowStart,
      source: "behavioral-ml",
      payload: selectedWindowFindings ?? {
        window: windowRecord,
      },
      metadata: {
        window_start: selectedWindowStart,
        event_count: windowRecord.event_count,
        unique_event_ids: windowRecord.unique_event_ids,
        unique_computers: windowRecord.unique_computers,
        unique_users: windowRecord.unique_users,
        unique_source_ips: windowRecord.unique_source_ips,
        anomaly_score: windowRecord.anomaly_score,
        is_anomalous: windowRecord.is_anomalous,
        sigma_matches: selectedWindowFindings?.sigma_summary.total_matches ?? 0,
      },
      priority: "high",
    });
  }, [clearAssistantFocus, result, selectedWindowFindings, selectedWindowStart, setAssistantFocus]);

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
  const selectedAnomalousRowIndex = selectedWindowStart
    ? anomalousWindows.findIndex((w) => w.window_start === selectedWindowStart)
    : -1;

  const selectedWindowEvents = selectedWindowFindings?.events ?? [];
  const selectedWindowTotal = selectedWindowFindings?.total_events ?? 0;
  const selectedWindowSigmaMatches = selectedWindowFindings?.sigma_matches ?? [];

  const selectedSigmaRows = selectedWindowSigmaMatches.slice(0, 100).map((match) => ({
    time: match.timestamp ? new Date(String(match.timestamp)).toLocaleString() : "—",
    severity: String(match.severity ?? "unknown").toUpperCase(),
    rule: match.rule_title ?? match.rule_id ?? "unknown",
    computer: match.computer ?? "—",
    event_id: match.event_id ?? "—",
  }));

  const selectedWindowEventsTable = selectedWindowEvents.map((evt) => ({
    timestamp: evt.timestamp ? new Date(String(evt.timestamp)).toLocaleString() : "—",
    event_id: evt.event_id ?? "—",
    channel: evt.channel ?? "—",
    computer: evt.computer ?? "—",
    user: evt.auth_user ?? "—",
    ip: evt.client_ip ?? "—",
  }));

  const openInRuleBasedDetection = () => {
    if (!selectedWindowFindings) return;
    const q = new URLSearchParams();
    q.set("source", "behavioral");
    q.set("window_start", selectedWindowFindings.window_start);
    q.set("window_end", selectedWindowFindings.window_end);
    q.set("anomalous_only", "true");
    router.push(`/windows-analysis?${q.toString()}`);
  };

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
                  onPointClick={(pointIndex) => setSelectedWindowStart(timelineWindows[pointIndex]?.window_start ?? null)}
                />
              </div>
            </WindowsDataPanel>
          )}

          {timelineLabels.length > 0 && <WindowsDivider />}

          {/* Anomalous Windows Table */}
          {anomalousWindows.length > 0 ? (
            <WindowsDataPanel
              title="Anomalous Time Windows"
              accent="#ff8800"
              actions={renderDetailsButton("anomalousWindows", "Anomalous Time Windows")}
            >
              {expandedDetails.anomalousWindows && (
                <div style={detailsBoxStyle}>
                  This view shows only flagged windows. Click a row or click a timeline point above to inspect that period and cross-check Sigma findings.
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
                selectedRowIndex={selectedAnomalousRowIndex}
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
                    This block is the drill-down view for one chosen window. It combines behavioral metrics, Sigma overlap summary, and raw events for triage.
                  </div>
                )}
                <WindowsStatGrid columns={5}>
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
                  <WindowsMetricCard
                    label="Sigma Matches"
                    value={String(selectedWindowFindings?.sigma_summary.total_matches ?? 0)}
                    sublabel={`${selectedWindowFindings?.sigma_summary.unique_rules ?? 0} unique rules`}
                  />
                </WindowsStatGrid>

                <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10, marginBottom: 10 }}>
                  <WindowsButton variant="secondary" onClick={openInRuleBasedDetection}>
                    OPEN IN RULE BASED DETECTION
                  </WindowsButton>
                </div>

                {selectedWindowError && (
                  <div style={{ padding: "12px", background: "#3d1a1a", border: "1px solid #8b3d3d", borderRadius: "4px", color: "#ff6b6b", fontSize: "11px" }}>
                    {selectedWindowError}
                  </div>
                )}

                {selectedWindowLoading ? (
                  <WindowsLoadingSkeleton count={2} height={60} />
                ) : (
                  <>
                    <WindowsDataPanel
                      title="Sigma Findings In Selected Window"
                      accent="#79a84e"
                      actions={renderDetailsButton("sigmaFindings", "Sigma Findings In Selected Window")}
                    >
                      {expandedDetails.sigmaFindings && (
                        <div style={detailsBoxStyle}>
                          These are rule-based detections that occurred in the exact selected behavioral window. Prioritize windows where anomaly and Sigma both trigger.
                        </div>
                      )}
                      <div style={{ fontSize: "11px", color: "#888", marginBottom: "6px" }}>
                        Showing {selectedSigmaRows.length.toLocaleString()} of {(selectedWindowFindings?.sigma_summary.total_matches ?? 0).toLocaleString()} sigma matches in this window.
                      </div>
                      <WindowsEventTable
                        columns={[
                          { key: "time", label: "Timestamp", width: "24%" },
                          { key: "severity", label: "Severity", width: "12%" },
                          { key: "rule", label: "Rule", width: "34%" },
                          { key: "computer", label: "Computer", width: "16%" },
                          { key: "event_id", label: "Event ID", width: "14%" },
                        ]}
                        data={selectedSigmaRows}
                        emptyMessage="No Sigma findings in this window"
                        density="compact"
                        maxHeight={isCompact ? 240 : undefined}
                      />
                    </WindowsDataPanel>

                    <WindowsDivider />
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
              {result.status.includes("insufficient") && " — Not enough data for ML model (need ≥20 windows)"}
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
