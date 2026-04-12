"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  getWindowsSigmaResults,
  getWindowsIOCs,
  getWindowsBehavioralResults,
  runWindowsSigmaAnalysis,
  getWindowsSigmaRunStatus,
  cancelWindowsSigmaRun,
  type WindowsIOCs,
} from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { DetectionDetailsPanel, type DetectionDetailsItem } from "@/components/detection-details-panel";
import {
  WindowsSectionHeader,
  WindowsMetricCard,
  WindowsDataPanel,
  WindowsStatGrid,
  WindowsFilterControls,
  FilterSelect,
  FilterInput,
  WindowsButton,
  SeverityBadge,
  WindowsEventTable,
  WindowsLoadingSkeleton,
  WindowsEmptyState,
  WindowsDivider,
  IoCBadge,
} from "@/components/windows-ui";

type WindowsSigmaResults = Awaited<ReturnType<typeof getWindowsSigmaResults>>;
type WindowsSigmaMatch = WindowsSigmaResults["matches"][number];
type WindowsBehavioralResults = Awaited<ReturnType<typeof getWindowsBehavioralResults>>;

type SortDirection = "asc" | "desc";
type SourceFilter = "all" | "sigma" | "behavioral";

type InvestigationRow = {
  id: string;
  source: "sigma" | "behavioral";
  title: string;
  timestamp?: string;
  severity: "critical" | "high" | "medium" | "low";
  computer?: string;
  event_id?: string | number;
  channel?: string;
  anomaly_score?: number | null;
  rule_id?: string;
  mitre_techniques?: Array<{ technique_id?: string; name?: string; tactic?: string }>;
  payload: Record<string, unknown>;
};

const severityOrder: Record<InvestigationRow["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const DEFAULT_COLUMNS = ["timestamp", "source", "severity", "title", "computer", "event_id", "channel", "anomaly_score"];

const EXTRA_FIELDS = ["auth_user", "client_ip", "command_line", "message", "process_name", "parent_process_name", "target_user", "logon_type"];

function normalizeSeverity(value: unknown): InvestigationRow["severity"] {
  const sev = String(value ?? "low").toLowerCase();
  if (sev === "critical" || sev === "high" || sev === "medium") return sev;
  return "low";
}

function anomalyToSeverity(score: number | null | undefined, isAnomalous: boolean): InvestigationRow["severity"] {
  if (!isAnomalous) return "low";
  const normalized = score ?? 0;
  if (normalized <= -0.6) return "critical";
  if (normalized <= -0.3) return "high";
  return "medium";
}

function readField(row: InvestigationRow, field: string): string {
  const entry = (row.payload.entry as Record<string, unknown> | undefined) ?? row.payload;

  if (field === "timestamp") return row.timestamp ? new Date(row.timestamp).toLocaleString() : "-";
  if (field === "source") return row.source.toUpperCase();
  if (field === "severity") return row.severity.toUpperCase();
  if (field === "title") return row.title;
  if (field === "computer") return row.computer || "-";
  if (field === "event_id") return row.event_id != null ? String(row.event_id) : "-";
  if (field === "channel") return row.channel || "-";
  if (field === "anomaly_score") return row.anomaly_score != null ? `${(row.anomaly_score * 100).toFixed(1)}%` : "-";

  const value = entry[field];
  if (value == null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return "[complex]";
  }
}

export default function WindowsAnalysisPage() {
  const searchParams = useSearchParams();
  const { activeProject, displayMode, setDisplayMode } = useAuthStore();
  const isCompact = displayMode === "compact";

  const [sigmaResults, setSigmaResults] = useState<WindowsSigmaResults | null>(null);
  const [behavioralResults, setBehavioralResults] = useState<WindowsBehavioralResults | null>(null);
  const [iocs, setIocs] = useState<WindowsIOCs | null>(null);

  const [loading, setLoading] = useState(false);
  const [runningSigma, setRunningSigma] = useState(false);
  const [cancellingSigma, setCancellingSigma] = useState(false);
  const [activeSigmaRunId, setActiveSigmaRunId] = useState<string | null>(null);
  const [sigmaRunStatus, setSigmaRunStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [computerFilter, setComputerFilter] = useState<string>("");
  const [eventIdFilter, setEventIdFilter] = useState<string>("");
  const [channelFilter, setChannelFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [showOnlyAnomalous, setShowOnlyAnomalous] = useState(false);
  const [windowStartFilter, setWindowStartFilter] = useState<string | null>(null);
  const [windowEndFilter, setWindowEndFilter] = useState<string | null>(null);

  const [sortKey, setSortKey] = useState<string>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [pageSize, setPageSize] = useState<number>(50);
  const [currentPage, setCurrentPage] = useState<number>(1);

  const [selectedColumns, setSelectedColumns] = useState<string[]>(DEFAULT_COLUMNS);
  const [showColumnPicker, setShowColumnPicker] = useState(false);
  const [selectedRowId, setSelectedRowId] = useState<string | null>(null);
  const [showDetailsPanel, setShowDetailsPanel] = useState(true);

  const deepLinkSource = searchParams.get("source");
  const deepLinkWindowStart = searchParams.get("window_start");
  const deepLinkWindowEnd = searchParams.get("window_end");
  const deepLinkAnomalousOnly = searchParams.get("anomalous_only") === "true";
  const isDeepLinked = Boolean(deepLinkSource || deepLinkWindowStart || deepLinkWindowEnd || deepLinkAnomalousOnly);

  const fetchResults = useCallback(async () => {
    if (!activeProject?.id) return;
    setLoading(true);
    setError(null);

    try {
      const sigmaPromise = getWindowsSigmaResults({ projectId: activeProject.id, includeEntry: true });
      const iocPromise = getWindowsIOCs({ projectId: activeProject.id });
      const behavioralPromise = getWindowsBehavioralResults({ projectId: activeProject.id }).catch(() => null);

      const [sigma, iocsData, behavioral] = await Promise.all([sigmaPromise, iocPromise, behavioralPromise]);

      setSigmaResults(sigma);
      setIocs(iocsData);
      setBehavioralResults(behavioral);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load Windows detection results");
    } finally {
      setLoading(false);
    }
  }, [activeProject?.id]);

  useEffect(() => {
    if (!activeProject?.id) return;
    fetchResults();
  }, [activeProject?.id, fetchResults]);

  useEffect(() => {
    if (!isDeepLinked) return;

    if (deepLinkSource === "behavioral" || deepLinkSource === "sigma") {
      setSourceFilter(deepLinkSource);
    }
    if (deepLinkAnomalousOnly) {
      setShowOnlyAnomalous(true);
      if (deepLinkSource !== "sigma") {
        setSourceFilter("behavioral");
      }
    }
    setWindowStartFilter(deepLinkWindowStart || null);
    setWindowEndFilter(deepLinkWindowEnd || null);
  }, [deepLinkAnomalousOnly, deepLinkSource, deepLinkWindowEnd, deepLinkWindowStart, isDeepLinked]);

  useEffect(() => {
    setCurrentPage(1);
  }, [severityFilter, sourceFilter, computerFilter, eventIdFilter, channelFilter, searchQuery, showOnlyAnomalous, windowStartFilter, windowEndFilter, pageSize, sortKey, sortDirection]);

  useEffect(() => {
    if (!activeProject?.id) return;
    const storageKey = `windows-table-columns:${activeProject.id}`;
    const saved = window.localStorage.getItem(storageKey);
    if (!saved) return;
    try {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed) && parsed.every((v) => typeof v === "string")) {
        setSelectedColumns(parsed.length > 0 ? parsed : DEFAULT_COLUMNS);
      }
    } catch {
      // ignore invalid local state
    }
  }, [activeProject?.id]);

  useEffect(() => {
    if (!activeProject?.id) return;
    const storageKey = `windows-table-columns:${activeProject.id}`;
    window.localStorage.setItem(storageKey, JSON.stringify(selectedColumns));
  }, [activeProject?.id, selectedColumns]);

  const pollSigmaRun = useCallback(async (runId: string) => {
    const maxPolls = 400;
    let polls = 0;

    while (polls < maxPolls) {
      polls += 1;
      const statusResult = await getWindowsSigmaRunStatus(runId);
      const status = String(statusResult.status ?? "unknown").toLowerCase();
      setSigmaRunStatus(`Sigma run status: ${status.toUpperCase()}`);

      if (status === "complete") {
        await fetchResults();
        setActiveSigmaRunId(null);
        return;
      }
      if (status === "cancelled") {
        setActiveSigmaRunId(null);
        return;
      }
      if (status === "failed" || status === "error") {
        setActiveSigmaRunId(null);
        throw new Error(String(statusResult.error ?? "Sigma detection failed."));
      }

      await new Promise((resolve) => setTimeout(resolve, 1500));
    }

    throw new Error("Sigma detection timed out. Check backend logs.");
  }, [fetchResults]);

  const handleRunSigmaDetection = useCallback(async () => {
    if (!activeProject?.id) return;
    setRunningSigma(true);
    setError(null);
    setSigmaRunStatus("Sigma run status: STARTING");

    try {
      const run = await runWindowsSigmaAnalysis({ project_id: activeProject.id });

      if (run.run_id) {
        setActiveSigmaRunId(String(run.run_id));
        await pollSigmaRun(String(run.run_id));
      } else {
        await fetchResults();
      }

      setSigmaRunStatus((prev) => (prev?.includes("CANCELLED") ? prev : "Sigma run status: COMPLETE"));
    } catch (err) {
      setSigmaRunStatus(null);
      setError(err instanceof Error ? err.message : "Failed to run Sigma detection");
    } finally {
      setRunningSigma(false);
      setCancellingSigma(false);
    }
  }, [activeProject?.id, fetchResults, pollSigmaRun]);

  const handleCancelSigma = useCallback(async () => {
    if (!activeSigmaRunId || cancellingSigma) return;
    setCancellingSigma(true);
    setError(null);

    try {
      await cancelWindowsSigmaRun(activeSigmaRunId);
      setSigmaRunStatus("Sigma run status: CANCELLING");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel Sigma run");
    } finally {
      setCancellingSigma(false);
    }
  }, [activeSigmaRunId, cancellingSigma]);

  const sigmaRows = useMemo((): InvestigationRow[] => {
    return (sigmaResults?.matches || []).map((match: WindowsSigmaMatch, idx) => ({
      id: `sigma:${match.rule_id || "unknown"}:${match.timestamp || "na"}:${match.computer || "na"}:${match.event_id || "na"}:${idx}`,
      source: "sigma",
      title: match.rule_title || "Unnamed Sigma Rule",
      timestamp: match.timestamp,
      severity: normalizeSeverity(match.severity),
      computer: match.computer,
      event_id: match.event_id,
      channel: match.channel,
      anomaly_score: null,
      rule_id: match.rule_id,
      mitre_techniques: (match.mitre_techniques as InvestigationRow["mitre_techniques"]) || [],
      payload: (match as unknown as Record<string, unknown>) || {},
    }));
  }, [sigmaResults?.matches]);

  const behavioralRows = useMemo((): InvestigationRow[] => {
    const windows = behavioralResults?.windows || [];
    return windows.map((windowRow, idx) => ({
      id: `behavioral:${windowRow.window_start}:${idx}`,
      source: "behavioral",
      title: windowRow.is_anomalous ? "Anomalous Time Window" : "Behavioral Baseline Window",
      timestamp: windowRow.window_start,
      severity: anomalyToSeverity(windowRow.anomaly_score, windowRow.is_anomalous),
      computer: `${windowRow.unique_computers} host(s)`,
      event_id: windowRow.unique_event_ids,
      channel: "window",
      anomaly_score: windowRow.anomaly_score,
      payload: windowRow as unknown as Record<string, unknown>,
    }));
  }, [behavioralResults?.windows]);

  const unifiedRows = useMemo(() => {
    return [...sigmaRows, ...behavioralRows];
  }, [sigmaRows, behavioralRows]);

  const dynamicFieldKeys = useMemo(() => {
    const keys = new Set<string>();
    sigmaRows.slice(0, 300).forEach((row) => {
      const entry = row.payload.entry as Record<string, unknown> | undefined;
      Object.keys(entry || {}).forEach((key) => keys.add(key));
    });
    EXTRA_FIELDS.forEach((field) => keys.add(field));
    return Array.from(keys).sort();
  }, [sigmaRows]);

  const filteredRows = useMemo(() => {
    let rows = unifiedRows;

    if (sourceFilter !== "all") {
      rows = rows.filter((row) => row.source === sourceFilter);
    }

    if (showOnlyAnomalous) {
      rows = rows.filter((row) => row.source === "behavioral" && (row.payload.is_anomalous as boolean) === true);
    }

    if (severityFilter !== "all") {
      rows = rows.filter((row) => row.severity === severityFilter);
    }

    if (computerFilter) {
      const query = computerFilter.toLowerCase();
      rows = rows.filter((row) => (row.computer || "").toLowerCase().includes(query));
    }

    if (eventIdFilter) {
      rows = rows.filter((row) => String(row.event_id || "").includes(eventIdFilter));
    }

    if (channelFilter !== "all") {
      rows = rows.filter((row) => (row.channel || "").toLowerCase() === channelFilter.toLowerCase());
    }

    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      rows = rows.filter((row) => {
        const values = [
          row.title,
          row.computer,
          row.channel,
          row.rule_id,
          readField(row, "command_line"),
          readField(row, "message"),
        ]
          .filter(Boolean)
          .map((v) => String(v).toLowerCase());
        return values.some((v) => v.includes(query));
      });
    }

    if (windowStartFilter || windowEndFilter) {
      const startTs = windowStartFilter ? new Date(windowStartFilter).getTime() : Number.NEGATIVE_INFINITY;
      const endTs = windowEndFilter ? new Date(windowEndFilter).getTime() : Number.POSITIVE_INFINITY;
      rows = rows.filter((row) => {
        if (!row.timestamp) return false;
        const rowTs = new Date(row.timestamp).getTime();
        if (Number.isNaN(rowTs)) return false;
        return rowTs >= startTs && rowTs < endTs;
      });
    }

    return rows;
  }, [unifiedRows, sourceFilter, showOnlyAnomalous, severityFilter, computerFilter, eventIdFilter, channelFilter, searchQuery, windowStartFilter, windowEndFilter]);

  const sortedRows = useMemo(() => {
    const clone = [...filteredRows];
    clone.sort((a, b) => {
      let compare = 0;

      if (sortKey === "severity") {
        compare = severityOrder[a.severity] - severityOrder[b.severity];
      } else if (sortKey === "anomaly_score") {
        compare = (a.anomaly_score ?? Number.NEGATIVE_INFINITY) - (b.anomaly_score ?? Number.NEGATIVE_INFINITY);
      } else if (sortKey === "timestamp") {
        compare = new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime();
      } else {
        compare = readField(a, sortKey).localeCompare(readField(b, sortKey));
      }

      return sortDirection === "asc" ? compare : -compare;
    });
    return clone;
  }, [filteredRows, sortKey, sortDirection]);

  const totalPages = Math.max(1, Math.ceil(sortedRows.length / pageSize));
  const currentPageRows = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedRows.slice(start, start + pageSize);
  }, [sortedRows, currentPage, pageSize]);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  const selectedRow = useMemo(() => {
    if (!selectedRowId) return null;
    return sortedRows.find((row) => row.id === selectedRowId) || null;
  }, [sortedRows, selectedRowId]);

  useEffect(() => {
    if (!isDeepLinked || sortedRows.length === 0) return;
    setSelectedRowId((prev) => {
      if (prev && sortedRows.some((row) => row.id === prev)) return prev;
      return sortedRows[0].id;
    });
  }, [isDeepLinked, sortedRows]);

  const sourceCounts = useMemo(() => {
    return {
      sigma: sigmaRows.length,
      behavioral: behavioralRows.length,
    };
  }, [sigmaRows.length, behavioralRows.length]);

  const severityCounts = useMemo(() => {
    return {
      critical: sortedRows.filter((r) => r.severity === "critical").length,
      high: sortedRows.filter((r) => r.severity === "high").length,
      medium: sortedRows.filter((r) => r.severity === "medium").length,
      low: sortedRows.filter((r) => r.severity === "low").length,
    };
  }, [sortedRows]);

  const uniqueChannels = useMemo(() => {
    const channels = new Set(unifiedRows.map((r) => r.channel).filter(Boolean));
    return Array.from(channels).sort();
  }, [unifiedRows]);

  const toggleColumn = (key: string) => {
    setSelectedColumns((prev) => {
      if (prev.includes(key)) {
        const next = prev.filter((c) => c !== key);
        return next.length > 0 ? next : prev;
      }
      return [...prev, key];
    });
  };

  const columnLabel = (key: string): string => {
    if (key === "event_id") return "Event ID";
    if (key === "anomaly_score") return "Anomaly Score";
    return key.replaceAll("_", " ").replace(/\b\w/g, (m) => m.toUpperCase());
  };

  const visibleColumns = useMemo(() => {
    return selectedColumns.map((key) => {
      if (key === "severity") {
        return {
          key,
          label: "Severity",
          width: "120px",
          sortable: true,
          render: (row: Record<string, unknown>) => (
            <SeverityBadge severity={normalizeSeverity(row.severity)} />
          ),
        };
      }

      if (key === "source") {
        return {
          key,
          label: "Source",
          width: "110px",
          sortable: true,
          render: (row: Record<string, unknown>) => {
            const source = String(row.source || "sigma");
            return (
              <span style={{
                display: "inline-block",
                border: "1px solid #2a2a2a",
                borderRadius: 3,
                padding: "3px 7px",
                fontSize: 9,
                letterSpacing: 0.7,
                textTransform: "uppercase",
                color: source === "sigma" ? "#7cb342" : "#ff8800",
                background: "#111",
              }}>{source}</span>
            );
          },
        };
      }

      if (key === "title") {
        return {
          key,
          label: "Detection",
          width: "300px",
          sortable: true,
          render: (row: Record<string, unknown>) => {
            const value = String(row.title || "-");
            return (
              <div style={{ display: "grid", gap: 4 }}>
                <div style={{ color: "#d2d2d2", fontSize: 12 }}>{value}</div>
                {Boolean(row.rule_id) && <div style={{ color: "#676767", fontSize: 10 }}>{String(row.rule_id)}</div>}
              </div>
            );
          },
        };
      }

      return {
        key,
        label: columnLabel(key),
        sortable: true,
        render: (row: Record<string, unknown>) => readField(row as InvestigationRow, key),
      };
    });
  }, [selectedColumns]);

  const handleSortChange = (key: string, direction: SortDirection) => {
    setSortKey(key);
    setSortDirection(direction);
  };

  const clearFilters = () => {
    setSeverityFilter("all");
    setSourceFilter("all");
    setComputerFilter("");
    setEventIdFilter("");
    setChannelFilter("all");
    setSearchQuery("");
    setShowOnlyAnomalous(false);
    setWindowStartFilter(null);
    setWindowEndFilter(null);
  };

  useEffect(() => {
    if (isCompact) {
      setShowDetailsPanel(false);
    }
  }, [isCompact]);

  if (!activeProject?.id) {
    return (
      <WindowsEmptyState
        title="No Project Selected"
        message="Select a Windows project from the sidebar to investigate detections."
      />
    );
  }

  if (activeProject.project_type === "web") {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#ffa726" }}>
        <h2 style={{ margin: 0, color: "#ffa726" }}>Windows Projects Only</h2>
        <p style={{ color: "#999", marginTop: 12 }}>
          This page is designed for Windows EVTX investigation.
        </p>
      </div>
    );
  }

  return (
    <main className="page-shell">
      <WindowsSectionHeader
        title="Windows Detection Explorer"
        subtitle={`${activeProject.name} — unified Sigma and behavioral detection workflow`}
        actions={
          <div style={{ display: "flex", gap: 10 }}>
            <WindowsButton
              variant={isCompact ? "secondary" : "primary"}
              onClick={() => setDisplayMode("default")}
              style={{ opacity: isCompact ? 0.7 : 1 }}
            >
              DEFAULT
            </WindowsButton>
            <WindowsButton
              variant={isCompact ? "primary" : "secondary"}
              onClick={() => setDisplayMode("compact")}
              style={{ opacity: isCompact ? 1 : 0.7 }}
            >
              COMPACT
            </WindowsButton>
            <WindowsButton onClick={handleRunSigmaDetection} disabled={runningSigma || loading}>
              {runningSigma ? "RUNNING SIGMA..." : "RUN SIGMA"}
            </WindowsButton>
            {runningSigma && activeSigmaRunId && (
              <WindowsButton variant="danger" onClick={handleCancelSigma} disabled={cancellingSigma}>
                {cancellingSigma ? "CANCELLING..." : "CANCEL"}
              </WindowsButton>
            )}
            <WindowsButton onClick={fetchResults} variant="secondary" disabled={loading || runningSigma}>
              {loading ? "LOADING..." : "REFRESH"}
            </WindowsButton>
          </div>
        }
      />

      {sigmaRunStatus && (
        <div style={{ padding: "8px 10px", background: "#101010", border: "1px solid #2a2a2a", borderRadius: 4, color: "#b7b7b7", fontSize: 11, marginBottom: 12 }}>
          {sigmaRunStatus}
        </div>
      )}

      {error && (
        <div style={{ padding: 12, background: "#3d1a1a", border: "1px solid #8b3d3d", borderRadius: 4, color: "#ff6b6b", fontSize: 11, marginBottom: 18 }}>
          {error}
        </div>
      )}

      {isDeepLinked && (windowStartFilter || windowEndFilter) && (
        <div style={{ padding: "8px 10px", background: "#101622", border: "1px solid #233750", borderRadius: 4, color: "#a9c5e1", fontSize: 11, marginBottom: 12, display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
          <span>
            Deep-link active: window filter {windowStartFilter ? new Date(windowStartFilter).toLocaleString() : "-"}
            {"  to  "}
            {windowEndFilter ? new Date(windowEndFilter).toLocaleString() : "-"}
          </span>
          <WindowsButton
            variant="secondary"
            onClick={() => {
              setWindowStartFilter(null);
              setWindowEndFilter(null);
            }}
          >
            CLEAR WINDOW FILTER
          </WindowsButton>
        </div>
      )}

      {loading && <WindowsLoadingSkeleton count={3} height={90} />}

      {!loading && (
        <>
          {isCompact ? (
            <div style={{ marginBottom: 10, color: "#8a8a8a", fontSize: 11 }}>
              Rows {sortedRows.length.toLocaleString()} • Sigma {sourceCounts.sigma.toLocaleString()} • Behavioral {sourceCounts.behavioral.toLocaleString()} • Fields {selectedColumns.length}
            </div>
          ) : (
            <>
              <WindowsStatGrid columns={4}>
                <WindowsMetricCard label="Visible Rows" value={sortedRows.length.toLocaleString()} accent="#7cb342" />
                <WindowsMetricCard label="Sigma Rows" value={sourceCounts.sigma.toLocaleString()} accent="#5b8fc8" />
                <WindowsMetricCard label="Behavioral Rows" value={sourceCounts.behavioral.toLocaleString()} accent="#8f8f8f" />
                <WindowsMetricCard label="Selected Fields" value={selectedColumns.length} accent="#5a5a5a" />
              </WindowsStatGrid>

              <WindowsDivider />
            </>
          )}

          <WindowsFilterControls>
            <FilterInput
              label="Search"
              type="text"
              placeholder="Rule, host, channel..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: isCompact ? 220 : 260 }}
            />

            <FilterSelect
              label="Source"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value as SourceFilter)}
              options={[
                { value: "all", label: "All" },
                { value: "sigma", label: "Sigma" },
                { value: "behavioral", label: "Behavioral" },
              ]}
            />

            <FilterSelect
              label="Severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              options={[
                { value: "all", label: "All" },
                { value: "critical", label: "Critical" },
                { value: "high", label: "High" },
                { value: "medium", label: "Medium" },
                { value: "low", label: "Low" },
              ]}
            />

            <FilterSelect
              label="Channel"
              value={channelFilter}
              onChange={(e) => setChannelFilter(e.target.value)}
              options={[{ value: "all", label: "All" }, ...uniqueChannels.map((ch) => ({ value: ch || "", label: ch || "unknown" }))]}
            />

            <FilterInput
              label="Host"
              type="text"
              placeholder="Hostname"
              value={computerFilter}
              onChange={(e) => setComputerFilter(e.target.value)}
              style={{ width: isCompact ? 140 : 160 }}
            />

            <FilterInput
              label="Event"
              type="text"
              placeholder="4688"
              value={eventIdFilter}
              onChange={(e) => setEventIdFilter(e.target.value)}
              style={{ width: isCompact ? 100 : 120 }}
            />

            <label style={{ display: "flex", alignItems: "center", gap: 7, color: "var(--foreground)", fontSize: 11 }}>
              <input
                type="checkbox"
                checked={showOnlyAnomalous}
                onChange={(e) => setShowOnlyAnomalous(e.target.checked)}
              />
              Anomalies
            </label>

            <div style={{ position: "relative" }}>
              <WindowsButton variant="secondary" onClick={() => setShowColumnPicker((v) => !v)}>
                Fields
              </WindowsButton>
              {showColumnPicker && (
                <div style={{
                  position: "absolute",
                  top: "110%",
                  left: 0,
                  width: 290,
                  maxHeight: 320,
                  overflowY: "auto",
                  background: "#0f0f0f",
                  border: "1px solid #2a2a2a",
                  borderRadius: 4,
                  padding: 10,
                  zIndex: 20,
                }}>
                  <div style={{ color: "#7b7b7b", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.7, marginBottom: 8 }}>
                    Core Fields
                  </div>
                  {[...DEFAULT_COLUMNS, ...dynamicFieldKeys].map((field) => (
                    <label key={field} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", color: "#c8c8c8", fontSize: 11 }}>
                      <input
                        type="checkbox"
                        checked={selectedColumns.includes(field)}
                        onChange={() => toggleColumn(field)}
                      />
                      {columnLabel(field)}
                    </label>
                  ))}
                </div>
              )}
            </div>

            <FilterSelect
              label="Rows"
              value={String(pageSize)}
              onChange={(e) => setPageSize(Number(e.target.value) || 50)}
              options={[
                { value: "25", label: "25" },
                { value: "50", label: "50" },
                { value: "100", label: "100" },
                { value: "200", label: "200" },
                { value: "400", label: "400" },
              ]}
            />

            <WindowsButton variant="secondary" onClick={() => setShowDetailsPanel((prev) => !prev)}>
              {showDetailsPanel ? "Hide" : "Details"}
            </WindowsButton>

            <WindowsButton variant="secondary" onClick={clearFilters}>
              Reset
            </WindowsButton>

            <div style={{ marginLeft: "auto", color: "var(--muted-text)", fontSize: 11 }}>
              Pg {currentPage}/{totalPages} • {currentPageRows.length} of {sortedRows.length}
            </div>
          </WindowsFilterControls>

          <WindowsDataPanel title="Detection Results">
            <div style={{ display: "grid", gridTemplateColumns: showDetailsPanel ? (isCompact ? "minmax(0, 1fr) minmax(280px, 340px)" : "minmax(0, 2.4fr) minmax(320px, 1fr)") : "minmax(0, 1fr)", gap: 12 }}>
              <div style={{ minWidth: 0 }}>
                <WindowsEventTable
                  columns={visibleColumns}
                  data={currentPageRows as unknown as Array<Record<string, unknown>>}
                  onRowClick={(row) => setSelectedRowId(String(row.id || ""))}
                  rowKey={(row) => String(row.id || "")}
                  selectedRowKey={selectedRowId ?? undefined}
                  emptyMessage="No detections found for the current filters"
                  density="compact"
                  maxHeight={isCompact ? 700 : 560}
                  stickyHeader
                  sortKey={sortKey}
                  sortDirection={sortDirection}
                  onSortChange={handleSortChange}
                />

                <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
                  <WindowsButton variant="secondary" disabled={currentPage <= 1} onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}>
                    PREV
                  </WindowsButton>
                  <WindowsButton variant="secondary" disabled={currentPage >= totalPages} onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}>
                    NEXT
                  </WindowsButton>
                </div>
              </div>

              {showDetailsPanel && (
                <DetectionDetailsPanel
                  compact={isCompact}
                  item={selectedRow ? ({
                    id: selectedRow.id,
                    source: selectedRow.source,
                    title: selectedRow.title,
                    severity: selectedRow.severity,
                    timestamp: selectedRow.timestamp,
                    computer: selectedRow.computer,
                    eventId: selectedRow.event_id,
                    channel: selectedRow.channel,
                    anomalyScore: selectedRow.anomaly_score,
                    mitreTechniques: selectedRow.mitre_techniques,
                    payload: selectedRow.payload,
                  } as DetectionDetailsItem) : null}
                />
              )}
            </div>
          </WindowsDataPanel>

          {!isCompact && (
            <>
              <WindowsDivider />

              <WindowsDataPanel title="Severity Snapshot" accent="#5f5f5f">
                <WindowsStatGrid columns={4}>
                  <WindowsMetricCard label="Critical" value={severityCounts.critical} accent="#8b3a3a" />
                  <WindowsMetricCard label="High" value={severityCounts.high} accent="#8c6a36" />
                  <WindowsMetricCard label="Medium" value={severityCounts.medium} accent="#7a7a52" />
                  <WindowsMetricCard label="Low" value={severityCounts.low} accent="#4d6c7f" />
                </WindowsStatGrid>
              </WindowsDataPanel>
            </>
          )}

          {!isCompact && iocs && iocs.total_iocs > 0 && (
            <>
              <WindowsDivider />
              <WindowsDataPanel title="IOC Highlights" accent="#ff8800">
                <div style={{ display: "grid", gap: 12 }}>
                  {iocs.ips.length > 0 && (
                    <div>
                      <div style={{ color: "#6f6f6f", fontSize: 10, textTransform: "uppercase", marginBottom: 8 }}>IP Addresses</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                        {iocs.ips.slice(0, 12).map((ip) => (
                          <IoCBadge key={ip} type="ip" value={ip} />
                        ))}
                      </div>
                    </div>
                  )}
                  {iocs.users.length > 0 && (
                    <div>
                      <div style={{ color: "#6f6f6f", fontSize: 10, textTransform: "uppercase", marginBottom: 8 }}>Users</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                        {iocs.users.slice(0, 10).map((user) => (
                          <IoCBadge key={user} type="user" value={user} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </WindowsDataPanel>
            </>
          )}
        </>
      )}
    </main>
  );
}
