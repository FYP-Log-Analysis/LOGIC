"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { getLogStatistics, getProjectUploads, type LogStatistics } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { SectionHeader, MetricCard, Divider, Spinner, DataTable, Btn } from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import PieChart from "@/components/charts/pie-chart";

interface UploadOption {
  upload_id: string;
  filename?: string;
  started_at?: string;
  status?: string;
  entry_count?: number;
}

/** Interpolate a count (0..maxCount) into a CSS background-color string. */
function heatColor(count: number, maxCount: number): string {
  if (maxCount === 0 || count === 0) return "#111";
  const ratio = count / maxCount;
  if (ratio > 0.75) return "#7c2020";
  if (ratio > 0.5) return "#5a3010";
  if (ratio > 0.25) return "#3a3010";
  return "#1a2a18";
}

export default function LogStatisticsPage() {
  const router = useRouter();
  const [stats, setStats] = useState<LogStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [uploads, setUploads] = useState<UploadOption[]>([]);
  const [uploadId, setUploadId] = useState<string | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const { activeProject } = useAuthStore();

  useEffect(() => {
    if (activeProject?.project_type === "windows") {
      router.replace("/overview");
    }
  }, [activeProject?.project_type, router]);

  if (activeProject?.project_type === "windows") {
    return null;
  }

  // Load available uploads whenever the active project changes
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setUploadId(null);
      setUploads([]);
      if (!activeProject?.id) return;
      getProjectUploads(activeProject.id)
        .then((rows) => {
          const completed = rows.filter((r) => r.status === "complete" && r.stage === "saved");
          setUploads(completed);
          if (completed.length > 0) setUploadId(completed[0].upload_id);
        })
        .catch(() => {});
    }, 0);
    return () => window.clearTimeout(timer);
  }, [activeProject?.id]);

  // eslint-disable-next-line react-hooks/preserve-manual-memoization
  const loadData = useCallback(() => {
    if (!activeProject?.id) { setLoading(false); return; }
    setLoading(true);
    setStatsError(null);
    getLogStatistics({ projectId: activeProject.id, uploadId: uploadId ?? undefined })
      .then((d) => setStats(d))
      .catch((err) => {
        setStats(null);
        setStatsError(err instanceof Error ? err.message : "No statistics available for this project.");
      })
      .finally(() => setLoading(false));
  }, [activeProject?.id, uploadId]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      loadData();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadData]);

  // Upload selector UI
  const uploadSelector = uploads.length > 1 ? (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
      <span style={{ fontSize: 12, color: "#666", letterSpacing: 0.8, textTransform: "uppercase" }}>Upload</span>
      <select
        value={uploadId ?? ""}
        onChange={(e) => setUploadId(e.target.value || null)}
        style={{
          background: "#111", border: "1px solid #2a2a2a", color: "#ccc",
          padding: "4px 10px", borderRadius: 3, fontSize: 13, cursor: "pointer",
        }}
      >
        {uploads.map((u) => (
          <option key={u.upload_id} value={u.upload_id}>
            {u.filename ?? u.upload_id.slice(0, 8)} — {u.entry_count?.toLocaleString() ?? "?"} entries
            {u.started_at ? ` (${u.started_at.slice(0, 10)})` : ""}
          </option>
        ))}
      </select>
    </div>
  ) : null;

  if (!activeProject?.id) {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
        Select a project from the sidebar to view log statistics.
      </div>
    );
  }

  if (loading) return <div style={{ textAlign: "center", padding: 60 }}><Spinner size={28} /></div>;

  const hasStats = !!stats && (
    stats.total_entries > 0 ||
    stats.unique_ips > 0 ||
    stats.top_ips.length > 0 ||
    stats.top_paths.length > 0 ||
    stats.top_user_agents.length > 0 ||
    Object.values(stats.status_classes).some((count) => count > 0) ||
    Object.values(stats.hourly_heatmap).some((count) => count > 0)
  );

  if (!hasStats) {
    return (
      <div>
        <SectionHeader title="Log Statistics" subtitle="Distribution analysis of ingested and normalised log data" />
        {uploadSelector}
        <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
          {statsError ?? (uploads.length === 0
            ? "No statistics are available for this project yet. Upload and process log files first."
            : "No statistics are available for the selected scope yet.")}
        </div>
        <Btn onClick={loadData}>Refresh</Btn>
      </div>
    );
  }

  if (!stats) return null;

  const { total_entries, unique_ips, hourly_heatmap, top_ips, top_paths, top_user_agents, status_classes, bot_count, human_count } = stats;

  const statusColors: Record<string, string> = { "2xx": "#4caf50", "3xx": "#4488ff", "4xx": "#f0c040", "5xx": "#ff4444", other: "#555" };
  const statusFiltered = (["2xx", "3xx", "4xx", "5xx", "other"] as const).filter((k) => (status_classes[k] ?? 0) > 0);

  // Hourly heatmap — the backend returns integer keys (hour of day 0-23)
  const hourCounts = Array.from({ length: 24 }, (_, h) => hourly_heatmap[h] ?? hourly_heatmap[String(h)] ?? 0);
  const maxHour = Math.max(...hourCounts, 1);
  const hasTimestamps = hourCounts.some((c) => c > 0);

  return (
    <div>
      <SectionHeader
        title="Log Statistics"
        subtitle="Distribution analysis of ingested and normalised log data"
      />

      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
        {uploadSelector}
        <Btn onClick={loadData} disabled={loading} style={{ marginLeft: "auto" }}>Refresh</Btn>
      </div>

      {/* Top metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 24 }}>
        <MetricCard label="Total Entries" value={total_entries.toLocaleString()} />
        <MetricCard label="Unique IPs" value={unique_ips.toLocaleString()} />
        <MetricCard label="Bot Requests" value={bot_count.toLocaleString()} accent="#f0c040" />
        <MetricCard label="Human Requests" value={human_count.toLocaleString()} accent="#4488ff" />
      </div>

      {/* Hourly Heatmap */}
      {hasTimestamps && (
        <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20, marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 14 }}>
            Hourly Traffic Distribution (UTC) — request volume per hour of day
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(24, 1fr)", gap: 3 }}>
            {hourCounts.map((count, h) => (
              <div key={h} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                <div
                  title={`${h.toString().padStart(2, "0")}:00 — ${count.toLocaleString()} requests`}
                  style={{
                    width: "100%",
                    height: 48,
                    background: heatColor(count, maxHour),
                    borderRadius: 2,
                    border: "1px solid #1a1a1a",
                    cursor: "default",
                  }}
                />
                <span style={{ fontSize: 9, color: "#333", letterSpacing: 0 }}>{h.toString().padStart(2, "0")}</span>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 10, alignItems: "center" }}>
            <span style={{ fontSize: 10, color: "#333" }}>Low</span>
            {["#1a2a18", "#3a3010", "#5a3010", "#7c2020"].map((c) => (
              <div key={c} style={{ width: 16, height: 10, background: c, borderRadius: 2 }} />
            ))}
            <span style={{ fontSize: 10, color: "#333" }}>High</span>
          </div>
        </div>
      )}

      {/* Charts row 1: Status Classes + Bot vs Human */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        {statusFiltered.length > 0 && (
          <PieChart
            title="Status Code Classes"
            labels={statusFiltered.map((k) => k === "2xx" ? "2xx Success" : k === "3xx" ? "3xx Redirect" : k === "4xx" ? "4xx Client Error" : k === "5xx" ? "5xx Server Error" : "Other")}
            values={statusFiltered.map((k) => status_classes[k])}
            colors={statusFiltered.map((k) => statusColors[k] ?? "#555")}
          />
        )}
        <PieChart
          title="Bot vs Human"
          labels={["Human", "Bot"]}
          values={[human_count, bot_count]}
          colors={["#4488ff", "#f0c040"]}
          height={180}
        />
      </div>

      <Divider />

      {/* Top Paths */}
      {top_paths.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <BarChart
            title="Top Requested Paths"
            labels={top_paths.map((p) => p.request_path.length > 40 ? p.request_path.slice(0, 40) + "…" : p.request_path)}
            values={top_paths.map((p) => p.count)}
            color="#606060"
            horizontal
          />
        </div>
      )}

      {/* Top IPs */}
      {top_ips.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <BarChart
            title="Top Source IPs"
            labels={top_ips.map((p) => p.client_ip)}
            values={top_ips.map((p) => p.request_count)}
            color="#484848"
            horizontal
          />
        </div>
      )}

      <Divider />

      {/* Top User-Agents */}
      {top_user_agents.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
            Top User-Agent Strings
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
                <th style={{ textAlign: "left", color: "#444", padding: "5px 8px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>User-Agent</th>
                <th style={{ textAlign: "right", color: "#444", padding: "5px 8px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>Requests</th>
              </tr>
            </thead>
            <tbody>
              {top_user_agents.map((ua, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #0f0f0f" }}>
                  <td style={{ padding: "6px 8px", color: "#808080", fontSize: 11, maxWidth: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={ua.user_agent}>
                    {ua.user_agent || "—"}
                  </td>
                  <td style={{ padding: "6px 8px", color: "#555", textAlign: "right", fontFamily: "monospace", fontSize: 11 }}>
                    {ua.count.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Top Paths Detail Table */}
      {top_paths.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
            Top Paths Detail
          </div>
          <DataTable
            columns={["Path", "Requests"]}
            rows={top_paths.map((p) => [p.request_path, p.count.toLocaleString()])}
          />
        </div>
      )}
    </div>
  );
}
