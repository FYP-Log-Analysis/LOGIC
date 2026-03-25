"use client";

import { useEffect, useState, useCallback } from "react";
import { getLogStatistics, type LogStatistics } from "@/lib/client";
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

export default function OverviewPage() {
  const [stats, setStats] = useState<LogStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { activeProject } = useAuthStore();
  const isWindowsProject = activeProject?.project_type === "windows";

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
  }, [activeProject?.id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

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
        <SectionHeader title="Overview" subtitle="Log statistics summary" />
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <Btn onClick={loadData} style={{ marginLeft: "auto" }}>Refresh</Btn>
        </div>
        <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
          {error ?? "No log statistics are available for this project yet."}
        </div>
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

  return (
    <div>
      <SectionHeader title="Overview" subtitle="Log statistics summary" />

      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
        <Btn onClick={loadData} disabled={loading} style={{ marginLeft: "auto" }}>Refresh</Btn>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: isWindowsProject ? "1fr" : "repeat(4, 1fr)",
          gap: 10,
          marginBottom: 24,
        }}
      >
        <MetricCard label="Total Entries" value={total_entries.toLocaleString()} />
        {!isWindowsProject && (
          <MetricCard label="Unique IPs" value={unique_ips.toLocaleString()} />
        )}
        {!isWindowsProject && (
          <MetricCard label="Bot Requests" value={bot_count.toLocaleString()} accent="#f0c040" />
        )}
        {!isWindowsProject && (
          <MetricCard label="Human Requests" value={human_count.toLocaleString()} accent="#4488ff" />
        )}
      </div>

      {hasTimestamps && (
        <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20, marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 14 }}>
            Hourly Traffic Distribution (UTC)
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(24, 1fr)", gap: 3 }}>
            {hourCounts.map((count, h) => (
              <div key={h} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                <div
                  title={`${h.toString().padStart(2, "0")}:00 - ${count.toLocaleString()} requests`}
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
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
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
            height={180}
          />
        )}
      </div>

      <Divider />

      {top_paths.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <BarChart
            title="Top Requested Paths"
            labels={top_paths.map((p) => p.request_path.length > 40 ? p.request_path.slice(0, 40) + "..." : p.request_path)}
            values={top_paths.map((p) => p.count)}
            color="#606060"
            horizontal
          />
        </div>
      )}

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
    </div>
  );
}
