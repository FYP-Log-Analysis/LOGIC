"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import {
  getLogStatistics,
  getWindowsSigmaRuleDetail,
  getWindowsSigmaRules,
  type LogStatistics,
  type WindowsSigmaRuleSummary,
} from "@/lib/client";
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
  const [sigmaRuleCatalog, setSigmaRuleCatalog] = useState<WindowsSigmaRuleSummary[]>([]);
  const [sigmaRuleLoading, setSigmaRuleLoading] = useState(false);
  const [sigmaRuleError, setSigmaRuleError] = useState<string | null>(null);
  const [ruleViewLoading, setRuleViewLoading] = useState(false);
  const [selectedRule, setSelectedRule] = useState<{ rule: WindowsSigmaRuleSummary; yaml: string } | null>(null);
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
  }, [activeProject]);

  const loadSigmaRules = useCallback(() => {
    if (!isWindowsProject) {
      setSigmaRuleCatalog([]);
      setSigmaRuleLoading(false);
      setSigmaRuleError(null);
      return;
    }

    setSigmaRuleLoading(true);
    setSigmaRuleError(null);
    getWindowsSigmaRules()
      .then((catalog) => setSigmaRuleCatalog(catalog.rules || []))
      .catch((e) => {
        setSigmaRuleCatalog([]);
        setSigmaRuleError(e instanceof Error ? e.message : "Failed to load Sigma rules.");
      })
      .finally(() => setSigmaRuleLoading(false));
  }, [isWindowsProject]);

  const openRuleView = useCallback(async (rulePath: string) => {
    setRuleViewLoading(true);
    try {
      const detail = await getWindowsSigmaRuleDetail(rulePath);
      setSelectedRule(detail);
    } catch (e) {
      setSigmaRuleError(e instanceof Error ? e.message : "Failed to load Sigma rule details.");
    } finally {
      setRuleViewLoading(false);
    }
  }, []);

  const sigmaRulesByFolder = useMemo(() => {
    const grouped = new Map<string, WindowsSigmaRuleSummary[]>();
    for (const rule of sigmaRuleCatalog) {
      const rawPath = (rule.rule_path || "").replace(/\\/g, "/").replace(/^\/+/, "");
      const lastSlash = rawPath.lastIndexOf("/");
      const folder = lastSlash > -1 ? rawPath.slice(0, lastSlash) : "(root)";
      const bucket = grouped.get(folder) ?? [];
      bucket.push(rule);
      grouped.set(folder, bucket);
    }

    return Array.from(grouped.entries())
      .map(([folder, rules]) => ({
        folder,
        rules: [...rules].sort((a, b) => (a.rule_path || "").localeCompare(b.rule_path || "")),
      }))
      .sort((a, b) => a.folder.localeCompare(b.folder));
  }, [sigmaRuleCatalog]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      loadData();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadData]);

  useEffect(() => {
    loadSigmaRules();
  }, [loadSigmaRules]);

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
        <Btn onClick={loadData} disabled={loading} style={{ marginLeft: "auto" }}>Refresh</Btn>
      </div>

      {isWindowsProject && (
        <div className="section-block">
          <div className="surface-panel" style={{ minHeight: 0, overflow: "auto" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px", marginBottom: "10px" }}>
              <h3 style={{ margin: 0, color: "#7cb342", fontSize: "12px", fontWeight: "bold", textTransform: "uppercase", letterSpacing: "0.8px" }}>
                Sigma Rule Library
              </h3>
              <div style={{ color: "#6f6f6f", fontSize: "11px" }}>{sigmaRuleCatalog.length} rules</div>
            </div>

            {sigmaRuleLoading && (
              <div style={{ color: "#666", fontSize: "11px", padding: "8px 0" }}>Loading Sigma rules...</div>
            )}

            {!sigmaRuleLoading && sigmaRuleError && (
              <div style={{ color: "#ff8a80", fontSize: "11px", padding: "8px 0" }}>{sigmaRuleError}</div>
            )}

            {!sigmaRuleLoading && !sigmaRuleError && sigmaRuleCatalog.length === 0 && (
              <div style={{ color: "#666", fontSize: "11px", padding: "8px 0" }}>No Sigma rules found.</div>
            )}

            {!sigmaRuleLoading && sigmaRuleCatalog.length > 0 && (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "320px", overflowY: "auto" }}>
                {sigmaRulesByFolder.map((group) => (
                  <div key={group.folder} style={{ border: "1px solid #1f1f1f", borderRadius: "4px", background: "#090909", padding: "8px" }}>
                    <div style={{ color: "#7cb342", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: "8px", fontFamily: "monospace" }}>
                      data/sigma_rules/{group.folder === "(root)" ? "" : group.folder} · {group.rules.length} file{group.rules.length === 1 ? "" : "s"}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {group.rules.map((rule) => (
                        <div
                          key={rule.rule_path}
                          style={{
                            border: "1px solid #1f1f1f",
                            borderRadius: "4px",
                            background: "#0b0b0b",
                            padding: "10px",
                            display: "flex",
                            alignItems: "center",
                            gap: "10px",
                          }}
                        >
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ color: "#d0d0d0", fontSize: "12px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontFamily: "monospace" }}>
                              {rule.rule_path.split("/").pop() || rule.rule_path}
                            </div>
                            <div style={{ color: "#707070", fontSize: "11px", marginTop: "3px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontFamily: "monospace" }}>
                              {rule.rule_path}
                            </div>
                            <div style={{ color: "#707070", fontSize: "11px", marginTop: "2px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              {rule.id} · {rule.level} · {rule.title}
                            </div>
                          </div>
                          <button
                            onClick={() => openRuleView(rule.rule_path)}
                            disabled={ruleViewLoading}
                            style={{
                              border: "1px solid #355a3b",
                              color: "#7cb342",
                              background: "#101a10",
                              fontSize: "11px",
                              borderRadius: "4px",
                              padding: "6px 10px",
                              cursor: ruleViewLoading ? "not-allowed" : "pointer",
                            }}
                          >
                            VIEW
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

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
          {!isWindowsProject && <MetricCard label="Bot Requests" value={bot_count.toLocaleString()} accent="#f0c040" />}
          {!isWindowsProject && <MetricCard label="Human Requests" value={human_count.toLocaleString()} accent="#4488ff" />}
          {isWindowsProject && <MetricCard label="Top Path Hits" value={topPathCount.toLocaleString()} sub="Most requested endpoint volume" accent="#7cb342" />}
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
              colors={["#4488ff", "#f0c040"]}
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
            color="#606060"
            horizontal
          />
        )}

        {!isWindowsProject && top_ips.length > 0 && (
          <BarChart
            title="Top Source IPs"
            labels={top_ips.map((p) => p.client_ip)}
            values={top_ips.map((p) => p.request_count)}
            color="#484848"
            horizontal
          />
        )}
      </div>

      {selectedRule && (
        <div
          onClick={() => setSelectedRule(null)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.72)",
            zIndex: 1300,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "18px",
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: "min(900px, 96vw)",
              maxHeight: "88vh",
              overflowY: "auto",
              borderRadius: "6px",
              border: "1px solid #254226",
              background: "#090d09",
              padding: "14px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px", marginBottom: "10px" }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ color: "#7cb342", fontSize: "13px", fontWeight: "bold" }}>{selectedRule.rule.title}</div>
                <div style={{ color: "#79907d", fontSize: "11px", marginTop: "2px" }}>
                  {selectedRule.rule.id} · {selectedRule.rule.level} · {selectedRule.rule.rule_path}
                </div>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                style={{ border: "1px solid #355a3b", color: "#7cb342", background: "#101a10", fontSize: "11px", borderRadius: "2px", padding: "5px 9px", cursor: "pointer" }}
              >
                CLOSE
              </button>
            </div>

            {selectedRule.rule.description && (
              <p style={{ margin: "0 0 10px", color: "#98a398", fontSize: "11px" }}>{selectedRule.rule.description}</p>
            )}

            <pre
              style={{
                margin: 0,
                background: "#060806",
                border: "1px solid #1b2a1c",
                borderRadius: "4px",
                padding: "10px",
                color: "#d3dfd3",
                fontSize: "11px",
                lineHeight: 1.45,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {selectedRule.yaml}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
