"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import {
  getBehavioralDefaults,
  getBehavioralResults,
  runBehavioralAnalysis,
  type BehavioralDefaults,
} from "@/lib/client";
import { ApiError } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import {
  SectionHeader,
  MetricCard,
  Btn,
  Tabs,
  SelectInput,
  Spinner,
} from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import ScatterChart from "@/components/charts/scatter-chart";
import LineChart from "@/components/charts/line-chart";

// ─── Types ────────────────────────────────────────────────────────────────────

interface RateSpike { ip?: string; client_ip?: string; window?: string; window_start?: string; count?: number; request_count?: number; rate?: number; is_anomaly?: boolean; timestamp?: string; }
interface UrlEnum { ip?: string; client_ip?: string; unique_paths?: number; distinct_paths?: number; total_requests?: number; window_start?: string; is_anomaly?: boolean; paths?: string[]; sample_paths?: string[]; }
interface StatusSpike { window?: string; window_start?: string; status?: number | string; count?: number; rate?: number; error_ratio?: number; error_count?: number; total_requests?: number; is_anomaly?: boolean; timestamp?: string; }
interface VisitorRate { ip?: string; window?: string; hour?: string; requests?: number; total_requests?: number; unique_visitors?: number; mean?: number; mean_visitors?: number; z_score?: number; flag?: string; is_anomaly?: boolean; timestamp?: string; }

interface BehavioralData {
  request_rate_spikes?: RateSpike[];
  url_enumeration?: UrlEnum[];
  status_code_spikes?: StatusSpike[];
  visitor_rates?: VisitorRate[];
  summary?: {
    total_rate_spikes?: number;
    total_url_enumerators?: number;
    total_status_spikes?: number;
    analysis_window?: string;
    total_rate_spike_windows?: number;
    total_enumeration_alerts?: number;
    total_status_spike_windows?: number;
    total_visitor_anomaly_hours?: number;
  };
}

const FALLBACK_DEFAULTS: BehavioralDefaults = {
  rate_window_minutes: 1,
  rate_threshold: 60,
  enum_window_hours: 1,
  enum_threshold: 50,
  status_window_minutes: 5,
  status_error_ratio: 0.5,
  visitor_zscore: 2,
};

type FeedCategory = "Rate Spike" | "URL Enumeration" | "Status Spike" | "Visitor Anomaly";
type FeedSeverity = "high" | "medium" | "low";

interface AnomalyFeedItem {
  id: string;
  category: FeedCategory;
  severity: FeedSeverity;
  score: number;
  ip: string;
  signal: string;
  details: string;
  whenLabel: string;
  whenTs: number;
}

const SEVERITY_COLORS: Record<FeedSeverity, string> = {
  high: "#ff4444",
  medium: "#f0c040",
  low: "#6e8796",
};

function formatBehavioralError(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    if (e.status === 404) return "No behavioral results yet. Run analysis first.";
    if (e.status === 401) return "Your session expired. Please sign in again.";
    if (e.status && e.status >= 500) return `Server error (${e.status}). Please try again.`;
    return e.message || fallback;
  }
  if (e instanceof Error) return e.message || fallback;
  return fallback;
}

function toSeverity(score: number): FeedSeverity {
  if (score >= 70) return "high";
  if (score >= 55) return "medium";
  return "low";
}

function clampScore(v: number): number {
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(99, Math.round(v)));
}

function parseWhen(raw?: string): { label: string; ts: number } {
  if (!raw) return { label: "Unknown", ts: 0 };
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return { label: raw, ts: 0 };
  return {
    label: `${dt.toLocaleDateString()} ${dt.toLocaleTimeString()}`,
    ts: dt.getTime(),
  };
}

function buildAnomalyFeed(data: BehavioralData | null): AnomalyFeedItem[] {
  if (!data) return [];
  const items: AnomalyFeedItem[] = [];

  (data.request_rate_spikes ?? []).forEach((r, idx) => {
    const isAnomaly = r.is_anomaly ?? true;
    if (!isAnomaly) return;
    const ip = r.ip ?? r.client_ip ?? "Unknown";
    const count = r.count ?? r.request_count ?? 0;
    const rate = r.rate ?? count;
    const score = clampScore(40 + Math.min(rate, 700) * 0.08 + Math.min(count, 700) * 0.03);
    const when = parseWhen(r.window_start ?? r.window ?? r.timestamp);
    items.push({
      id: `rate-${idx}-${ip}-${when.ts}`,
      category: "Rate Spike",
      severity: toSeverity(score),
      score,
      ip,
      signal: `${count.toLocaleString()} req`,
      details: `window rate ${Number(rate).toFixed(1)}`,
      whenLabel: when.label,
      whenTs: when.ts,
    });
  });

  (data.url_enumeration ?? []).forEach((u, idx) => {
    const isAnomaly = u.is_anomaly ?? true;
    if (!isAnomaly) return;
    const ip = u.ip ?? u.client_ip ?? "Unknown";
    const uniquePaths = u.unique_paths ?? u.distinct_paths ?? 0;
    const totalReq = u.total_requests ?? 0;
    const score = clampScore(38 + Math.min(uniquePaths, 400) * 0.14 + Math.min(totalReq, 1200) * 0.02);
    const when = parseWhen(u.window_start);
    items.push({
      id: `url-${idx}-${ip}-${when.ts}`,
      category: "URL Enumeration",
      severity: toSeverity(score),
      score,
      ip,
      signal: `${uniquePaths.toLocaleString()} unique paths`,
      details: `${totalReq.toLocaleString()} requests`,
      whenLabel: when.label,
      whenTs: when.ts,
    });
  });

  (data.status_code_spikes ?? []).forEach((s, idx) => {
    const isAnomaly = s.is_anomaly ?? true;
    if (!isAnomaly) return;
    const ratioRaw = s.error_ratio ?? s.rate ?? 0;
    const ratioPct = ratioRaw <= 1 ? ratioRaw * 100 : ratioRaw;
    const errorCount = s.error_count ?? s.count ?? 0;
    const status = s.status ?? "?";
    const score = clampScore(35 + Math.min(ratioPct, 100) * 0.55 + Math.min(errorCount, 900) * 0.03);
    const when = parseWhen(s.window_start ?? s.timestamp ?? s.window);
    items.push({
      id: `status-${idx}-${status}-${when.ts}`,
      category: "Status Spike",
      severity: toSeverity(score),
      score,
      ip: "Multiple",
      signal: `HTTP ${status}`,
      details: `${ratioPct.toFixed(1)}% error ratio`,
      whenLabel: when.label,
      whenTs: when.ts,
    });
  });

  (data.visitor_rates ?? []).forEach((v, idx) => {
    const flaggedByLabel = (v.flag ?? "").toLowerCase().includes("anomaly");
    const isAnomaly = v.is_anomaly ?? flaggedByLabel;
    if (!isAnomaly) return;
    const ip = v.ip ?? "Unknown";
    const visitors = v.unique_visitors ?? v.requests ?? 0;
    const z = Math.abs(v.z_score ?? 0);
    const score = clampScore(30 + Math.min(z, 7) * 9 + Math.min(visitors, 600) * 0.05);
    const when = parseWhen(v.hour ?? v.timestamp ?? v.window);
    items.push({
      id: `visitor-${idx}-${ip}-${when.ts}`,
      category: "Visitor Anomaly",
      severity: toSeverity(score),
      score,
      ip,
      signal: `z=${z.toFixed(2)}`,
      details: `${visitors.toLocaleString()} visitors`,
      whenLabel: when.label,
      whenTs: when.ts,
    });
  });

  return items.sort((a, b) => b.score - a.score || b.whenTs - a.whenTs);
}

function SeverityPill({ severity }: { severity: FeedSeverity }) {
  return (
    <span
      style={{
        background: `${SEVERITY_COLORS[severity]}22`,
        border: `1px solid ${SEVERITY_COLORS[severity]}66`,
        color: SEVERITY_COLORS[severity],
        fontSize: 10,
        letterSpacing: 1,
        textTransform: "uppercase",
        padding: "2px 8px",
        borderRadius: 3,
      }}
    >
      {severity}
    </span>
  );
}

// ─── Tab 1: Rate Spikes ───────────────────────────────────────────────────────

function RateSpikesTab({ data }: { data: RateSpike[] }) {
  const anomalies = data.filter((d) => d.is_anomaly);
  const topIPs: { label: string; count: number }[] = Object.entries(
    data.reduce<Record<string, number>>((acc, r) => {
      const ip = r.ip ?? r.client_ip ?? "?";
      const count = r.count ?? r.request_count ?? 0;
      acc[ip] = (acc[ip] ?? 0) + count;
      return acc;
    }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([label, count]) => ({ label, count }));

  const scatterAll = data.map((r) => ({ x: r.count ?? r.request_count ?? 0, y: r.rate ?? r.request_count ?? 0 }));
  const scatterAnomaly = anomalies.map((r) => ({ x: r.count ?? r.request_count ?? 0, y: r.rate ?? r.request_count ?? 0 }));

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10, marginBottom: 18 }}>
        <MetricCard label="Anomalies" value={anomalies.length.toLocaleString()} accent="#ff8800" />
        <MetricCard label="Unique IPs" value={new Set(data.map((d) => d.ip)).size.toLocaleString()} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
        <BarChart
          title="Top IPs by Request Count"
          labels={topIPs.map((i) => i.label)}
          values={topIPs.map((i) => i.count)}
          color="#808080"
          horizontal
        />
        <ScatterChart
          title="Request Count vs Rate"
          datasets={[
            { label: "Normal", data: scatterAll.filter((_, i) => !data[i]?.is_anomaly), color: "#444" },
            { label: "Anomaly", data: scatterAnomaly, color: "#ff8800" },
          ]}
          xLabel="Count"
          yLabel="Rate"
        />
      </div>
    </div>
  );
}

// ─── Tab 2: URL Enumeration ───────────────────────────────────────────────────

function UrlEnumTab({ data }: { data: UrlEnum[] }) {
  const anomalies = data.filter((d) => d.is_anomaly);
  const sorted = [...data].sort((a, b) => (b.unique_paths ?? b.distinct_paths ?? 0) - (a.unique_paths ?? a.distinct_paths ?? 0)).slice(0, 10);

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10, marginBottom: 18 }}>
        <MetricCard label="Flagged" value={anomalies.length.toLocaleString()} accent="#ff4444" />
        <MetricCard label="Max Paths" value={(Math.max(...data.map((d) => d.unique_paths ?? d.distinct_paths ?? 0), 0)).toLocaleString()} />
      </div>

      <BarChart
        title="Top IPs by Unique Paths"
        labels={sorted.map((s) => s.ip ?? s.client_ip ?? "?")}
        values={sorted.map((s) => s.unique_paths ?? s.distinct_paths ?? 0)}
        color="#808080"
        horizontal
      />

      {anomalies.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>
            Flagged Enumerators
          </div>
          {anomalies.slice(0, 20).map((a, i) => (
            <div key={i} style={{ borderBottom: "1px solid #111", padding: "8px 0", display: "flex", gap: 16 }}>
              <span style={{ color: "#ff4444", fontFamily: "var(--font-mono-stack)", fontSize: 12 }}>{a.ip ?? a.client_ip}</span>
              <span style={{ color: "#808080", fontSize: 12 }}>{a.unique_paths ?? a.distinct_paths} unique paths</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Tab 3: Status Spikes ─────────────────────────────────────────────────────

function StatusSpikesTab({ data }: { data: StatusSpike[] }) {
  const anomalies = data.filter((d) => d.is_anomaly);
  const sorted = [...data].sort((a, b) => (a.window_start ?? a.timestamp ?? "").localeCompare(b.window_start ?? b.timestamp ?? ""));
  const labels = sorted.map((s) => s.window_start ?? s.timestamp ?? s.window ?? "");
  const datasets = [
    {
      label: "Error Ratio",
      data: sorted.map((s) => s.error_ratio ?? s.rate ?? 0),
      color: "#ff8800",
      fill: false,
    },
    {
      label: "Error Count",
      data: sorted.map((s) => s.error_count ?? s.count ?? 0),
      color: "#ff4444",
      fill: false,
    },
  ];

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10, marginBottom: 18 }}>
        <MetricCard label="Anomalies" value={anomalies.length.toLocaleString()} accent="#ff4444" />
        <MetricCard label="Peak Error Ratio" value={`${Math.max(...data.map((d) => d.error_ratio ?? 0), 0).toFixed(2)}`} />
      </div>

      <LineChart
        title="Error Ratio Over Time"
        labels={labels.map((t) => (t ? new Date(t).toLocaleTimeString() || t : ""))}
        datasets={datasets}
        yLabel="Value"
      />
    </div>
  );
}

// ─── Tab 4: Visitor Rates ─────────────────────────────────────────────────────

function VisitorRatesTab({ data }: { data: VisitorRate[] }) {
  const anomalies = data.filter((d) => d.is_anomaly);
  const sorted = [...data].sort((a, b) => (a.hour ?? a.timestamp ?? "").localeCompare(b.hour ?? b.timestamp ?? ""));
  const labels = sorted.map((d) => d.hour ?? d.timestamp ?? d.window ?? "");
  const avgMean = data.length ? data.reduce((s, d) => s + (d.mean ?? d.mean_visitors ?? 0), 0) / data.length : 0;
  const datasets = [
    {
      label: "Unique Visitors",
      data: sorted.map((d) => d.unique_visitors ?? d.requests ?? 0),
      color: "#4488ff",
      fill: false,
    },
    {
      label: "Z-Score",
      data: sorted.map((d) => d.z_score ?? 0),
      color: "#f0c040",
      fill: false,
    },
  ];

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10, marginBottom: 18 }}>
        <MetricCard label="Anomalies" value={anomalies.length.toLocaleString()} accent="#f0c040" />
        <MetricCard label="Avg Mean Rate" value={avgMean.toFixed(1)} />
      </div>

      <LineChart
        title="Visitor Anomaly Trend"
        labels={labels.map((t) => (t ? new Date(t).toLocaleTimeString() || t : ""))}
        datasets={datasets}
        yLabel="Visitors / Z-Score"
        threshold={avgMean > 0 ? avgMean : undefined}
        thresholdLabel="Mean"
      />
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function BehavioralPage() {
  const [data, setData] = useState<BehavioralData | null>(null);
  const [defaults, setDefaults] = useState<BehavioralDefaults>(FALLBACK_DEFAULTS);
  const [defaultsLoading, setDefaultsLoading] = useState(true);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [runStatus, setRunStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState("Rate Spikes");
  const [feedCategory, setFeedCategory] = useState<string>("");
  const [feedSeverity, setFeedSeverity] = useState<string>("");
  const [feedVisibleCount, setFeedVisibleCount] = useState(40);
  const { activeProject, timeRange } = useAuthStore();

  const fetchBehavioralResults = useCallback(
    async (projectId?: string, isCancelled?: () => boolean) => {
      if (!projectId) {
        if (!isCancelled?.()) {
          setLoading(false);
          setData(null);
          setError(null);
        }
        return;
      }
      if (!isCancelled?.()) {
        setLoading(true);
        setError(null);
      }
      try {
        const d = await getBehavioralResults({ projectId });
        if (isCancelled?.()) return;
        setData((d as unknown as BehavioralData) ?? {});
      } catch (e) {
        if (isCancelled?.()) return;
        setData(null);
        setError(formatBehavioralError(e, "Failed to load behavioral results"));
      } finally {
        if (!isCancelled?.()) setLoading(false);
      }
    },
    [],
  );

  const load = useCallback(async (projectId?: string) => {
    await fetchBehavioralResults(projectId);
  }, [fetchBehavioralResults]);

  useEffect(() => {
    let cancelled = false;
    void fetchBehavioralResults(activeProject?.id, () => cancelled);
    return () => {
      cancelled = true;
    };
  }, [activeProject?.id, fetchBehavioralResults]);

  useEffect(() => {
    let cancelled = false;
    setDefaultsLoading(true);
    getBehavioralDefaults()
      .then((res) => {
        if (cancelled) return;
        setDefaults(res.defaults ?? FALLBACK_DEFAULTS);
      })
      .catch(() => {
        if (cancelled) return;
        setDefaults(FALLBACK_DEFAULTS);
      })
      .finally(() => {
        if (!cancelled) setDefaultsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleRun = async () => {
    setRunning(true);
    setRunStatus("Running behavioral analysis...");
    setError(null);
    try {
      await runBehavioralAnalysis({
        project_id: activeProject?.id,
        start_ts: timeRange?.from,
        end_ts: timeRange?.to,
      });
      await load(activeProject?.id);
      setRunStatus("Analysis complete");
      setTimeout(() => setRunStatus(null), 3000);
    } catch (e) {
      setError(formatBehavioralError(e, "Behavioral analysis failed"));
      setRunStatus("Analysis failed");
    }
    setRunning(false);
  };

  const summary = data?.summary;
  const anomalyFeed = useMemo(() => buildAnomalyFeed(data), [data]);
  const filteredFeed = useMemo(
    () => anomalyFeed.filter((item) => {
      if (feedCategory && item.category !== feedCategory) return false;
      if (feedSeverity && item.severity !== feedSeverity) return false;
      return true;
    }),
    [anomalyFeed, feedCategory, feedSeverity],
  );

  const severityCounts = useMemo(() => ({
    high: anomalyFeed.filter((x) => x.severity === "high").length,
    medium: anomalyFeed.filter((x) => x.severity === "medium").length,
    low: anomalyFeed.filter((x) => x.severity === "low").length,
  }), [anomalyFeed]);

  const dominantCategory = useMemo(() => {
    const counts: Record<FeedCategory, number> = {
      "Rate Spike": 0,
      "URL Enumeration": 0,
      "Status Spike": 0,
      "Visitor Anomaly": 0,
    };
    anomalyFeed.forEach((item) => { counts[item.category] += 1; });
    const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    return ranked[0] && ranked[0][1] > 0
      ? { label: ranked[0][0], count: ranked[0][1] }
      : { label: "None", count: 0 };
  }, [anomalyFeed]);

  const topRiskIps = useMemo(() => {
    const byIp: Record<string, { totalScore: number; maxScore: number; count: number }> = {};
    filteredFeed.forEach((item) => {
      if (!item.ip || item.ip === "Unknown" || item.ip === "Multiple") return;
      if (!byIp[item.ip]) byIp[item.ip] = { totalScore: 0, maxScore: 0, count: 0 };
      byIp[item.ip].totalScore += item.score;
      byIp[item.ip].maxScore = Math.max(byIp[item.ip].maxScore, item.score);
      byIp[item.ip].count += 1;
    });
    return Object.entries(byIp)
      .sort((a, b) => b[1].totalScore - a[1].totalScore)
      .slice(0, 8);
  }, [filteredFeed]);

  useEffect(() => {
    setFeedVisibleCount(40);
  }, [feedCategory, feedSeverity, anomalyFeed.length]);

  if (!activeProject?.id) return (
    <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
      Select a project from the sidebar to view this page.
    </div>
  );

  if (activeProject.project_type === "windows") return (
    <div style={{ textAlign: "center", padding: 60, color: "#ff6b6b" }}>
      <h2 style={{ margin: 0, color: "#ff6b6b" }}>Web Projects Only</h2>
      <p style={{ color: "#999", marginTop: 12 }}>
        This behavioral page is for web projects.
      </p>
    </div>
  );

  return (
    <div>
      <SectionHeader
        title="Behavioral Analysis"
        subtitle="Anomaly detection across request rate spikes, URL enumeration, status spikes, and visitor patterns"
      />

      {/* Controls */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, alignItems: "center" }}>
        <Btn onClick={handleRun} disabled={running} aria-label="Run behavioral analysis">
          {running ? <><Spinner size={12} />&nbsp;&nbsp;RUNNING…</> : "RUN ANALYSIS"}
        </Btn>
        <Btn variant="ghost" onClick={() => load(activeProject?.id)} aria-label="Refresh behavioral results">REFRESH</Btn>
        {runStatus && <span style={{ fontSize: 12, color: running ? "#f0c040" : "#8bc34a", marginLeft: 8 }}>{runStatus}</span>}
      </div>

      <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 16, marginBottom: 20 }}>
        <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>
          Detection Defaults
        </div>
        {defaultsLoading ? (
          <div style={{ fontSize: 12, color: "#6e8796" }}>Loading defaults...</div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 10 }}>
            <div style={{ background: "#111", border: "1px solid #1f1f1f", borderRadius: 4, padding: 10 }}>
              <div style={{ fontSize: 10, color: "#5e7180", textTransform: "uppercase", letterSpacing: 0.9 }}>Rate Window</div>
              <div style={{ fontSize: 13, color: "#cfd8de", marginTop: 4 }}>{defaults.rate_window_minutes} minute(s)</div>
            </div>
            <div style={{ background: "#111", border: "1px solid #1f1f1f", borderRadius: 4, padding: 10 }}>
              <div style={{ fontSize: 10, color: "#5e7180", textTransform: "uppercase", letterSpacing: 0.9 }}>Rate Threshold</div>
              <div style={{ fontSize: 13, color: "#cfd8de", marginTop: 4 }}>{defaults.rate_threshold.toLocaleString()} requests</div>
            </div>
            <div style={{ background: "#111", border: "1px solid #1f1f1f", borderRadius: 4, padding: 10 }}>
              <div style={{ fontSize: 10, color: "#5e7180", textTransform: "uppercase", letterSpacing: 0.9 }}>Enumeration Window</div>
              <div style={{ fontSize: 13, color: "#cfd8de", marginTop: 4 }}>{defaults.enum_window_hours} hour(s)</div>
            </div>
            <div style={{ background: "#111", border: "1px solid #1f1f1f", borderRadius: 4, padding: 10 }}>
              <div style={{ fontSize: 10, color: "#5e7180", textTransform: "uppercase", letterSpacing: 0.9 }}>Enumeration Threshold</div>
              <div style={{ fontSize: 13, color: "#cfd8de", marginTop: 4 }}>{defaults.enum_threshold.toLocaleString()} unique paths</div>
            </div>
            <div style={{ background: "#111", border: "1px solid #1f1f1f", borderRadius: 4, padding: 10 }}>
              <div style={{ fontSize: 10, color: "#5e7180", textTransform: "uppercase", letterSpacing: 0.9 }}>Status Window</div>
              <div style={{ fontSize: 13, color: "#cfd8de", marginTop: 4 }}>{defaults.status_window_minutes} minute(s)</div>
            </div>
            <div style={{ background: "#111", border: "1px solid #1f1f1f", borderRadius: 4, padding: 10 }}>
              <div style={{ fontSize: 10, color: "#5e7180", textTransform: "uppercase", letterSpacing: 0.9 }}>Status Error Ratio</div>
              <div style={{ fontSize: 13, color: "#cfd8de", marginTop: 4 }}>{Math.round(defaults.status_error_ratio * 100)}%</div>
            </div>
            <div style={{ background: "#111", border: "1px solid #1f1f1f", borderRadius: 4, padding: 10 }}>
              <div style={{ fontSize: 10, color: "#5e7180", textTransform: "uppercase", letterSpacing: 0.9 }}>Visitor Z-Score</div>
              <div style={{ fontSize: 13, color: "#cfd8de", marginTop: 4 }}>{defaults.visitor_zscore.toFixed(1)}</div>
            </div>
          </div>
        )}
      </div>

      {loading ? (
        <div style={{ textAlign: "center", padding: 60 }}><Spinner size={28} /></div>
      ) : !data ? (
        <div style={{ color: "#444", fontSize: 13, padding: "24px 0" }}>
          {error ? `Behavioral results unavailable: ${error}` : "No behavioral data — run analysis first"}
        </div>
      ) : (
        <>
          {/* Summary metrics */}
          {summary && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 10, marginBottom: 20 }}>
              <MetricCard label="Rate Spikes" value={(summary.total_rate_spikes ?? summary.total_rate_spike_windows ?? 0).toLocaleString()} accent="#ff8800" />
              <MetricCard label="URL Enumerators" value={(summary.total_url_enumerators ?? summary.total_enumeration_alerts ?? 0).toLocaleString()} accent="#ff4444" />
              <MetricCard label="Status Spikes" value={(summary.total_status_spikes ?? summary.total_status_spike_windows ?? 0).toLocaleString()} accent="#f0c040" />
              <MetricCard label="Visitor Anomalies" value={(summary.total_visitor_anomaly_hours ?? 0).toLocaleString()} />
            </div>
          )}

          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 18, marginBottom: 24 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8, marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase" }}>
                Anomaly Triage Board
              </div>
              <div style={{ fontSize: 10, color: "#5e7180", letterSpacing: 0.6 }}>
                Showing {filteredFeed.length.toLocaleString()} of {anomalyFeed.length.toLocaleString()} flagged events
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 10, marginBottom: 14 }}>
              <div style={{ background: "#111", border: "1px solid #1e1e1e", borderLeft: "2px solid #ff444466", borderRadius: 6, padding: "12px 14px" }}>
                <div style={{ fontSize: 10, letterSpacing: 1.2, textTransform: "uppercase", color: "var(--theme-muted-blue)", marginBottom: 8 }}>
                  Triage Snapshot
                </div>
                <div style={{ fontSize: 12, color: "#d7e2e9", lineHeight: 1.9 }}>
                  <div>
                    <span style={{ color: "#ff6e6e" }}>{(severityCounts.high).toLocaleString()}</span>
                    {" "}high events
                  </div>
                  <div>
                    <span style={{ color: "#8aa0ad" }}>{dominantCategory.label}</span>
                    {" "}is the dominant detector
                  </div>
                  <div>
                    Top risk IP:{" "}
                    <span style={{ color: "#c0c0c0", fontFamily: "var(--font-mono-stack)" }}>
                      {topRiskIps[0]?.[0] ?? "None"}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 10, marginBottom: 14 }}>
              <label style={{ display: "grid", gap: 6 }}>
                <span style={{ fontSize: 10, color: "#6e8796", textTransform: "uppercase", letterSpacing: 0.8 }}>Detector Filter</span>
                <SelectInput
                  value={feedCategory}
                  onChange={setFeedCategory}
                  options={["Rate Spike", "URL Enumeration", "Status Spike", "Visitor Anomaly"]}
                  placeholder="All detectors"
                />
              </label>
              <label style={{ display: "grid", gap: 6 }}>
                <span style={{ fontSize: 10, color: "#6e8796", textTransform: "uppercase", letterSpacing: 0.8 }}>Severity Filter</span>
                <SelectInput
                  value={feedSeverity}
                  onChange={setFeedSeverity}
                  options={["high", "medium", "low"]}
                  placeholder="All severities"
                />
              </label>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
              <div style={{ border: "1px solid #1a1a1a", borderRadius: 4, background: "#0a0a0a", minHeight: 250 }}>
                <div style={{ padding: "10px 12px", borderBottom: "1px solid #1a1a1a", fontSize: 11, color: "#5e7180", letterSpacing: 1, textTransform: "uppercase" }}>
                  Priority Queue
                </div>
                <div style={{ maxHeight: 340, overflowY: "auto" }}>
                  {filteredFeed.slice(0, feedVisibleCount).map((item) => (
                    <div
                      key={item.id}
                      style={{
                        borderBottom: "1px solid #111",
                        borderLeft: `2px solid ${SEVERITY_COLORS[item.severity]}66`,
                        padding: "10px 12px",
                        display: "flex",
                        justifyContent: "space-between",
                        gap: 10,
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                          <SeverityPill severity={item.severity} />
                          <span style={{ fontSize: 10, color: "#6e8796", textTransform: "uppercase", letterSpacing: 0.8 }}>{item.category}</span>
                          <span style={{ fontSize: 11, color: "#999" }}>score {item.score}</span>
                        </div>
                        <div style={{ color: "#d7e2e9", fontSize: 12, lineHeight: 1.5 }}>
                          <span
                            style={{
                              fontFamily: "var(--font-mono-stack)",
                              color: "#c0c0c0",
                              whiteSpace: "nowrap",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              maxWidth: 180,
                              display: "inline-block",
                              verticalAlign: "bottom",
                            }}
                          >
                            {item.ip}
                          </span>
                          <span style={{ color: "#4a5560", margin: "0 8px" }}>•</span>
                          <span>{item.signal}</span>
                          <span style={{ color: "#4a5560", margin: "0 8px" }}>•</span>
                          <span style={{ color: "#8aa0ad" }}>{item.details}</span>
                        </div>
                      </div>
                      <div style={{ fontSize: 10, color: "#5e7180", whiteSpace: "nowrap", marginTop: 2 }}>
                        {item.whenLabel}
                      </div>
                    </div>
                  ))}
                  {filteredFeed.length === 0 && (
                    <div style={{ padding: 24, textAlign: "center", color: "#4a5560", fontSize: 12 }}>
                      No anomalies match the current filters.
                    </div>
                  )}
                  {filteredFeed.length > feedVisibleCount && (
                    <div style={{ padding: 10, borderTop: "1px solid #111" }}>
                      <Btn
                        variant="ghost"
                        onClick={() => setFeedVisibleCount((c) => c + 40)}
                        style={{ width: "100%" }}
                        aria-label="Load more priority queue rows"
                      >
                        LOAD MORE
                      </Btn>
                    </div>
                  )}
                </div>
              </div>

              <div style={{ border: "1px solid #1a1a1a", borderRadius: 4, background: "#0a0a0a", minHeight: 250 }}>
                <div style={{ padding: "10px 12px", borderBottom: "1px solid #1a1a1a", fontSize: 11, color: "#5e7180", letterSpacing: 1, textTransform: "uppercase" }}>
                  Top Risk IPs
                </div>
                <div style={{ padding: 12 }}>
                  {topRiskIps.map(([ip, stats]) => {
                    const width = topRiskIps[0] ? Math.max(8, Math.round((stats.totalScore / topRiskIps[0][1].totalScore) * 100)) : 0;
                    const tone = stats.maxScore >= 85 ? "#ff4444" : stats.maxScore >= 70 ? "#ff8800" : "#f0c040";
                    return (
                      <div key={ip} style={{ marginBottom: 12 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 5 }}>
                          <span style={{ color: "#c0c0c0", fontFamily: "var(--font-mono-stack)", fontSize: 12 }}>{ip}</span>
                          <span style={{ color: tone, fontSize: 11 }}>score {stats.totalScore}</span>
                        </div>
                        <div style={{ height: 6, background: "#141414", borderRadius: 999 }}>
                          <div style={{ width: `${width}%`, height: "100%", background: tone, borderRadius: 999, transition: "width 0.2s" }} />
                        </div>
                        <div style={{ marginTop: 4, fontSize: 10, color: "#5e7180" }}>{stats.count} events</div>
                      </div>
                    );
                  })}
                  {topRiskIps.length === 0 && (
                    <div style={{ color: "#4a5560", fontSize: 12, paddingTop: 6 }}>
                      No IP-attributed anomalies in current filters.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
          <Tabs
            tabs={["Rate Spikes", "URL Enumeration", "Status Spikes", "Visitor Rates"]}
            active={tab}
            onChange={setTab}
          />

          {tab === "Rate Spikes" && <RateSpikesTab data={data.request_rate_spikes ?? []} />}
          {tab === "URL Enumeration" && <UrlEnumTab data={data.url_enumeration ?? []} />}
          {tab === "Status Spikes" && <StatusSpikesTab data={data.status_code_spikes ?? []} />}
          {tab === "Visitor Rates" && <VisitorRatesTab data={data.visitor_rates ?? []} />}
        </>
      )}
    </div>
  );
}
