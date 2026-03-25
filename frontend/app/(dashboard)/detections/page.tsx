"use client";

import { useEffect, useState, useCallback } from "react";
import { getRuleMatches, getDetectionAggregations, type DetectionAggregations } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import {
  SectionHeader,
  MetricCard,
  Tabs,
  SearchInput,
  SelectInput,
  Btn,
  Spinner,
} from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import PieChart from "@/components/charts/pie-chart";
import LineChart from "@/components/charts/line-chart";
import HawkinsChat from "@/components/hawkins-chat";
import { ThreatTimeline, type ThreatEvent } from "@/components/threat-timeline";
import { EventDetailModal } from "@/components/event-detail-modal";

// ─── Types ────────────────────────────────────────────────────────────────────

interface RuleMatch {
  rule_id?: string;
  rule_title?: string;
  severity?: string;
  client_ip?: string;
  method?: string;
  path?: string;
  status_code?: number | string;
  timestamp?: string;
}

type TriageStatus = "new" | "investigating" | "resolved";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_ORDER = ["critical", "high", "medium", "low", "unknown"];
const SEV_COLORS: Record<string, string> = {
  critical: "#ff4444", high: "#ff8800", medium: "#f0c040", low: "#4488ff", unknown: "#555",
};

/** Derive attack category from OWASP CRS rule ID range or rule title. */
function getCrsCategory(ruleId?: string, ruleTitle?: string): string {
  const title = (ruleTitle ?? "").toLowerCase();
  if (title.includes("sql") || title.includes("sqli")) return "SQLi";
  if (title.includes("xss") || title.includes("cross-site")) return "XSS";
  if (title.includes("lfi") || title.includes("local file")) return "LFI";
  if (title.includes("rfi") || title.includes("remote file inclusion")) return "RFI";
  if (title.includes("rce") || title.includes("command injection") || title.includes("os command")) return "RCE";
  if (title.includes("php")) return "PHP Injection";
  if (title.includes("scanner") || title.includes("user-agent") || title.includes("nikto") || title.includes("nmap")) return "Scanner";
  if (title.includes("protocol")) return "Protocol Attack";
  if (title.includes("session") || title.includes("fixation")) return "Session Fixation";
  if (title.includes("java")) return "Java Attack";
  if (title.includes("anomaly") || title.includes("inbound anomaly") || title.includes("outbound anomaly")) return "Anomaly Score";
  const id = parseInt((ruleId ?? "").replace(/\D/g, ""), 10);
  if (id >= 941000 && id < 942000) return "XSS";
  if (id >= 942000 && id < 943000) return "SQLi";
  if (id >= 930000 && id < 931000) return "LFI";
  if (id >= 931000 && id < 932000) return "RFI";
  if (id >= 932000 && id < 933000) return "RCE";
  if (id >= 933000 && id < 934000) return "PHP Injection";
  if (id >= 913000 && id < 914000) return "Scanner";
  if (id >= 920000 && id < 922000) return "Protocol Attack";
  if (id >= 943000 && id < 944000) return "Session Fixation";
  if (id >= 944000 && id < 945000) return "Java Attack";
  if (id >= 949000 && id < 950000) return "Anomaly Score";
  return "Other";
}

function getAlertKey(m: RuleMatch): string {
  return `${m.rule_id ?? "?"}_${m.client_ip ?? "?"}_${m.timestamp ?? "?"}`;
}

const TRIAGE_CYCLE: Record<TriageStatus, TriageStatus> = {
  new: "investigating",
  investigating: "resolved",
  resolved: "new",
};

const TRIAGE_COLORS: Record<TriageStatus, string> = {
  new: "#ff4444",
  investigating: "#f0c040",
  resolved: "#4caf50",
};

function loadTriageMap(): Record<string, TriageStatus> {
  try {
    const raw = localStorage.getItem("logic_triage");
    return raw ? JSON.parse(raw) : {};
  } catch { return {}; }
}

function saveTriageMap(map: Record<string, TriageStatus>) {
  try { localStorage.setItem("logic_triage", JSON.stringify(map)); } catch {}
}

function exportCsv(matches: RuleMatch[], triageMap: Record<string, TriageStatus>) {
  const headers = ["Severity", "Rule", "IP", "Method", "Path", "Status", "Time", "Triage"];
  const rows = matches.map((m) => [
    m.severity ?? "",
    m.rule_title ?? m.rule_id ?? "",
    m.client_ip ?? "",
    m.method ?? "",
    m.path ?? "",
    String(m.status_code ?? ""),
    m.timestamp ?? "",
    triageMap[getAlertKey(m)] ?? "new",
  ]);
  const csv = [headers, ...rows]
    .map((row) => row.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `detections_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function OverviewCharts({ agg }: { agg: DetectionAggregations }) {
  const sevCounts = agg.severity_breakdown;
  const topRules = agg.top_rules;
  const topIPs = agg.top_ips;
  const topPaths = agg.top_paths;
  const methodCounts = agg.method_distribution;
  const statusCounts = agg.status_distribution;
  const hourlyTimeline = agg.hourly_timeline;

  const orderedSev = SEV_ORDER.filter((s) => sevCounts[s] != null);
  const statusOrdered = ["2xx", "3xx", "4xx", "5xx", "other"] as const;
  const statusLabelMap: Record<string, string> = { "2xx": "2xx Success", "3xx": "3xx Redirect", "4xx": "4xx Client Error", "5xx": "5xx Server Error", other: "Other" };
  const statusColorMap: Record<string, string> = { "2xx": "#4caf50", "3xx": "#4488ff", "4xx": "#f0c040", "5xx": "#ff4444", other: "#555" };
  const statusFiltered = statusOrdered.filter((k) => (statusCounts[k] ?? 0) > 0);

  // CRS Attack Categories (derived from top_rules)
  const catCounts: Record<string, number> = {};
  topRules.forEach((r) => {
    const cat = getCrsCategory(r.rule_id, r.rule_title);
    catCounts[cat] = (catCounts[cat] ?? 0) + r.hit_count;
  });
  const catColors = ["#ff4444", "#ff8800", "#f0c040", "#4488ff", "#4caf50", "#a855f7", "#06b6d4", "#ec4899", "#84cc16"];
  const catEntries = Object.entries(catCounts).sort((a, b) => b[1] - a[1]);

  // Detection Timeline
  const tlHours = Object.keys(hourlyTimeline).sort().slice(-24);
  const tlLabels = tlHours.map((h) =>
    new Date(h + ":00Z").toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );
  const tlDatasets = ["critical", "high", "medium", "low"].map((sev) => ({
    label: sev.charAt(0).toUpperCase() + sev.slice(1),
    data: tlHours.map((h) => hourlyTimeline[h]?.[sev] ?? 0),
    color: SEV_COLORS[sev] ?? "#555",
    fill: false,
  }));

  return (
    <div>
      {/* Row 0: Detection Timeline */}
      {tlHours.length > 1 && (
        <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20, marginBottom: 16 }}>
          <LineChart
            title="Detection Timeline — rule matches grouped by hour and severity"
            labels={tlLabels}
            datasets={tlDatasets}
            yLabel="Matches"
            height={240}
          />
        </div>
      )}

      {/* Row 1: Severity + Top Rules */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <BarChart
          title="Alerts by Severity"
          labels={orderedSev.map((s) => `${s.toUpperCase()} (${sevCounts[s]})`)}
          values={orderedSev.map((s) => sevCounts[s] ?? 0)}
          color={orderedSev.map((s) => SEV_COLORS[s] ?? "#555")}
          height={240}
        />
        <BarChart
          title="Top Triggered Rules"
          labels={topRules.map((r) => {
            const l = r.rule_title || r.rule_id;
            return l.length > 38 ? l.slice(0, 38) + "…" : l;
          })}
          values={topRules.map((r) => r.hit_count)}
          color="#5a5a9a"
          horizontal
          height={240}
        />
      </div>

      {/* Row 2: CRS Attack Categories + Top IPs */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        {catEntries.length > 0 && (
          <PieChart
            title="CRS Attack Categories — rule matches grouped by attack class"
            labels={catEntries.map(([l]) => l)}
            values={catEntries.map(([, v]) => v)}
            colors={catEntries.map((_, i) => catColors[i % catColors.length])}
          />
        )}
        <BarChart
          title="Top Offending IPs"
          labels={topIPs.map((i) => i.client_ip)}
          values={topIPs.map((i) => i.hit_count)}
          color="#7a4a4a"
          horizontal
          height={240}
        />
      </div>

      {/* Row 3: HTTP Methods + Status Classes */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <PieChart
          title="HTTP Method Distribution"
          labels={Object.keys(methodCounts)}
          values={Object.values(methodCounts)}
          colors={["#5a7a9a", "#4a6a8a", "#3a5a7a", "#2a4a6a", "#1a3a5a"]}
        />
        {statusFiltered.length > 0 && (
          <PieChart
            title="Response Status Classes"
            labels={statusFiltered.map((k) => statusLabelMap[k])}
            values={statusFiltered.map((k) => statusCounts[k])}
            colors={statusFiltered.map((k) => statusColorMap[k])}
          />
        )}
      </div>

      {/* Row 4: Top Paths */}
      {topPaths.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <BarChart
            title="Most Targeted Paths"
            labels={topPaths.map((p) => p.path.length > 50 ? "…" + p.path.slice(-47) : p.path)}
            values={topPaths.map((p) => p.hit_count)}
            color="#4a7a4a"
            horizontal
            height={240}
          />
        </div>
      )}
    </div>
  );
}

function ThreatTable({
  matches,
  triageMap,
  onTriageChange,
}: {
  matches: RuleMatch[];
  triageMap: Record<string, TriageStatus>;
  onTriageChange: (key: string, status: TriageStatus) => void;
}) {
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [methodFilter, setMethodFilter] = useState("");
  const [triageFilter, setTriageFilter] = useState("");
  const [successfulOnly, setSuccessfulOnly] = useState(false);

  const severities = [...new Set(matches.map((m) => (m.severity ?? "unknown").toLowerCase()))].sort();
  const methods = [...new Set(matches.map((m) => m.method ?? "").filter(Boolean))].sort();

  const filtered = matches.filter((m) => {
    const sev = (m.severity ?? "").toLowerCase();
    if (sevFilter && sev !== sevFilter) return false;
    if (methodFilter && (m.method ?? "") !== methodFilter) return false;
    if (successfulOnly && ![200, 201, 204].includes(Number(m.status_code ?? -1))) return false;
    const t = triageMap[getAlertKey(m)] ?? "new";
    if (triageFilter && t !== triageFilter) return false;
    if (search) {
      const s = search.toLowerCase();
      return (
        (m.rule_title ?? m.rule_id ?? "").toLowerCase().includes(s) ||
        (m.client_ip ?? "").toLowerCase().includes(s) ||
        (m.path ?? "").toLowerCase().includes(s)
      );
    }
    return true;
  });

  return (
    <div>
      {/* Toolbar */}
      <div style={{ display: "flex", gap: 10, marginBottom: 10, flexWrap: "wrap", alignItems: "center" }}>
        <SearchInput value={search} onChange={setSearch} placeholder="Search rule, IP, path…" />
        <SelectInput
          value={sevFilter}
          onChange={setSevFilter}
          options={[{ value: "", label: "All Severities" }, ...severities.map((s) => ({ value: s, label: s.toUpperCase() }))]}
        />
        {methods.length > 0 && (
          <SelectInput
            value={methodFilter}
            onChange={setMethodFilter}
            options={[{ value: "", label: "All Methods" }, ...methods.map((m) => ({ value: m, label: m }))]}
          />
        )}
        <SelectInput
          value={triageFilter}
          onChange={setTriageFilter}
          options={[
            { value: "", label: "All Triage" },
            { value: "new", label: "NEW" },
            { value: "investigating", label: "INVESTIGATING" },
            { value: "resolved", label: "RESOLVED" },
          ]}
        />
        <button
          onClick={() => setSuccessfulOnly((v) => !v)}
          style={{
            background: successfulOnly ? "#1a2a1a" : "#111",
            border: `1px solid ${successfulOnly ? "#4caf50" : "#2a2a2a"}`,
            color: successfulOnly ? "#4caf50" : "#555",
            borderRadius: 3,
            padding: "5px 10px",
            fontSize: 10,
            letterSpacing: 0.8,
            textTransform: "uppercase",
            cursor: "pointer",
          }}
        >
          {successfulOnly ? "⚠ Successful Hits" : "Successful Hits"}
        </button>
        <div style={{ fontSize: 11, color: "#444", alignSelf: "center", whiteSpace: "nowrap" }}>
          {filtered.length.toLocaleString()} / {matches.length.toLocaleString()}
        </div>
        <Btn
          variant="ghost"
          onClick={() => exportCsv(filtered.slice(0, 200), triageMap)}
          style={{ marginLeft: "auto", fontSize: 10 }}
        >
          EXPORT CSV
        </Btn>
      </div>

      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
            {["Triage", "Severity", "Rule", "IP", "Method", "Path", "Status", "Time"].map((h) => (
              <th key={h} style={{ textAlign: "left", color: "#444", padding: "6px 8px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.slice(0, 200).map((m, i) => {
            const sev = (m.severity ?? "unknown").toLowerCase();
            const c = SEV_COLORS[sev] ?? "#555";
            const key = getAlertKey(m);
            const triage = triageMap[key] ?? "new";
            return (
              <tr key={i} style={{ borderBottom: "1px solid #0f0f0f" }}>
                <td style={{ padding: "6px 8px" }}>
                  <button
                    onClick={() => onTriageChange(key, TRIAGE_CYCLE[triage])}
                    title="Click to cycle: New → Investigating → Resolved"
                    style={{
                      background: "transparent",
                      border: `1px solid ${TRIAGE_COLORS[triage]}44`,
                      color: TRIAGE_COLORS[triage],
                      borderRadius: 2,
                      padding: "2px 6px",
                      fontSize: 9,
                      letterSpacing: 0.6,
                      textTransform: "uppercase",
                      cursor: "pointer",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {triage}
                  </button>
                </td>
                <td style={{ padding: "6px 8px" }}>
                  <span style={{ color: c, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>{m.severity ?? "—"}</span>
                </td>
                <td style={{ padding: "6px 8px", color: "#c0c0c0", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={m.rule_title ?? m.rule_id ?? ""}>
                  {m.rule_title ?? m.rule_id ?? "—"}
                </td>
                <td style={{ padding: "6px 8px", color: "#808080", fontFamily: "monospace", fontSize: 11 }}>{m.client_ip ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#666", fontFamily: "monospace", fontSize: 11 }}>{m.method ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#555", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={m.path ?? ""}>{m.path ?? "—"}</td>
                <td style={{ padding: "6px 8px", fontFamily: "monospace", fontSize: 11 }}>
                  <span style={{ color: Number(m.status_code ?? 0) >= 500 ? "#ff4444" : Number(m.status_code ?? 0) >= 400 ? "#f0c040" : Number(m.status_code ?? 0) >= 200 ? "#4caf50" : "#555" }}>
                    {m.status_code ?? "—"}
                  </span>
                </td>
                <td style={{ padding: "6px 8px", color: "#444", whiteSpace: "nowrap", fontSize: 11 }}>
                  {m.timestamp ? new Date(m.timestamp).toLocaleString() : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {filtered.length > 200 && (
        <div style={{ color: "#444", fontSize: 11, marginTop: 6, textAlign: "center" }}>
          Showing 200 of {filtered.length.toLocaleString()} — refine filters to narrow results
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function DetectionsPage() {
  const [matches, setMatches] = useState<RuleMatch[]>([]);
  const [agg, setAgg] = useState<DetectionAggregations | null>(null);
  const [aggError, setAggError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("Overview Charts");
  const [triageMap, setTriageMap] = useState<Record<string, TriageStatus>>({});
  const [selectedTimelineEvent, setSelectedTimelineEvent] = useState<ThreatEvent | null>(null);
  const { activeProject, timeRange } = useAuthStore();
  const scope = { projectId: activeProject?.id, startTs: timeRange?.from, endTs: timeRange?.to };

  const loadData = useCallback(() => {
    if (!activeProject?.id) { setLoading(false); return; }
    setLoading(true);
    setAggError(null);
    setTriageMap(loadTriageMap());
    Promise.allSettled([
      getDetectionAggregations(scope),
      getRuleMatches(scope),
    ]).then(([aggResult, ruleResult]) => {
      if (aggResult.status === "fulfilled") {
        setAgg(aggResult.value);
      } else {
        setAgg(null);
        setAggError("Overview charts are unavailable right now. The detections table is still loaded below.");
      }

      if (ruleResult.status === "fulfilled") {
        setMatches(ruleResult.value.matches as RuleMatch[]);
      } else {
        setMatches([]);
      }

      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeProject?.id, timeRange?.from, timeRange?.to]);

  useEffect(() => { loadData(); }, [loadData]);

  const handleTriageChange = useCallback((key: string, status: TriageStatus) => {
    setTriageMap((prev) => {
      const next = { ...prev, [key]: status };
      saveTriageMap(next);
      return next;
    });
  }, []);

  if (!activeProject?.id) return (
    <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
      Select a project from the sidebar to view this page.
    </div>
  );

  if (activeProject.project_type === "windows") return (
    <div style={{ textAlign: "center", padding: 60, color: "#ff6b6b" }}>
      <h2 style={{ margin: 0, color: "#ff6b6b" }}>Web Projects Only</h2>
      <p style={{ color: "#999", marginTop: 12 }}>
        This detections page is for web projects.
      </p>
    </div>
  );

  if (loading) return <div style={{ textAlign: "center", padding: 60 }}><Spinner size={28} /></div>;

  const matchSeverityCounts = matches.reduce<Record<string, number>>((acc, match) => {
    const severity = (match.severity ?? "unknown").toLowerCase();
    acc[severity] = (acc[severity] ?? 0) + 1;
    return acc;
  }, {});
  const totalDetections = matches.length;
  const uniqueRules = new Set(matches.map((match) => match.rule_id).filter(Boolean)).size;
  const openAlerts = matches.filter((m) => {
    const t = triageMap[getAlertKey(m)] ?? "new";
    return t === "new" || t === "investigating";
  }).length;
  const hasOverviewData = !!agg && (
    agg.total_detections > 0 ||
    Object.keys(agg.severity_breakdown).length > 0 ||
    agg.top_rules.length > 0 ||
    agg.top_ips.length > 0 ||
    agg.top_paths.length > 0 ||
    Object.keys(agg.method_distribution).length > 0 ||
    Object.keys(agg.status_distribution).length > 0 ||
    Object.keys(agg.hourly_timeline).length > 0
  );

  const timelineEvents: ThreatEvent[] = matches.map((match) => {
    const sev = (match.severity ?? "low").toLowerCase();
    const severity: ThreatEvent["severity"] =
      sev === "critical" || sev === "high"
        ? "critical"
        : sev === "medium"
          ? "warning"
          : "info";

    return {
      timestamp: match.timestamp || new Date().toISOString(),
      severity,
      type: "detection",
      title: match.rule_title || match.rule_id || "Rule match",
      details: `${match.client_ip || "unknown ip"} | ${match.method || "-"} ${match.path || "-"} | status ${match.status_code || "-"}`,
      source: "rule-detection",
      payload: match,
    };
  });

  return (
    <div>
      <SectionHeader
        title="Detected Threats"
        subtitle="Rule-based detection results — matched alerts, source IP analysis, and request detail"
      />

      {/* Controls */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
        <Btn onClick={loadData} disabled={loading}>Refresh</Btn>
      </div>

      {/* Top metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, marginBottom: 24 }}>
        <MetricCard label="Total Alerts" value={totalDetections.toLocaleString()} />
        <MetricCard label="Unique Rules" value={uniqueRules.toLocaleString()} />
        <MetricCard label="Critical" value={(matchSeverityCounts.critical ?? 0).toLocaleString()} accent="#ff4444" />
        <MetricCard label="High" value={(matchSeverityCounts.high ?? 0).toLocaleString()} accent="#ff8800" />
        <MetricCard label="Open Alerts" value={openAlerts.toLocaleString()} accent="#f0c040" sub="New + Investigating" />
      </div>

      <Tabs
        tabs={["Overview Charts", "Detected Threats"]}
        active={tab}
        onChange={setTab}
      />

      {tab === "Overview Charts" && aggError && (
        <div style={{ color: "#f0c040", fontSize: 13, border: "1px dashed #3a2f12", borderRadius: 4, padding: 18, marginTop: 16 }}>
          {aggError}
        </div>
      )}
      {tab === "Overview Charts" && !aggError && !hasOverviewData && (
        <div style={{ color: "#555", fontSize: 13, border: "1px dashed #2a2a2a", borderRadius: 4, padding: 18, marginTop: 16 }}>
          No overview chart data is available for the current project and time range yet.
        </div>
      )}
      {tab === "Overview Charts" && agg && hasOverviewData && <OverviewCharts agg={agg} />}
      {tab === "Detected Threats" && (
        <>
          <div style={{ marginBottom: 16 }}>
            <ThreatTimeline
              events={timelineEvents}
              height={280}
              onEventClick={(event) => setSelectedTimelineEvent(event)}
            />
          </div>
          <ThreatTable matches={matches} triageMap={triageMap} onTriageChange={handleTriageChange} />
        </>
      )}

      <div style={{ marginTop: 40 }}>
        <HawkinsChat
          title="Hawkins — Detections"
          description="Ask about specific threats, attack patterns, or suspicious IPs"
          dataSummary={`${totalDetections} rule matches across ${uniqueRules} unique rules. Critical: ${matchSeverityCounts.critical ?? 0}, High: ${matchSeverityCounts.high ?? 0}. Open alerts (unresolved): ${openAlerts}.${selectedTimelineEvent ? ` Selected threat: ${selectedTimelineEvent.title} (${selectedTimelineEvent.severity}) at ${new Date(selectedTimelineEvent.timestamp).toLocaleString()}.` : " No selected timeline threat yet."}`}
          componentKey="detections"
          helpGuide="Try: 'Which IPs are most suspicious?' or 'Explain the SQL injection alerts'. Use the Triage column to mark alerts as Investigating or Resolved — status persists in your browser. Toggle Successful Hits to see attacks that may have landed (server returned 2xx). Export CSV sends the current filtered view to your downloads folder."
          selectedThreat={selectedTimelineEvent}
        />
      </div>

      {selectedTimelineEvent && (
        <EventDetailModal
          title={selectedTimelineEvent.title}
          subtitle={`${selectedTimelineEvent.severity.toUpperCase()} · ${selectedTimelineEvent.type.toUpperCase()} · ${new Date(selectedTimelineEvent.timestamp).toLocaleString()}`}
          payload={selectedTimelineEvent.payload ?? selectedTimelineEvent}
          onClose={() => setSelectedTimelineEvent(null)}
        />
      )}
    </div>
  );
}
