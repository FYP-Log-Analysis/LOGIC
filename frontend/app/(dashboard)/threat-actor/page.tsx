"use client";

import { useEffect, useState, useCallback } from "react";
import {
  getRuleMatches,
  getBehavioralResults,
  getIpSummary,
} from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import {
  SectionHeader,
  MetricCard,
  Btn,
  SearchInput,
  StatusBadge,
  Spinner,
  Divider,
  Badge,
} from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
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
  status_code?: number;
  timestamp?: string;
  tags?: string[];
}

interface BehResult {
  request_rate_spikes?: Array<{ ip?: string; client_ip?: string; count?: number; rate?: number; is_anomaly?: boolean; timestamp?: string; }>;
  url_enumeration?: Array<{ ip?: string; client_ip?: string; unique_paths?: number; is_anomaly?: boolean; }>;
  status_code_spikes?: Array<{ window?: string; status?: number | string; count?: number; is_anomaly?: boolean; timestamp?: string; }>;
  visitor_rates?: Array<{ ip?: string; window?: string; requests?: number; is_anomaly?: boolean; timestamp?: string; }>;
}

interface IpProfile {
  client_ip: string;
  request_count: number;
  unique_paths: number;
  first_seen: string | null;
  last_seen: string | null;
  user_agents: Array<{ user_agent: string; count: number }>;
  status_distribution: Record<string, number>;
  top_paths: Array<{ request_path: string; count: number }>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function getCrsCategory(ruleId?: string, ruleTitle?: string): string {
  const title = (ruleTitle ?? "").toLowerCase();
  if (title.includes("sql")) return "SQLi";
  if (title.includes("xss") || title.includes("cross-site")) return "XSS";
  if (title.includes("lfi") || title.includes("local file")) return "LFI";
  if (title.includes("rfi") || title.includes("remote file")) return "RFI";
  if (title.includes("rce") || title.includes("remote code")) return "RCE";
  if (title.includes("php")) return "PHP Inject";
  if (title.includes("scan") || title.includes("crawler") || title.includes("dos")) return "Scanner";
  const id = parseInt(ruleId ?? "0");
  if (id >= 941000 && id < 942000) return "XSS";
  if (id >= 942000 && id < 943000) return "SQLi";
  if (id >= 930000 && id < 931000) return "LFI";
  if (id >= 931000 && id < 932000) return "RFI";
  if (id >= 932000 && id < 933000) return "RCE";
  return "Other";
}

function severityColor(sev?: string): string {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL": return "#ff4c4c";
    case "HIGH": return "#ff9800";
    case "MEDIUM": return "#f0c040";
    default: return "#8bc34a";
  }
}

const panelStyle = {
  background: "#0d0d0d",
  border: "1px solid #1e1e1e",
  borderRadius: 6,
  padding: "16px 20px",
} as const;

const panelTitleStyle = {
  fontSize: 11,
  color: "#666",
  letterSpacing: 1,
  textTransform: "uppercase" as const,
  marginBottom: 12,
};

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatActorPage() {
  const [allMatches, setAllMatches] = useState<RuleMatch[]>([]);
  const [behResults, setBehResults] = useState<BehResult>({});
  const [knownIps, setKnownIps] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [ipProfile, setIpProfile] = useState<IpProfile | null>(null);
  const [loadingProfile, setLoadingProfile] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selectedTimelineEvent, setSelectedTimelineEvent] = useState<ThreatEvent | null>(null);

  const { activeProject, timeRange } = useAuthStore();
  const scope = { projectId: activeProject?.id, startTs: timeRange?.from, endTs: timeRange?.to };

  const loadData = useCallback(() => {
    if (!activeProject?.id) { setLoading(false); return; }
    setLoading(true);
    Promise.all([getRuleMatches(scope), getBehavioralResults({ projectId: scope.projectId })]).then(([rm, beh]) => {
      const matches = rm.matches as RuleMatch[];
      setAllMatches(matches);
      setBehResults(beh as BehResult);
      const ips = [...new Set(matches.map((m) => m.client_ip).filter(Boolean))] as string[];
      setKnownIps(ips.sort());
      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeProject?.id, timeRange?.from, timeRange?.to]);

  useEffect(() => { loadData(); }, [loadData]);

  const selectIp = useCallback(async (ip: string) => {
    setSelectedIp(ip);
    setIpProfile(null);
    setLoadingProfile(true);
    try {
      const profile = await getIpSummary(ip);
      setIpProfile(profile as IpProfile);
    } catch {
      // Profile fetch failed (no logs stored); leave null
    } finally {
      setLoadingProfile(false);
    }
  }, []);

  // ── Derived data for selected IP ──────────────────────────────────────────

  const ipMatches = allMatches.filter((m) => m.client_ip === selectedIp);

  const ruleFreq = Object.entries(
    ipMatches.reduce<Record<string, { title?: string; sev?: string; count: number }>>((acc, m) => {
      const key = m.rule_id ?? "?";
      if (!acc[key]) acc[key] = { title: m.rule_title, sev: m.severity, count: 0 };
      acc[key].count++;
      return acc;
    }, {})
  ).sort((a, b) => b[1].count - a[1].count);

  const highestSev = ipMatches.reduce<string>((best, m) => {
    const sev = (m.severity ?? "").toUpperCase();
    return (SEV_ORDER[sev] ?? 0) > (SEV_ORDER[best] ?? 0) ? sev : best;
  }, "LOW");

  const attackCategories = [...new Set(ipMatches.map((m) => getCrsCategory(m.rule_id, m.rule_title)))];

  const timelineEvents: ThreatEvent[] = ipMatches.map((match) => {
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
      source: "threat-actor",
      payload: match,
    };
  });

  // Behavioral coverage
  const behRateSpikes = (behResults.request_rate_spikes ?? []).filter(
    (r) => (r.ip ?? r.client_ip) === selectedIp && r.is_anomaly
  );
  const behUrlEnum = (behResults.url_enumeration ?? []).filter(
    (r) => (r.ip ?? r.client_ip) === selectedIp && r.is_anomaly
  );
  const behVisitors = (behResults.visitor_rates ?? []).filter(
    (r) => r.ip === selectedIp && r.is_anomaly
  );
  const totalBehEvents = behRateSpikes.length + behUrlEnum.length + behVisitors.length;

  // Risk score
  const riskScore = behRateSpikes.length * 3 + behUrlEnum.length * 2 + behVisitors.length;
  const hasCritical = highestSev === "CRITICAL";
  const hasHigh = highestSev === "HIGH";
  const finalRisk = riskScore + (hasCritical ? 20 : hasHigh ? 10 : 0);

  // Top paths (from ipProfile if available, else derive from matches)
  const topPaths: Array<{ label: string; count: number }> = ipProfile?.top_paths?.length
    ? ipProfile.top_paths.slice(0, 10).map((p) => ({ label: p.request_path, count: p.count }))
    : Object.entries(
        ipMatches.reduce<Record<string, number>>((acc, m) => {
          if (m.path) acc[m.path] = (acc[m.path] ?? 0) + 1;
          return acc;
        }, {})
      ).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([label, count]) => ({ label, count }));

  // Success rate
  const successfulHits = ipMatches.filter((m) => m.status_code && m.status_code >= 200 && m.status_code < 300).length;
  const successRate = ipMatches.length > 0 ? ((successfulHits / ipMatches.length) * 100).toFixed(0) : "0";

  // Filtered IP list for typeahead
  const filteredIps = knownIps.filter((ip) => ip.includes(searchQuery)).slice(0, 30);

  // Export
  const exportProfile = () => {
    const payload = {
      client_ip: selectedIp,
      exported_at: new Date().toISOString(),
      risk_score: finalRisk,
      highest_severity: highestSev,
      attack_categories: attackCategories,
      rule_matches: ruleFreq.map(([id, d]) => ({ rule_id: id, ...d })),
      behavioral_events: { rate_spikes: behRateSpikes.length, url_enum: behUrlEnum.length, visitor_anomalies: behVisitors.length },
      ip_profile: ipProfile,
      top_paths: topPaths,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat-actor-${selectedIp ?? "unknown"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── Render ────────────────────────────────────────────────────────────────

  if (!activeProject?.id) return (
    <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
      Select a project from the sidebar to view this page.
    </div>
  );

  return (
    <div className="page-shell">
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
        <SectionHeader
          title="Threat Actor Profile"
          subtitle="Deep-dive into a single IP's attack footprint across all detection modules."
        />
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          <Btn variant="ghost" onClick={() => loadData()}>Refresh</Btn>
        </div>
      </div>

      {/* IP Selection */}
      <div style={{ ...panelStyle, marginBottom: 24 }}>
        <div style={{ ...panelTitleStyle, marginBottom: 10 }}>
          Select IP to Profile ({knownIps.length} known threat actors)
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <SearchInput
            placeholder="Filter IP address..."
            value={searchQuery}
            onChange={setSearchQuery}
          />
          {loading && <Spinner />}
        </div>
        {searchQuery.length > 0 && filteredIps.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
            {filteredIps.map((ip) => (
              <button
                key={ip}
                onClick={() => { selectIp(ip); setSearchQuery(""); }}
                style={{
                  background: selectedIp === ip ? "#1a3a1a" : "#111",
                  color: selectedIp === ip ? "#7cb342" : "#888",
                  border: `1px solid ${selectedIp === ip ? "#355a3b" : "#2a2a2a"}`,
                  borderRadius: 4,
                  padding: "4px 12px",
                  fontSize: 12,
                  cursor: "pointer",
                }}
              >
                {ip}
              </button>
            ))}
          </div>
        )}
        {selectedIp && (
          <div style={{ marginTop: 10, fontSize: 13, color: "#888" }}>
            Profiling: <span style={{ color: "#c0c0c0", fontWeight: 700 }}>{selectedIp}</span>
          </div>
        )}
      </div>

      {!selectedIp && !loading && (
        <div style={{ textAlign: "center", padding: "60px 0", color: "#6b7280", fontSize: 14 }}>
          Search for an IP address above to display its threat actor profile.
        </div>
      )}

      {selectedIp && (
        <>
          {/* KPI Row */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 12, marginBottom: 24 }}>
            <MetricCard
              label="Rule Matches"
              value={ipMatches.length}
              sub="detections triggered"
              accent="#c0c0c0"
            />
            <MetricCard
              label="Unique Paths Targeted"
              value={ipProfile?.unique_paths ?? new Set(ipMatches.map((m) => m.path)).size}
              sub="distinct endpoints"
              accent="#2196f3"
            />
            <MetricCard
              label="Highest Severity"
              value={highestSev}
              sub={`${hasCritical || hasHigh ? "⚠ Escalation risk" : "Moderate activity"}`}
              accent={severityColor(highestSev)}
            />
            <MetricCard
              label="Behavioral Events"
              value={totalBehEvents}
              sub="anomalies flagged"
              accent="#ff9800"
            />
            <MetricCard
              label="Risk Score"
              value={finalRisk}
              sub={`Success rate: ${successRate}%`}
              accent={finalRisk >= 20 ? "#ff4c4c" : finalRisk >= 10 ? "#ff9800" : "#8bc34a"}
            />
          </div>

          {/* Detection Coverage Badges */}
          <div style={{ ...panelStyle, padding: "14px 20px", marginBottom: 24 }}>
            <div style={{ ...panelTitleStyle, marginBottom: 10 }}>
              Detection Module Coverage
            </div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              {[
                { label: "Rule Matches", hit: ipMatches.length > 0 },
                { label: "Rate Spike", hit: behRateSpikes.length > 0 },
                { label: "URL Enumeration", hit: behUrlEnum.length > 0 },
                { label: "Visitor Anomaly", hit: behVisitors.length > 0 },
                { label: "Suspected Successful", hit: successfulHits > 0 },
              ].map(({ label, hit }) => (
                <span
                  key={label}
                  style={{
                    background: hit ? "#0f180f" : "#111",
                    border: `1px solid ${hit ? "#2a5a2a" : "#2a2a2a"}`,
                    color: hit ? "#7cb342" : "#666",
                    borderRadius: 20,
                    padding: "4px 14px",
                    fontSize: 12,
                    fontWeight: 600,
                  }}
                >
                  {hit ? "✓" : "✗"} {label}
                </span>
              ))}
            </div>
          </div>

          {/* Attack Categories + First/Last Seen */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16, marginBottom: 24 }}>
            <div style={{ ...panelStyle, padding: "14px 20px" }}>
              <div style={{ ...panelTitleStyle, marginBottom: 10 }}>
                Attack Categories
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {attackCategories.length > 0 ? attackCategories.map((cat) => (
                  <Badge key={cat} label={cat} color="#888" />
                )) : <span style={{ color: "#6b7280", fontSize: 13 }}>None detected</span>}
              </div>
            </div>
            <div style={{ ...panelStyle, padding: "14px 20px" }}>
              <div style={{ ...panelTitleStyle, marginBottom: 10 }}>
                Activity Window
              </div>
              {loadingProfile ? <Spinner /> : (
                <div style={{ fontSize: 13, lineHeight: 2 }}>
                  <div><span style={{ color: "#666" }}>First seen: </span><span style={{ color: "#c0c0c0" }}>{ipProfile?.first_seen ?? "N/A"}</span></div>
                  <div><span style={{ color: "#666" }}>Last seen: </span><span style={{ color: "#c0c0c0" }}>{ipProfile?.last_seen ?? "N/A"}</span></div>
                  <div><span style={{ color: "#666" }}>Total requests: </span><span style={{ color: "#c0c0c0" }}>{ipProfile?.request_count ?? "N/A"}</span></div>
                </div>
              )}
            </div>
          </div>

          {/* Detection Timeline */}
          <div style={{ ...panelStyle, marginBottom: 24 }}>
            <div style={panelTitleStyle}>
              Threat Timeline
            </div>
            <ThreatTimeline
              events={timelineEvents}
              height={300}
              onEventClick={(event) => setSelectedTimelineEvent(event)}
              emptyState="No detection events for this IP in the selected scope"
            />
          </div>

          {/* Rules Triggered & Top Paths */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 16, marginBottom: 24 }}>
            <div style={{ ...panelStyle, overflow: "hidden" }}>
              <div style={panelTitleStyle}>
                Rules Triggered ({ruleFreq.length})
              </div>
              {ruleFreq.length === 0
                ? <span style={{ color: "#6b7280", fontSize: 13 }}>No rules matched.</span>
                : (
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid #2a2a2a", color: "#666" }}>
                          <th style={{ textAlign: "left", padding: "6px 8px" }}>Rule ID</th>
                          <th style={{ textAlign: "left", padding: "6px 8px" }}>Title</th>
                          <th style={{ textAlign: "left", padding: "6px 8px" }}>Sev</th>
                          <th style={{ textAlign: "right", padding: "6px 8px" }}>Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ruleFreq.slice(0, 15).map(([id, d]) => (
                          <tr key={id} style={{ borderBottom: "1px solid #1a1a1a" }}>
                            <td style={{ padding: "6px 8px", color: "#c0c0c0", fontFamily: "monospace" }}>{id}</td>
                            <td style={{ padding: "6px 8px", color: "#999", maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={d.title}>{d.title ?? "—"}</td>
                            <td style={{ padding: "6px 8px" }}><StatusBadge status={d.sev ?? "LOW"} /></td>
                            <td style={{ padding: "6px 8px", color: "#d0d0d0", textAlign: "right", fontWeight: 700 }}>{d.count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {ruleFreq.length > 15 && (
                      <div style={{ fontSize: 11, color: "#6b7280", marginTop: 8 }}>
                        + {ruleFreq.length - 15} more rules
                      </div>
                    )}
                  </div>
                )}
            </div>

            <div style={{ ...panelStyle }}>
              <div style={panelTitleStyle}>
                Top Targeted Paths
              </div>
              {topPaths.length === 0
                ? <span style={{ color: "#6b7280", fontSize: 13 }}>No path data available.</span>
                : <BarChart labels={topPaths.map((p) => p.label)} values={topPaths.map((p) => p.count)} color="#7cb342" horizontal />}
            </div>
          </div>

          {/* Behavioral Events */}
          {totalBehEvents > 0 && (
            <div style={{ ...panelStyle, marginBottom: 24 }}>
              <div style={panelTitleStyle}>
                Behavioral Events
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {behRateSpikes.map((e, i) => (
                  <div key={`rate-${i}`} style={{ background: "#0a0a0a", border: "1px solid #1a1a1a", borderRadius: 4, padding: "8px 14px", fontSize: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span><span style={{ color: "#ff9800", fontWeight: 700 }}>RATE SPIKE</span> — {e.count} requests in window</span>
                    <span style={{ color: "#666" }}>{e.timestamp ?? "—"}</span>
                  </div>
                ))}
                {behUrlEnum.map((e, i) => (
                  <div key={`url-${i}`} style={{ background: "#0a0a0a", border: "1px solid #1a1a1a", borderRadius: 4, padding: "8px 14px", fontSize: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span><span style={{ color: "#2196f3", fontWeight: 700 }}>URL ENUM</span> — {e.unique_paths} unique paths probed</span>
                    <span style={{ color: "#666" }}>—</span>
                  </div>
                ))}
                {behVisitors.map((e, i) => (
                  <div key={`vis-${i}`} style={{ background: "#0a0a0a", border: "1px solid #1a1a1a", borderRadius: 4, padding: "8px 14px", fontSize: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span><span style={{ color: "#e91e63", fontWeight: 700 }}>VISITOR ANOMALY</span> — {e.requests} requests</span>
                    <span style={{ color: "#666" }}>{e.timestamp ?? "—"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* User Agents */}
          {(ipProfile?.user_agents?.length ?? 0) > 0 && (
            <div style={{ ...panelStyle, marginBottom: 24 }}>
              <div style={panelTitleStyle}>
                User Agent Strings
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {ipProfile!.user_agents.slice(0, 8).map((ua, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0a0a0a", border: "1px solid #1a1a1a", borderRadius: 4, padding: "6px 12px", fontSize: 11 }}>
                    <span style={{ color: "#999", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "85%" }} title={ua.user_agent}>
                      {ua.user_agent || "(empty)"}
                    </span>
                    <span style={{ color: "#c0c0c0", fontWeight: 700, marginLeft: 8 }}>{ua.count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <Divider />

          {/* Export */}
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 16 }}>
            <Btn onClick={exportProfile}>Export Profile JSON</Btn>
          </div>
        </>
      )}

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
