"use client";

import { useEffect, useState, useCallback } from "react";
import { getRuleMatches, getBehavioralResults } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import {
  SectionHeader,
  MetricCard,
  Btn,
  Spinner,
  StatusBadge,
  Badge,
} from "@/components/ui-primitives";

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
}

interface BehResult {
  request_rate_spikes?: Array<{ ip?: string; client_ip?: string; count?: number; rate?: number; is_anomaly?: boolean; }>;
  url_enumeration?: Array<{ ip?: string; client_ip?: string; unique_paths?: number; is_anomaly?: boolean; }>;
  status_code_spikes?: Array<{ window?: string; status?: number | string; count?: number; is_anomaly?: boolean; }>;
  visitor_rates?: Array<{ ip?: string; window?: string; requests?: number; is_anomaly?: boolean; }>;
}

interface IpRow {
  ip: string;
  ruleMatchCount: number;
  highestSev: string;
  rateSpike: boolean;
  urlEnum: boolean;
  statusSpike: boolean;
  visitorAnomaly: boolean;
  riskScore: number;
  isCorrelated: boolean;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function severityColor(sev: string): string {
  switch (sev) {
    case "CRITICAL": return "#ff4c4c";
    case "HIGH": return "#ff9800";
    case "MEDIUM": return "#f0c040";
    default: return "#8bc34a";
  }
}

function cellColor(count: number, max: number): string {
  if (max === 0 || count === 0) return "#0d1117";
  const t = count / max;
  const r = Math.round(13 + t * (255 - 13));
  const g = Math.round(17 + t * (76 - 17));
  const b = Math.round(23 + t * (76 - 23));
  return `rgb(${r},${g},${b})`;
}

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

// ─── Matrix Cell ──────────────────────────────────────────────────────────────

function MatrixCell({ hit, color }: { hit: boolean; color?: string }) {
  return (
    <div style={{
      background: hit ? (color ?? "#44444422") : "#0a0a0a",
      border: `1px solid ${hit ? (color ?? "#666") : "#1e1e1e"}`,
      borderRadius: 4,
      width: "100%",
      height: 28,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontSize: 10,
      color: hit ? "#fff" : "#2a2a3e",
    }}>
      {hit ? "●" : ""}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CorrelationPage() {
  const [loading, setLoading] = useState(true);
  const [ipRows, setIpRows] = useState<IpRow[]>([]);
  const [heatRules, setHeatRules] = useState<string[]>([]);
  const [heatIps, setHeatIps] = useState<string[]>([]);
  const [heatGrid, setHeatGrid] = useState<Record<string, Record<string, number>>>({});
  const [heatMax, setHeatMax] = useState(1);

  const { activeProject, timeRange } = useAuthStore();
  const scope = { projectId: activeProject?.id, startTs: timeRange?.from, endTs: timeRange?.to };

  const loadData = useCallback(() => {
    if (!activeProject?.id) { setLoading(false); return; }
    setLoading(true);
    Promise.all([getRuleMatches(scope), getBehavioralResults({ projectId: scope.projectId })]).then(([rm, beh]) => {
      const matches = rm.matches as RuleMatch[];
      const behData = beh as BehResult;

      // Collect all known IPs from matches
      const allIps = [...new Set(matches.map((m) => m.client_ip).filter(Boolean))] as string[];

      // Behavioral IP sets
      const rateIps = new Set(
        (behData.request_rate_spikes ?? []).filter((r) => r.is_anomaly).map((r) => r.ip ?? r.client_ip).filter(Boolean) as string[]
      );
      const urlIps = new Set(
        (behData.url_enumeration ?? []).filter((r) => r.is_anomaly).map((r) => r.ip ?? r.client_ip).filter(Boolean) as string[]
      );
      const statusIps = new Set(
        (behData.status_code_spikes ?? []).filter((r) => r.is_anomaly).map(() => "").filter(Boolean) as string[]
      );
      const visitorIps = new Set(
        (behData.visitor_rates ?? []).filter((r) => r.is_anomaly).map((r) => r.ip).filter(Boolean) as string[]
      );

      // Build per-IP rows
      const rows: IpRow[] = allIps.map((ip) => {
        const ipMatches = matches.filter((m) => m.client_ip === ip);
        const highestSev = ipMatches.reduce<string>((best, m) => {
          const sev = (m.severity ?? "").toUpperCase();
          return (SEV_ORDER[sev] ?? 0) > (SEV_ORDER[best] ?? 0) ? sev : best;
        }, "LOW");
        const rateSpike = rateIps.has(ip);
        const urlEnum = urlIps.has(ip);
        const statusSpike = statusIps.has(ip);
        const visitorAnomaly = visitorIps.has(ip);
        const riskScore =
          (rateSpike ? 3 : 0) +
          (urlEnum ? 2 : 0) +
          (visitorAnomaly ? 1 : 0) +
          ((highestSev === "CRITICAL") ? 20 : (highestSev === "HIGH") ? 10 : 0);
        const isCorrelated = ipMatches.length > 0 && (rateSpike || urlEnum || visitorAnomaly);
        return { ip, ruleMatchCount: ipMatches.length, highestSev, rateSpike, urlEnum, statusSpike, visitorAnomaly, riskScore, isCorrelated };
      });

      rows.sort((a, b) => b.riskScore - a.riskScore);
      setIpRows(rows);

      // Build Rule x IP heatmap (top 10 rules x top 15 IPs)
      const topHeatIps = rows.slice(0, 15).map((r) => r.ip);
      const ruleCountMap: Record<string, number> = {};
      matches.forEach((m) => {
        if (m.rule_id) ruleCountMap[m.rule_id] = (ruleCountMap[m.rule_id] ?? 0) + 1;
      });
      const topRules = Object.entries(ruleCountMap).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([id]) => id);

      const grid: Record<string, Record<string, number>> = {};
      let maxVal = 0;
      topRules.forEach((ruleId) => {
        grid[ruleId] = {};
        topHeatIps.forEach((ip) => {
          const count = matches.filter((m) => m.rule_id === ruleId && m.client_ip === ip).length;
          grid[ruleId][ip] = count;
          if (count > maxVal) maxVal = count;
        });
      });

      setHeatRules(topRules);
      setHeatIps(topHeatIps);
      setHeatGrid(grid);
      setHeatMax(maxVal);
      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeProject?.id, timeRange?.from, timeRange?.to]);

  useEffect(() => { loadData(); }, [loadData]);

  if (!activeProject?.id) return (
    <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
      Select a project from the sidebar to view this page.
    </div>
  );

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <Spinner />
        <span style={{ color: "#666" }}>Loading correlation data...</span>
      </div>
    );
  }

  const correlatedRows = ipRows.filter((r) => r.isCorrelated);
  const totalIps = ipRows.length;
  const criticalCount = ipRows.filter((r) => r.highestSev === "CRITICAL").length;
  const highCount = ipRows.filter((r) => r.highestSev === "HIGH").length;

  // Category breakdown across all IPs
  return (
    <div className="page-shell">
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
        <SectionHeader
          title="Cross-Module Correlation"
          subtitle="IPs that appear in multiple detection modules — highest-confidence threat actors."
        />
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          <Btn variant="ghost" onClick={() => loadData()}>Refresh</Btn>
        </div>
      </div>

      {/* KPI Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 24 }}>
        <MetricCard label="Known IPs" value={totalIps} sub="from rule matches" accent="#c0c0c0" />
        <MetricCard label="Correlated IPs" value={correlatedRows.length} sub="rules + behavioral" accent="#22c55e" />
        <MetricCard label="Critical Severity" value={criticalCount} sub="highest-severity IPs" accent="#ff4c4c" />
        <MetricCard label="High Severity" value={highCount} sub="high-severity IPs" accent="#ff9800" />
      </div>

      {/* High Confidence Threat Actors */}
      <div style={{ ...panelStyle, marginBottom: 24 }}>
        <div style={panelTitleStyle}>
          High Confidence Threat Actors
          <span style={{ marginLeft: 10, color: "#7cb342", fontSize: 11 }}>({correlatedRows.length} correlated IPs)</span>
        </div>
        {correlatedRows.length === 0 ? (
          <div style={{ color: "#6b7280", fontSize: 13 }}>No IPs found in both rule matches and behavioral analysis.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #2a2a2a", color: "#666" }}>
                  <th style={{ textAlign: "left", padding: "6px 10px" }}>IP Address</th>
                  <th style={{ textAlign: "center", padding: "6px 10px" }}>Rule Matches</th>
                  <th style={{ textAlign: "center", padding: "6px 10px" }}>Severity</th>
                  <th style={{ textAlign: "center", padding: "6px 10px" }}>Rate Spike</th>
                  <th style={{ textAlign: "center", padding: "6px 10px" }}>URL Enum</th>
                  <th style={{ textAlign: "center", padding: "6px 10px" }}>Visitor Anomaly</th>
                  <th style={{ textAlign: "right", padding: "6px 10px" }}>Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {correlatedRows.map((row) => (
                  <tr key={row.ip} style={{ borderBottom: "1px solid #1a1a1a" }}>
                    <td style={{ padding: "7px 10px", color: "#c0c0c0", fontFamily: "monospace", fontWeight: 700 }}>
                      {row.ip}
                      {row.highestSev === "CRITICAL" && (
                        <span style={{ marginLeft: 6, background: "#ff4c4c22", color: "#ff4c4c", borderRadius: 4, padding: "1px 6px", fontSize: 10, fontWeight: 700 }}>CRITICAL</span>
                      )}
                    </td>
                    <td style={{ padding: "7px 10px", textAlign: "center", color: "#d0d0d0" }}>{row.ruleMatchCount}</td>
                    <td style={{ padding: "7px 10px", textAlign: "center" }}>
                      <StatusBadge status={row.highestSev} />
                    </td>
                    <td style={{ padding: "7px 10px", textAlign: "center" }}>
                      <span style={{ color: row.rateSpike ? "#ff9800" : "#333" }}>{row.rateSpike ? "●" : "○"}</span>
                    </td>
                    <td style={{ padding: "7px 10px", textAlign: "center" }}>
                      <span style={{ color: row.urlEnum ? "#2196f3" : "#333" }}>{row.urlEnum ? "●" : "○"}</span>
                    </td>
                    <td style={{ padding: "7px 10px", textAlign: "center" }}>
                      <span style={{ color: row.visitorAnomaly ? "#e91e63" : "#333" }}>{row.visitorAnomaly ? "●" : "○"}</span>
                    </td>
                    <td style={{ padding: "7px 10px", textAlign: "right", fontWeight: 700, color: row.riskScore >= 20 ? "#ff4c4c" : row.riskScore >= 10 ? "#ff9800" : "#8bc34a" }}>
                      {row.riskScore}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detection Coverage Matrix */}
      <div style={{ ...panelStyle, marginBottom: 24 }}>
        <div style={{ ...panelTitleStyle, marginBottom: 14 }}>
          Detection Coverage Matrix
          <span style={{ marginLeft: 10, color: "#666", fontSize: 11, fontWeight: 400 }}>Top 15 IPs × Detection Modules</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ borderCollapse: "collapse", fontSize: 11, minWidth: 700 }}>
            <thead>
              <tr>
                <th style={{ padding: "6px 10px", color: "#666", textAlign: "left", minWidth: 120 }}>IP</th>
                {["Rule Match", "Rate Spike", "URL Enum", "Visitor Anomaly", "High/Critical"].map((col) => (
                  <th key={col} style={{ padding: "6px 8px", color: "#666", textAlign: "center", minWidth: 90 }}>{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ipRows.slice(0, 15).map((row) => (
                <tr key={row.ip} style={{ borderBottom: "1px solid #161616" }}>
                  <td style={{ padding: "4px 10px", color: "#c0c0c0", fontFamily: "monospace", fontSize: 11 }}>{row.ip}</td>
                  <td style={{ padding: "4px 6px" }}>
                    <MatrixCell hit={row.ruleMatchCount > 0} color="#808080" />
                  </td>
                  <td style={{ padding: "4px 6px" }}>
                    <MatrixCell hit={row.rateSpike} color="#ff9800" />
                  </td>
                  <td style={{ padding: "4px 6px" }}>
                    <MatrixCell hit={row.urlEnum} color="#2196f3" />
                  </td>
                  <td style={{ padding: "4px 6px" }}>
                    <MatrixCell hit={row.visitorAnomaly} color="#e91e63" />
                  </td>
                  <td style={{ padding: "4px 6px" }}>
                    <MatrixCell hit={row.highestSev === "CRITICAL" || row.highestSev === "HIGH"} color="#ff4c4c" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ display: "flex", gap: 16, marginTop: 12, flexWrap: "wrap" }}>
          {[
            { label: "Rule Match", color: "#808080" },
            { label: "Rate Spike", color: "#ff9800" },
            { label: "URL Enum", color: "#2196f3" },
            { label: "Visitor Anomaly", color: "#e91e63" },
            { label: "High/Critical", color: "#ff4c4c" },
          ].map(({ label, color }) => (
            <span key={label} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "#666" }}>
              <span style={{ width: 10, height: 10, background: color, borderRadius: 2, display: "inline-block" }} />
              {label}
            </span>
          ))}
        </div>
      </div>

      {/* Rule × IP Heatmap */}
      {heatRules.length > 0 && heatIps.length > 0 && (
        <div style={{ ...panelStyle, marginBottom: 24 }}>
          <div style={{ ...panelTitleStyle, marginBottom: 14 }}>
            Rule × IP Heatmap
            <span style={{ marginLeft: 10, color: "#666", fontSize: 11, fontWeight: 400 }}>Match count — darker = higher</span>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ borderCollapse: "collapse", fontSize: 10 }}>
              <thead>
                <tr>
                  <th style={{ padding: "4px 8px", color: "#666", textAlign: "left", minWidth: 100 }}>Rule ID</th>
                  {heatIps.map((ip) => (
                    <th key={ip} style={{ padding: "4px 4px", color: "#666", textAlign: "center", minWidth: 56, maxWidth: 56, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ip}>
                      {ip.length > 12 ? ip.slice(-8) : ip}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {heatRules.map((ruleId) => (
                  <tr key={ruleId}>
                    <td style={{ padding: "3px 8px", color: "#c0c0c0", fontFamily: "monospace", fontSize: 10 }}>{ruleId}</td>
                    {heatIps.map((ip) => {
                      const count = heatGrid[ruleId]?.[ip] ?? 0;
                      return (
                        <td key={ip} style={{ padding: "2px 3px" }} title={`${ruleId} × ${ip}: ${count}`}>
                          <div style={{
                            width: 50,
                            height: 24,
                            background: cellColor(count, heatMax),
                            borderRadius: 3,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: 9,
                            color: count > 0 ? "#fff" : "#2a2a3e",
                            fontWeight: count > 0 ? 700 : 400,
                          }}>
                            {count > 0 ? count : ""}
                          </div>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* All IPs Table */}
      <div style={panelStyle}>
        <div style={panelTitleStyle}>
          All Threat Actors by Risk Score ({ipRows.length} IPs)
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #2a2a2a", color: "#666" }}>
                <th style={{ textAlign: "left", padding: "6px 10px" }}>IP</th>
                <th style={{ textAlign: "center", padding: "6px 10px" }}>Matches</th>
                <th style={{ textAlign: "center", padding: "6px 10px" }}>Severity</th>
                <th style={{ textAlign: "center", padding: "6px 10px" }}>Modules</th>
                <th style={{ textAlign: "right", padding: "6px 10px" }}>Risk</th>
              </tr>
            </thead>
            <tbody>
              {ipRows.map((row) => {
                const modules = [row.rateSpike && "R", row.urlEnum && "U", row.visitorAnomaly && "V"].filter(Boolean);
                return (
                  <tr key={row.ip} style={{ borderBottom: "1px solid #161616" }}>
                    <td style={{ padding: "6px 10px", color: "#c0c0c0", fontFamily: "monospace" }}>
                      {row.ip}
                      {row.isCorrelated && <span style={{ marginLeft: 6, color: "#7cb342", fontSize: 10, fontWeight: 700 }}>CORRELATED</span>}
                    </td>
                    <td style={{ padding: "6px 10px", textAlign: "center", color: "#d0d0d0" }}>{row.ruleMatchCount}</td>
                    <td style={{ padding: "6px 10px", textAlign: "center" }}>
                      <span style={{ color: severityColor(row.highestSev), fontWeight: 700, fontSize: 11 }}>{row.highestSev}</span>
                    </td>
                    <td style={{ padding: "6px 10px", textAlign: "center" }}>
                      <span style={{ fontFamily: "monospace", color: "#666", fontSize: 11 }}>
                        {modules.length > 0 ? modules.join("+") : "—"}
                      </span>
                    </td>
                    <td style={{ padding: "6px 10px", textAlign: "right", fontWeight: 700, color: row.riskScore >= 20 ? "#ff4c4c" : row.riskScore >= 10 ? "#ff9800" : "#8bc34a" }}>
                      {row.riskScore}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
