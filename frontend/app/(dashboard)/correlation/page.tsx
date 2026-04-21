"use client";

import Link from "next/link";
import { useEffect, useState, useCallback, useMemo } from "react";
import { getRuleMatches, getBehavioralResults } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import {
  SectionHeader,
  MetricCard,
  Btn,
  Spinner,
  StatusBadge,
} from "@/components/ui-primitives";
import { WindowsEventTable } from "@/components/windows-ui";
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
}

interface BehResult {
  request_rate_spikes?: Array<{ ip?: string; client_ip?: string; count?: number; rate?: number; is_anomaly?: boolean; }>;
  url_enumeration?: Array<{ ip?: string; client_ip?: string; unique_paths?: number; is_anomaly?: boolean; }>;
  status_code_spikes?: Array<{ ip?: string; client_ip?: string; window?: string; status?: number | string; count?: number; is_anomaly?: boolean; }>;
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
  lastSeen: string | null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

function sevColor(sev: string) {
  switch (sev) {
    case "HIGH": return "#ff4c4c";
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

function getRiskColor(score: number): string {
  if (score >= 20) return "#ff4c4c";
  if (score >= 12) return "#ff9800";
  if (score >= 6) return "#f0c040";
  return "#8bc34a";
}

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
  const [error, setError] = useState<string | null>(null);
  const [ipRows, setIpRows] = useState<IpRow[]>([]);
  const [ruleMatchesByIp, setRuleMatchesByIp] = useState<Record<string, RuleMatch[]>>({});
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [correlatedOnly, setCorrelatedOnly] = useState(true);
  const [heatRules, setHeatRules] = useState<string[]>([]);
  const [heatIps, setHeatIps] = useState<string[]>([]);
  const [heatGrid, setHeatGrid] = useState<Record<string, Record<string, number>>>({});
  const [heatMax, setHeatMax] = useState(1);

  const { activeProject, timeRange } = useAuthStore();
  const scope = { projectId: activeProject?.id, startTs: timeRange?.from, endTs: timeRange?.to };

  const loadData = useCallback(async () => {
    if (!activeProject?.id) {
      setLoading(false);
      setError(null);
      return;
    }

    setLoading(true);
    setError(null);

    const [ruleResult, behavioralResult] = await Promise.allSettled([
      getRuleMatches(scope),
      getBehavioralResults({ projectId: scope.projectId }),
    ]);

    if (ruleResult.status !== "fulfilled") {
      setIpRows([]);
      setHeatRules([]);
      setHeatIps([]);
      setHeatGrid({});
      setHeatMax(1);
      setLoading(false);
      setError("Unable to load rule matches for correlation.");
      return;
    }

    const matches = ruleResult.value.matches as RuleMatch[];
    const behData = behavioralResult.status === "fulfilled" ? (behavioralResult.value as BehResult) : {};
    if (behavioralResult.status !== "fulfilled") {
      setError("Behavioral results not available yet. Correlation currently uses rule matches only.");
    }

    const byIp: Record<string, RuleMatch[]> = {};
    for (const match of matches) {
      if (!match.client_ip) continue;
      if (!byIp[match.client_ip]) byIp[match.client_ip] = [];
      byIp[match.client_ip].push(match);
    }
    setRuleMatchesByIp(byIp);

    // Behavioral IP sets
    const rateIps = new Set(
      (behData.request_rate_spikes ?? []).filter((r) => r.is_anomaly).map((r) => r.ip ?? r.client_ip).filter(Boolean) as string[]
    );
    const urlIps = new Set(
      (behData.url_enumeration ?? []).filter((r) => r.is_anomaly).map((r) => r.ip ?? r.client_ip).filter(Boolean) as string[]
    );
    const statusIps = new Set(
      (behData.status_code_spikes ?? []).filter((r) => r.is_anomaly).map((r) => r.ip ?? r.client_ip).filter(Boolean) as string[]
    );
    const visitorIps = new Set(
      (behData.visitor_rates ?? []).filter((r) => r.is_anomaly).map((r) => r.ip).filter(Boolean) as string[]
    );

    // Union of all IPs observed in any module
    const allIps = [...new Set([
      ...Object.keys(byIp),
      ...Array.from(rateIps),
      ...Array.from(urlIps),
      ...Array.from(statusIps),
      ...Array.from(visitorIps),
    ])] as string[];

    // Build per-IP rows
    const rows: IpRow[] = allIps.map((ip) => {
      const ipMatches = byIp[ip] ?? [];
      const highestSev = ipMatches.reduce<string>((best, m) => {
        const sev = (m.severity ?? "").toUpperCase();
        return (SEV_ORDER[sev] ?? 0) > (SEV_ORDER[best] ?? 0) ? sev : best;
      }, "LOW");
      const rateSpike = rateIps.has(ip);
      const urlEnum = urlIps.has(ip);
      const statusSpike = statusIps.has(ip);
      const visitorAnomaly = visitorIps.has(ip);
      const behaviorSignalCount = [rateSpike, urlEnum, statusSpike, visitorAnomaly].filter(Boolean).length;
      const riskScore =
        Math.min(ipMatches.length, 5) +
        (rateSpike ? 3 : 0) +
        (urlEnum ? 2 : 0) +
        (statusSpike ? 1 : 0) +
        (visitorAnomaly ? 1 : 0) +
        (highestSev === "HIGH" ? 10 : 0);
      const isCorrelated = ipMatches.length >= 2 || (ipMatches.length > 0 && behaviorSignalCount > 0) || behaviorSignalCount >= 2;
      const lastSeen = ipMatches.length > 0
        ? ipMatches
            .map((m) => m.timestamp)
            .filter(Boolean)
            .sort((a, b) => new Date(b ?? 0).getTime() - new Date(a ?? 0).getTime())[0] ?? null
        : null;
      return { ip, ruleMatchCount: ipMatches.length, highestSev, rateSpike, urlEnum, statusSpike, visitorAnomaly, riskScore, isCorrelated, lastSeen };
    });

    rows.sort((a, b) => {
      if (a.isCorrelated !== b.isCorrelated) return a.isCorrelated ? -1 : 1;
      return b.riskScore - a.riskScore;
    });
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
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeProject?.id, timeRange?.from, timeRange?.to]);

  useEffect(() => { loadData(); }, [loadData]);

  useEffect(() => {
    if (!selectedIp) return;
    const stillVisible = ipRows.some((row) => row.ip === selectedIp);
    if (!stillVisible) {
      setSelectedIp(null);
      setShowDetailsModal(false);
    }
  }, [selectedIp, ipRows]);

  const selectedRow = useMemo(() => ipRows.find((row) => row.ip === selectedIp) ?? null, [ipRows, selectedIp]);
  const selectedMatches = useMemo(() => (selectedRow ? (ruleMatchesByIp[selectedRow.ip] ?? []) : []), [selectedRow, ruleMatchesByIp]);

  const severityOptions = useMemo(
    () => [...new Set(ipRows.map((row) => row.highestSev).filter(Boolean))].sort((a, b) => (SEV_ORDER[b] ?? 0) - (SEV_ORDER[a] ?? 0)),
    [ipRows]
  );

  const filteredRows = useMemo(() => {
    return ipRows.filter((row) => {
      if (correlatedOnly && !row.isCorrelated) return false;
      if (severityFilter && row.highestSev !== severityFilter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      const topRules = (ruleMatchesByIp[row.ip] ?? [])
        .slice(0, 6)
        .map((m) => (m.rule_title ?? m.rule_id ?? "").toLowerCase());
      return row.ip.toLowerCase().includes(q) || topRules.some((r) => r.includes(q));
    });
  }, [correlatedOnly, ipRows, ruleMatchesByIp, search, severityFilter]);

  const tableRows = useMemo(
    () => filteredRows.slice(0, 300).map((row) => ({ id: row.ip, row })) as Array<Record<string, unknown>>,
    [filteredRows]
  );

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

      {error && (
        <div style={{ marginBottom: 16, border: "1px solid #2a2a2a", borderRadius: 4, padding: "8px 12px", color: "#8a8a8a", fontSize: 11 }}>
          {error}
        </div>
      )}

      {/* KPI Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 24 }}>
        <MetricCard label="Known IPs" value={totalIps} sub="from rule matches" accent="#c0c0c0" />
        <MetricCard label="Correlated IPs" value={correlatedRows.length} sub="rules + behavioral" accent="#22c55e" />
        <MetricCard label="High Severity" value={highCount} sub="highest-severity IPs" accent="#ff4c4c" />
      </div>

      {/* High Confidence Threat Actors */}
      <div style={{ ...panelStyle, marginBottom: 24 }}>
        <div style={{ ...panelTitleStyle, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
          <span>
            Correlated Threat Actors
            <span style={{ marginLeft: 10, color: "#7cb342", fontSize: 11 }}>({correlatedRows.length} correlated IPs)</span>
          </span>
          <Link
            href="/detections"
            style={{
              color: "#7cb342",
              border: "1px solid #2f4a20",
              background: "#111",
              borderRadius: 3,
              padding: "6px 10px",
              fontSize: 10,
              letterSpacing: 0.7,
              textTransform: "uppercase",
              textDecoration: "none",
            }}
          >
            Open Detections
          </Link>
        </div>

        <div style={{ display: "flex", gap: 10, marginBottom: 10, flexWrap: "wrap", alignItems: "center" }}>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP or rule..."
            style={{
              background: "#111",
              border: "1px solid #2a2a2a",
              color: "#aaa",
              borderRadius: 2,
              padding: "7px 10px",
              fontSize: 11,
              minWidth: 260,
            }}
          />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{
              background: "#111",
              border: "1px solid #2a2a2a",
              color: "#aaa",
              borderRadius: 2,
              padding: "7px 10px",
              fontSize: 11,
            }}
          >
            <option value="">All Severities</option>
            {severityOptions.map((sev) => (
              <option key={sev} value={sev}>{sev}</option>
            ))}
          </select>
          <button
            onClick={() => setCorrelatedOnly((v) => !v)}
            style={{
              background: correlatedOnly ? "#1a2a1a" : "#111",
              border: `1px solid ${correlatedOnly ? "#4caf50" : "#2a2a2a"}`,
              color: correlatedOnly ? "#4caf50" : "#666",
              borderRadius: 3,
              padding: "7px 10px",
              fontSize: 10,
              letterSpacing: 0.8,
              textTransform: "uppercase",
              cursor: "pointer",
            }}
          >
            {correlatedOnly ? "Correlated Only" : "All Actors"}
          </button>
          <div style={{ color: "#666", fontSize: 11, marginLeft: "auto" }}>
            {filteredRows.length.toLocaleString()} / {ipRows.length.toLocaleString()}
          </div>
        </div>

        <WindowsEventTable
          density="compact"
          stickyHeader
          maxHeight={560}
          emptyMessage="No correlation results for current filters"
          rowKey={(row) => String(row.id ?? "")}
          data={tableRows}
          selectedRowKey={selectedIp ?? undefined}
          onRowClick={(tableRow) => {
            const ipRow = (tableRow.row ?? null) as IpRow | null;
            if (!ipRow) return;
            setSelectedIp(ipRow.ip);
          }}
          columns={[
            {
              key: "state",
              label: "State",
              width: "130px",
              render: (tableRow) => {
                const row = tableRow.row as IpRow;
                return (
                  <span style={{
                    color: row.isCorrelated ? "#7cb342" : "#666",
                    border: `1px solid ${row.isCorrelated ? "#2f4a20" : "#2a2a2a"}`,
                    borderRadius: 3,
                    padding: "2px 7px",
                    fontSize: 9,
                    letterSpacing: 0.6,
                    textTransform: "uppercase",
                  }}>
                    {row.isCorrelated ? "Correlated" : "Observed"}
                  </span>
                );
              },
            },
            {
              key: "ip",
              label: "IP",
              width: "150px",
              render: (tableRow) => {
                const row = tableRow.row as IpRow;
                return <span style={{ color: "#c0c0c0", fontFamily: "var(--font-mono-stack)", fontSize: 11 }}>{row.ip}</span>;
              },
            },
            {
              key: "matches",
              label: "Rule Matches",
              width: "110px",
              render: (tableRow) => {
                const row = tableRow.row as IpRow;
                return <span style={{ color: "#d7d7d7", fontFamily: "var(--font-mono-stack)" }}>{row.ruleMatchCount}</span>;
              },
            },
            {
              key: "severity",
              label: "Highest Severity",
              width: "140px",
              render: (tableRow) => {
                const row = tableRow.row as IpRow;
                return <StatusBadge status={row.highestSev} />;
              },
            },
            {
              key: "signals",
              label: "Behavioral Signals",
              width: "180px",
              render: (tableRow) => {
                const row = tableRow.row as IpRow;
                return (
                  <span style={{ display: "inline-flex", gap: 5, fontSize: 10, letterSpacing: 0.4, fontFamily: "var(--font-mono-stack)" }}>
                    <span style={{ color: row.rateSpike ? "#ff9800" : "#444" }}>R</span>
                    <span style={{ color: row.urlEnum ? "#2196f3" : "#444" }}>U</span>
                    <span style={{ color: row.statusSpike ? "#9c27b0" : "#444" }}>S</span>
                    <span style={{ color: row.visitorAnomaly ? "#e91e63" : "#444" }}>V</span>
                  </span>
                );
              },
            },
            {
              key: "risk",
              label: "Risk",
              width: "90px",
              render: (tableRow) => {
                const row = tableRow.row as IpRow;
                return <span style={{ color: getRiskColor(row.riskScore), fontWeight: 700 }}>{row.riskScore}</span>;
              },
            },
            {
              key: "last_seen",
              label: "Last Seen",
              width: "190px",
              render: (tableRow) => {
                const row = tableRow.row as IpRow;
                return <span style={{ color: "#666", whiteSpace: "nowrap", fontSize: 11 }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : "-"}</span>;
              },
            },
          ]}
        />

        {selectedRow && (
          <div
            style={{
              marginTop: 12,
              border: "1px solid #1e1e1e",
              background: "#0d0d0d",
              borderRadius: 4,
              padding: 12,
              display: "grid",
              gap: 10,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
              <div>
                <div style={{ color: "#8c8c8c", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>
                  Selected Correlation Actor
                </div>
                <div style={{ color: "#d7e2e9", fontSize: 12, marginTop: 4, fontFamily: "var(--font-mono-stack)" }}>
                  {selectedRow.ip}
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Btn variant="ghost" style={{ fontSize: 10 }} onClick={() => setShowDetailsModal(true)}>
                  View Full Analysis
                </Btn>
                <Btn
                  variant="ghost"
                  style={{ fontSize: 10 }}
                  onClick={() => {
                    setSelectedIp(null);
                    setShowDetailsModal(false);
                  }}
                >
                  Clear Selection
                </Btn>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 8 }}>
              <div style={{ border: "1px solid #1e1e1e", borderRadius: 4, padding: 8 }}>
                <div style={{ fontSize: 10, color: "#777", textTransform: "uppercase", marginBottom: 4 }}>Severity</div>
                <StatusBadge status={selectedRow.highestSev} />
              </div>
              <div style={{ border: "1px solid #1e1e1e", borderRadius: 4, padding: 8 }}>
                <div style={{ fontSize: 10, color: "#777", textTransform: "uppercase", marginBottom: 4 }}>Rule Matches</div>
                <div style={{ color: "#d7d7d7", fontSize: 15, fontWeight: 600 }}>{selectedRow.ruleMatchCount}</div>
              </div>
              <div style={{ border: "1px solid #1e1e1e", borderRadius: 4, padding: 8 }}>
                <div style={{ fontSize: 10, color: "#777", textTransform: "uppercase", marginBottom: 4 }}>Correlation State</div>
                <div style={{ color: selectedRow.isCorrelated ? "#7cb342" : "#888", fontSize: 12, fontWeight: 600 }}>
                  {selectedRow.isCorrelated ? "Correlated" : "Observed"}
                </div>
              </div>
              <div style={{ border: "1px solid #1e1e1e", borderRadius: 4, padding: 8 }}>
                <div style={{ fontSize: 10, color: "#777", textTransform: "uppercase", marginBottom: 4 }}>Risk Score</div>
                <div style={{ color: getRiskColor(selectedRow.riskScore), fontSize: 15, fontWeight: 700 }}>{selectedRow.riskScore}</div>
              </div>
            </div>

            <div style={{ color: "#888", fontSize: 11 }}>
              Signals: <span style={{ color: selectedRow.rateSpike ? "#ff9800" : "#555" }}>Request Rate</span> | <span style={{ color: selectedRow.urlEnum ? "#2196f3" : "#555" }}>URL Enumeration</span> | <span style={{ color: selectedRow.statusSpike ? "#9c27b0" : "#555" }}>Status Spike</span> | <span style={{ color: selectedRow.visitorAnomaly ? "#e91e63" : "#555" }}>Visitor Anomaly</span>
            </div>

            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1f1f1f", color: "#666" }}>
                    <th style={{ textAlign: "left", padding: "6px 8px" }}>Rule</th>
                    <th style={{ textAlign: "left", padding: "6px 8px" }}>Path</th>
                    <th style={{ textAlign: "center", padding: "6px 8px" }}>Method</th>
                    <th style={{ textAlign: "center", padding: "6px 8px" }}>Status</th>
                    <th style={{ textAlign: "right", padding: "6px 8px" }}>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedMatches.slice(0, 8).map((match, idx) => (
                    <tr key={`${selectedRow.ip}-${idx}`} style={{ borderBottom: "1px solid #151515" }}>
                      <td style={{ padding: "6px 8px", color: "#c0c0c0" }} title={match.rule_title ?? match.rule_id ?? "-"}>
                        {match.rule_title ?? match.rule_id ?? "-"}
                      </td>
                      <td style={{ padding: "6px 8px", color: "#666" }} title={match.path ?? "-"}>{match.path ?? "-"}</td>
                      <td style={{ padding: "6px 8px", color: "#888", textAlign: "center", fontFamily: "var(--font-mono-stack)" }}>{match.method ?? "-"}</td>
                      <td style={{ padding: "6px 8px", color: "#999", textAlign: "center", fontFamily: "var(--font-mono-stack)" }}>{match.status_code ?? "-"}</td>
                      <td style={{ padding: "6px 8px", color: "#555", textAlign: "right", whiteSpace: "nowrap" }}>{match.timestamp ? new Date(match.timestamp).toLocaleString() : "-"}</td>
                    </tr>
                  ))}
                  {selectedMatches.length === 0 && (
                    <tr>
                      <td colSpan={5} style={{ padding: "10px 8px", color: "#666", textAlign: "center" }}>
                        No direct rule matches for this actor. Correlation is driven by behavioral signals.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
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
                {["Rule Match", "Rate Spike", "URL Enum", "Visitor Anomaly", "High Sev"].map((col) => (
                  <th key={col} style={{ padding: "6px 8px", color: "#666", textAlign: "center", minWidth: 90 }}>{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ipRows.slice(0, 15).map((row) => (
                <tr key={row.ip} style={{ borderBottom: "1px solid #161616" }}>
                  <td style={{ padding: "4px 10px", color: "#c0c0c0", fontFamily: "var(--font-mono-stack)", fontSize: 11 }}>{row.ip}</td>
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
                    <MatrixCell hit={row.highestSev === "HIGH"} color="#ff4c4c" />
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
            { label: "High Sev", color: "#ff4c4c" },
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
                    <td style={{ padding: "3px 8px", color: "#c0c0c0", fontFamily: "var(--font-mono-stack)", fontSize: 10 }}>{ruleId}</td>
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

      {showDetailsModal && selectedRow && (
        <EventDetailModal
          title={`Correlation Detail: ${selectedRow.ip}`}
          subtitle={`${selectedRow.highestSev} severity | Risk ${selectedRow.riskScore} | ${selectedMatches.length} related rule events`}
          payload={{
            actor: selectedRow,
            related_events: selectedMatches,
            analysis: {
              correlation_definition: "Shared source IP with repeated or multi-module suspicious behavior within active project scope",
              behavioral_signals: {
                request_rate_spike: selectedRow.rateSpike,
                url_enumeration: selectedRow.urlEnum,
                status_spike: selectedRow.statusSpike,
                visitor_anomaly: selectedRow.visitorAnomaly,
              },
            },
          }}
          onClose={() => setShowDetailsModal(false)}
        />
      )}
    </div>
  );
}
