"use client";

import { useEffect, useState, useRef } from "react";
import { getThreatInsights, getInsightsStatus, getRuleMatches, getBehavioralResults } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import {
  SectionHeader,
  Btn,
  StatusBadge,
  Divider,
  Spinner,
  AlertBanner,
} from "@/components/ui-primitives";
import HawkinsChat from "@/components/hawkins-chat";

interface InsightsStatus {
  status?: string;
  ready?: boolean;
  generated_at?: string;
}

interface InsightsData {
  status?: string;
  narrative?: string;
  summary?: string;
  threats?: { title?: string; description?: string; severity?: string }[];
  recommendations?: string[];
  generated_at?: string;
}

interface RuleMatch {
  rule_id?: string;
  rule_title?: string;
  severity?: string;
  client_ip?: string;
  status_code?: number | string;
}

interface BehavioralSummary {
  total_rate_spikes?: number;
  total_url_enumerators?: number;
  total_status_spikes?: number;
}

interface ContextSummary {
  topIps: { ip: string; count: number; categories: string[] }[];
  topRules: { rule: string; count: number }[];
  correlatedIps: string[];
  successRate: number;
  totalMatches: number;
  criticalCount: number;
}

function buildContext(matches: RuleMatch[], behavioralData: Record<string, unknown> | null): ContextSummary {
  const ipCounts: Record<string, number> = {};
  const ruleCounts: Record<string, number> = {};
  let criticalCount = 0;
  let successHits = 0;

  matches.forEach((m) => {
    if (m.client_ip) ipCounts[m.client_ip] = (ipCounts[m.client_ip] ?? 0) + 1;
    const rk = m.rule_title ?? m.rule_id ?? "Unknown";
    ruleCounts[rk] = (ruleCounts[rk] ?? 0) + 1;
    if ((m.severity ?? "").toLowerCase() === "critical") criticalCount++;
    if ([200, 201, 204].includes(Number(m.status_code ?? -1))) successHits++;
  });

  const topIps = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, count]) => {
      const catMap: Record<string, boolean> = {};
      matches.filter((m) => m.client_ip === ip).forEach((m) => {
        const t = (m.rule_title ?? "").toLowerCase();
        if (t.includes("sql")) catMap["SQLi"] = true;
        if (t.includes("xss")) catMap["XSS"] = true;
        if (t.includes("command") || t.includes("rce")) catMap["RCE"] = true;
        if (t.includes("scanner") || t.includes("nikto")) catMap["Scan"] = true;
        if (t.includes("local file") || t.includes("lfi")) catMap["LFI"] = true;
      });
      return { ip, count, categories: Object.keys(catMap) };
    });

  const topRules = Object.entries(ruleCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([rule, count]) => ({ rule, count }));

  // IPs also flagged in behavioral
  const behavIps = new Set<string>();
  const behavObj = behavioralData ?? {};
  for (const arr of [
    (behavObj.request_rate_spikes ?? []) as Array<{ client_ip?: string; ip?: string }>,
    (behavObj.url_enumeration ?? []) as Array<{ client_ip?: string; ip?: string }>,
  ]) {
    arr.forEach((r) => {
      const ip = r.client_ip ?? r.ip;
      if (ip) behavIps.add(ip);
    });
  }
  const correlatedIps = topIps.map((x) => x.ip).filter((ip) => behavIps.has(ip));

  return {
    topIps,
    topRules,
    correlatedIps,
    successRate: matches.length > 0 ? Math.round((successHits / matches.length) * 100) : 0,
    totalMatches: matches.length,
    criticalCount,
  };
}

export default function AiInsightsPage() {
  const { activeProject } = useAuthStore();
  const projectId = activeProject?.id;
  const [generating, setGenerating] = useState(false);
  const [polling, setPolling] = useState(false);
  const [insightsStatus, setInsightsStatus] = useState<InsightsStatus | null>(null);
  const [insights, setInsights] = useState<InsightsData | null>(null);
  const [error, setError] = useState("");
  const [ctxSummary, setCtxSummary] = useState<ContextSummary | null>(null);
  const [behavSummary, setBehavSummary] = useState<BehavioralSummary | null>(null);
  const pollingRef = useRef(false);

  useEffect(() => {
    if (!projectId) return;
    // Load detection context + behavioral summary for display
    getRuleMatches({ projectId })
      .then((d) => {
        const matches = (d.matches ?? []) as RuleMatch[];
        getBehavioralResults({ projectId })
          .then((b) => {
            const bd = b as Record<string, unknown>;
            setCtxSummary(buildContext(matches, bd));
            const sum = (bd.summary ?? {}) as BehavioralSummary;
            setBehavSummary(sum);
          })
          .catch(() => { setCtxSummary(buildContext(matches, null)); });
      })
      .catch(() => {});

    getInsightsStatus(projectId)
      .then((s) => {
        const status = s as unknown as InsightsStatus;
        setInsightsStatus(status);
        if (status.ready || status.status === "complete") fetchInsights();
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  const fetchInsights = async () => {
    try {
      const data = await getThreatInsights(projectId);
      setInsights(data as unknown as InsightsData);
    } catch {}
  };

  const pollStatus = async () => {
    pollingRef.current = true;
    setPolling(true);
    while (pollingRef.current) {
      try {
        const s = await getInsightsStatus(projectId);
        const status = s as unknown as InsightsStatus;
        setInsightsStatus(status);
        if (status.ready || status.status === "complete") { await fetchInsights(); break; }
        if (status.status === "failed" || status.status === "error") {
          setError("Insight generation failed — check API logs"); break;
        }
      } catch { break; }
      await new Promise((r) => setTimeout(r, 2000));
    }
    pollingRef.current = false;
    setPolling(false);
  };

  const handleGenerate = async () => {
    setGenerating(true); setError("");
    try {
      await getThreatInsights(projectId);
      await pollStatus();
    } catch (e) { setError(String(e)); }
    setGenerating(false);
  };

  const sevColor: Record<string, string> = {
    critical: "#ff4444", high: "#ff8800", medium: "#f0c040", low: "#4488ff",
  };

  const isReady = insights && (insights.narrative || insights.summary || (insights.threats && insights.threats.length > 0));
  const statusLabel: "running" | "complete" | undefined =
    polling ? "running" : isReady ? "complete" : undefined;

  if (!projectId) return (
    <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
      Select a project from the sidebar to view this page.
    </div>
  );

  return (
    <div>
      <SectionHeader
        title="AI Insights"
        subtitle="LLM-generated threat narrative and actionable recommendations"
      />

      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
        <Btn onClick={handleGenerate} disabled={generating || polling}>
          {generating || polling ? <><Spinner size={12} />&nbsp;&nbsp;GENERATING…</> : "GENERATE INSIGHTS"}
        </Btn>
        {statusLabel && <StatusBadge status={statusLabel} />}
        {insightsStatus?.generated_at && !polling && (
          <span style={{ fontSize: 11, color: "#444" }}>
            Last generated: {new Date(insightsStatus.generated_at).toLocaleString()}
          </span>
        )}
      </div>

      {error && <AlertBanner type="error" message={error} />}

      {/* Detection Context Summary */}
      {ctxSummary && (
        <div style={{ background: "#0a0e0a", border: "1px solid #1a2a1a", borderRadius: 4, padding: 16, marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#2a5a2a", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>
            Detection Context — data that will inform AI analysis
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 12 }}>
            <div>
              <div style={{ fontSize: 10, color: "#444", letterSpacing: 0.8, textTransform: "uppercase", marginBottom: 6 }}>Top Threat Actors</div>
              {ctxSummary.topIps.map((x, i) => (
                <div key={i} style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 4 }}>
                  <span style={{ color: "#808080", fontFamily: "monospace", fontSize: 11 }}>{x.ip}</span>
                  <span style={{ color: "#444", fontSize: 10 }}>×{x.count}</span>
                  {x.categories.map((cat) => (
                    <span key={cat} style={{ background: "#1a1a2a", border: "1px solid #2a2a4a", color: "#6666cc", fontSize: 9, borderRadius: 2, padding: "1px 4px" }}>
                      {cat}
                    </span>
                  ))}
                </div>
              ))}
            </div>
            <div>
              <div style={{ fontSize: 10, color: "#444", letterSpacing: 0.8, textTransform: "uppercase", marginBottom: 6 }}>Top Rules Triggered</div>
              {ctxSummary.topRules.map((r, i) => (
                <div key={i} style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 4 }}>
                  <span style={{ color: "#808080", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 160 }}
                    title={r.rule}>{r.rule}</span>
                  <span style={{ color: "#444", fontSize: 10, whiteSpace: "nowrap" }}>×{r.count}</span>
                </div>
              ))}
            </div>
            <div>
              <div style={{ fontSize: 10, color: "#444", letterSpacing: 0.8, textTransform: "uppercase", marginBottom: 6 }}>Key Metrics</div>
              <div style={{ fontSize: 12, color: "#c0c0c0", lineHeight: 2 }}>
                <div>Total Matches: <span style={{ color: "#ff8800" }}>{ctxSummary.totalMatches}</span></div>
                <div>Critical Hits: <span style={{ color: "#ff4444" }}>{ctxSummary.criticalCount}</span></div>
                <div>Attack Success Rate: <span style={{ color: ctxSummary.successRate > 10 ? "#ff4444" : "#4caf50" }}>{ctxSummary.successRate}%</span></div>
                {ctxSummary.correlatedIps.length > 0 && (
                  <div>Cross-Module IPs: <span style={{ color: "#f0c040" }}>{ctxSummary.correlatedIps.join(", ")}</span></div>
                )}
                {behavSummary && (
                  <div>Behavioral Alerts: <span style={{ color: "#f0c040" }}>
                    {(behavSummary.total_rate_spikes ?? 0) + (behavSummary.total_url_enumerators ?? 0)} events
                  </span></div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {isReady && (
        <>
          <Divider />

          {/* Narrative */}
          {(insights.narrative || insights.summary) && (
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Threat Narrative
              </div>
              <div style={{
                background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 16,
                color: "#c0c0c0", fontSize: 13, lineHeight: 1.75, whiteSpace: "pre-wrap",
              }}>
                {insights.narrative ?? insights.summary}
              </div>
            </div>
          )}

          {/* Individual threats with evidence tags */}
          {insights.threats && insights.threats.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Identified Threats
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {insights.threats.map((t, i) => {
                  const sev = (t.severity ?? "low").toLowerCase();
                  const c = sevColor[sev] ?? "#555";
                  // Evidence tags: fuzzy match threat title against top IPs / rule names
                  const titleLower = (t.title ?? "").toLowerCase();
                  const descLower = (t.description ?? "").toLowerCase();
                  const evidenceIps = ctxSummary?.topIps
                    .filter((x) => descLower.includes(x.ip) || titleLower.includes(x.ip))
                    .map((x) => x.ip) ?? [];
                  const evidenceRules = ctxSummary?.topRules
                    .filter((r) => {
                      const rl = r.rule.toLowerCase();
                      return titleLower.split(" ").some((w) => w.length > 4 && rl.includes(w))
                        || descLower.split(" ").some((w) => w.length > 4 && rl.includes(w));
                    })
                    .map((r) => r.rule.length > 30 ? r.rule.slice(0, 30) + "…" : r.rule) ?? [];
                  const isCorrelated = ctxSummary?.correlatedIps.some((ip) => descLower.includes(ip));
                  return (
                    <div key={i} style={{
                      background: "#0d0d0d", border: `1px solid ${c}22`,
                      borderLeft: `3px solid ${c}`, borderRadius: 4, padding: "12px 14px",
                    }}>
                      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6, flexWrap: "wrap" }}>
                        <span style={{ color: c, fontSize: 10, letterSpacing: 1, textTransform: "uppercase" }}>
                          {t.severity?.toUpperCase() ?? "—"}
                        </span>
                        {t.title && <span style={{ color: "#e0e0e0", fontSize: 13 }}>{t.title}</span>}
                        {isCorrelated && (
                          <span style={{ background: "#1a1a2a", border: "1px solid #3a3a6a", color: "#6666ff", fontSize: 9, borderRadius: 2, padding: "1px 6px" }}>
                            CROSS-MODULE
                          </span>
                        )}
                        {evidenceIps.map((ip) => (
                          <span key={ip} style={{ background: "#1a1a1a", border: "1px solid #2a2a2a", color: "#808080", fontSize: 9, borderRadius: 2, padding: "1px 5px", fontFamily: "monospace" }}>
                            {ip}
                          </span>
                        ))}
                        {evidenceRules.slice(0, 2).map((r) => (
                          <span key={r} style={{ background: "#1a1a2a", border: "1px solid #2a2a3a", color: "#5a5a8a", fontSize: 9, borderRadius: 2, padding: "1px 5px" }}>
                            {r}
                          </span>
                        ))}
                      </div>
                      {t.description && (
                        <div style={{ color: "#808080", fontSize: 12, lineHeight: 1.6 }}>{t.description}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {insights.recommendations && insights.recommendations.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Recommendations
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {insights.recommendations.map((r, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                    <span style={{ color: "#404040", fontSize: 12, marginTop: 2 }}>{i + 1}.</span>
                    <span style={{ color: "#c0c0c0", fontSize: 13, lineHeight: 1.6 }}>{r}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {!isReady && !polling && !generating && (
        <div style={{ color: "#333", fontSize: 13, padding: "24px 0" }}>
          No insights generated yet — click Generate Insights to analyse current detection data
        </div>
      )}

      <div style={{ marginTop: 40 }}>
        <HawkinsChat
          title="Hawkins — AI Insights"
          description="Ask Hawkins to elaborate on threats, explain patterns, or suggest mitigations"
          dataSummary={isReady ? (insights.summary ?? insights.narrative ?? "Insights available") : "No insights yet"}
          componentKey="ai_insights"
          helpGuide="Try: 'What is the most critical threat?' or 'Explain the SQL injection findings'. The Detection Context panel shows the top threat actors and rules that will inform the LLM analysis. Cross-module IPs are those flagged in BOTH rule detection and behavioral analysis — highest confidence threats."
        />
      </div>
    </div>
  );
}
