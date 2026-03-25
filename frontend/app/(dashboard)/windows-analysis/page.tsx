"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getWindowsSigmaResults,
  getWindowsSigmaRuleDetail,
  getWindowsSigmaRules,
  type WindowsSigmaRuleSummary,
} from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { ThreatTimeline, type ThreatEvent } from "@/components/threat-timeline";
import { HawkinsChat } from "@/components/hawkins-chat";
import { EventDetailModal } from "@/components/event-detail-modal";

type WindowsSigmaResults = Awaited<ReturnType<typeof getWindowsSigmaResults>>;
type WindowsSigmaMatch = WindowsSigmaResults["matches"][number];

export default function WindowsAnalysisPage() {
  const { activeProject } = useAuthStore();
  const [sigmaResults, setSigmaResults] = useState<WindowsSigmaResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showChat, setShowChat] = useState(false);
  const [sigmaRuleCatalog, setSigmaRuleCatalog] = useState<WindowsSigmaRuleSummary[]>([]);
  const [ruleCatalogLoading, setRuleCatalogLoading] = useState(false);
  const [ruleViewLoading, setRuleViewLoading] = useState(false);
  const [selectedRule, setSelectedRule] = useState<{ rule: WindowsSigmaRuleSummary; yaml: string } | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null);

  const fetchResults = useCallback(async () => {
    if (!activeProject?.id) return;
    setLoading(true);
    setError(null);

    try {
      const sigma = await getWindowsSigmaResults({ projectId: activeProject.id });
      setSigmaResults(sigma);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load results");
    } finally {
      setLoading(false);
    }
  }, [activeProject?.id]);

  const fetchSigmaRules = useCallback(async () => {
    setRuleCatalogLoading(true);
    try {
      const catalog = await getWindowsSigmaRules();
      setSigmaRuleCatalog(catalog.rules || []);
    } catch {
      setSigmaRuleCatalog([]);
    } finally {
      setRuleCatalogLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!activeProject?.id) return;
    fetchResults();
    fetchSigmaRules();
  }, [activeProject?.id, fetchResults, fetchSigmaRules]);

  const openRuleView = useCallback(async (rulePath: string) => {
    setRuleViewLoading(true);
    try {
      const detail = await getWindowsSigmaRuleDetail(rulePath);
      setSelectedRule(detail);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load Sigma rule details");
    } finally {
      setRuleViewLoading(false);
    }
  }, []);

  const filteredSigmaMatches = useMemo(() => sigmaResults?.matches || [], [sigmaResults?.matches]);

  const buildThreatEvents = (): ThreatEvent[] => {
    const events: ThreatEvent[] = [];
    if (filteredSigmaMatches.length > 0) {
      filteredSigmaMatches.forEach((match: WindowsSigmaMatch) => {
        const severity = (match.severity || "low").toLowerCase();
        events.push({
          timestamp: match.timestamp || new Date().toISOString(),
          severity: severity === "critical" || severity === "high" ? "critical" : severity === "medium" ? "warning" : "info",
          type: "windows",
          title: `Sigma: ${match.rule_title || "Unknown"}`,
          details: `Computer: ${match.computer || "unknown"} | EventID: ${match.event_id} | Channel: ${match.channel || "unknown"}`,
          source: "sigma-detection",
          payload: match,
        });
      });
    }
    return events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  };

  if (!activeProject?.id) {
    return (
      <div style={{ textAlign: "center", padding: "60px", color: "#666" }}>
        Select a Windows project from the sidebar to view rule based detection
      </div>
    );
  }

  // Only allow Windows projects on this page
  if (activeProject?.project_type === "web") {
    return (
      <div style={{ textAlign: "center", padding: "60px", color: "#ffa726" }}>
        <h2 style={{ margin: 0, color: "#ffa726" }}>Windows Projects Only</h2>
        <p style={{ color: "#999", marginTop: "12px" }}>
          This page is for Windows rule based detection. Your active project is a WEB project.
        </p>
        <p style={{ color: "#666", fontSize: "12px", marginTop: "8px" }}>
          Go to Web Analysis for web server logs.
        </p>
      </div>
    );
  }

  return (
    <main style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "16px", height: "100%", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ margin: 0, color: "#7cb342", fontSize: "18px", fontWeight: "bold" }}>
            Rule Based Detection
          </h1>
          <p style={{ margin: "4px 0 0", color: "#666", fontSize: "11px" }}>
            {activeProject?.name} — Sigma rule detection and event timeline analysis
          </p>
        </div>
        <button
          onClick={() => setShowChat(!showChat)}
          style={{
            padding: "6px 12px",
            background: showChat ? "#1a3d2a" : "#1a1a1a",
            border: `1px solid ${showChat ? "#4a7c59" : "#333"}`,
            color: showChat ? "#7cb342" : "#888",
            borderRadius: "2px",
            cursor: "pointer",
            fontSize: "10px",
            fontWeight: "bold",
            textTransform: "uppercase",
            letterSpacing: "0.5px",
          }}
        >
          {showChat ? "Hide Chat" : "Show Chat"}
        </button>
      </div>

      {error && (
        <div style={{ padding: "12px", background: "#3d1a1a", border: "1px solid #8b3d3d", borderRadius: "4px", color: "#ff6b6b", fontSize: "11px" }}>
          {error}
        </div>
      )}

      {loading && <div style={{ textAlign: "center", color: "#666", padding: "20px" }}>Loading forensics data...</div>}

      {!loading && sigmaResults && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px", flex: 1, minHeight: 0, overflow: "auto" }}>
          {/* Summary Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "10px" }}>
            <div style={{ padding: "12px", background: "#1a1a1a", border: "1px solid #333", borderRadius: "4px", borderLeft: "3px solid #7cb342" }}>
              <div style={{ color: "#666", fontSize: "10px", marginBottom: "4px" }}>Sigma Matches</div>
              <div style={{ color: "#7cb342", fontSize: "20px", fontWeight: "bold" }}>
                {filteredSigmaMatches.length}
              </div>
            </div>
            <div style={{ padding: "12px", background: "#1a1a1a", border: "1px solid #333", borderRadius: "4px", borderLeft: "3px solid #42a5f5" }}>
              <div style={{ color: "#666", fontSize: "10px", marginBottom: "4px" }}>Sigma Rule Library</div>
              <div style={{ color: "#42a5f5", fontSize: "20px", fontWeight: "bold" }}>
                {sigmaRuleCatalog.length}
              </div>
            </div>
          </div>

          {/* Timeline */}
          <div style={{ background: "#0d0d0d", border: "1px solid #222", borderRadius: "4px", padding: "12px" }}>
            <h3 style={{ margin: "0 0 12px", color: "#7cb342", fontSize: "12px", fontWeight: "bold", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Threat Timeline
            </h3>
            <ThreatTimeline
              events={buildThreatEvents()}
              height={260}
              onEventClick={(event) => setSelectedThreat(event)}
            />
          </div>

          {/* Events Table */}
          {filteredSigmaMatches.length > 0 && (
            <div style={{ background: "#0d0d0d", border: "1px solid #222", borderRadius: "4px", padding: "12px", overflow: "auto", flex: 1 }}>
              <h3 style={{ margin: "0 0 12px", color: "#7cb342", fontSize: "12px", fontWeight: "bold", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                Detection Events ({filteredSigmaMatches.length} total)
              </h3>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "10px" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #333", stickyTop: 0 }}>
                    {["Timestamp", "Rule", "Computer", "Event ID", "Channel", "Severity"].map((h) => (
                      <th key={h} style={{ padding: "6px", textAlign: "left", color: "#888", fontSize: "9px", fontWeight: "bold" }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredSigmaMatches.slice(0, 50).map((match, idx: number) => (
                    <tr
                      key={idx}
                      onClick={() => setSelectedThreat({
                        timestamp: match.timestamp || new Date().toISOString(),
                        severity: match.severity === "critical" || match.severity === "high" ? "critical" : match.severity === "medium" ? "warning" : "info",
                        type: "windows",
                        title: `Sigma: ${match.rule_title || match.rule_id}`,
                        details: `Computer: ${match.computer || "unknown"} | EventID: ${match.event_id} | Channel: ${match.channel || "unknown"}`,
                        source: "sigma-detection",
                        payload: match,
                      })}
                      style={{ borderBottom: "1px solid #1a1a1a", cursor: "pointer" }}
                    >
                      <td style={{ padding: "6px", color: "#999" }}>
                        {new Date(match.timestamp || 0).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: "6px", color: "#7cb342", whiteSpace: "nowrap" }}>
                        {match.rule_title || match.rule_id}
                      </td>
                      <td style={{ padding: "6px", color: "#aaa" }}>{match.computer || "-"}</td>
                      <td style={{ padding: "6px", color: "#aaa" }}>{match.event_id}</td>
                      <td style={{ padding: "6px", color: "#aaa" }}>{match.channel || "-"}</td>
                      <td style={{ padding: "6px" }}>
                        <span style={{
                          padding: "2px 6px",
                          background: match.severity === "critical" ? "#ef5350" : match.severity === "high" ? "#ffa726" : "#42a5f5",
                          color: "#000",
                          borderRadius: "2px",
                          fontSize: "9px",
                          fontWeight: "bold",
                        }}>
                          {match.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredSigmaMatches.length > 50 && (
                <div style={{ padding: "8px", color: "#666", fontSize: "9px", marginTop: "8px" }}>
                  Showing 50 of {filteredSigmaMatches.length} events
                </div>
              )}
            </div>
          )}

          <div style={{ background: "#0d0d0d", border: "1px solid #222", borderRadius: "4px", padding: "12px", minHeight: 0, overflow: "auto" }}>
            <h3 style={{ margin: "0 0 8px", color: "#7cb342", fontSize: "12px", fontWeight: "bold", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Sigma Rule Library
            </h3>

            {ruleCatalogLoading && (
              <div style={{ color: "#666", fontSize: "11px", padding: "8px 0" }}>Loading Sigma rules...</div>
            )}

            {!ruleCatalogLoading && sigmaRuleCatalog.length === 0 && (
              <div style={{ color: "#666", fontSize: "11px", padding: "8px 0" }}>No Sigma rules found.</div>
            )}

            {!ruleCatalogLoading && sigmaRuleCatalog.length > 0 && (
              <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "320px", overflowY: "auto" }}>
                {sigmaRuleCatalog.map((rule) => (
                  <div
                    key={rule.rule_path}
                    style={{
                      border: "1px solid #1f1f1f",
                      borderRadius: "3px",
                      background: "#090909",
                      padding: "8px",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: "#d0d0d0", fontSize: "11px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {rule.title}
                      </div>
                      <div style={{ color: "#707070", fontSize: "10px", marginTop: "2px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {rule.id} · {rule.level}
                      </div>
                    </div>
                    <button
                      onClick={() => openRuleView(rule.rule_path)}
                      disabled={ruleViewLoading}
                      style={{
                        border: "1px solid #355a3b",
                        color: "#7cb342",
                        background: "#101a10",
                        fontSize: "10px",
                        borderRadius: "2px",
                        padding: "4px 8px",
                        cursor: ruleViewLoading ? "not-allowed" : "pointer",
                      }}
                    >
                      VIEW
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Chat */}
      {showChat && (
        <div style={{ height: "300px", borderTop: "1px solid #222", paddingTop: "12px", overflow: "hidden" }}>
          <HawkinsChat projectId={activeProject?.id} />
        </div>
      )}

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

      {selectedThreat && (
        <EventDetailModal
          title={selectedThreat.title}
          subtitle={`${selectedThreat.severity.toUpperCase()} · ${selectedThreat.type.toUpperCase()} · ${new Date(selectedThreat.timestamp).toLocaleString()}`}
          payload={selectedThreat.payload ?? selectedThreat}
          onClose={() => setSelectedThreat(null)}
        />
      )}
    </main>
  );
}
