"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getWindowsSigmaResults,
} from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { ThreatTimeline, type ThreatEvent } from "@/components/threat-timeline";
import HawkinsChat from "@/components/hawkins-chat";
import { EventDetailModal } from "@/components/event-detail-modal";

type WindowsSigmaResults = Awaited<ReturnType<typeof getWindowsSigmaResults>>;
type WindowsSigmaMatch = WindowsSigmaResults["matches"][number];

export default function WindowsAnalysisPage() {
  const { activeProject } = useAuthStore();
  const [sigmaResults, setSigmaResults] = useState<WindowsSigmaResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
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

  useEffect(() => {
    if (!activeProject?.id) return;
    fetchResults();
  }, [activeProject?.id, fetchResults]);

  const filteredSigmaMatches = useMemo(() => sigmaResults?.matches || [], [sigmaResults?.matches]);

  const threatEvents = useMemo((): ThreatEvent[] => {
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
  }, [filteredSigmaMatches]);

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
    <main className="page-shell" style={{ display: "flex", flexDirection: "column", gap: "20px", height: "100%", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16 }}>
        <div>
          <h1 style={{ margin: 0, color: "#7cb342", fontSize: "22px", fontWeight: 500, letterSpacing: 0.4 }}>
            Rule Based Detection
          </h1>
          <p style={{ margin: "8px 0 0", color: "#666", fontSize: "12px", lineHeight: 1.5 }}>
            {activeProject?.name} — Sigma rule detection and threat timeline analysis
          </p>
        </div>
      </div>

      {error && (
        <div style={{ padding: "12px", background: "#3d1a1a", border: "1px solid #8b3d3d", borderRadius: "4px", color: "#ff6b6b", fontSize: "11px" }}>
          {error}
        </div>
      )}

      {loading && <div style={{ textAlign: "center", color: "#666", padding: "20px" }}>Loading forensics data...</div>}

      {!loading && sigmaResults && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 20, flex: 1, minHeight: 0, overflow: "hidden" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "20px", minHeight: 0, overflow: "auto", paddingRight: 2 }}>
          {/* Summary Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "14px" }}>
            <div style={{ padding: "18px", background: "#111", border: "1px solid #262626", borderRadius: "6px", borderLeft: "3px solid #7cb342" }}>
              <div style={{ color: "#666", fontSize: "11px", marginBottom: "8px", textTransform: "uppercase", letterSpacing: 0.8 }}>Sigma Matches</div>
              <div style={{ color: "#7cb342", fontSize: "24px", fontWeight: 500 }}>
                {filteredSigmaMatches.length}
              </div>
            </div>
            <div style={{ padding: "18px", background: "#111", border: "1px solid #262626", borderRadius: "6px", borderLeft: "3px solid #c0c0c0" }}>
              <div style={{ color: "#666", fontSize: "11px", marginBottom: "8px", textTransform: "uppercase", letterSpacing: 0.8 }}>Selected Threat</div>
              <div style={{ color: selectedThreat ? "#e0e0e0" : "#777", fontSize: "13px", lineHeight: 1.35, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {selectedThreat ? selectedThreat.title : "None attached"}
              </div>
            </div>
          </div>

          {/* Timeline */}
          <div className="surface-panel">
            <h3 style={{ margin: "0 0 14px", color: "#7cb342", fontSize: "12px", fontWeight: "bold", textTransform: "uppercase", letterSpacing: "0.8px" }}>
              Threat Timeline
            </h3>
            <ThreatTimeline
              events={threatEvents}
              height={300}
              onEventClick={(event) => setSelectedThreat(event)}
            />
          </div>

          </div>
        </div>
      )}

      <HawkinsChat
        title="Hawkins — Windows Detection"
        description="Deep forensic analysis for Sigma detections and suspicious Windows events"
        dataSummary={`Sigma matches: ${filteredSigmaMatches.length}. ${selectedThreat ? "A specific threat is attached for deep forensics." : "No threat selected yet."}`}
        componentKey="windows-analysis"
        helpGuide="Select a timeline event or table row, then ask for root-cause hypotheses, attack chain mapping, and exact next investigative steps."
        selectedThreat={selectedThreat}
      />

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
