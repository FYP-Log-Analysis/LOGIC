"use client";

import { useCallback, useEffect, useState, useMemo } from "react";
import { getWindowsCorrelation, getWindowsSigmaResults, type WindowsCorrelation } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { ProcessTreePanel } from "@/components/process-tree";
import {
  WindowsSectionHeader,
  WindowsMetricCard,
  WindowsDataPanel,
  WindowsStatGrid,
  WindowsFilterControls,
  FilterInput,
  WindowsButton,
  WindowsLoadingSkeleton,
  WindowsEmptyState,
  WindowsDivider,
  MitreTag,
  SeverityBadge,
} from "@/components/windows-ui";

export default function WindowsCorrelationPage() {
  const { activeProject } = useAuthStore();
  const [loading, setLoading] = useState(true);
  const [correlation, setCorrelation] = useState<WindowsCorrelation | null>(null);
  const [sigmaResults, setSigmaResults] = useState<any>(null);
  const [timeWindow, setTimeWindow] = useState(60);
  const [error, setError] = useState("");

  const loadData = useCallback(async (projectId: string) => {
    setLoading(true);
    setError("");
    try {
      const [corrData, sigmaData] = await Promise.all([
        getWindowsCorrelation({ projectId, timeWindowMinutes: timeWindow }),
        getWindowsSigmaResults({ projectId }),
      ]);
      setCorrelation(corrData);
      setSigmaResults(sigmaData);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [timeWindow]);

  useEffect(() => {
    if (!activeProject?.id) {
      setLoading(false);
      return;
    }
    loadData(activeProject.id);
  }, [activeProject?.id, loadData]);

  const processEvents = useMemo(() => {
    if (!sigmaResults?.matches) return [];
    return sigmaResults.matches
      .map((m: any) => ({
        event_id: m.event_id,
        computer: m.computer,
        timestamp: m.timestamp,
        event_data: m.entry?.event_data || {},
      }))
      .filter((e: any) => e.event_id === 4688);
  }, [sigmaResults]);

  if (!activeProject?.id) {
    return (
      <WindowsEmptyState
        icon="🔗"
        title="No Project Selected"
        message="Select a Windows project from the sidebar to view correlation analysis"
      />
    );
  }

  if (activeProject.project_type === "web") {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#ffa726" }}>
        <h2 style={{ margin: 0, color: "#ffa726" }}>Windows Projects Only</h2>
        <p style={{ color: "#999", marginTop: 12 }}>
          This page is for Windows correlation analysis.
        </p>
      </div>
    );
  }

  return (
    <main className="page-shell">
      <WindowsSectionHeader
        title="Attack Chain Correlation"
        subtitle={`${activeProject?.name} — Event correlation and attack pattern detection`}
        actions={
          <WindowsButton onClick={() => loadData(activeProject.id)} disabled={loading}>
            {loading ? "LOADING..." : "🔄 REFRESH"}
          </WindowsButton>
        }
      />

      {/* Time Window Control */}
      <WindowsFilterControls>
        <FilterInput
          label="Correlation Window (minutes)"
          type="number"
          min={5}
          max={180}
          value={timeWindow}
          onChange={(e) => setTimeWindow(Math.max(5, Math.min(180, Number(e.target.value) || 60)))}
          style={{ width: "150px" }}
        />
        <WindowsButton onClick={() => loadData(activeProject.id)} disabled={loading}>
          APPLY
        </WindowsButton>
      </WindowsFilterControls>

      {error && (
        <div style={{ padding: "12px", background: "#3d1a1a", border: "1px solid #8b3d3d", borderRadius: "4px", color: "#ff6b6b", fontSize: "11px", marginBottom: "20px" }}>
          ⚠️ {error}
        </div>
      )}

      {loading && <WindowsLoadingSkeleton count={3} height={100} />}

      {!loading && correlation && (
        <>
          {/* Summary Metrics */}
          <WindowsStatGrid columns={3}>
            <WindowsMetricCard
              label="Attack Chains"
              value={correlation.total_chains}
              accent="#ff4444"
              icon="🔗"
              sublabel="Correlated event sequences"
            />
            <WindowsMetricCard
              label="Attack Patterns"
              value={correlation.patterns.length}
              accent="#ff8800"
              icon="🎯"
              sublabel="Detected TTPs"
            />
            <WindowsMetricCard
              label="Time Window"
              value={`${correlation.time_window_minutes} min`}
              accent="#4488ff"
              icon="⏱️"
            />
          </WindowsStatGrid>

          <WindowsDivider />

          {/* Attack Patterns */}
          {correlation.patterns.length > 0 && (
            <>
              <WindowsDataPanel title="Detected Attack Patterns" accent="#ff8800">
                <div style={{ display: "grid", gap: "12px" }}>
                  {correlation.patterns.map((pattern, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: "14px",
                        background: "#0a0a0a",
                        border: "1px solid #2a2a2a",
                        borderRadius: "4px",
                        borderLeft: `3px solid ${pattern.confidence === "high" ? "#ff4444" : "#ff8800"}`,
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
                        <span style={{ fontSize: "14px", color: "#ff8800", fontWeight: 600 }}>
                          {pattern.pattern_name}
                        </span>
                        <MitreTag technique={pattern.mitre_technique} tactic={pattern.pattern_type} />
                        <span
                          style={{
                            background: pattern.confidence === "high" ? "#ff4444" : "#ff8800",
                            color: "#000",
                            padding: "2px 8px",
                            borderRadius: "3px",
                            fontSize: "8px",
                            fontWeight: "bold",
                            textTransform: "uppercase",
                            marginLeft: "auto",
                          }}
                        >
                          {pattern.confidence} CONFIDENCE
                        </span>
                      </div>
                      <div style={{ fontSize: "11px", color: "#888", marginBottom: "6px" }}>
                        {pattern.description}
                      </div>
                      <div style={{ fontSize: "10px", color: "#555" }}>
                        🖥️ {pattern.computer} • 📊 {pattern.event_count} events
                      </div>
                    </div>
                  ))}
                </div>
              </WindowsDataPanel>
              <WindowsDivider />
            </>
          )}

          {/* Attack Chains */}
          {correlation.chains.length > 0 && (
            <>
              <WindowsDataPanel title="Correlated Attack Chains" accent="#ff4444">
                <div style={{ display: "grid", gap: "16px" }}>
                  {correlation.chains.map((chain) => (
                    <div
                      key={chain.chain_id}
                      style={{
                        padding: "16px",
                        background: "#0a0a0a",
                        border: "1px solid #3a2a2a",
                        borderRadius: "6px",
                        borderLeft: "4px solid #ff4444",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "12px" }}>
                        <span style={{ fontSize: "14px", color: "#ff4444", fontWeight: 600 }}>
                          🔗 Chain {chain.chain_id.split("_")[1]}
                        </span>
                        <SeverityBadge severity={chain.severity as any} />
                        <span style={{ fontSize: "10px", color: "#666", marginLeft: "auto" }}>
                          {chain.event_count} events • {Math.round(chain.duration_seconds / 60)} min duration
                        </span>
                      </div>
                      
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", marginBottom: "12px" }}>
                        <div>
                          <div style={{ fontSize: "9px", color: "#555", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "4px" }}>
                            Computers
                          </div>
                          <div style={{ fontSize: "11px", color: "#c0c0c0" }}>
                            {chain.computers.join(", ") || "N/A"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: "9px", color: "#555", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "4px" }}>
                            Users
                          </div>
                          <div style={{ fontSize: "11px", color: "#c0c0c0" }}>
                            {chain.users.length > 0 ? chain.users.join(", ") : "N/A"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: "9px", color: "#555", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "4px" }}>
                            Correlation
                          </div>
                          <div style={{ fontSize: "10px", color: "#ff8800" }}>
                            {chain.correlation_reasons.join(", ")}
                          </div>
                        </div>
                      </div>
                      
                      <div style={{ fontSize: "10px", color: "#666" }}>
                        ⏱️ {new Date(chain.start_time).toLocaleString()} → {new Date(chain.end_time).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              </WindowsDataPanel>
              <WindowsDivider />
            </>
          )}

          {/* Process Tree */}
          {processEvents.length > 0 && (
            <WindowsDataPanel title="Process Execution Tree" accent="#7cb342">
              <ProcessTreePanel events={processEvents} />
            </WindowsDataPanel>
          )}

          {/* Empty States */}
          {correlation.chains.length === 0 && correlation.patterns.length === 0 && (
            <WindowsEmptyState
              icon="✅"
              title="No Correlated Attack Chains"
              message="Events appear to be isolated incidents without clear correlation patterns"
            />
          )}
        </>
      )}
    </main>
  );
}
