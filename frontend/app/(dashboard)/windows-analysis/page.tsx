"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { getWindowsSigmaResults, getWindowsIOCs, type WindowsIOCs } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { ThreatTimeline, type ThreatEvent } from "@/components/threat-timeline";
import HawkinsChat from "@/components/hawkins-chat";
import { EventDetailModal } from "@/components/event-detail-modal";
import {
  WindowsSectionHeader,
  WindowsMetricCard,
  WindowsDataPanel,
  WindowsStatGrid,
  WindowsFilterControls,
  FilterSelect,
  FilterInput,
  WindowsButton,
  SeverityBadge,
  WindowsLoadingSkeleton,
  WindowsEmptyState,
  WindowsDivider,
  MitreTag,
  IoCBadge,
} from "@/components/windows-ui";

type WindowsSigmaResults = Awaited<ReturnType<typeof getWindowsSigmaResults>>;
type WindowsSigmaMatch = WindowsSigmaResults["matches"][number];

export default function WindowsAnalysisPage() {
  const { activeProject } = useAuthStore();
  const [sigmaResults, setSigmaResults] = useState<WindowsSigmaResults | null>(null);
  const [iocs, setIocs] = useState<WindowsIOCs | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null);
  
  // Filter states
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [computerFilter, setComputerFilter] = useState<string>("");
  const [eventIdFilter, setEventIdFilter] = useState<string>("");
  const [channelFilter, setChannelFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const fetchResults = useCallback(async () => {
    if (!activeProject?.id) return;
    setLoading(true);
    setError(null);

    try {
      const [sigma, iocsData] = await Promise.all([
        getWindowsSigmaResults({ projectId: activeProject.id }),
        getWindowsIOCs({ projectId: activeProject.id }),
      ]);
      setSigmaResults(sigma);
      setIocs(iocsData);
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

  const filteredSigmaMatches = useMemo(() => {
    let matches = sigmaResults?.matches || [];
    
    // Severity filter
    if (severityFilter !== "all") {
      matches = matches.filter((m) => {
        const sev = (m.severity || "low").toLowerCase();
        if (severityFilter === "critical_high") return sev === "critical" || sev === "high";
        return sev === severityFilter;
      });
    }
    
    // Computer filter
    if (computerFilter) {
      matches = matches.filter((m) => 
        (m.computer || "").toLowerCase().includes(computerFilter.toLowerCase())
      );
    }
    
    // Event ID filter
    if (eventIdFilter) {
      matches = matches.filter((m) => 
        String(m.event_id).includes(eventIdFilter)
      );
    }
    
    // Channel filter
    if (channelFilter !== "all") {
      matches = matches.filter((m) => 
        (m.channel || "").toLowerCase() === channelFilter.toLowerCase()
      );
    }
    
    // Search query (rule title, computer, channel)
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      matches = matches.filter((m) => 
        (m.rule_title || "").toLowerCase().includes(query) ||
        (m.computer || "").toLowerCase().includes(query) ||
        (m.channel || "").toLowerCase().includes(query)
      );
    }
    
    return matches;
  }, [sigmaResults?.matches, severityFilter, computerFilter, eventIdFilter, channelFilter, searchQuery]);

  const uniqueChannels = useMemo(() => {
    const channels = new Set(
      (sigmaResults?.matches || []).map((m) => m.channel).filter(Boolean)
    );
    return Array.from(channels).sort();
  }, [sigmaResults?.matches]);

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

  const severityCounts = useMemo(() => {
    const matches = sigmaResults?.matches || [];
    return {
      critical: matches.filter((m) => (m.severity || "").toLowerCase() === "critical").length,
      high: matches.filter((m) => (m.severity || "").toLowerCase() === "high").length,
      medium: matches.filter((m) => (m.severity || "").toLowerCase() === "medium").length,
      low: matches.filter((m) => (m.severity || "").toLowerCase() === "low").length,
    };
  }, [sigmaResults?.matches]);

  const uniqueComputers = useMemo(() => {
    const computers = new Set(
      (sigmaResults?.matches || []).map((m) => m.computer).filter(Boolean)
    );
    return computers.size;
  }, [sigmaResults?.matches]);

  const handleExportCSV = () => {
    if (!activeProject?.id) return;
    window.open(`/api/analysis/windows/export/sigma-csv?project_id=${activeProject.id}`, "_blank");
  };

  const handleExportReport = () => {
    if (!activeProject?.id) return;
    window.open(`/api/analysis/windows/export/report?project_id=${activeProject.id}`, "_blank");
  };

  if (!activeProject?.id) {
    return (
      <WindowsEmptyState
        icon="🖥️"
        title="No Project Selected"
        message="Select a Windows project from the sidebar to view rule-based detection"
      />
    );
  }

  if (activeProject?.project_type === "web") {
    return (
      <div style={{ textAlign: "center", padding: "60px", color: "#ffa726" }}>
        <h2 style={{ margin: 0, color: "#ffa726" }}>Windows Projects Only</h2>
        <p style={{ color: "#999", marginTop: "12px" }}>
          This page is for Windows rule-based detection. Your active project is a WEB project.
        </p>
        <p style={{ color: "#666", fontSize: "12px", marginTop: "8px" }}>
          Go to Web Analysis for web server logs.
        </p>
      </div>
    );
  }

  return (
    <main className="page-shell">
      <WindowsSectionHeader
        title="Rule Based Detection"
        subtitle={`${activeProject?.name} — Sigma rule detection and threat timeline analysis`}
        actions={
          <div style={{ display: "flex", gap: "10px" }}>
            <WindowsButton onClick={handleExportCSV} variant="secondary" disabled={!sigmaResults}>
              📊 EXPORT CSV
            </WindowsButton>
            <WindowsButton onClick={handleExportReport} variant="secondary" disabled={!sigmaResults}>
              📄 EXPORT REPORT
            </WindowsButton>
            <WindowsButton onClick={fetchResults} disabled={loading}>
              {loading ? "LOADING..." : "🔄 REFRESH"}
            </WindowsButton>
          </div>
        }
      />

      {error && (
        <div style={{ padding: "12px", background: "#3d1a1a", border: "1px solid #8b3d3d", borderRadius: "4px", color: "#ff6b6b", fontSize: "11px", marginBottom: "20px" }}>
          ⚠️ {error}
        </div>
      )}

      {loading && <WindowsLoadingSkeleton count={3} height={80} />}

      {!loading && sigmaResults && (
        <>
          {/* Summary Metrics */}
          <WindowsStatGrid columns={4}>
            <WindowsMetricCard
              label="Total Matches"
              value={sigmaResults.matches?.length || 0}
              accent="#7cb342"
              icon="🎯"
            />
            <WindowsMetricCard
              label="Critical + High"
              value={severityCounts.critical + severityCounts.high}
              accent="#ff4444"
              icon="🚨"
            />
            <WindowsMetricCard
              label="Unique Computers"
              value={uniqueComputers}
              accent="#4488ff"
              icon="🖥️"
            />
            <WindowsMetricCard
              label="Matched Rules"
              value={sigmaResults.matched_rules?.length || 0}
              accent="#aa66cc"
              icon="📋"
            />
          </WindowsStatGrid>

          <WindowsDivider />

          {/* Severity Breakdown */}
          <WindowsDataPanel title="Severity Distribution">
            <WindowsStatGrid columns={4}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "20px", color: "#ff4444", fontWeight: 600 }}>
                  {severityCounts.critical}
                </div>
                <div style={{ fontSize: "9px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginTop: "4px" }}>
                  Critical
                </div>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "20px", color: "#ff8800", fontWeight: 600 }}>
                  {severityCounts.high}
                </div>
                <div style={{ fontSize: "9px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginTop: "4px" }}>
                  High
                </div>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "20px", color: "#f0c040", fontWeight: 600 }}>
                  {severityCounts.medium}
                </div>
                <div style={{ fontSize: "9px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginTop: "4px" }}>
                  Medium
                </div>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "20px", color: "#4488ff", fontWeight: 600 }}>
                  {severityCounts.low}
                </div>
                <div style={{ fontSize: "9px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginTop: "4px" }}>
                  Low
                </div>
              </div>
            </WindowsStatGrid>
          </WindowsDataPanel>

          <WindowsDivider />

          {/* Filter Controls */}
          <WindowsFilterControls>
            <FilterInput
              label="Search"
              type="text"
              placeholder="Rule, computer, or channel..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: "240px" }}
            />
            <FilterSelect
              label="Severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              options={[
                { value: "all", label: "All Severities" },
                { value: "critical_high", label: "Critical + High" },
                { value: "critical", label: "Critical Only" },
                { value: "high", label: "High Only" },
                { value: "medium", label: "Medium Only" },
                { value: "low", label: "Low Only" },
              ]}
            />
            <FilterSelect
              label="Channel"
              value={channelFilter}
              onChange={(e) => setChannelFilter(e.target.value)}
              options={[
                { value: "all", label: "All Channels" },
                ...uniqueChannels.map((ch) => ({ value: ch, label: ch })),
              ]}
            />
            <FilterInput
              label="Event ID"
              type="text"
              placeholder="e.g., 4688"
              value={eventIdFilter}
              onChange={(e) => setEventIdFilter(e.target.value)}
              style={{ width: "120px" }}
            />
            <FilterInput
              label="Computer"
              type="text"
              placeholder="Hostname..."
              value={computerFilter}
              onChange={(e) => setComputerFilter(e.target.value)}
              style={{ width: "180px" }}
            />
            {(severityFilter !== "all" || computerFilter || eventIdFilter || channelFilter !== "all" || searchQuery) && (
              <WindowsButton
                variant="secondary"
                onClick={() => {
                  setSeverityFilter("all");
                  setComputerFilter("");
                  setEventIdFilter("");
                  setChannelFilter("all");
                  setSearchQuery("");
                }}
                style={{ fontSize: "10px", padding: "6px 12px" }}
              >
                ✕ CLEAR
              </WindowsButton>
            )}
            <div style={{ marginLeft: "auto", fontSize: "11px", color: "#666" }}>
              Showing {filteredSigmaMatches.length} of {sigmaResults.matches?.length || 0} matches
            </div>
          </WindowsFilterControls>

          {/* Threat Timeline */}
          <WindowsDataPanel title="Threat Timeline">
            {threatEvents.length > 0 ? (
              <ThreatTimeline
                events={threatEvents}
                height={400}
                onEventClick={(event) => setSelectedThreat(event)}
              />
            ) : (
              <WindowsEmptyState
                icon="✅"
                title="No threats detected"
                message={severityFilter !== "all" ? "No matches for selected severity filter" : "No Sigma rule matches found"}
              />
            )}
          </WindowsDataPanel>

          {/* IOCs Section */}
          {iocs && iocs.total_iocs > 0 && (
            <>
              <WindowsDivider />
              <WindowsDataPanel title="Indicators of Compromise (IOCs)" accent="#ff8800">
                <WindowsStatGrid columns={3}>
                  <WindowsMetricCard
                    label="Total IOCs"
                    value={iocs.total_iocs}
                    accent="#ff8800"
                    icon="🎯"
                  />
                  <WindowsMetricCard
                    label="IP Addresses"
                    value={iocs.ips.length}
                    accent="#4488ff"
                    icon="🌐"
                  />
                  <WindowsMetricCard
                    label="File Hashes"
                    value={
                      (iocs.hashes.md5?.length || 0) +
                      (iocs.hashes.sha1?.length || 0) +
                      (iocs.hashes.sha256?.length || 0)
                    }
                    accent="#ff8800"
                    icon="#️⃣"
                  />
                </WindowsStatGrid>

                <div style={{ display: "grid", gap: "16px", marginTop: "20px" }}>
                  {/* IP Addresses */}
                  {iocs.ips.length > 0 && (
                    <div>
                      <div style={{ fontSize: "10px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "10px" }}>
                        IP Addresses ({iocs.ips.length})
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                        {iocs.ips.slice(0, 10).map((ip) => (
                          <IoCBadge key={ip} type="ip" value={ip} />
                        ))}
                        {iocs.ips.length > 10 && (
                          <span style={{ fontSize: "10px", color: "#666", padding: "4px 8px" }}>
                            +{iocs.ips.length - 10} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Domains */}
                  {iocs.domains.length > 0 && (
                    <div>
                      <div style={{ fontSize: "10px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "10px" }}>
                        Domains ({iocs.domains.length})
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                        {iocs.domains.slice(0, 10).map((domain) => (
                          <IoCBadge key={domain} type="domain" value={domain} />
                        ))}
                        {iocs.domains.length > 10 && (
                          <span style={{ fontSize: "10px", color: "#666", padding: "4px 8px" }}>
                            +{iocs.domains.length - 10} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Users */}
                  {iocs.users.length > 0 && (
                    <div>
                      <div style={{ fontSize: "10px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "10px" }}>
                        Users ({iocs.users.length})
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                        {iocs.users.slice(0, 8).map((user) => (
                          <IoCBadge key={user} type="user" value={user} />
                        ))}
                        {iocs.users.length > 8 && (
                          <span style={{ fontSize: "10px", color: "#666", padding: "4px 8px" }}>
                            +{iocs.users.length - 8} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Suspicious Processes */}
                  {iocs.processes.length > 0 && (
                    <div>
                      <div style={{ fontSize: "10px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "10px" }}>
                        Suspicious Processes ({iocs.processes.length})
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                        {iocs.processes.slice(0, 8).map((process) => (
                          <IoCBadge key={process} type="file" value={process.split("\\").pop() || process} />
                        ))}
                        {iocs.processes.length > 8 && (
                          <span style={{ fontSize: "10px", color: "#666", padding: "4px 8px" }}>
                            +{iocs.processes.length - 8} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </WindowsDataPanel>
            </>
          )}
        </>
      )}

      {!loading && !sigmaResults && !error && (
        <WindowsEmptyState
          icon="🔍"
          title="No Analysis Results"
          message="Sigma detection has not been run yet for this project"
          action={
            <WindowsButton onClick={fetchResults}>
              LOAD RESULTS
            </WindowsButton>
          }
        />
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
