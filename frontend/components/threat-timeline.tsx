"use client";

import { useMemo, useState, type ReactNode } from "react";

export interface ThreatEvent {
  timestamp: string;
  severity: "info" | "warning" | "critical";
  type: "web" | "windows" | "detection";
  title: string;
  details?: string;
  source?: string;
  payload?: unknown;
}

export interface ThreatTimelineProps {
  events: ThreatEvent[];
  onEventClick?: (event: ThreatEvent) => void;
  height?: number;
  emptyState?: ReactNode;
}

const severityColors: Record<string, string> = {
  info: "#42a5f5",
  warning: "#ffa726",
  critical: "#ef5350",
};

export function ThreatTimeline({ events, onEventClick, height = 300, emptyState }: ThreatTimelineProps) {
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string | null>(null);

  const filteredEvents = useMemo(() => {
    return events
      .filter((e) => !filterSeverity || e.severity === filterSeverity)
      .filter((e) => !filterType || e.type === filterType)
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [events, filterSeverity, filterType]);

  if (!events || events.length === 0) {
    return (
      <div
        style={{
          padding: "20px",
          textAlign: "center",
          color: "#666",
          background: "#0d0d0d",
          border: "1px solid #222",
          borderRadius: "4px",
        }}
      >
        {emptyState ?? "No threat events in this timeline"}
      </div>
    );
  }
  const sortedEvents = [...filteredEvents].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {/* Filters */}
      <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
        <span style={{ fontSize: "10px", color: "#666", textTransform: "uppercase", letterSpacing: "0.5px" }}>
          Filter:
        </span>

        <div style={{ display: "flex", gap: "6px" }}>
          {["info", "warning", "critical"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(filterSeverity === sev ? null : sev)}
              style={{
                padding: "4px 8px",
                fontSize: "10px",
                background: filterSeverity === sev ? severityColors[sev] : "#1a1a1a",
                color: filterSeverity === sev ? "#000" : severityColors[sev],
                border: `1px solid ${severityColors[sev]}`,
                borderRadius: "2px",
                cursor: "pointer",
                textTransform: "uppercase",
                letterSpacing: "0.5px",
                transition: "all 0.15s",
              }}
              onMouseEnter={(e) => {
                if (filterSeverity !== sev) {
                  (e.currentTarget as HTMLButtonElement).style.opacity = "0.7";
                }
              }}
              onMouseLeave={(e) => {
                if (filterSeverity !== sev) {
                  (e.currentTarget as HTMLButtonElement).style.opacity = "1";
                }
              }}
            >
              {sev}
            </button>
          ))}
        </div>

        <div style={{ display: "flex", gap: "6px" }}>
          {["web", "windows", "detection"].map((typ) => (
            <button
              key={typ}
              onClick={() => setFilterType(filterType === typ ? null : typ)}
              style={{
                padding: "4px 8px",
                fontSize: "10px",
                background: filterType === typ ? "#1a3d2a" : "#1a1a1a",
                color: filterType === typ ? "#7cb342" : "#666",
                border: `1px solid ${filterType === typ ? "#4a7c59" : "#333"}`,
                borderRadius: "2px",
                cursor: "pointer",
                textTransform: "uppercase",
                letterSpacing: "0.5px",
                transition: "all 0.15s",
              }}
            >
              {typ}
            </button>
          ))}
        </div>
      </div>

      {/* Timeline visualization */}
      <div
        style={{
          height: `${height}px`,
          overflowY: "auto",
          background: "#0d0d0d",
          border: "1px solid #222",
          borderRadius: "4px",
          padding: "12px",
        }}
      >
        <div style={{ position: "relative", minHeight: "100%", paddingLeft: "22px" }}>
          <div
            style={{
              position: "absolute",
              left: "8px",
              top: 0,
              bottom: 0,
              width: "2px",
              background: "#2f2f2f",
            }}
          />

          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {sortedEvents.map((event, idx) => (
              <button
                key={`${event.timestamp}_${event.title}_${idx}`}
                onClick={() => onEventClick?.(event)}
                style={{
                  border: "1px solid #1f1f1f",
                  background: "#111",
                  borderRadius: "4px",
                  color: "inherit",
                  cursor: "pointer",
                  textAlign: "left",
                  padding: "10px 10px 10px 12px",
                  position: "relative",
                }}
              >
                <span
                  style={{
                    position: "absolute",
                    left: "-20px",
                    top: "14px",
                    width: "12px",
                    height: "12px",
                    borderRadius: "50%",
                    background: severityColors[event.severity],
                    border: "2px solid #0d0d0d",
                    boxShadow: `0 0 8px ${severityColors[event.severity]}`,
                  }}
                />

                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px", flexWrap: "wrap" }}>
                  <span style={{ color: severityColors[event.severity], fontSize: "10px", letterSpacing: "0.6px", textTransform: "uppercase", fontWeight: 700 }}>
                    {event.severity}
                  </span>
                  <span style={{ color: "#777", fontSize: "10px", letterSpacing: "0.6px", textTransform: "uppercase" }}>
                    {event.type}
                  </span>
                  <span style={{ color: "#666", fontSize: "10px" }}>
                    {new Date(event.timestamp).toLocaleString()}
                  </span>
                </div>
                <div style={{ color: "#cfcfcf", fontSize: "12px", marginBottom: event.details ? "4px" : 0 }}>
                  {event.title}
                </div>
                {event.details && (
                  <div style={{ color: "#888", fontSize: "10px", lineHeight: 1.4 }}>
                    {event.details}
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: "16px", fontSize: "11px", color: "#666" }}>
        <span>{filteredEvents.length} event(s) in range</span>
        {sortedEvents.length > 0 && (
          <>
            <span>Latest: {new Date(sortedEvents[0].timestamp).toLocaleString()}</span>
            <span>Oldest: {new Date(sortedEvents[sortedEvents.length - 1].timestamp).toLocaleString()}</span>
          </>
        )}
      </div>
    </div>
  );
}
