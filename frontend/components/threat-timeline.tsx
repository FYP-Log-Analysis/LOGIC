"use client";

import { useState, useMemo } from "react";

export interface ThreatEvent {
  timestamp: string;
  severity: "info" | "warning" | "critical";
  type: "web" | "windows" | "detection";
  title: string;
  details?: string;
  source?: string;
}

export interface ThreatTimelineProps {
  events: ThreatEvent[];
  onEventClick?: (event: ThreatEvent) => void;
  height?: number;
}

const severityColors: Record<string, string> = {
  info: "#42a5f5",
  warning: "#ffa726",
  critical: "#ef5350",
};

const severityOrder: Record<string, number> = {
  critical: 3,
  warning: 2,
  info: 1,
};

export function ThreatTimeline({ events, onEventClick, height = 300 }: ThreatTimelineProps) {
  const [selectedEvent, setSelectedEvent] = useState<ThreatEvent | null>(null);
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
        No threat events in this timeline
      </div>
    );
  }

  // Sort events by timestamp for display
  const sortedEvents = [...filteredEvents].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  const minTime = sortedEvents.length > 0 ? new Date(sortedEvents[0].timestamp).getTime() : Date.now();
  const maxTime = sortedEvents.length > 0 ? new Date(sortedEvents[sortedEvents.length - 1].timestamp).getTime() : Date.now();
  const timeRange = maxTime - minTime || 1;

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
          position: "relative",
          background: "#1a1a1a",
          border: "1px solid #222",
          borderRadius: "4px",
          padding: "12px",
          display: "flex",
          alignItems: "center",
        }}
      >
        {/* Horizontal line */}
        <div
          style={{
            position: "absolute",
            top: "50%",
            left: "12px",
            right: "12px",
            height: "2px",
            background: "#333",
            transform: "translateY(-50%)",
          }}
        />

        {/* Events */}
        <div style={{ position: "relative", width: "100%", height: "100%" }}>
          {sortedEvents.map((event, idx) => {
            const eventTime = new Date(event.timestamp).getTime();
            const position = timeRange > 0 ? ((eventTime - minTime) / timeRange) * 90 + 5 : 50;

            return (
              <div
                key={idx}
                onClick={() => {
                  setSelectedEvent(event);
                  onEventClick?.(event);
                }}
                style={{
                  position: "absolute",
                  left: `${position}%`,
                  top: "50%",
                  transform: "translate(-50%, -50%)",
                  cursor: "pointer",
                  zIndex: severityOrder[event.severity],
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLDivElement).style.transform =
                    "translate(-50%, -50%) scale(1.3)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLDivElement).style.transform =
                    "translate(-50%, -50%)";
                }}
              >
                <div
                  style={{
                    width: "12px",
                    height: "12px",
                    borderRadius: "50%",
                    background: severityColors[event.severity],
                    border: `2px solid ${selectedEvent === event ? "#fff" : "#0d0d0d"}`,
                    boxShadow: `0 0 8px ${severityColors[event.severity]}`,
                    transition: "all 0.15s",
                  }}
                />
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: "16px", fontSize: "11px", color: "#666" }}>
        <span>{filteredEvents.length} event(s) in range</span>
        {sortedEvents.length > 0 && (
          <>
            <span>First: {new Date(sortedEvents[0].timestamp).toLocaleString()}</span>
            <span>Last: {new Date(sortedEvents[sortedEvents.length - 1].timestamp).toLocaleString()}</span>
          </>
        )}
      </div>

      {/* Selected event details */}
      {selectedEvent && (
        <div
          style={{
            padding: "12px",
            background: "#1a1a1a",
            border: `2px solid ${severityColors[selectedEvent.severity]}`,
            borderRadius: "4px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", marginBottom: "8px" }}>
            <div>
              <div style={{ color: severityColors[selectedEvent.severity], fontWeight: "bold", fontSize: "12px" }}>
                {selectedEvent.severity.toUpperCase()} — {selectedEvent.type.toUpperCase()}
              </div>
              <div style={{ color: "#aaa", fontSize: "10px", marginTop: "2px" }}>
                {new Date(selectedEvent.timestamp).toLocaleString()}
              </div>
            </div>
            <button
              onClick={() => setSelectedEvent(null)}
              style={{
                background: "#333",
                border: "1px solid #555",
                color: "#aaa",
                padding: "2px 6px",
                fontSize: "10px",
                cursor: "pointer",
                borderRadius: "2px",
              }}
            >
              Close
            </button>
          </div>
          <div style={{ color: "#ccc", fontSize: "11px", marginBottom: "6px" }}>
            {selectedEvent.title}
          </div>
          {selectedEvent.details && (
            <div style={{ color: "#888", fontSize: "10px", marginBottom: "6px", lineHeight: "1.4" }}>
              {selectedEvent.details}
            </div>
          )}
          {selectedEvent.source && (
            <div style={{ color: "#666", fontSize: "9px" }}>
              Source: {selectedEvent.source}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
