"use client";

import { useMemo, useState } from "react";

type PanelTab = "overview" | "raw" | "mitre";

export interface DetectionDetailsItem {
  id: string;
  source: "sigma" | "behavioral";
  title: string;
  severity?: string;
  timestamp?: string;
  computer?: string;
  eventId?: string | number;
  channel?: string;
  anomalyScore?: number | null;
  mitreTechniques?: Array<{ technique_id?: string; name?: string; tactic?: string }>;
  payload: Record<string, unknown>;
}

interface DetectionDetailsPanelProps {
  item: DetectionDetailsItem | null;
  compact?: boolean;
}

const tabStyles: Record<PanelTab, { label: string }> = {
  overview: { label: "Overview" },
  raw: { label: "Raw Event" },
  mitre: { label: "MITRE" },
};

function metric(label: string, value: string) {
  return (
    <div style={{
      padding: "10px 12px",
      border: "1px solid #202020",
      borderRadius: 4,
      background: "#101010",
    }}>
      <div style={{ color: "#707070", fontSize: 10, letterSpacing: 0.7, textTransform: "uppercase", marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ color: "#d0d0d0", fontSize: 12, wordBreak: "break-word" }}>{value || "-"}</div>
    </div>
  );
}

function toPrettyJson(payload: unknown): string {
  try {
    return JSON.stringify(payload, null, 2);
  } catch {
    return "{}";
  }
}

export function DetectionDetailsPanel({ item, compact = false }: DetectionDetailsPanelProps) {
  const [activeTab, setActiveTab] = useState<PanelTab>("overview");

  const prettyPayload = useMemo(() => toPrettyJson(item?.payload ?? {}), [item?.payload]);

  return (
    <aside style={{
      border: "1px solid #202020",
      borderRadius: 6,
      background: "#0d0d0d",
      minHeight: compact ? 420 : 520,
      display: "flex",
      flexDirection: "column",
      overflow: "hidden",
    }}>
      <div style={{
        borderBottom: "1px solid #1b1b1b",
        padding: compact ? "10px 12px" : "12px 14px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 8,
      }}>
        <div>
          <div style={{ color: "#9c9c9c", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.8 }}>
            Detection Details
          </div>
          <div style={{ color: "#d8d8d8", fontSize: 13, fontWeight: 600, marginTop: 6 }}>
            {item ? item.title : "Select a row"}
          </div>
        </div>
        {item && (
          <div style={{
            color: item.source === "sigma" ? "#7cb342" : "#ff8800",
            border: "1px solid #2a2a2a",
            background: "#111",
            borderRadius: 4,
            padding: "4px 8px",
            fontSize: 10,
            textTransform: "uppercase",
            letterSpacing: 0.7,
            fontWeight: 600,
          }}>
            {item.source}
          </div>
        )}
      </div>

      <div style={{
        display: "flex",
        gap: 8,
        padding: "10px 12px",
        borderBottom: "1px solid #1b1b1b",
      }}>
        {(Object.keys(tabStyles) as PanelTab[]).map((tab) => (
            <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              border: "1px solid #2a2a2a",
              background: activeTab === tab ? "#1f2a16" : "#111",
              color: activeTab === tab ? "#9ed26f" : "#a5a5a5",
              borderRadius: 3,
              padding: compact ? "5px 8px" : "6px 10px",
              fontSize: 10,
              textTransform: "uppercase",
              letterSpacing: 0.7,
              cursor: "pointer",
            }}
          >
            {tabStyles[tab].label}
          </button>
        ))}
      </div>

      <div style={{ padding: 12, overflowY: "auto", flex: 1 }}>
        {!item && (
          <div style={{ color: "#6f6f6f", fontSize: 12, lineHeight: 1.5 }}>
            Select any detection row to inspect key fields, raw event JSON, and MITRE mapping.
          </div>
        )}

        {item && activeTab === "overview" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 10 }}>
            {metric("Severity", (item.severity || "unknown").toUpperCase())}
            {metric("Timestamp", item.timestamp ? new Date(item.timestamp).toLocaleString() : "-")}
            {metric("Computer", item.computer || "-")}
            {metric("Event ID", item.eventId != null ? String(item.eventId) : "-")}
            {metric("Channel", item.channel || "-")}
            {metric(
              "Anomaly Score",
              item.anomalyScore != null ? `${(item.anomalyScore * 100).toFixed(1)}%` : "-",
            )}
          </div>
        )}

        {item && activeTab === "raw" && (
          <pre style={{
            margin: 0,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            fontSize: 11,
            lineHeight: 1.45,
            color: "#d0d0d0",
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
            background: "#090909",
            border: "1px solid #1b1b1b",
            borderRadius: 4,
            padding: 10,
          }}>{prettyPayload}</pre>
        )}

        {item && activeTab === "mitre" && (
          <div style={{ display: "grid", gap: 8 }}>
            {(item.mitreTechniques || []).length === 0 && (
              <div style={{ color: "#6f6f6f", fontSize: 12 }}>
                No MITRE mappings available for this row.
              </div>
            )}
            {(item.mitreTechniques || []).map((technique, index) => (
              <div
                key={`${technique.technique_id || "t"}-${index}`}
                style={{
                  padding: "10px 12px",
                  border: "1px solid #202020",
                  borderRadius: 4,
                  background: "#101010",
                }}
              >
                <div style={{ color: "#8ecf62", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.7 }}>
                  {technique.technique_id || "Technique"}
                </div>
                <div style={{ color: "#d0d0d0", fontSize: 12, marginTop: 4 }}>
                  {technique.name || "Unknown"}
                </div>
                <div style={{ color: "#777", fontSize: 10, marginTop: 4 }}>
                  Tactic: {technique.tactic || "Unknown"}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}
