"use client";

import { useMemo, useState } from "react";
import { IoCBadge } from "@/components/windows-ui";

type PanelTab = "overview" | "iocs" | "raw" | "mitre";

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
  iocs: { label: "IOCs" },
  raw: { label: "Raw Event" },
  mitre: { label: "MITRE" },
};

type ExtractedIocs = {
  ips: string[];
  domains: string[];
  hashes: string[];
  files: string[];
  users: string[];
};

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const DOMAIN_RE = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
const HASH_RE = /\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g;
const WIN_PATH_RE = /\b(?:[a-zA-Z]:\\[^\r\n\t"']+|\\\\[^\r\n\t"']+)\b/g;

function collectStrings(value: unknown, out: string[], depth = 0) {
  if (depth > 6) return;

  if (typeof value === "string") {
    out.push(value);
    return;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    out.push(String(value));
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((entry) => collectStrings(entry, out, depth + 1));
    return;
  }

  if (value && typeof value === "object") {
    Object.values(value as Record<string, unknown>).forEach((entry) => collectStrings(entry, out, depth + 1));
  }
}

function uniqueSorted(values: Iterable<string>): string[] {
  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}

function extractEventIocs(item: DetectionDetailsItem | null): ExtractedIocs {
  if (!item) {
    return { ips: [], domains: [], hashes: [], files: [], users: [] };
  }

  const payloadStrings: string[] = [];
  collectStrings(item.payload, payloadStrings);

  const ips: string[] = [];
  const domains: string[] = [];
  const hashes: string[] = [];
  const files: string[] = [];

  payloadStrings.forEach((text) => {
    const ipMatches = text.match(IPV4_RE) ?? [];
    const domainMatches = text.match(DOMAIN_RE) ?? [];
    const hashMatches = text.match(HASH_RE) ?? [];
    const fileMatches = text.match(WIN_PATH_RE) ?? [];

    ips.push(...ipMatches);
    hashes.push(...hashMatches.map((v) => v.toLowerCase()));
    files.push(...fileMatches);

    domainMatches.forEach((domain) => {
      const lower = domain.toLowerCase();
      if (!lower.endsWith(".exe") && !lower.endsWith(".dll") && !lower.endsWith(".sys")) {
        domains.push(lower);
      }
    });
  });

  const entry = ((item.payload.entry as Record<string, unknown> | undefined) ?? item.payload) as Record<string, unknown>;
  const users = uniqueSorted([
    String(entry.auth_user ?? ""),
    String(entry.user ?? ""),
    String(entry.target_user ?? ""),
    String(entry.SubjectUserName ?? ""),
    String(entry.TargetUserName ?? ""),
  ].filter((value) => value && value !== "-") as string[]);

  return {
    ips: uniqueSorted(ips),
    domains: uniqueSorted(domains),
    hashes: uniqueSorted(hashes),
    files: uniqueSorted(files),
    users,
  };
}

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
  const eventIocs = useMemo(() => extractEventIocs(item), [item]);
  const hasIocs =
    eventIocs.ips.length > 0 ||
    eventIocs.domains.length > 0 ||
    eventIocs.hashes.length > 0 ||
    eventIocs.files.length > 0 ||
    eventIocs.users.length > 0;

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

        {item && activeTab === "iocs" && (
          <div style={{ display: "grid", gap: 10 }}>
            {!hasIocs && (
              <div style={{ color: "#6f6f6f", fontSize: 12, lineHeight: 1.5 }}>
                No obvious IOCs extracted from this event payload.
              </div>
            )}

            {eventIocs.ips.length > 0 && (
              <div>
                <div style={{ color: "#6f6f6f", fontSize: 10, textTransform: "uppercase", marginBottom: 7 }}>IP Addresses</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                  {eventIocs.ips.slice(0, 20).map((ip) => (
                    <IoCBadge key={`ip-${ip}`} type="ip" value={ip} />
                  ))}
                </div>
              </div>
            )}

            {eventIocs.domains.length > 0 && (
              <div>
                <div style={{ color: "#6f6f6f", fontSize: 10, textTransform: "uppercase", marginBottom: 7 }}>Domains</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                  {eventIocs.domains.slice(0, 20).map((domain) => (
                    <IoCBadge key={`domain-${domain}`} type="domain" value={domain} />
                  ))}
                </div>
              </div>
            )}

            {eventIocs.hashes.length > 0 && (
              <div>
                <div style={{ color: "#6f6f6f", fontSize: 10, textTransform: "uppercase", marginBottom: 7 }}>Hashes</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                  {eventIocs.hashes.slice(0, 20).map((hash) => (
                    <IoCBadge key={`hash-${hash}`} type="hash" value={hash} />
                  ))}
                </div>
              </div>
            )}

            {eventIocs.files.length > 0 && (
              <div>
                <div style={{ color: "#6f6f6f", fontSize: 10, textTransform: "uppercase", marginBottom: 7 }}>File Paths</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                  {eventIocs.files.slice(0, 20).map((filePath) => (
                    <IoCBadge key={`file-${filePath}`} type="file" value={filePath} />
                  ))}
                </div>
              </div>
            )}

            {eventIocs.users.length > 0 && (
              <div>
                <div style={{ color: "#6f6f6f", fontSize: 10, textTransform: "uppercase", marginBottom: 7 }}>Users</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                  {eventIocs.users.slice(0, 20).map((user) => (
                    <IoCBadge key={`user-${user}`} type="user" value={user} />
                  ))}
                </div>
              </div>
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
