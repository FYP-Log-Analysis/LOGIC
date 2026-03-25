"use client";

import { useState, useMemo } from "react";

export interface SigmaRule {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  detection_count?: number;
  last_matched?: string;
  enabled?: boolean;
}

export interface ActiveSigmaRulesProps {
  rules: SigmaRule[];
  onRuleToggle?: (ruleId: string, enabled: boolean) => void;
  matchSummary?: Record<string, number>;
}

const severityBadgeColor: Record<string, string> = {
  low: "#42a5f5",
  medium: "#ffa726",
  high: "#ef5350",
  critical: "#c62828",
};

export function ActiveSigmaRules({ rules, onRuleToggle, matchSummary = {} }: ActiveSigmaRulesProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);

  const filteredRules = useMemo(() => {
    return rules
      .filter((r) => !searchTerm || r.title.toLowerCase().includes(searchTerm.toLowerCase()) || r.id.toLowerCase().includes(searchTerm.toLowerCase()))
      .filter((r) => !filterSeverity || r.severity === filterSeverity)
      .sort((a, b) => {
        const aCount = matchSummary[a.id] || 0;
        const bCount = matchSummary[b.id] || 0;
        if (aCount !== bCount) return bCount - aCount;
        return a.title.localeCompare(b.title);
      });
  }, [rules, searchTerm, filterSeverity, matchSummary]);

  const activeCount = rules.filter((r) => r.enabled !== false).length;
  const totalMatches = Object.values(matchSummary).reduce((sum, count) => sum + count, 0);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {/* Header */}
      <div style={{ paddingBottom: "12px", borderBottom: "1px solid #222" }}>
        <h3 style={{ margin: 0, color: "#7cb342", fontSize: "13px", fontWeight: "bold", marginBottom: "6px" }}>
          Active Sigma Rules
        </h3>
        <div style={{ display: "flex", gap: "16px", fontSize: "11px", color: "#888" }}>
          <span>{activeCount} rules enabled</span>
          <span>{filteredRules.length} rules shown</span>
          <span>{totalMatches} total matches</span>
        </div>
      </div>

      {/* Search and filter */}
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
        <input
          type="text"
          placeholder="Search rules..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{
            flex: 1,
            minWidth: "200px",
            padding: "6px 8px",
            fontSize: "11px",
            background: "#1a1a1a",
            border: "1px solid #333",
            color: "#aaa",
            borderRadius: "2px",
            outline: "none",
          }}
          onFocus={(e) => {
            (e.target as HTMLInputElement).style.borderColor = "#4a7c59";
          }}
          onBlur={(e) => {
            (e.target as HTMLInputElement).style.borderColor = "#333";
          }}
        />

        <div style={{ display: "flex", gap: "4px" }}>
          {["low", "medium", "high", "critical"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(filterSeverity === sev ? null : sev)}
              style={{
                padding: "4px 6px",
                fontSize: "9px",
                background: filterSeverity === sev ? severityBadgeColor[sev] : "#1a1a1a",
                color: filterSeverity === sev ? "#000" : severityBadgeColor[sev],
                border: `1px solid ${severityBadgeColor[sev]}`,
                borderRadius: "2px",
                cursor: "pointer",
                textTransform: "uppercase",
                letterSpacing: "0.4px",
                fontWeight: "bold",
                transition: "all 0.15s",
              }}
              title={`Filter by ${sev} severity`}
            >
              {sev[0].toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Rules list */}
      <div style={{ maxHeight: "600px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "6px" }}>
        {filteredRules.length === 0 ? (
          <div style={{ padding: "16px", color: "#666", fontSize: "11px", textAlign: "center" }}>
            No rules match your filters
          </div>
        ) : (
          filteredRules.map((rule) => {
            const matchCount = matchSummary[rule.id] || 0;
            const isExpanded = expandedRule === rule.id;

            return (
              <div
                key={rule.id}
                onClick={() => setExpandedRule(isExpanded ? null : rule.id)}
                style={{
                  padding: "8px 10px",
                  background: "#1a1a1a",
                  border: `1px solid ${isExpanded ? "#4a7c59" : "#222"}`,
                  borderRadius: "2px",
                  cursor: "pointer",
                  transition: "all 0.15s",
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLDivElement).style.borderColor = "#444";
                  (e.currentTarget as HTMLDivElement).style.background = "#1a1a2a";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLDivElement).style.borderColor = isExpanded ? "#4a7c59" : "#222";
                  (e.currentTarget as HTMLDivElement).style.background = "#1a1a1a";
                }}
              >
                {/* Rule header */}
                <div style={{ display: "flex", alignItems: "center", gap: "8px", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1 }}>
                    {/* Checkbox */}
                    <input
                      type="checkbox"
                      checked={rule.enabled !== false}
                      onChange={(e) => {
                        e.stopPropagation();
                        onRuleToggle?.(rule.id, e.target.checked);
                      }}
                      style={{
                        cursor: "pointer",
                        width: "16px",
                        height: "16px",
                        accentColor: "#7cb342",
                      }}
                    />

                    {/* Severity badge */}
                    <span
                      style={{
                        display: "inline-block",
                        padding: "2px 4px",
                        background: severityBadgeColor[rule.severity],
                        color: "#000",
                        fontSize: "9px",
                        borderRadius: "2px",
                        fontWeight: "bold",
                        minWidth: "32px",
                        textAlign: "center",
                        textTransform: "uppercase",
                        letterSpacing: "0.3px",
                      }}
                    >
                      {rule.severity}
                    </span>

                    {/* Title */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: "#aaa", fontSize: "11px", fontWeight: "500", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {rule.title}
                      </div>
                      <div style={{ color: "#666", fontSize: "9px", marginTop: "2px" }}>
                        {rule.id}
                      </div>
                    </div>
                  </div>

                  {/* Match count */}
                  <span
                    style={{
                      padding: "2px 6px",
                      background: matchCount > 0 ? "#ef5350" : "#333",
                      color: matchCount > 0 ? "#fff" : "#666",
                      fontSize: "10px",
                      borderRadius: "2px",
                      fontWeight: "bold",
                      minWidth: "32px",
                      textAlign: "center",
                    }}
                  >
                    {matchCount}
                  </span>

                  {/* Expand arrow */}
                  <span style={{ color: "#666", fontSize: "12px", transition: "transform 0.15s", transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)" }}>
                    ▶
                  </span>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div style={{ marginTop: "8px", paddingTop: "8px", borderTop: "1px solid #222", display: "flex", flexDirection: "column", gap: "4px" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "10px", color: "#888" }}>
                      <div>
                        <span style={{ color: "#666" }}>Enabled:</span> {rule.enabled !== false ? "Yes" : "No"}
                      </div>
                      <div>
                        <span style={{ color: "#666" }}>Matches:</span> {matchCount}
                      </div>
                      {rule.last_matched && (
                        <div style={{ gridColumn: "1 / -1" }}>
                          <span style={{ color: "#666" }}>Last matched:</span> {new Date(rule.last_matched).toLocaleString()}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
