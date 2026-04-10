"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getWindowsSigmaRuleDetail,
  getWindowsSigmaRules,
  type WindowsSigmaRuleSummary,
} from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { Btn, SectionHeader, Spinner } from "@/components/ui-primitives";

export default function RulesSetupPage() {
  const { activeProject } = useAuthStore();
  const [rules, setRules] = useState<WindowsSigmaRuleSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [viewLoading, setViewLoading] = useState(false);
  const [selectedRule, setSelectedRule] = useState<{ rule: WindowsSigmaRuleSummary; yaml: string } | null>(null);

  const loadRules = useCallback(async () => {
    if (activeProject?.project_type !== "windows") {
      setRules([]);
      setError(null);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const catalog = await getWindowsSigmaRules();
      setRules(catalog.rules || []);
    } catch (e) {
      setRules([]);
      setError(e instanceof Error ? e.message : "Failed to load Sigma rules.");
    } finally {
      setLoading(false);
    }
  }, [activeProject?.project_type]);

  useEffect(() => {
    void loadRules();
  }, [loadRules]);

  const openRuleView = useCallback(async (rulePath: string) => {
    setViewLoading(true);
    try {
      const detail = await getWindowsSigmaRuleDetail(rulePath);
      setSelectedRule(detail);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load Sigma rule details.");
    } finally {
      setViewLoading(false);
    }
  }, []);

  const rulesByFolder = useMemo(() => {
    const grouped = new Map<string, WindowsSigmaRuleSummary[]>();
    for (const rule of rules) {
      const rawPath = (rule.rule_path || "").replace(/\\/g, "/").replace(/^\/+/, "");
      const lastSlash = rawPath.lastIndexOf("/");
      const folder = lastSlash > -1 ? rawPath.slice(0, lastSlash) : "(root)";
      const bucket = grouped.get(folder) ?? [];
      bucket.push(rule);
      grouped.set(folder, bucket);
    }

    return Array.from(grouped.entries())
      .map(([folder, folderRules]) => ({
        folder,
        rules: [...folderRules].sort((a, b) => (a.rule_path || "").localeCompare(b.rule_path || "")),
      }))
      .sort((a, b) => a.folder.localeCompare(b.folder));
  }, [rules]);

  if (!activeProject?.id) {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
        Select a project from the sidebar to view this page.
      </div>
    );
  }

  if (activeProject.project_type !== "windows") {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#777" }}>
        Rules Setup is available for Windows projects only.
      </div>
    );
  }

  return (
    <div>
      <SectionHeader
        title="Rules Setup"
        subtitle="Browse and inspect Sigma rule definitions used for Windows detections"
      />

      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
        <Btn onClick={() => void loadRules()} disabled={loading}>
          {loading ? "LOADING..." : "REFRESH RULES"}
        </Btn>
      </div>

      {error && (
        <div style={{ color: "#ff8a80", fontSize: 12, marginBottom: 12 }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: "center", padding: 40 }}>
          <Spinner size={22} />
        </div>
      ) : rulesByFolder.length === 0 ? (
        <div style={{ color: "#666", fontSize: 12, border: "1px dashed #1e1e1e", borderRadius: 4, padding: 20 }}>
          No Sigma rules found.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {rulesByFolder.map((group) => (
            <div key={group.folder} style={{ border: "1px solid #1f1f1f", borderRadius: 4, background: "#090909", padding: 10 }}>
              <div style={{ color: "#7cb342", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.7, marginBottom: 8, fontFamily: "monospace" }}>
                data/sigma_rules/{group.folder === "(root)" ? "" : group.folder} · {group.rules.length} file{group.rules.length === 1 ? "" : "s"}
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {group.rules.map((rule) => (
                  <div
                    key={rule.rule_path}
                    style={{
                      border: "1px solid #1f1f1f",
                      borderRadius: 4,
                      background: "#0b0b0b",
                      padding: "10px",
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: "#d0d0d0", fontSize: "12px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontFamily: "monospace" }}>
                        {rule.rule_path.split("/").pop() || rule.rule_path}
                      </div>
                      <div style={{ color: "#707070", fontSize: "11px", marginTop: "3px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontFamily: "monospace" }}>
                        {rule.rule_path}
                      </div>
                      <div style={{ color: "#707070", fontSize: "11px", marginTop: "2px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {rule.id} · {rule.level} · {rule.title}
                      </div>
                    </div>
                    <button
                      onClick={() => void openRuleView(rule.rule_path)}
                      disabled={viewLoading}
                      style={{
                        border: "1px solid #355a3b",
                        color: "#7cb342",
                        background: "#101a10",
                        fontSize: "11px",
                        borderRadius: "4px",
                        padding: "6px 10px",
                        cursor: viewLoading ? "not-allowed" : "pointer",
                      }}
                    >
                      VIEW
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))}
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
    </div>
  );
}
