"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import {
  getProjects,
  createProject,
  deleteProject,
  deleteProjectUpload,
  getProjectUploads,
  generateProjectApiKey,
  getProjectApiKey,
  getProjectNxlogConfig,
  getLiveAgentMonitor,
  type LiveAgentMonitorData,
  type ProjectType,
} from "@/lib/client";
import {
  SectionHeader,
  Btn,
  Badge,
  Divider,
  TextInput,
  Spinner,
} from "@/components/ui-primitives";
import UploadStepper from "@/components/upload-stepper";

interface Project {
  id: string;
  name?: string;
  description?: string;
  status?: string;
  last_run_at?: string;
  project_type?: ProjectType;
}

interface UploadRecord {
  upload_id: string;
  filename?: string;
  stage?: string;
  status?: string;
  entry_count?: number;
  started_at?: string;
}

function formatBytes(bytes: number): string {
  if (bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}


function formatUptime(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${h}h ${m}m ${s}s`;
}

// ── Upload status badge helper ────────────────────────────────────────────────

function UploadStatusBadge({ stage, status }: { stage?: string; status?: string }) {
  if (stage === "saved" && status === "complete") return <Badge color="#4caf50">SAVED</Badge>;
  if (stage === "error" || status === "error") return <Badge color="#cc4444">ERROR</Badge>;
  if (stage === "normalizing") return <Badge color="#f0c040">NORMALIZING</Badge>;
  if (stage === "parsing") return <Badge color="#f0c040">PARSING</Badge>;
  if (stage === "uploading") return <Badge color="#4488ff">UPLOADING</Badge>;
  return <Badge color="#555">{(stage ?? status ?? "UNKNOWN").toUpperCase()}</Badge>;
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ProjectsPage() {
  const { activeProject, setActiveProject, setProjectSelectPending, setTimeRange } = useAuthStore();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newProjectType, setNewProjectType] = useState<ProjectType>("web");
  const [createError, setCreateError] = useState("");
  const [actionError, setActionError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [expandedUploads, setExpandedUploads] = useState<Record<string, UploadRecord[]>>({});
  const [loadingUploads, setLoadingUploads] = useState<Record<string, boolean>>({});
  const [deletingUploads, setDeletingUploads] = useState<Record<string, boolean>>({});
  const [selectedUploads, setSelectedUploads] = useState<Record<string, Record<string, boolean>>>({});
  const [apiKeys, setApiKeys] = useState<Record<string, string | null>>({});
  const [generatingKey, setGeneratingKey] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<Record<string, boolean>>({});
  const [copiedCommand, setCopiedCommand] = useState<Record<string, boolean>>({});
  const [nxlogConfByProject, setNxlogConfByProject] = useState<Record<string, string>>({});
  const [agentSetupProjectId, setAgentSetupProjectId] = useState<string | null>(null);
  const [liveMonitor, setLiveMonitor] = useState<LiveAgentMonitorData | null>(null);
  const [liveMonitorLoading, setLiveMonitorLoading] = useState(false);
  const [liveMonitorError, setLiveMonitorError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await getProjects();
      setProjects(data);
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadUploads = async (projectId: string) => {
    if (expandedUploads[projectId]) {
      // Toggle collapse
      setExpandedUploads((prev) => { const n = { ...prev }; delete n[projectId]; return n; });
      setSelectedUploads((prev) => {
        const next = { ...prev };
        delete next[projectId];
        return next;
      });
      return;
    }
    setLoadingUploads((prev) => ({ ...prev, [projectId]: true }));
    setActionError("");
    try {
      const uploads = await getProjectUploads(projectId);
      setExpandedUploads((prev) => ({ ...prev, [projectId]: uploads }));
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
    setLoadingUploads((prev) => ({ ...prev, [projectId]: false }));
  };

  const handleCreate = async () => {
    if (!newName.trim()) { setCreateError("Project name required"); return; }
    setCreating(true); setCreateError("");
    try {
      await createProject(newName.trim(), newDesc.trim(), newProjectType);
      setNewName(""); setNewDesc(""); setNewProjectType("web"); setShowCreate(false);
      await load();
    } catch (e) { setCreateError(String(e)); }
    setCreating(false);
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this project and all associated data?")) return;
    setActionError("");
    try {
      await deleteProject(id);
      if (activeProject?.id === id) { setActiveProject(null); setTimeRange(null); }
      setExpandedUploads((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
      setSelectedUploads((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  };

  const toggleUploadSelection = (projectId: string, uploadId: string) => {
    setSelectedUploads((prev) => ({
      ...prev,
      [projectId]: {
        ...(prev[projectId] || {}),
        [uploadId]: !(prev[projectId]?.[uploadId]),
      },
    }));
  };

  const toggleSelectAllUploads = (projectId: string, uploads: UploadRecord[]) => {
    const selected = selectedUploads[projectId] || {};
    const allSelected = uploads.length > 0 && uploads.every((u) => selected[u.upload_id]);
    const nextMap: Record<string, boolean> = {};
    if (!allSelected) {
      uploads.forEach((u) => {
        nextMap[u.upload_id] = true;
      });
    }
    setSelectedUploads((prev) => ({ ...prev, [projectId]: nextMap }));
  };

  const handleDeleteSelectedUploads = async (projectId: string) => {
    const selected = selectedUploads[projectId] || {};
    const uploadIds = Object.keys(selected).filter((id) => selected[id]);
    if (uploadIds.length === 0) return;
    if (!confirm(`Delete ${uploadIds.length} selected uploaded log file(s)?`)) return;

    setDeletingUploads((prev) => ({ ...prev, [projectId]: true }));
    setActionError("");
    try {
      for (const uploadId of uploadIds) {
        await deleteProjectUpload(projectId, uploadId);
      }
      const refreshed = await getProjectUploads(projectId);
      setExpandedUploads((prev) => ({ ...prev, [projectId]: refreshed }));
      setSelectedUploads((prev) => ({ ...prev, [projectId]: {} }));
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingUploads((prev) => ({ ...prev, [projectId]: false }));
    }
  };

  const openAgentSetup = async (projectId: string) => {
    setAgentSetupProjectId(projectId);
    try {
      const [keyData, nxlogConf] = await Promise.all([
        getProjectApiKey(projectId),
        getProjectNxlogConfig(projectId),
      ]);
      setApiKeys((prev) => ({ ...prev, [projectId]: keyData.api_key ?? null }));
      setNxlogConfByProject((prev) => ({ ...prev, [projectId]: nxlogConf }));
    } catch {
      if (!(projectId in apiKeys)) {
        setApiKeys((prev) => ({ ...prev, [projectId]: null }));
      }
      setNxlogConfByProject((prev) => ({ ...prev, [projectId]: "" }));
    }
  };

  useEffect(() => {
    if (!agentSetupProjectId) {
      setLiveMonitor(null);
      setLiveMonitorError("");
      return;
    }

    let cancelled = false;

    const refresh = async () => {
      setLiveMonitorLoading(true);
      try {
        const data = await getLiveAgentMonitor(agentSetupProjectId);
        if (!cancelled) {
          setLiveMonitor(data);
          setLiveMonitorError("");
        }
      } catch (err) {
        if (!cancelled) {
          setLiveMonitorError(String(err));
        }
      } finally {
        if (!cancelled) setLiveMonitorLoading(false);
      }
    };

    refresh();
    const id = window.setInterval(refresh, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [agentSetupProjectId]);

  const handleGenerateKey = async (projectId: string) => {
    setGeneratingKey((prev) => ({ ...prev, [projectId]: true }));
    try {
      const data = await generateProjectApiKey(projectId);
      setApiKeys((prev) => ({ ...prev, [projectId]: data.api_key }));
    } catch {}
    setGeneratingKey((prev) => ({ ...prev, [projectId]: false }));
  };

  const handleCopyKey = (projectId: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedKey((prev) => ({ ...prev, [projectId]: true }));
      setTimeout(() => setCopiedKey((prev) => ({ ...prev, [projectId]: false })), 2000);
    });
  };

  const handleCopyCommand = (projectId: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedCommand((prev) => ({ ...prev, [projectId]: true }));
      setTimeout(() => setCopiedCommand((prev) => ({ ...prev, [projectId]: false })), 2000);
    });
  };

  const handleSetActive = (p: Project) => {
    setActiveProject({
      id: p.id,
      name: p.name ?? p.id,
      project_type: p.project_type === "windows" ? "windows" : "web",
    });
    setProjectSelectPending(false);
  };

  const closeAgentSetup = () => {
    setAgentSetupProjectId(null);
  };

  const handleDeactivate = () => {
    setActiveProject(null);
    setTimeRange(null);
  };

  const agentSetupProject = agentSetupProjectId
    ? projects.find((project) => project.id === agentSetupProjectId)
    : null;
  const agentsDashboardPath =
    agentSetupProject?.project_type === "windows" ? "/windows-agents" : "/agents";

  return (
    <div>
      <SectionHeader
        title="Projects"
        subtitle="Isolate log pipelines by project — each project maintains its own log data and analysis results"
      />

      {/* Active Project Banner */}
      {activeProject && (
        <div style={{
          background: "#0d1a0d", border: "1px solid #1a4a1a", borderRadius: 4,
          padding: "12px 16px", marginBottom: 20, display: "flex", alignItems: "center", gap: 12,
        }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#4caf50" }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 11, color: "#4caf50", letterSpacing: 1, textTransform: "uppercase", marginBottom: 2 }}>
              Active Project
            </div>
            <div style={{ color: "#c0c0c0", fontSize: 13 }}>{activeProject.name}</div>
            <div style={{ color: activeProject.project_type === "windows" ? "#42a5f5" : "#7cb342", fontSize: 10, letterSpacing: 0.8, marginTop: 2, textTransform: "uppercase" }}>
              {activeProject.project_type === "windows" ? "Windows" : "Web"}
            </div>
          </div>
          <Btn variant="ghost" onClick={handleDeactivate} style={{ fontSize: 11 }}>
            DEACTIVATE
          </Btn>
        </div>
      )}

      {/* Upload Stepper for active project */}
      {activeProject && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
            Upload Logs → {activeProject.name}
          </div>
          <UploadStepper
            projectId={activeProject.id}
            projectType={activeProject.project_type === "windows" ? "windows" : "web"}
            onComplete={() => {
              load();
              // Refresh uploads list if expanded
              if (expandedUploads[activeProject.id]) {
                getProjectUploads(activeProject.id)
                  .then((u) => setExpandedUploads((prev) => ({ ...prev, [activeProject.id]: u })))
                  .catch(() => {});
              }
            }}
          />
        </div>
      )}

      <Divider />

      {actionError && (
        <div style={{
          background: "#2b1111",
          border: "1px solid #5a2222",
          color: "#ff8888",
          borderRadius: 4,
          padding: "10px 12px",
          fontSize: 12,
          marginBottom: 12,
        }}>
          {actionError}
        </div>
      )}

      {/* Create New */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase" }}>
          {projects.length} Project{projects.length !== 1 ? "s" : ""}
        </div>
        <Btn variant="default" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? "CANCEL" : "NEW PROJECT"}
        </Btn>
      </div>

      {showCreate && (
        <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 16, marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>
            Create Project
          </div>
          <TextInput label="Name *" value={newName} onValueChange={setNewName} placeholder="e.g. Production Apache 2025" />
          <TextInput label="Description" value={newDesc} onValueChange={setNewDesc} placeholder="Optional description" />
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>
              Project Type
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                onClick={() => setNewProjectType("web")}
                style={{
                  flex: 1,
                  background: newProjectType === "web" ? "#1a3d2a" : "#111",
                  border: `1px solid ${newProjectType === "web" ? "#4a7c59" : "#333"}`,
                  color: newProjectType === "web" ? "#7cb342" : "#777",
                  borderRadius: 3,
                  padding: "8px 10px",
                  fontSize: 11,
                  letterSpacing: 0.8,
                  textTransform: "uppercase",
                  cursor: "pointer",
                }}
                type="button"
              >
                Web
              </button>
              <button
                onClick={() => setNewProjectType("windows")}
                style={{
                  flex: 1,
                  background: newProjectType === "windows" ? "#0d1a3d" : "#111",
                  border: `1px solid ${newProjectType === "windows" ? "#4a5c7c" : "#333"}`,
                  color: newProjectType === "windows" ? "#42a5f5" : "#777",
                  borderRadius: 3,
                  padding: "8px 10px",
                  fontSize: 11,
                  letterSpacing: 0.8,
                  textTransform: "uppercase",
                  cursor: "pointer",
                }}
                type="button"
              >
                Windows
              </button>
            </div>
          </div>
          {createError && <div style={{ color: "#cc4444", fontSize: 12, marginBottom: 8 }}>{createError}</div>}
          <Btn onClick={handleCreate} disabled={creating}>
            {creating ? <Spinner size={12} /> : "CREATE"}
          </Btn>
        </div>
      )}

      {/* Project List */}
      {loading ? (
        <div style={{ textAlign: "center", padding: 40 }}><Spinner size={24} /></div>
      ) : projects.length === 0 ? (
        <div style={{ textAlign: "center", color: "#444", padding: 48, fontSize: 13 }}>
          No projects yet — create one to begin
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {projects.map((p) => {
            const isActive = activeProject?.id === p.id;
            const uploads = expandedUploads[p.id];
            const uploadsLoading = loadingUploads[p.id];
            const uploadSelection = selectedUploads[p.id] || {};
            const selectedCount = uploads ? uploads.filter((u) => uploadSelection[u.upload_id]).length : 0;
            return (
              <div key={p.id} style={{
                background: isActive ? "#0d1a0d" : "#0d0d0d",
                border: `1px solid ${isActive ? "#1a4a1a" : "#1e1e1e"}`,
                borderRadius: 4,
              }}>
                {/* Project header row */}
                <div style={{ padding: "14px 16px", display: "flex", alignItems: "center", gap: 14 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <div style={{ color: "#e0e0e0", fontSize: 13, fontWeight: 500 }}>{p.name}</div>
                      <Badge color={p.project_type === "windows" ? "#42a5f5" : "#7cb342"}>
                        {p.project_type === "windows" ? "WINDOWS" : "WEB"}
                      </Badge>
                      {isActive && <Badge color="#4caf50">ACTIVE</Badge>}
                    </div>
                    {p.description && (
                      <div style={{ color: "#555", fontSize: 12 }}>{p.description}</div>
                    )}
                    <div style={{ color: "#333", fontSize: 11, marginTop: 4 }}>
                      {p.last_run_at ? `Last run: ${new Date(p.last_run_at).toLocaleDateString()}` : ""}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
                    <Btn variant="ghost" onClick={() => loadUploads(p.id)} style={{ fontSize: 11 }}>
                      {uploadsLoading ? <Spinner size={10} /> : uploads ? "HIDE FILES" : "FILES"}
                    </Btn>
                    <Btn variant="ghost" onClick={() => openAgentSetup(p.id)} style={{ fontSize: 11 }}>
                      AGENT SETUP
                    </Btn>
                    {isActive ? (
                      <Btn variant="ghost" onClick={handleDeactivate}>DEACTIVATE</Btn>
                    ) : (
                      <Btn variant="default" onClick={() => handleSetActive(p)}>SET ACTIVE</Btn>
                    )}
                    <Btn variant="danger" onClick={() => handleDelete(p.id)}>DELETE</Btn>
                  </div>
                </div>

                {/* Uploads list */}
                {uploads && (
                  <div style={{ borderTop: "1px solid #1a1a1a", padding: "10px 16px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                      <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase" }}>
                        Uploaded Log Files
                      </div>
                      {uploads.length > 0 && (
                        <>
                          <Btn variant="ghost" onClick={() => toggleSelectAllUploads(p.id, uploads)} style={{ fontSize: 10 }}>
                            {selectedCount === uploads.length ? "CLEAR" : "SELECT ALL"}
                          </Btn>
                          <Btn
                            variant="danger"
                            onClick={() => handleDeleteSelectedUploads(p.id)}
                            disabled={selectedCount === 0 || deletingUploads[p.id]}
                            style={{ fontSize: 10 }}
                          >
                            {deletingUploads[p.id] ? <Spinner size={10} /> : `DELETE SELECTED (${selectedCount})`}
                          </Btn>
                        </>
                      )}
                    </div>
                    {uploads.length === 0 ? (
                      <div style={{ color: "#333", fontSize: 12 }}>No log files uploaded yet</div>
                    ) : (
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        {uploads.map((u) => (
                          <div key={u.upload_id} style={{
                            display: "flex", alignItems: "center", gap: 10,
                            background: "#0a0a0a", border: "1px solid #1a1a1a",
                            borderRadius: 3, padding: "7px 10px",
                          }}>
                            <input
                              type="checkbox"
                              checked={Boolean(uploadSelection[u.upload_id])}
                              onChange={() => toggleUploadSelection(p.id, u.upload_id)}
                              style={{ cursor: "pointer" }}
                              aria-label={`Select ${u.filename ?? u.upload_id}`}
                            />
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ color: "#c0c0c0", fontSize: 12, marginBottom: 2 }}>
                                {u.filename ?? u.upload_id}
                              </div>
                              <div style={{ color: "#444", fontSize: 11 }}>
                                {u.started_at ? new Date(u.started_at).toLocaleString() : ""}
                                {u.entry_count ? ` · ${u.entry_count.toLocaleString()} entries` : ""}
                              </div>
                            </div>
                            <UploadStatusBadge stage={u.stage} status={u.status} />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {agentSetupProjectId && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.78)",
            zIndex: 1200,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 16,
          }}
          onClick={closeAgentSetup}
        >
          <div
            style={{
              width: "min(980px, 96vw)",
              maxHeight: "90vh",
              overflowY: "auto",
              background: "#0c0f12",
              border: "1px solid #1f2a33",
              borderRadius: 8,
              padding: 16,
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 12, color: "#6e8796", letterSpacing: 1, textTransform: "uppercase" }}>NXLog Agent</div>
                <div style={{ color: "#d7e2e9", fontSize: 15, fontWeight: 600 }}>Project Agent Setup + Live Monitor</div>
              </div>
              <Btn variant="ghost" onClick={closeAgentSetup}>Close</Btn>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 14 }}>
              <div style={{ background: "#0a0d10", border: "1px solid #1a222a", borderRadius: 6, padding: 12 }}>
                <div style={{ fontSize: 11, color: "#7fa8bf", marginBottom: 8, letterSpacing: 1, textTransform: "uppercase" }}>Installation Guide</div>
                <div style={{ color: "#8fa6b3", fontSize: 12, marginBottom: 8 }}>
                  Use the generated NXLog configuration below. Copy it into nxlog.conf, then restart the NXLog service.
                </div>
                <div style={{ color: "#6e8796", fontSize: 11, marginBottom: 10 }}>
                  The configuration includes your project ID and API key header for direct ingestion to LOGIC.
                </div>
                <div style={{ fontSize: 11, color: "#6e8796", marginBottom: 4 }}>NXLog Configuration</div>
                <pre style={{ fontFamily: "monospace", fontSize: 11, color: "#a7d97a", background: "#06090c", border: "1px solid #1a222a", padding: 8, borderRadius: 4, marginBottom: 10, whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 320, overflowY: "auto" }}>
                  {nxlogConfByProject[agentSetupProjectId] || "NXLog config unavailable. Click AGENT SETUP again to regenerate."}
                </pre>

                <div style={{ fontSize: 11, color: "#6e8796", marginBottom: 4 }}>Copy-ready API key command</div>
                <div style={{ fontFamily: "monospace", fontSize: 11, color: "#9fd4ff", background: "#06090c", border: "1px solid #1a222a", padding: 8, borderRadius: 4, marginBottom: 10, wordBreak: "break-all" }}>
                  {(() => {
                    const key = apiKeys[agentSetupProjectId] || "<generate-project-key-first>";
                    return `Write-Output \"${key}\" | Set-Clipboard`;
                  })()}
                </div>

                <div style={{ display: "flex", gap: 8 }}>
                  <Btn
                    variant="ghost"
                    onClick={() => {
                      const conf = nxlogConfByProject[agentSetupProjectId] || "";
                      handleCopyCommand(agentSetupProjectId, conf);
                    }}
                    disabled={!nxlogConfByProject[agentSetupProjectId]}
                    style={{ fontSize: 11 }}
                  >
                    {copiedCommand[agentSetupProjectId] ? "COPIED!" : "COPY NXLOG CONF"}
                  </Btn>
                  <Btn
                    variant="ghost"
                    onClick={() => {
                      const key = apiKeys[agentSetupProjectId] || "";
                      handleCopyKey(agentSetupProjectId, key);
                    }}
                    style={{ fontSize: 11 }}
                  >
                    {copiedKey[agentSetupProjectId] ? "COPIED!" : "COPY API KEY"}
                  </Btn>
                  {!apiKeys[agentSetupProjectId] && (
                    <Btn
                      variant="ghost"
                      onClick={() => handleGenerateKey(agentSetupProjectId)}
                      style={{ fontSize: 11 }}
                      disabled={generatingKey[agentSetupProjectId]}
                    >
                      {generatingKey[agentSetupProjectId] ? <Spinner size={10} /> : "GENERATE API KEY"}
                    </Btn>
                  )}
                  <Btn
                    variant="ghost"
                    onClick={() => {
                      closeAgentSetup();
                      window.location.href = agentsDashboardPath;
                    }}
                    style={{ fontSize: 11 }}
                  >
                    AGENTS DASHBOARD
                  </Btn>
                </div>
              </div>

              <div style={{ background: "#0a0d10", border: "1px solid #1a222a", borderRadius: 6, padding: 12 }}>
                <div style={{ fontSize: 11, color: "#7fa8bf", marginBottom: 8, letterSpacing: 1, textTransform: "uppercase" }}>Incoming Live Logs</div>
                {liveMonitorLoading && !liveMonitor ? (
                  <div style={{ padding: 12 }}><Spinner size={16} /></div>
                ) : liveMonitorError ? (
                  <div style={{ color: "#d56a6a", fontSize: 12 }}>{liveMonitorError}</div>
                ) : (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 10 }}>
                      <div style={{ background: "#070a0d", border: "1px solid #1a222a", borderRadius: 4, padding: 8 }}>
                        <div style={{ fontSize: 10, color: "#6e8796" }}>Status</div>
                        <div style={{ color: liveMonitor?.status === "active" ? "#70d08c" : "#c5b27b", fontSize: 12, fontWeight: 600 }}>{(liveMonitor?.status ?? "idle").toUpperCase()}</div>
                      </div>
                      <div style={{ background: "#070a0d", border: "1px solid #1a222a", borderRadius: 4, padding: 8 }}>
                        <div style={{ fontSize: 10, color: "#6e8796" }}>Uptime</div>
                        <div style={{ color: "#d7e2e9", fontSize: 12 }}>{formatUptime(liveMonitor?.uptime_seconds ?? 0)}</div>
                      </div>
                      <div style={{ background: "#070a0d", border: "1px solid #1a222a", borderRadius: 4, padding: 8 }}>
                        <div style={{ fontSize: 10, color: "#6e8796" }}>Total Logs</div>
                        <div style={{ color: "#d7e2e9", fontSize: 12 }}>{(liveMonitor?.total_logs ?? 0).toLocaleString()}</div>
                      </div>
                      <div style={{ background: "#070a0d", border: "1px solid #1a222a", borderRadius: 4, padding: 8 }}>
                        <div style={{ fontSize: 10, color: "#6e8796" }}>Total Size</div>
                        <div style={{ color: "#d7e2e9", fontSize: 12 }}>{formatBytes(liveMonitor?.total_size_bytes ?? 0)}</div>
                      </div>
                    </div>

                    <div style={{ color: "#8fa6b3", fontSize: 11, marginBottom: 8 }}>
                      Last batch: {liveMonitor?.last_batch_at ? new Date(liveMonitor.last_batch_at * 1000).toLocaleString() : "No batches received yet"}
                    </div>

                    <div style={{ fontSize: 10, color: "#6e8796", letterSpacing: 1, textTransform: "uppercase", marginBottom: 6 }}>Validation Errors</div>
                    <div style={{ maxHeight: 110, overflowY: "auto", border: "1px solid #1a222a", borderRadius: 4, padding: 6, marginBottom: 10, background: "#06090c" }}>
                      {(liveMonitor?.validation_errors?.length ?? 0) === 0 ? (
                        <div style={{ color: "#50606a", fontSize: 11 }}>No validation errors</div>
                      ) : (
                        liveMonitor!.validation_errors.map((e, idx) => (
                          <div key={`v-${idx}`} style={{ color: "#d56a6a", fontSize: 11, marginBottom: 4 }}>
                            [{new Date(e.timestamp * 1000).toLocaleTimeString()}] {e.message}
                          </div>
                        ))
                      )}
                    </div>

                    <div style={{ fontSize: 10, color: "#6e8796", letterSpacing: 1, textTransform: "uppercase", marginBottom: 6 }}>Processing Errors</div>
                    <div style={{ maxHeight: 110, overflowY: "auto", border: "1px solid #1a222a", borderRadius: 4, padding: 6, background: "#06090c" }}>
                      {(liveMonitor?.processing_errors?.length ?? 0) === 0 ? (
                        <div style={{ color: "#50606a", fontSize: 11 }}>No processing errors</div>
                      ) : (
                        liveMonitor!.processing_errors.map((e, idx) => (
                          <div key={`p-${idx}`} style={{ color: "#d56a6a", fontSize: 11, marginBottom: 4 }}>
                            [{new Date(e.timestamp * 1000).toLocaleTimeString()}] {e.message}
                          </div>
                        ))
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
