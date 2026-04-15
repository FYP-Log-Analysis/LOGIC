"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  controlLiveAgentMonitor,
  getLiveAgentMonitor,
  type LiveAgentMonitorData,
  type MonitorControlAction,
  type ProjectType,
} from "@/lib/client";
import { Btn } from "@/components/ui-primitives";

interface AgentMonitorControlsProps {
  projectId?: string | null;
  projectType?: ProjectType;
  onMonitorChange?: (monitor: LiveAgentMonitorData) => void;
}

function statusColor(status: string | undefined): string {
  if (status === "active") return "#70d08c";
  if (status === "stopped") return "#d56a6a";
  return "#c5b27b";
}

export default function AgentMonitorControls({
  projectId,
  projectType = "web",
  onMonitorChange,
}: AgentMonitorControlsProps) {
  const [monitor, setMonitor] = useState<LiveAgentMonitorData | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<MonitorControlAction | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refreshMonitor = useCallback(async (silent = false) => {
    if (!projectId) {
      setMonitor(null);
      return;
    }

    if (!silent) setLoading(true);

    try {
      const data = await getLiveAgentMonitor(projectId);
      setMonitor(data);
      onMonitorChange?.(data);
      if (!silent) setError("");
    } catch (err) {
      if (!silent) {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      if (!silent) setLoading(false);
    }
  }, [onMonitorChange, projectId]);

  useEffect(() => {
    setMessage("");
    setError("");

    if (!projectId) {
      setMonitor(null);
      return;
    }

    let cancelled = false;

    const run = async () => {
      if (cancelled) return;
      await refreshMonitor(false);
    };

    void run();
    const id = window.setInterval(() => {
      if (cancelled) return;
      void refreshMonitor(true);
    }, 8000);

    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [projectId, refreshMonitor]);

  const monitorState = useMemo(() => {
    if (!monitor) return "running";
    return monitor.monitoring_state ?? (monitor.status === "stopped" ? "stopped" : "running");
  }, [monitor]);

  const runAction = useCallback(async (action: MonitorControlAction) => {
    if (!projectId) return;

    setActionLoading(action);
    setError("");
    setMessage("");

    try {
      const result = await controlLiveAgentMonitor(projectId, action);
      setMonitor(result.monitor);
      onMonitorChange?.(result.monitor);
      setMessage(result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionLoading(null);
    }
  }, [onMonitorChange, projectId]);

  const panelStatus = monitor?.status ?? "idle";
  const hasProject = Boolean(projectId);

  return (
    <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14 }}>
      <div
        style={{
          minWidth: 360,
          maxWidth: 720,
          width: "fit-content",
          border: "1px solid #1e1e1e",
          borderRadius: 6,
          background: "#0f1114",
          padding: 10,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
          <div>
            <div style={{ fontSize: 10, color: "#6e8796", letterSpacing: 1, textTransform: "uppercase" }}>
              Agent Controls ({projectType === "windows" ? "Windows" : "Web"})
            </div>
            <div style={{ fontSize: 11, color: "#8d9ba5" }}>
              {hasProject ? "Stop, resume, or restart live monitoring" : "Select an active project to enable controls"}
            </div>
          </div>
          <div style={{ fontSize: 11, color: statusColor(panelStatus), fontWeight: 600, letterSpacing: 0.5 }}>
            {(loading ? "loading" : panelStatus).toUpperCase()}
          </div>
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
          <Btn
            variant="danger"
            disabled={!hasProject || actionLoading !== null || monitorState === "stopped"}
            onClick={() => void runAction("stop")}
          >
            {actionLoading === "stop" ? "STOPPING..." : "STOP"}
          </Btn>
          <Btn
            variant="ghost"
            disabled={!hasProject || actionLoading !== null || monitorState === "running"}
            onClick={() => void runAction("resume")}
          >
            {actionLoading === "resume" ? "RESUMING..." : "RESUME"}
          </Btn>
          <Btn
            variant="ghost"
            disabled={!hasProject || actionLoading !== null}
            onClick={() => void runAction("restart")}
          >
            {actionLoading === "restart" ? "RESTARTING..." : "RESTART"}
          </Btn>
        </div>

        {message && <div style={{ marginTop: 8, color: "#70d08c", fontSize: 11 }}>{message}</div>}
        {error && <div style={{ marginTop: 8, color: "#d56a6a", fontSize: 11 }}>{error}</div>}
      </div>
    </div>
  );
}
