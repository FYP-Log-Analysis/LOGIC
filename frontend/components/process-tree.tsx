"use client";

import React, { useMemo } from "react";

interface ProcessNode {
  processId: string;
  processName: string;
  commandLine: string;
  timestamp: string;
  user: string;
  parentProcessId: string;
  children: ProcessNode[];
  eventId: number;
  computer: string;
}

type ProcessEventData = Record<string, unknown>;

interface ProcessEvent {
  event_id: number;
  computer: string;
  timestamp: string;
  event_data: ProcessEventData;
}

function stringifyValue(value: unknown, fallback = ""): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

interface ProcessTreeProps {
  events: ProcessEvent[];
  onNodeClick?: (node: ProcessNode) => void;
}

export function ProcessTree({ events, onNodeClick }: ProcessTreeProps) {
  const processTree = useMemo(() => {
    // Build process map from 4688 events (Process Creation)
    const processMap = new Map<string, ProcessNode>();
    const rootProcesses: ProcessNode[] = [];
    
    // Filter and sort process creation events
    const processEvents = events
      .filter((e) => e.event_id === 4688)
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    
    // First pass: Create all nodes
    processEvents.forEach((event) => {
      const data = event.event_data ?? {};
      const processId = stringifyValue(data.NewProcessId ?? data.ProcessId);
      const parentProcessId = stringifyValue(data.ParentProcessId);
      
      if (!processId) return;
      
      const node: ProcessNode = {
        processId,
        processName: stringifyValue(data.NewProcessName ?? data.ProcessName, "Unknown").split("\\").pop() || "Unknown",
        commandLine: stringifyValue(data.CommandLine),
        timestamp: event.timestamp,
        user: stringifyValue(data.SubjectUserName ?? data.User),
        parentProcessId,
        children: [],
        eventId: event.event_id,
        computer: event.computer,
      };
      
      processMap.set(processId, node);
    });
    
    // Second pass: Build tree structure
    processMap.forEach((node) => {
      if (node.parentProcessId && processMap.has(node.parentProcessId)) {
        const parent = processMap.get(node.parentProcessId)!;
        parent.children.push(node);
      } else {
        rootProcesses.push(node);
      }
    });
    
    return rootProcesses;
  }, [events]);
  
  const renderNode = (node: ProcessNode, level: number = 0) => {
    const isSuspicious = 
      node.processName.toLowerCase().includes("powershell") ||
      node.processName.toLowerCase().includes("cmd") ||
      node.processName.toLowerCase().includes("wmic") ||
      node.commandLine.toLowerCase().includes("invoke-expression") ||
      node.commandLine.toLowerCase().includes("download");
    
    return (
      <div key={node.processId} style={{ marginLeft: level * 24 }}>
        <div
          onClick={() => onNodeClick?.(node)}
          style={{
            padding: "10px 12px",
            background: isSuspicious ? "#2a1a1a" : "#0d0d0d",
            border: `1px solid ${isSuspicious ? "#5a2a2a" : "#1e1e1e"}`,
            borderRadius: "4px",
            marginBottom: "8px",
            cursor: onNodeClick ? "pointer" : "default",
            transition: "all 0.2s ease",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = isSuspicious ? "#3a2a2a" : "#151515";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = isSuspicious ? "#2a1a1a" : "#0d0d0d";
          }}
        >
          {/* Process Info */}
          <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "6px" }}>
            <span style={{ fontSize: "16px" }}>
              {level === 0 ? "🌳" : "└─"}
            </span>
            <span style={{ color: isSuspicious ? "#ff8800" : "#7cb342", fontWeight: 600, fontSize: "12px" }}>
              {node.processName}
            </span>
            {isSuspicious && (
              <span style={{ background: "#ff8800", color: "#000", padding: "2px 6px", borderRadius: "2px", fontSize: "8px", fontWeight: "bold" }}>
                SUSPICIOUS
              </span>
            )}
            <span style={{ fontSize: "10px", color: "#666", marginLeft: "auto" }}>
              PID: {node.processId}
            </span>
          </div>
          
          {/* Command Line */}
          {node.commandLine && (
            <div style={{ fontSize: "10px", color: "#888", fontFamily: "var(--font-mono-stack)", marginLeft: "28px", marginBottom: "4px", wordBreak: "break-all" }}>
              {node.commandLine.length > 100 ? `${node.commandLine.substring(0, 100)}...` : node.commandLine}
            </div>
          )}
          
          {/* Metadata */}
          <div style={{ display: "flex", gap: "16px", fontSize: "9px", color: "#555", marginLeft: "28px" }}>
            <span>👤 {node.user || "N/A"}</span>
            <span>🖥️ {node.computer}</span>
            <span>⏱️ {new Date(node.timestamp).toLocaleString()}</span>
            {node.children.length > 0 && (
              <span style={{ color: "#ff8800" }}>👶 {node.children.length} child{node.children.length > 1 ? "ren" : ""}</span>
            )}
          </div>
        </div>
        
        {/* Render children */}
        {node.children.length > 0 && (
          <div style={{ marginLeft: "12px", borderLeft: "2px dashed #2a2a2a", paddingLeft: "12px" }}>
            {node.children.map((child) => renderNode(child, level + 1))}
          </div>
        )}
      </div>
    );
  };
  
  if (processTree.length === 0) {
    return (
      <div style={{ textAlign: "center", padding: "40px", color: "#666" }}>
        <div style={{ fontSize: "32px", marginBottom: "12px", opacity: 0.4 }}>🌲</div>
        <div style={{ fontSize: "12px" }}>No process creation events (EventID 4688) found</div>
      </div>
    );
  }
  
  return (
    <div style={{ maxHeight: "600px", overflowY: "auto", padding: "4px" }}>
      {processTree.map((root) => renderNode(root, 0))}
    </div>
  );
}

interface ProcessTreePanelProps {
  events: ProcessEvent[];
}

export function ProcessTreePanel({ events }: ProcessTreePanelProps) {
  const [selectedNode, setSelectedNode] = React.useState<ProcessNode | null>(null);
  
  return (
    <div>
      <ProcessTree events={events} onNodeClick={setSelectedNode} />
      
      {selectedNode && (
        <div style={{ marginTop: "20px", padding: "16px", background: "#0a0a0a", border: "1px solid #2a2a2a", borderRadius: "6px" }}>
          <div style={{ fontSize: "11px", color: "#666", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "12px" }}>
            Selected Process Details
          </div>
          <div style={{ display: "grid", gap: "8px", fontSize: "11px" }}>
            <div><span style={{ color: "#666" }}>Process:</span> <span style={{ color: "#7cb342" }}>{selectedNode.processName}</span></div>
            <div><span style={{ color: "#666" }}>PID:</span> <span style={{ color: "#c0c0c0" }}>{selectedNode.processId}</span></div>
            <div><span style={{ color: "#666" }}>Parent PID:</span> <span style={{ color: "#c0c0c0" }}>{selectedNode.parentProcessId || "N/A"}</span></div>
            <div><span style={{ color: "#666" }}>User:</span> <span style={{ color: "#c0c0c0" }}>{selectedNode.user}</span></div>
            <div><span style={{ color: "#666" }}>Computer:</span> <span style={{ color: "#c0c0c0" }}>{selectedNode.computer}</span></div>
            <div><span style={{ color: "#666" }}>Timestamp:</span> <span style={{ color: "#c0c0c0" }}>{new Date(selectedNode.timestamp).toLocaleString()}</span></div>
            {selectedNode.commandLine && (
              <div style={{ marginTop: "8px" }}>
                <div style={{ color: "#666", marginBottom: "4px" }}>Command Line:</div>
                <div style={{ fontFamily: "var(--font-mono-stack)", fontSize: "10px", color: "#aaa", background: "#000", padding: "8px", borderRadius: "4px", wordBreak: "break-all" }}>
                  {selectedNode.commandLine}
                </div>
              </div>
            )}
            <button
              onClick={() => setSelectedNode(null)}
              style={{ marginTop: "12px", padding: "6px 12px", background: "#2a2a2a", border: "none", color: "#c0c0c0", borderRadius: "4px", cursor: "pointer", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.8px" }}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
