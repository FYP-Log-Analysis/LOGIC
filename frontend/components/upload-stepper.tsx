"use client";

import { useState, useRef, useEffect } from "react";
import { uploadFile, getUploadStatus, getUploadLogs } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import type { ProjectType } from "@/lib/client";

const STAGES = [
  { key: "uploading", label: "Uploading" },
  { key: "parsing", label: "Parsing" },
  { key: "normalizing", label: "Normalizing" },
  { key: "detecting", label: "Detecting Threats" },
  { key: "saved", label: "Saved" },
];

function stageIndex(stage: string) {
  if (stage === "error") return -1;
  return STAGES.findIndex((s) => s.key === stage);
}

// ── Timestamp scanning ────────────────────────────────────────────────────────

const MONTH_MAP: Record<string, string> = {
  Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
  Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
};

function parseLogTimestamps(text: string): Date[] {
  const dates: Date[] = [];

  // Apache/Nginx combined: [02/Jan/2026:14:23:00 +0000]
  const apacheRe = /\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]/g;
  for (const m of text.matchAll(apacheRe)) {
    const [, dd, mon, yyyy, hh, mm, ss, tz] = m;
    const mo = MONTH_MAP[mon];
    if (!mo) continue;
    const sign = tz[0];
    const tzH = tz.slice(1, 3);
    const tzM = tz.slice(3, 5);
    const d = new Date(`${yyyy}-${mo}-${dd}T${hh}:${mm}:${ss}${sign}${tzH}:${tzM}`);
    if (!isNaN(d.getTime())) dates.push(d);
  }

  // Nginx error: 2026/01/02 14:23:00
  const nginxRe = /(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})/g;
  for (const m of text.matchAll(nginxRe)) {
    const d = new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`);
    if (!isNaN(d.getTime())) dates.push(d);
  }

  // ISO 8601: 2026-01-02T14:23:00
  const isoRe = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/g;
  for (const m of text.matchAll(isoRe)) {
    const d = new Date(m[1]);
    if (!isNaN(d.getTime())) dates.push(d);
  }

  return dates;
}

/** Convert a Date to "YYYY-MM-DDTHH:MM" for datetime-local inputs (local time). */
function toDatetimeLocal(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

async function scanFileRange(file: File): Promise<{ from: string; to: string } | null> {
  const CHUNK = 51200; // 50 KB
  const headText = await file.slice(0, CHUNK).text();
  const tailText = await file.slice(Math.max(0, file.size - CHUNK)).text();

  const dates = [...parseLogTimestamps(headText), ...parseLogTimestamps(tailText)];
  if (dates.length === 0) return null;

  const minDate = new Date(Math.min(...dates.map((d) => d.getTime())));
  const maxDate = new Date(Math.max(...dates.map((d) => d.getTime())));
  return { from: toDatetimeLocal(minDate), to: toDatetimeLocal(maxDate) };
}

interface StepperProps {
  currentStage: string;
  currentStatus: string;
  entryCount: number;
  logLines: string[];
}

function Stepper({ currentStage, currentStatus, entryCount, logLines }: StepperProps) {
  const idx = stageIndex(currentStage);
  const isError = currentStage === "error";
  const isDone = currentStage === "saved" && currentStatus === "complete";
  const termRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, [logLines]);

  return (
    <div>
      <div style={{ display: "flex", gap: 0 }}>
        {STAGES.map((s, i) => {
          let icon = "○";
          let color = "#333";
          let labelColor = "#555";

          if (isError && currentStage === s.key) { icon = "✗"; color = "#ff4444"; labelColor = "#ff4444"; }
          else if (isDone || i < idx) { icon = "✓"; color = "#e0e0e0"; labelColor = "#e0e0e0"; }
          else if (i === idx && currentStatus === "running") { icon = "◌"; color = "#888"; labelColor = "#ccc"; }
          else if (i === idx) { icon = "✓"; color = "#e0e0e0"; labelColor = "#e0e0e0"; }

          return (
            <div key={s.key} style={{ flex: 1, textAlign: "center", padding: "10px 2px" }}>
              <div style={{ fontSize: 20, color, fontWeight: 300 }}>{icon}</div>
              <div style={{ fontSize: 10, color: labelColor, marginTop: 4, letterSpacing: 0.6, textTransform: "uppercase" }}>
                {s.label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Terminal log viewer */}
      <div
        ref={termRef}
        style={{
          background: "#0a0a0a",
          border: "1px solid #1a1a1a",
          borderRadius: 3,
          padding: "10px 12px",
          maxHeight: 180,
          minHeight: 80,
          overflowY: "auto",
          fontFamily: "'SF Mono', 'Fira Code', Consolas, monospace",
          fontSize: 11,
          lineHeight: 1.6,
          marginTop: 8,
        }}
      >
        {logLines.length === 0 ? (
          <div style={{ color: "#333" }}>Waiting for pipeline output…</div>
        ) : (
          logLines.map((line, i) => (
            <div key={i} style={{ color: line.includes("ERROR") ? "#cc4444" : line.includes("complete") || line.includes("ready") ? "#4caf50" : "#6a6a6a" }}>
              {line}
            </div>
          ))
        )}
        {!isDone && !isError && (
          <div style={{ color: "#444" }}>
            <span style={{ animation: "none" }}>▍</span>
          </div>
        )}
      </div>

      {/* Status line */}
      <div style={{ marginTop: 8, textAlign: "center", fontSize: 12 }}>
        {isDone ? (
          <span style={{ color: "#4caf50" }}>
            {entryCount.toLocaleString()} log entries stored — ready for analysis
          </span>
        ) : isError ? (
          <span style={{ color: "#ff4444" }}>
            Processing error — check terminal output above
          </span>
        ) : (
          <span style={{ color: "#555" }}>
            {STAGES.find((s) => s.key === currentStage)?.label ?? currentStage}…
          </span>
        )}
      </div>
    </div>
  );
}

interface UploadStepperProps {
  projectId: string;
  projectType: ProjectType;
  onComplete?: () => void;
}

export default function UploadStepper({ projectId, projectType, onComplete }: UploadStepperProps) {
  const { setTimeRange } = useAuthStore();
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [stage, setStage] = useState("idle");
  const [status, setStatus] = useState("idle");
  const [entryCount, setEntryCount] = useState(0);
  const [error, setError] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [logLines, setLogLines] = useState<string[]>([]);

  // Timestamp scan state
  const [scanning, setScanning] = useState(false);
  const [showRangeConfirm, setShowRangeConfirm] = useState(false);
  const [detectedFrom, setDetectedFrom] = useState("");
  const [detectedTo, setDetectedTo] = useState("");
  const [confirmFrom, setConfirmFrom] = useState("");
  const [confirmTo, setConfirmTo] = useState("");
  // ISO timestamps committed by the user — sent to backend for server-side filtering
  const [appliedTimeFrom, setAppliedTimeFrom] = useState<string | undefined>(undefined);
  const [appliedTimeTo, setAppliedTimeTo] = useState<string | undefined>(undefined);

  const handleFile = async (f: File) => {
    setFile(f);
    setStage("idle");
    setStatus("idle");
    setError("");
    setLogLines([]);
    setShowRangeConfirm(false);
    setAppliedTimeFrom(undefined);
    setAppliedTimeTo(undefined);
    setScanning(true);
    try {
      const range = await scanFileRange(f);
      if (range) {
        setDetectedFrom(range.from);
        setDetectedTo(range.to);
        setConfirmFrom(range.from);
        setConfirmTo(range.to);
        setShowRangeConfirm(true);
      }
    } catch {
      // Scanning failed — proceed without range detection
    } finally {
      setScanning(false);
    }
  };

  const handleConfirmRange = () => {
    if (confirmFrom && confirmTo) {
      const isoFrom = new Date(confirmFrom).toISOString();
      const isoTo   = new Date(confirmTo).toISOString();
      setTimeRange({ from: isoFrom, to: isoTo });
      setAppliedTimeFrom(isoFrom);
      setAppliedTimeTo(isoTo);
    }
    setShowRangeConfirm(false);
  };

  const handleSkipRange = () => {
    setAppliedTimeFrom(undefined);
    setAppliedTimeTo(undefined);
    setShowRangeConfirm(false);
  };

  const startUpload = async () => {
    if (!file) return;
    setUploading(true);
    setStage("uploading");
    setStatus("running");
    setError("");
    setLogLines([]);

    try {
      const result = await uploadFile(file, projectId, projectType, appliedTimeFrom, appliedTimeTo);
      const uploadId = result.upload_id;
      if (!uploadId) throw new Error("No upload_id returned");

      setLogLines((prev) => [...prev, `[--:--:--] Uploaded ${file.name} — processing started`]);

      // Poll until complete (max 600 iterations = 10 minutes)
      const MAX_POLLS = 600;
      let polls = 0;
      while (polls < MAX_POLLS) {
        polls++;
        const [s, logs] = await Promise.all([
          getUploadStatus(uploadId),
          getUploadLogs(uploadId),
        ]);
        setStage(s.stage ?? "uploading");
        setStatus(s.status ?? "running");
        setEntryCount(s.entry_count ?? 0);
        if (logs.lines?.length) setLogLines(logs.lines);

        if (s.stage === "saved" && s.status === "complete") {
          onComplete?.();
          break;
        }
        if (s.stage === "error") {
          setError(s.error ?? "Upload failed");
          break;
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      if (polls >= MAX_POLLS) {
        setError("Processing timed out — check API logs");
        setStage("error");
      }
    } catch (e) {
      setError(String(e));
      setStage("error");
    } finally {
      setUploading(false);
    }
  };

  const dtInputStyle: React.CSSProperties = {
    background: "#111", border: "1px solid #2a2a2a", color: "#c0c0c0",
    padding: "6px 8px", fontSize: 12, borderRadius: 3, width: "100%",
    boxSizing: "border-box",
  };

  return (
    <div>
      {/* Drop zone */}
      {!uploading && stage === "idle" && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          style={{
            border: `1px dashed ${dragOver ? "#808080" : "#2a2a2a"}`,
            borderRadius: 4,
            padding: "32px 20px",
            textAlign: "center",
            cursor: "pointer",
            background: dragOver ? "#111" : "#0d0d0d",
            marginBottom: 12,
            transition: "all 0.15s",
          }}
          onClick={() => document.getElementById("upload-file-input")?.click()}
        >
          <input
            id="upload-file-input"
            type="file"
            accept={projectType === "windows" ? ".evtx,.xml" : ".log,.txt,.gz,.json,.access,.error"}
            style={{ display: "none" }}
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
          />
          {file ? (
            <div style={{ color: "#c0c0c0", fontSize: 13 }}>
              <span style={{ color: "#e0e0e0" }}>{file.name}</span>
              <span style={{ color: "#555", marginLeft: 8, fontSize: 11 }}>
                ({(file.size / 1024).toFixed(1)} KB)
              </span>
            </div>
          ) : (
            <div style={{ color: "#444", fontSize: 13, letterSpacing: 0.5 }}>
              Drag & drop a {projectType === "windows" ? "Windows EVTX/XML" : "web server log"} file here, or click to browse
            </div>
          )}
        </div>
      )}

      {/* Scanning indicator */}
      {scanning && (
        <div style={{ fontSize: 12, color: "#555", marginBottom: 12, letterSpacing: 0.5 }}>
          Scanning timestamps…
        </div>
      )}

      {/* Time-range confirmation */}
      {!scanning && showRangeConfirm && (
        <div style={{
          background: "#0d0d0d", border: "1px solid #2a2a2a", borderRadius: 4,
          padding: 16, marginBottom: 14,
        }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>
            Log Time Range Detected
          </div>
          {detectedFrom && (
            <div style={{ fontSize: 11, color: "#444", marginBottom: 12 }}>
              File spans&nbsp;
              <span style={{ color: "#666" }}>{new Date(detectedFrom).toLocaleString()}</span>
              &nbsp;→&nbsp;
              <span style={{ color: "#666" }}>{new Date(detectedTo).toLocaleString()}</span>
            </div>
          )}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
            <div>
              <div style={{ fontSize: 10, color: "#404040", letterSpacing: 0.8, textTransform: "uppercase", marginBottom: 4 }}>From</div>
              <input
                type="datetime-local"
                value={confirmFrom}
                onChange={(e) => setConfirmFrom(e.target.value)}
                style={dtInputStyle}
              />
            </div>
            <div>
              <div style={{ fontSize: 10, color: "#404040", letterSpacing: 0.8, textTransform: "uppercase", marginBottom: 4 }}>To</div>
              <input
                type="datetime-local"
                value={confirmTo}
                onChange={(e) => setConfirmTo(e.target.value)}
                style={dtInputStyle}
              />
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <button
              onClick={handleConfirmRange}
              disabled={!confirmFrom || !confirmTo}
              style={{
                background: "#111", border: "1px solid #404040", color: "#c0c0c0",
                borderRadius: 2, fontSize: 11, letterSpacing: 1, textTransform: "uppercase",
                padding: "7px 16px", fontFamily: "inherit", cursor: "pointer",
              }}
            >
              Confirm &amp; Set Time Range
            </button>
            {(confirmFrom !== detectedFrom || confirmTo !== detectedTo) && detectedFrom && (
              <button
                onClick={() => { setConfirmFrom(detectedFrom); setConfirmTo(detectedTo); }}
                style={{
                  background: "transparent", border: "1px solid #333", color: "#555",
                  borderRadius: 2, fontSize: 10, letterSpacing: 1, textTransform: "uppercase",
                  padding: "7px 12px", fontFamily: "inherit", cursor: "pointer",
                }}
              >
                Reset
              </button>
            )}
            <button
              onClick={handleSkipRange}
              style={{
                background: "transparent", border: "none", color: "#444",
                fontSize: 11, letterSpacing: 0.5, padding: "7px 8px",
                fontFamily: "inherit", cursor: "pointer",
              }}
            >
              Skip
            </button>
          </div>
        </div>
      )}

      {/* Upload button — only when file picked, not scanning, not in confirm mode */}
      {file && !uploading && stage === "idle" && !scanning && !showRangeConfirm && (
        <button
          onClick={startUpload}
          style={{
            background: "#111", border: "1px solid #404040", color: "#c0c0c0",
            borderRadius: 2, fontSize: 11, letterSpacing: 1, textTransform: "uppercase",
            padding: "8px 20px", fontFamily: "inherit", cursor: "pointer",
          }}
        >
          Upload &amp; Process
        </button>
      )}

      {(uploading || stage !== "idle") && stage !== "error" && (
        <Stepper currentStage={stage} currentStatus={status} entryCount={entryCount} logLines={logLines} />
      )}

      {error && (
        <div style={{ color: "#cc4444", fontSize: 12, marginTop: 8 }}>{error}</div>
      )}

      {stage === "saved" && status === "complete" && (
        <button
          onClick={() => { setFile(null); setStage("idle"); setStatus("idle"); setShowRangeConfirm(false); setLogLines([]); setAppliedTimeFrom(undefined); setAppliedTimeTo(undefined); }}
          style={{
            marginTop: 12, background: "transparent", border: "1px solid #333",
            color: "#555", fontSize: 10, letterSpacing: 1, padding: "6px 12px",
            borderRadius: 2, cursor: "pointer", fontFamily: "inherit",
          }}
        >
          UPLOAD ANOTHER
        </button>
      )}
    </div>
  );
}
