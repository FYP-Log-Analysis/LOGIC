"use client";

import { useState } from "react";

export type TimeRange = {
  startTs?: string;
  endTs?: string;
  preset?: "1h" | "24h" | "7d" | "custom";
};

export interface TimeRangePickerProps {
  onRangeChange: (range: TimeRange) => void;
  initialRange?: TimeRange;
  disabled?: boolean;
}

type TimePreset = NonNullable<TimeRange["preset"]>;
const PRESETS: TimePreset[] = ["1h", "24h", "7d", "custom"];

export function TimeRangePicker({ onRangeChange, initialRange, disabled }: TimeRangePickerProps) {
  const [preset, setPreset] = useState<TimePreset>(initialRange?.preset ?? "24h");
  const [startTs, setStartTs] = useState(initialRange?.startTs || "");
  const [endTs, setEndTs] = useState(initialRange?.endTs || "");
  const [showCustom, setShowCustom] = useState(initialRange?.preset === "custom");

  const getTimeRangeFromPreset = (p: TimePreset): [string, string] => {
    const now = new Date();
    const end = now.toISOString();

    if (p === "1h") {
      const start = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
      return [start, end];
    } else if (p === "24h") {
      const start = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
      return [start, end];
    } else if (p === "7d") {
      const start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
      return [start, end];
    }
    return ["", ""];
  };

  const handlePresetClick = (p: TimePreset) => {
    setPreset(p);
    setShowCustom(false);

    if (p === "custom") {
      setShowCustom(true);
      return;
    }

    const [start, end] = getTimeRangeFromPreset(p);
    setStartTs(start);
    setEndTs(end);
    onRangeChange({ startTs: start, endTs: end, preset: p });
  };

  const handleCustomApply = () => {
    if (startTs && endTs) {
      onRangeChange({ startTs, endTs, preset: "custom" });
    }
  };

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        padding: "8px 12px",
        background: "#0d0d0d",
        border: "1px solid #222",
        borderRadius: "4px",
        fontSize: "12px",
      }}
    >
      <span style={{ color: "#666", textTransform: "uppercase", letterSpacing: "0.5px" }}>
        Time Range:
      </span>

      {PRESETS.map((p) => (
        <button
          key={p}
          onClick={() => handlePresetClick(p)}
          disabled={disabled}
          style={{
            padding: "4px 10px",
            background: preset === p ? "#1a3d2a" : "#1a1a1a",
            border: `1px solid ${preset === p ? "#4a7c59" : "#333"}`,
            color: preset === p ? "#7cb342" : "#888",
            borderRadius: "2px",
            cursor: disabled ? "default" : "pointer",
            fontSize: "10px",
            fontWeight: preset === p ? "bold" : "normal",
            transition: "all 0.15s",
            textTransform: "uppercase",
            letterSpacing: "0.5px",
            opacity: disabled ? 0.5 : 1,
          }}
          onMouseEnter={(e) => {
            if (!disabled && preset !== p) {
              (e.currentTarget as HTMLButtonElement).style.borderColor = "#444";
            }
          }}
          onMouseLeave={(e) => {
            if (!disabled && preset !== p) {
              (e.currentTarget as HTMLButtonElement).style.borderColor = "#333";
            }
          }}
        >
          {p === "1h" ? "1H" : p === "24h" ? "24H" : p === "7d" ? "7D" : "Custom"}
        </button>
      ))}

      {showCustom && (
        <div style={{ display: "flex", gap: "6px", alignItems: "center", marginLeft: "8px" }}>
          <input
            type="datetime-local"
            value={startTs.slice(0, 16)}
            onChange={(e) => {
              const dt = new Date(e.target.value).toISOString();
              setStartTs(dt);
            }}
            disabled={disabled}
            style={{
              padding: "4px 6px",
              fontSize: "10px",
              background: "#1a1a1a",
              border: "1px solid #333",
              color: "#aaa",
              borderRadius: "2px",
              cursor: disabled ? "default" : "pointer",
              opacity: disabled ? 0.5 : 1,
            }}
          />
          <span style={{ color: "#555" }}>→</span>
          <input
            type="datetime-local"
            value={endTs.slice(0, 16)}
            onChange={(e) => {
              const dt = new Date(e.target.value).toISOString();
              setEndTs(dt);
            }}
            disabled={disabled}
            style={{
              padding: "4px 6px",
              fontSize: "10px",
              background: "#1a1a1a",
              border: "1px solid #333",
              color: "#aaa",
              borderRadius: "2px",
              cursor: disabled ? "default" : "pointer",
              opacity: disabled ? 0.5 : 1,
            }}
          />
          <button
            onClick={handleCustomApply}
            disabled={disabled || !startTs || !endTs}
            style={{
              padding: "4px 10px",
              background: "#1a3d2a",
              border: "1px solid #4a7c59",
              color: "#7cb342",
              borderRadius: "2px",
              cursor: disabled || !startTs || !endTs ? "default" : "pointer",
              fontSize: "10px",
              fontWeight: "bold",
              transition: "all 0.15s",
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              opacity: disabled || !startTs || !endTs ? 0.5 : 1,
            }}
          >
            Apply
          </button>
        </div>
      )}
    </div>
  );
}
