/**
 * Shared UI primitives for the LOGIC dark terminal theme.
 * These are lightweight inline-style components rather than full shadcn
 * to avoid Tailwind v4 config incompatibilities.
 */

import React from "react";

// ── MetricCard ────────────────────────────────────────────────────────────────

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}

export function MetricCard({ label, value, sub, accent }: MetricCardProps) {
  return (
    <div
      style={{
        background: "#111",
        border: "1px solid #1e1e1e",
        borderRadius: 4,
        padding: "16px 20px",
      }}
    >
      <div
        style={{
          fontSize: 10,
          letterSpacing: 1.2,
          textTransform: "uppercase",
          color: "#555",
          marginBottom: 8,
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 28,
          fontWeight: 300,
          color: accent ?? "#e8e8e8",
          lineHeight: 1,
        }}
      >
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      {sub && (
        <div style={{ fontSize: 11, color: "#444", marginTop: 4 }}>{sub}</div>
      )}
    </div>
  );
}

// ── SectionHeader ─────────────────────────────────────────────────────────────

interface SectionHeaderProps {
  title: string;
  subtitle?: string;
}

export function SectionHeader({ title, subtitle }: SectionHeaderProps) {
  return (
    <div style={{ marginBottom: 24 }}>
      <h2
        style={{
          fontSize: 24,
          fontWeight: 300,
          letterSpacing: 3,
          color: "#e0e0e0",
          margin: 0,
        }}
      >
        {title}
      </h2>
      {subtitle && (
        <p
          style={{
            fontSize: 13,
            color: "#555",
            letterSpacing: 0.5,
            marginTop: 4,
            marginBottom: 0,
          }}
        >
          {subtitle}
        </p>
      )}
    </div>
  );
}

// ── Btn ───────────────────────────────────────────────────────────────────────

interface BtnProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "danger" | "ghost" | "purple";
  loading?: boolean;
}

export function Btn({
  children,
  variant = "default",
  loading,
  disabled,
  style,
  ...rest
}: BtnProps) {
  const styles: Record<string, React.CSSProperties> = {
    default: {
      background: "#111",
      border: "1px solid #404040",
      color: "#c0c0c0",
    },
    danger: {
      background: "#1a0a0a",
      border: "1px solid #8a0000",
      color: "#cc4444",
    },
    ghost: {
      background: "transparent",
      border: "1px solid #2a2a2a",
      color: "#555",
    },
    purple: {
      background: "#1a0d2e",
      border: "1px solid #6b46c1",
      color: "#a78bfa",
    },
  };

  return (
    <button
      disabled={disabled || loading}
      style={{
        ...styles[variant],
        borderRadius: 2,
        fontSize: 11,
        letterSpacing: 1,
        textTransform: "uppercase",
        padding: "8px 16px",
        fontFamily: "inherit",
        cursor: disabled || loading ? "not-allowed" : "pointer",
        opacity: disabled || loading ? 0.6 : 1,
        transition: "all 0.15s",
        ...style,
      }}
      {...rest}
    >
      {loading ? "LOADING…" : children}
    </button>
  );
}

// ── Badge ─────────────────────────────────────────────────────────────────────

interface BadgeProps {
  label?: string;
  children?: React.ReactNode;
  color?: string;
  bgColor?: string;
}

export function Badge({
  label,
  children,
  color = "#c0c0c0",
  bgColor = "#111",
}: BadgeProps) {
  return (
    <span
      style={{
        background: bgColor,
        color,
        fontSize: 9,
        letterSpacing: 1.5,
        textTransform: "uppercase",
        borderRadius: 2,
        padding: "2px 7px",
        border: `1px solid ${color}44`,
      }}
    >
      {children ?? label}
    </span>
  );
}

// ── StatusBadge ───────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<
  string,
  { bg: string; color: string; label: string }
> = {
  success: { bg: "#0a0f0a", color: "#2E8B57", label: "SUCCESS" },
  complete: { bg: "#0a0f0a", color: "#2E8B57", label: "COMPLETE" },
  failed: { bg: "#1a0a0a", color: "#cc4444", label: "FAILED" },
  error: { bg: "#1a0a0a", color: "#cc4444", label: "ERROR" },
  timeout: { bg: "#1a0a0a", color: "#cc8800", label: "TIMEOUT" },
  running: { bg: "#0a0a1a", color: "#4488ff", label: "RUNNING" },
  idle: { bg: "#111", color: "#555", label: "IDLE" },
};

export function StatusBadge({ status }: { status: string }) {
  const conf = STATUS_CONFIG[status?.toLowerCase()] ?? {
    bg: "#111",
    color: "#555",
    label: status?.toUpperCase() ?? "UNKNOWN",
  };
  return (
    <span
      style={{
        background: conf.bg,
        border: `1px solid ${conf.color}33`,
        color: conf.color,
        padding: "2px 10px",
        borderRadius: 2,
        fontSize: 10,
        letterSpacing: 1,
      }}
    >
      {conf.label}
    </span>
  );
}

// ── Divider ───────────────────────────────────────────────────────────────────

export function Divider() {
  return (
    <div
      style={{ height: 1, background: "#1a1a1a", margin: "20px 0" }}
    />
  );
}

// ── AlertBanner ───────────────────────────────────────────────────────────────

interface AlertEntry {
  severity?: string;
  rule_title?: string;
  client_ip?: string;
  method?: string;
  path?: string;
  timestamp?: string;
}

type AlertBannerProps =
  | { match: AlertEntry; type?: never; message?: never }
  | { match?: never; type: "error" | "warning" | "info" | "success"; message: string };

export function AlertBanner(props: AlertBannerProps) {
  // Generic error/warning/info banner
  if (props.message != null) {
    const colorMap = { error: "#cc4444", warning: "#cc8800", info: "#4488ff", success: "#4caf50" };
    const bgMap = { error: "#1a0a0a", warning: "#1a1000", info: "#0a0a1a", success: "#0a1a0a" };
    const t = props.type ?? "error";
    return (
      <div style={{
        background: bgMap[t], border: `1px solid ${colorMap[t]}44`,
        borderLeft: `3px solid ${colorMap[t]}`, color: "#ccc",
        padding: "10px 14px", borderRadius: 2, marginBottom: 12, fontSize: 13,
      }}>
        {props.message}
      </div>
    );
  }

  // Log-entry alert banner
  const match = props.match!;
  const sev = (match.severity ?? "").toUpperCase();
  const color = sev === "CRITICAL" ? "#cc0000" : "#cc5500";
  const bg = sev === "CRITICAL" ? "#8B000022" : "#7a330022";

  return (
    <div
      style={{
        background: bg,
        border: `1px solid ${color}44`,
        borderLeft: `3px solid ${color}`,
        color: "#ccc",
        padding: "8px 14px",
        borderRadius: 2,
        marginBottom: 4,
        fontSize: 12,
        fontFamily: "monospace",
      }}
    >
      <span style={{ color, fontSize: 10, letterSpacing: 1 }}>[{sev}]</span>
      {" "}
      {match.rule_title ?? "—"}
      <span style={{ color: "#555", marginLeft: 16 }}>IP:</span>{" "}
      {match.client_ip ?? "—"}
      <span style={{ color: "#555", marginLeft: 16 }}>
        {match.method} {match.path}
      </span>
      <span style={{ color: "#444", fontSize: 10, marginLeft: 12 }}>
        {match.timestamp}
      </span>
    </div>
  );
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

interface TabsProps {
  tabs: string[];
  active: string;
  onChange: (tab: string) => void;
}

export function Tabs({ tabs, active, onChange }: TabsProps) {
  return (
    <div
      style={{
        display: "flex",
        borderBottom: "1px solid #1a1a1a",
        marginBottom: 20,
        gap: 0,
      }}
    >
      {tabs.map((tab) => (
        <button
          key={tab}
          onClick={() => onChange(tab)}
          style={{
            background: "transparent",
            border: "none",
            borderBottom:
              active === tab ? "2px solid #808080" : "2px solid transparent",
            color: active === tab ? "#e0e0e0" : "#555",
            fontSize: 11,
            letterSpacing: 1,
            textTransform: "uppercase",
            padding: "10px 20px",
            cursor: "pointer",
            fontFamily: "inherit",
            transition: "all 0.15s",
          }}
        >
          {tab}
        </button>
      ))}
    </div>
  );
}

// ── SearchInput ───────────────────────────────────────────────────────────────

interface SearchInputProps {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}

export function SearchInput({
  value,
  onChange,
  placeholder = "Search…",
}: SearchInputProps) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      style={{
        background: "#111",
        border: "1px solid #2a2a2a",
        borderRadius: 3,
        color: "#c0c0c0",
        fontFamily: "inherit",
        fontSize: 12,
        padding: "7px 12px",
        outline: "none",
        width: "100%",
      }}
    />
  );
}

// ── SelectInput ───────────────────────────────────────────────────────────────

interface SelectOption {
  value: string;
  label: string;
}

interface SelectInputProps {
  value: string;
  options: string[] | SelectOption[];
  onChange: (v: string) => void;
  placeholder?: string;
}

export function SelectInput({
  value,
  options,
  onChange,
  placeholder = "All",
}: SelectInputProps) {
  const normalised: SelectOption[] = options.map((o) =>
    typeof o === "string" ? { value: o, label: o } : o,
  );
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={{
        background: "#111",
        border: "1px solid #2a2a2a",
        borderRadius: 3,
        color: "#c0c0c0",
        fontFamily: "inherit",
        fontSize: 12,
        padding: "7px 12px",
        outline: "none",
        cursor: "pointer",
        width: "100%",
      }}
    >
      <option value="">{placeholder}</option>
      {normalised.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

// ── DataTable ─────────────────────────────────────────────────────────────────

interface DataTableProps {
  columns: string[];
  rows: (Record<string, unknown> | (string | number)[])[];
  maxRows?: number;
}

export function DataTable({ columns, rows, maxRows = 200 }: DataTableProps) {
  const displayRows = rows.slice(0, maxRows);
  return (
    <div style={{ overflowX: "auto" }}>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: 11,
          fontFamily: "monospace",
        }}
      >
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col}
                style={{
                  textAlign: "left",
                  padding: "8px 12px",
                  borderBottom: "1px solid #1e1e1e",
                  color: "#444",
                  fontSize: 10,
                  letterSpacing: 1,
                  textTransform: "uppercase",
                  whiteSpace: "nowrap",
                }}
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {displayRows.map((row, i) => (
            <tr
              key={i}
              style={{
                borderBottom: "1px solid #111",
                background: i % 2 === 0 ? "transparent" : "#0a0a0a",
              }}
            >
              {columns.map((col) => (
                <td
                  key={col}
                  style={{
                    padding: "7px 12px",
                    color: "#c0c0c0",
                    maxWidth: 240,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {Array.isArray(row) ? String(row[columns.indexOf(col)] ?? "—") : String((row as Record<string, unknown>)[col] ?? "—")}
                </td>
              ))}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td
                colSpan={columns.length}
                style={{
                  padding: "24px 12px",
                  textAlign: "center",
                  color: "#333",
                  fontSize: 12,
                }}
              >
                No data
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {rows.length > maxRows && (
        <div
          style={{
            padding: "8px 12px",
            color: "#444",
            fontSize: 11,
            borderTop: "1px solid #111",
          }}
        >
          Showing {maxRows.toLocaleString()} of {rows.length.toLocaleString()} rows
        </div>
      )}
    </div>
  );
}

// ── TextInput ─────────────────────────────────────────────────────────────────

interface TextInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  /** Convenience: called with the string value instead of the full event */
  onValueChange?: (v: string) => void;
}

export function TextInput({ label, style, onValueChange, onChange, ...rest }: TextInputProps) {
  const handleChange: React.ChangeEventHandler<HTMLInputElement> = (e) => {
    onValueChange?.(e.target.value);
    onChange?.(e);
  };
  return (
    <div style={{ marginBottom: 12 }}>
      {label && (
        <label
          style={{
            display: "block",
            fontSize: 10,
            letterSpacing: 1.5,
            textTransform: "uppercase",
            color: "#555",
            marginBottom: 6,
          }}
        >
          {label}
        </label>
      )}
      <input
        style={{
          background: "#111",
          border: "1px solid #2a2a2a",
          borderRadius: 3,
          color: "#c0c0c0",
          fontFamily: "inherit",
          fontSize: 13,
          padding: "8px 12px",
          outline: "none",
          width: "100%",
          ...style,
        }}
        onChange={handleChange}
        {...rest}
      />
    </div>
  );
}

// ── ApiStatusLine ─────────────────────────────────────────────────────────────

export function ApiStatusLine({ healthy, up }: { healthy?: boolean | null; up?: boolean | null }) {
  const isUp = healthy ?? up;
  if (isUp === null || isUp === undefined) return null;
  return (
    <div
      style={{
        fontSize: 10,
        letterSpacing: 1,
        color: isUp ? "#2E8B57" : "#cc4444",
        marginBottom: 20,
        display: "flex",
        alignItems: "center",
        gap: 6,
      }}
    >
      <span
        style={{
          display: "inline-block",
          width: 6,
          height: 6,
          borderRadius: "50%",
          background: isUp ? "#2E8B57" : "#cc4444",
        }}
      />
      API {isUp ? "ONLINE" : "OFFLINE"}
    </div>
  );
}

// ── StatusDot ─────────────────────────────────────────────────────────────────

export function StatusDot({ active }: { active: boolean }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: 6,
        height: 6,
        borderRadius: "50%",
        background: active ? "#2E8B57" : "#cc4444",
        marginRight: 8,
        verticalAlign: "middle",
      }}
    />
  );
}

// ── Spinner ───────────────────────────────────────────────────────────────────

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: size,
        height: size,
        border: "2px solid #222",
        borderTop: "2px solid #808080",
        borderRadius: "50%",
        animation: "spin 0.7s linear infinite",
      }}
    />
  );
}
