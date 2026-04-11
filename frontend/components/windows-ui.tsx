/**
 * Windows-Themed UI Components
 * Consistent components for Windows log analysis pages
 */

import React from "react";

interface MetricCardProps {
  label: string;
  value: string | number;
  sublabel?: string;
  accent?: string;
}

export function WindowsMetricCard({ label, value, sublabel, accent = "#7cb342" }: MetricCardProps) {
  return (
    <div style={{
      padding: 14,
      background: "#111",
      border: "1px solid #262626",
      borderRadius: 6,
      borderLeft: `3px solid ${accent}`,
      transition: "all 0.2s ease",
    }}>
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        marginBottom: 10,
      }}>
        <span style={{
          color: "var(--theme-muted-blue)",
          fontSize: 11,
          textTransform: "uppercase",
          letterSpacing: 0.8,
          fontWeight: 500,
        }}>{label}</span>
      </div>
      <div style={{
        fontSize: 22,
        fontWeight: 600,
        letterSpacing: -0.5,
        lineHeight: 1,
      }}>
        {value}
      </div>
      {sublabel && <div style={{
        marginTop: 6,
        fontSize: 10,
        color: "#5e7180",
        letterSpacing: 0.3,
      }}>{sublabel}</div>}
    </div>
  );
}

interface SectionHeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}

export function WindowsSectionHeader({ title, subtitle, actions }: SectionHeaderProps) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      gap: 20,
      marginBottom: 24,
    }}>
      <div>
        <h1 style={{
          margin: 0,
          fontSize: 22,
          fontWeight: 500,
          letterSpacing: 0.4,
        }}>
          {title}
        </h1>
        {subtitle && <p style={{
          margin: "8px 0 0",
          color: "var(--theme-muted-blue)",
          fontSize: 12,
          lineHeight: 1.5,
          letterSpacing: 0.2,
        }}>{subtitle}</p>}
      </div>
      {actions && <div style={{
        display: "flex",
        gap: 12,
        alignItems: "center",
      }}>{actions}</div>}
    </div>
  );
}

interface DataPanelProps {
  title?: string;
  children: React.ReactNode;
  className?: string;
  accent?: string;
  actions?: React.ReactNode;
}

export function WindowsDataPanel({ title, children, className = "", accent, actions }: DataPanelProps) {
  return (
    <div style={{
      background: "#0d0d0d",
      border: "1px solid #1e1e1e",
      borderTop: accent ? `2px solid ${accent}` : "1px solid #1e1e1e",
      borderRadius: 6,
      padding: 14,
      transition: "border-color 0.2s ease",
    }} className={className}>
      {title && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            margin: "0 0 16px",
          }}
        >
          <h3 style={{
            margin: 0,
            fontSize: 12,
            fontWeight: "bold",
            textTransform: "uppercase",
            letterSpacing: 0.8,
          }}>
            {title}
          </h3>
          {actions && <div>{actions}</div>}
        </div>
      )}
      <div style={{
        display: "flex",
        flexDirection: "column",
        gap: 12,
      }}>
        {children}
      </div>
    </div>
  );
}

interface FilterControlsProps {
  children: React.ReactNode;
}

export function WindowsFilterControls({ children }: FilterControlsProps) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 10,
      flexWrap: "wrap",
      padding: 10,
      background: "var(--card-bg)",
      border: "1px solid var(--border)",
      borderRadius: 6,
      marginBottom: 16,
    }}>
      {children}
    </div>
  );
}

interface FilterInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
}

export function FilterInput({ label, ...props }: FilterInputProps) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
    }}>
      <label style={{
        color: "var(--muted-text)",
        fontSize: 10,
        letterSpacing: 0.2,
        fontWeight: 500,
        whiteSpace: "nowrap",
      }}>{label}</label>
      <input style={{
        background: "var(--input-bg)",
        border: "1px solid var(--input-border)",
        color: "var(--foreground)",
        padding: "5px 8px",
        borderRadius: 4,
        fontSize: 12,
        fontFamily: "inherit",
        transition: "all 0.2s ease",
      }} {...props} />
    </div>
  );
}

interface FilterSelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label: string;
  options: Array<{ value: string; label: string }>;
}

export function FilterSelect({ label, options, ...props }: FilterSelectProps) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
    }}>
      <label style={{
        color: "var(--muted-text)",
        fontSize: 10,
        letterSpacing: 0.2,
        fontWeight: 500,
        whiteSpace: "nowrap",
      }}>{label}</label>
      <select style={{
        background: "var(--input-bg)",
        border: "1px solid var(--input-border)",
        color: "var(--foreground)",
        padding: "5px 8px",
        borderRadius: 4,
        fontSize: 12,
        fontFamily: "inherit",
        transition: "all 0.2s ease",
      }} {...props}>
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
}

interface WindowsButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger";
  loading?: boolean;
}

export function WindowsButton({ 
  children, 
  variant = "primary", 
  loading = false, 
  disabled,
  ...props 
}: WindowsButtonProps) {
  const variantStyles = {
    primary: { background: "var(--theme-green-bg)", color: "var(--theme-green)", border: "1px solid var(--theme-green-border)" },
    secondary: { background: "var(--theme-blue-bg)", color: "var(--theme-blue)", border: "1px solid var(--theme-blue-border)" },
    danger: { background: "#ff4444", color: "#000" },
  };

  return (
    <button
      style={{
        ...variantStyles[variant],
        padding: "7px 12px",
        border: variantStyles[variant].border ?? "none",
        borderRadius: 4,
        fontSize: 12,
        fontWeight: 600,
        letterSpacing: 0.2,
        cursor: disabled || loading ? "not-allowed" : "pointer",
        transition: "all 0.2s ease",
        opacity: disabled || loading ? 0.6 : 1,
      }}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? <span style={{ fontSize: 10, letterSpacing: 0.6 }}>LOADING...</span> : children}
    </button>
  );
}

type TableSortDirection = "asc" | "desc";

interface EventTableColumn {
  key: string;
  label: string;
  width?: string;
  sortable?: boolean;
  render?: (row: Record<string, unknown>, rowIndex: number) => React.ReactNode;
}

interface EventTableProps {
  columns: EventTableColumn[];
  data: Array<Record<string, unknown>>;
  onRowClick?: (row: Record<string, unknown>, index: number) => void;
  selectedRowIndex?: number;
  selectedRowKey?: string;
  rowKey?: (row: Record<string, unknown>, index: number) => string;
  emptyMessage?: string;
  maxHeight?: number;
  stickyHeader?: boolean;
  density?: "comfortable" | "compact";
  sortKey?: string;
  sortDirection?: TableSortDirection;
  onSortChange?: (key: string, direction: TableSortDirection) => void;
}

export function WindowsEventTable({
  columns,
  data,
  onRowClick,
  selectedRowIndex,
  selectedRowKey,
  rowKey,
  emptyMessage = "No events found",
  maxHeight,
  stickyHeader = true,
  density = "comfortable",
  sortKey,
  sortDirection,
  onSortChange,
}: EventTableProps) {
  const cellPadding = density === "compact" ? "5px 8px" : "10px 12px";

  const resolveRowKey = (row: Record<string, unknown>, idx: number): string => {
    if (rowKey) return rowKey(row, idx);
    const explicitKey = row.id;
    if (typeof explicitKey === "string" || typeof explicitKey === "number") {
      return String(explicitKey);
    }
    return String(idx);
  };

  const handleSortClick = (col: EventTableColumn) => {
    if (!col.sortable || !onSortChange) return;
    const isSameKey = sortKey === col.key;
    const nextDirection: TableSortDirection = isSameKey && sortDirection === "asc" ? "desc" : "asc";
    onSortChange(col.key, nextDirection);
  };

  if (data.length === 0) {
    return (
      <div style={{
        textAlign: "center",
        padding: 40,
        color: "#666",
      }}>
        <div style={{ fontSize: 12 }}>{emptyMessage}</div>
      </div>
    );
  }

  return (
    <div style={{ overflowX: "auto", maxHeight: maxHeight ? `${maxHeight}px` : undefined, overflowY: maxHeight ? "auto" : undefined }}>
      <table style={{
        width: "100%",
        borderCollapse: "collapse",
        fontSize: 12,
      }}>
        <thead>
          <tr style={{
            borderBottom: "1px solid #2a2a2a",
            background: "#0a0a0a",
          }}>
            {columns.map((col) => (
              <th key={col.key} style={{
                width: col.width,
                padding: cellPadding,
                textAlign: "left",
                fontSize: 10,
                fontWeight: "bold",
                color: "#777",
                textTransform: "uppercase",
                letterSpacing: 0.8,
                position: stickyHeader ? "sticky" : "static",
                top: stickyHeader ? 0 : undefined,
                zIndex: stickyHeader ? 2 : undefined,
                background: "#0a0a0a",
              }}>
                <button
                  type="button"
                  onClick={() => handleSortClick(col)}
                  disabled={!col.sortable || !onSortChange}
                  style={{
                    border: "none",
                    background: "transparent",
                    color: "inherit",
                    cursor: col.sortable && onSortChange ? "pointer" : "default",
                    padding: 0,
                    margin: 0,
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    font: "inherit",
                    letterSpacing: "inherit",
                    textTransform: "inherit",
                  }}
                >
                  <span>{col.label}</span>
                  {col.sortable && (
                    <span style={{ color: sortKey === col.key ? "#9ed26f" : "#4f4f4f", fontSize: 9 }}>
                      {sortKey === col.key ? (sortDirection === "asc" ? "▲" : "▼") : "↕"}
                    </span>
                  )}
                </button>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, idx) => {
            const resolvedKey = resolveRowKey(row, idx);
            const isSelected = selectedRowKey != null ? selectedRowKey === resolvedKey : selectedRowIndex === idx;
            const defaultRowBg = isSelected ? "#1f2a16" : idx % 2 === 0 ? "#111" : "#0d0d0d";

            return (
              <tr
                key={resolvedKey}
                onClick={() => onRowClick?.(row, idx)}
                style={{
                  borderBottom: "1px solid #1a1a1a",
                  background: defaultRowBg,
                  cursor: onRowClick ? "pointer" : "default",
                  transition: "background 0.2s ease",
                }}
                onMouseEnter={(e) => {
                  if (onRowClick && !isSelected) e.currentTarget.style.background = "#171717";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = defaultRowBg;
                }}
              >
                {columns.map((col) => (
                  <td key={col.key} style={{
                    padding: cellPadding,
                    color: "#c0c0c0",
                    verticalAlign: "top",
                  }}>
                    {col.render ? col.render(row, idx) : (row[col.key] as React.ReactNode) ?? "—"}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

interface SeverityBadgeProps {
  severity: "critical" | "high" | "medium" | "low";
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const colors = {
    critical: "#ff4444",
    high: "#ff8800",
    medium: "#f0c040",
    low: "#4488ff",
  };

  return (
    <span style={{
      display: "inline-block",
      padding: "4px 8px",
      borderRadius: 3,
      fontSize: 9,
      fontWeight: "bold",
      letterSpacing: 0.8,
      textTransform: "uppercase",
      background: colors[severity],
      color: "#000",
    }}>
      {severity.toUpperCase()}
    </span>
  );
}

interface LoadingSkeletonProps {
  count?: number;
  height?: number;
}

export function WindowsLoadingSkeleton({ count = 3, height = 60 }: LoadingSkeletonProps) {
  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      gap: 12,
    }}>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          style={{
            height: `${height}px`,
            background: "linear-gradient(90deg, #111 25%, #1a1a1a 50%, #111 75%)",
            backgroundSize: "200% 100%",
            animation: "skeleton-loading 1.5s infinite",
            borderRadius: 6,
          }}
        />
      ))}
    </div>
  );
}

interface EmptyStateProps {
  title: string;
  message?: string;
  action?: React.ReactNode;
  icon?: string;
}

export function WindowsEmptyState({ title, message, action, icon }: EmptyStateProps) {
  return (
    <div style={{
      textAlign: "center",
      padding: "60px 24px",
      color: "#666",
    }}>
      {icon && <div style={{
        fontSize: 48,
        marginBottom: 16,
      }}>{icon}</div>}
      <h3 style={{
        margin: "0 0 12px",
        fontSize: 16,
        fontWeight: 500,
        color: "#999",
      }}>{title}</h3>
      {message && <p style={{
        margin: "0 0 20px",
        fontSize: 12,
        lineHeight: 1.6,
        color: "#666",
      }}>{message}</p>}
      {action && <div style={{
        display: "flex",
        justifyContent: "center",
        gap: 12,
      }}>{action}</div>}
    </div>
  );
}

interface StatGridProps {
  children: React.ReactNode;
  columns?: number;
}

export function WindowsStatGrid({ children, columns = 3 }: StatGridProps) {
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
      gap: 16,
      marginBottom: 24,
    }}>
      {children}
    </div>
  );
}

interface MitreTagProps {
  technique: string;
  tactic?: string;
}

export function MitreTag({ technique, tactic }: MitreTagProps) {
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 4,
      padding: "3px 8px",
      background: "#1a1a2e",
      border: "1px solid #2a2a4e",
      borderRadius: 3,
      fontSize: 9,
      fontWeight: "bold",
      letterSpacing: 0.5,
      textTransform: "uppercase",
    }} title={tactic || technique}>
      <span style={{ color: "#7cb342" }}>MITRE</span>
      <span style={{ color: "#999" }}>{technique}</span>
    </span>
  );
}

interface IoCBadgeProps {
  type: "ip" | "domain" | "hash" | "file" | "user";
  value: string;
  onClick?: () => void;
}

export function IoCBadge({ type, value, onClick }: IoCBadgeProps) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        padding: "3px 8px",
        background: "#1a1a1a",
        border: "1px solid #2a2a2a",
        borderRadius: 3,
        fontSize: 10,
        cursor: onClick ? "pointer" : "default",
        transition: "all 0.2s ease",
      }}
      onClick={onClick}
      title={`${type.toUpperCase()}: ${value}`}
      onMouseEnter={(e) => {
        if (onClick) e.currentTarget.style.background = "#2a2a2a";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "#1a1a1a";
      }}
    >
      <span style={{ 
        color: "#f0c040",
        fontWeight: "bold",
        fontSize: 9,
        letterSpacing: 0.5,
        textTransform: "uppercase",
      }}>{type.toUpperCase()}</span>
      <span style={{ 
        color: "#c0c0c0",
        fontFamily: "var(--font-mono-stack)",
      }}>{value}</span>
    </span>
  );
}

export function WindowsDivider() {
  return <div style={{
    height: 1,
    background: "#1e1e1e",
    margin: "24px 0",
  }} />;
}
