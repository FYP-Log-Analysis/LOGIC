"use client";

import type { ReactNode } from "react";
import { useEffect } from "react";

interface EventDetailModalProps {
  title: string;
  subtitle?: string;
  payload: unknown;
  onClose: () => void;
  actions?: ReactNode;
  children?: ReactNode;
}

export function EventDetailModal({ title, subtitle, payload, onClose, actions, children }: EventDetailModalProps) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.75)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: 18,
      }}
    >
      <div
        onClick={(event) => event.stopPropagation()}
        style={{
          width: "min(900px, 96vw)",
          maxHeight: "88vh",
          overflow: "hidden",
          background: "#0d0d0d",
          border: "1px solid #2a2a2a",
          borderRadius: 6,
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            gap: 12,
            borderBottom: "1px solid #1f1f1f",
            padding: "14px 16px",
          }}
        >
          <div style={{ minWidth: 0 }}>
            <div style={{ color: "#d7d7d7", fontSize: 13, fontWeight: 600 }}>{title}</div>
            {subtitle && (
              <div style={{ color: "#777", fontSize: 11, marginTop: 4, lineHeight: 1.4 }}>{subtitle}</div>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              border: "1px solid #2a2a2a",
              color: "#aaa",
              background: "#111",
              borderRadius: 3,
              padding: "5px 10px",
              fontSize: 10,
              letterSpacing: 0.8,
              textTransform: "uppercase",
              cursor: "pointer",
            }}
          >
            Close
          </button>
        </div>

        {actions && (
          <div
            style={{
              borderBottom: "1px solid #1f1f1f",
              padding: "10px 16px",
              display: "flex",
              alignItems: "center",
              gap: 10,
              justifyContent: "space-between",
            }}
          >
            {actions}
          </div>
        )}

        <div style={{ overflow: "auto", padding: 16 }}>
          <div
            style={{
              background: "#090909",
              border: "1px solid #1a1a1a",
              borderRadius: 4,
              padding: 12,
            }}
          >
            <pre
              style={{
                margin: 0,
                color: "#d0d0d0",
                fontSize: 11,
                lineHeight: 1.5,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
              }}
            >
              {JSON.stringify(payload, null, 2)}
            </pre>
          </div>

          {children && (
            <div
              style={{
                marginTop: 12,
                background: "#090909",
                border: "1px solid #1a1a1a",
                borderRadius: 4,
                padding: 12,
              }}
            >
              {children}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
