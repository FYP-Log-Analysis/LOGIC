"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Sidebar from "@/components/sidebar";
import { getLogTimeRange } from "@/lib/client";
import HawkinsChat from "@/components/hawkins-chat";

// ── Time-range change modal (inline in layout) ─────────────────────────────

function TimeRangeModal({
  projectId,
  onConfirm,
  onCancel,
}: {
  projectId: string;
  onConfirm: (from: string, to: string) => void;
  onCancel: () => void;
}) {
  const { timeRange } = useAuthStore();
  const [loading, setLoading] = useState(true);
  const [from, setFrom] = useState(timeRange?.from ? timeRange.from.slice(0, 16) : "");
  const [to, setTo] = useState(timeRange?.to ? timeRange.to.slice(0, 16) : "");
  const [minTs, setMinTs] = useState("");
  const [maxTs, setMaxTs] = useState("");

  useEffect(() => {
    getLogTimeRange(projectId)
      .then((d) => {
        setMinTs(d.min_timestamp ?? "");
        setMaxTs(d.max_timestamp ?? "");
        if (!from && d.min_timestamp) setFrom(d.min_timestamp.slice(0, 16));
        if (!to && d.max_timestamp) setTo(d.max_timestamp.slice(0, 16));
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  const overlayStyle: React.CSSProperties = {
    position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)",
    display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000,
  };
  const boxStyle: React.CSSProperties = {
    background: "#0d0d0d", border: "1px solid #2a2a2a", borderRadius: 6,
    padding: 28, width: 420, maxWidth: "92vw",
  };

  return (
    <div style={overlayStyle} onClick={onCancel}>
      <div style={boxStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 14 }}>
          Change Time Range
        </div>
        {loading ? (
          <div style={{ textAlign: "center", padding: 24, color: "#555", fontSize: 12 }}>Loading…</div>
        ) : (
          <>
            {minTs && (
              <div style={{ fontSize: 11, color: "#444", marginBottom: 12 }}>
                Available: {new Date(minTs).toLocaleString()} → {new Date(maxTs).toLocaleString()}
              </div>
            )}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 11, color: "#555", marginBottom: 4 }}>FROM</div>
                <input
                  type="datetime-local"
                  value={from}
                  onChange={(e) => setFrom(e.target.value)}
                  style={{
                    background: "#111", border: "1px solid #2a2a2a", color: "#c0c0c0",
                    padding: "6px 8px", fontSize: 12, borderRadius: 3, width: "100%",
                    colorScheme: "dark",
                  }}
                />
              </div>
              <div>
                <div style={{ fontSize: 11, color: "#555", marginBottom: 4 }}>TO</div>
                <input
                  type="datetime-local"
                  value={to}
                  onChange={(e) => setTo(e.target.value)}
                  style={{
                    background: "#111", border: "1px solid #2a2a2a", color: "#c0c0c0",
                    padding: "6px 8px", fontSize: 12, borderRadius: 3, width: "100%",
                    colorScheme: "dark",
                  }}
                />
              </div>
            </div>
            {minTs && (
              <button
                onClick={() => { setFrom(minTs.slice(0, 16)); setTo(maxTs.slice(0, 16)); }}
                style={{
                  background: "none", border: "1px solid #2a2a2a", color: "#666",
                  padding: "4px 10px", fontSize: 11, borderRadius: 3, cursor: "pointer",
                  marginBottom: 16, letterSpacing: 1,
                }}
              >
                USE FULL RANGE
              </button>
            )}
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                onClick={onCancel}
                style={{
                  background: "none", border: "1px solid #2a2a2a", color: "#666",
                  padding: "5px 14px", fontSize: 11, borderRadius: 3, cursor: "pointer", letterSpacing: 1,
                }}
              >
                CANCEL
              </button>
              <button
                onClick={() => from && to && onConfirm(from, to)}
                disabled={!from || !to}
                style={{
                  background: from && to ? "#1a3a1a" : "#1a1a1a",
                  border: `1px solid ${from && to ? "#2a5a2a" : "#2a2a2a"}`,
                  color: from && to ? "#e0e0e0" : "#444",
                  padding: "5px 14px", fontSize: 11, borderRadius: 3,
                  cursor: from && to ? "pointer" : "not-allowed", letterSpacing: 1,
                }}
              >
                APPLY
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Time filter bar ────────────────────────────────────────────────────────────

function TimeFilterBar() {
  const { activeProject, timeRange, setActiveProject, setTimeRange } = useAuthStore();
  const [showModal, setShowModal] = useState(false);

  if (!activeProject) return null;

  const fmt = (iso: string) => {
    try { return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" }); }
    catch { return iso; }
  };

  const handleConfirm = (from: string, to: string) => {
    setTimeRange({ from: new Date(from).toISOString(), to: new Date(to).toISOString() });
    setShowModal(false);
  };

  return (
    <>
      {showModal && (
        <TimeRangeModal
          projectId={activeProject.id}
          onConfirm={handleConfirm}
          onCancel={() => setShowModal(false)}
        />
      )}
      <div style={{
        background: "#0a140a", borderBottom: "1px solid #1a3a1a",
        padding: "6px 20px", display: "flex", alignItems: "center", gap: 12,
        fontSize: 11, color: "#4caf50", letterSpacing: 0.5, flexShrink: 0,
      }}>
        <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#4caf50", flexShrink: 0 }} />
        <span style={{ color: "#c0c0c0" }}>{activeProject.name}</span>
        {timeRange && (
          <>
            <span style={{ color: "#333" }}>|</span>
            <span style={{ color: "#777" }}>{fmt(timeRange.from)} → {fmt(timeRange.to)}</span>
          </>
        )}
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <button
            onClick={() => setShowModal(true)}
            style={{
              background: "none", border: "1px solid #2a2a2a", color: "#666",
              padding: "2px 10px", fontSize: 10, borderRadius: 2, cursor: "pointer", letterSpacing: 1,
            }}
          >
            CHANGE RANGE
          </button>
          <button
            onClick={() => { setActiveProject(null); setTimeRange(null); }}
            style={{
              background: "none", border: "1px solid #2a2a2a", color: "#555",
              padding: "2px 10px", fontSize: 10, borderRadius: 2, cursor: "pointer", letterSpacing: 1,
            }}
          >
            CLEAR
          </button>
        </div>
      </div>
    </>
  );
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const {
    user,
    setUser,
    hydrated,
    setHydrated,
    activeProject,
    timeRange,
    assistantFocus,
    clearAssistantFocus,
  } = useAuthStore();
  const router = useRouter();
  const pathname = usePathname();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  useEffect(() => {
    if (hydrated) return;
    useAuthStore.persist.rehydrate();
    if (useAuthStore.persist.hasHydrated()) {
      setHydrated(true);
    }
  }, [hydrated, setHydrated]);

  useEffect(() => {
    if (!hydrated) return;
    // Hydrate auth store from the cookie-backed /api/auth/me endpoint
    if (!user) {
      fetch("/api/auth/me")
        .then((r) => {
          if (!r.ok) throw new Error("Not authenticated");
          return r.json();
        })
        .then((me) =>
          setUser({
            username: me.username,
            role: me.role,
            userId: me.user_id,
            email: me.email,
          }),
        )
        .catch(() => router.push("/login"));
    }
  }, [hydrated, user, setUser, router]);

  useEffect(() => {
    clearAssistantFocus();
  }, [pathname, clearAssistantFocus]);

  if (!hydrated || !user) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100vh",
          background: "#080808",
          color: "#555",
          fontFamily: "var(--font-mono-stack)",
          fontSize: 12,
          letterSpacing: 2,
        }}
      >
        LOADING…
      </div>
    );
  }

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden", position: "relative" }}>
      {sidebarOpen && <Sidebar onHide={() => setSidebarOpen(false)} />}
      {!sidebarOpen && (
        <button
          type="button"
          onClick={() => setSidebarOpen(true)}
          aria-label="Open sidebar"
          style={{
            position: "absolute",
            top: 12,
            left: 12,
            zIndex: 20,
            border: "1px solid #2a2a2a",
            background: "#111",
            color: "#c0c0c0",
            borderRadius: 2,
            padding: "6px 10px",
            fontSize: 10,
            letterSpacing: 1,
            textTransform: "uppercase",
            cursor: "pointer",
            fontFamily: "inherit",
          }}
          onMouseEnter={(e) => {
            (e.target as HTMLButtonElement).style.borderColor = "#4a4a4a";
            (e.target as HTMLButtonElement).style.color = "#fff";
          }}
          onMouseLeave={(e) => {
            (e.target as HTMLButtonElement).style.borderColor = "#2a2a2a";
            (e.target as HTMLButtonElement).style.color = "#c0c0c0";
          }}
        >
          Open
        </button>
      )}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <TimeFilterBar />
        <main
          style={{
            flex: 1,
            overflowY: "auto",
            background: "#080808",
            padding: "44px 56px",
          }}
        >
          {children}
        </main>
      </div>

      <HawkinsChat
        title="Hawkins — Assistant"
        description="Workspace-wide SOC copilot for this dashboard"
        dataSummary={{
          page: pathname,
          project_id: activeProject?.id ?? null,
          project_name: activeProject?.name ?? null,
          project_type: activeProject?.project_type ?? null,
          time_range: timeRange ?? null,
        }}
        componentKey={`global${pathname || "/dashboard"}`}
        helpGuide="Ask about the current page, detections, anomalies, timelines, or next investigation actions."
        selectedContext={assistantFocus}
      />
    </div>
  );
}


