"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import {
  adminStats,
  adminListUsers,
  adminCreateAnalyst,
  adminSetUserActive,
  adminDeleteUser,
} from "@/lib/client";
import {
  SectionHeader,
  MetricCard,
  Btn,
  Badge,
  StatusDot,
  Divider,
  TextInput,
  Spinner,
  AlertBanner,
} from "@/components/ui-primitives";

interface User {
  user_id?: number;
  id?: number;
  username: string;
  role: string;
  is_active: boolean | number;
  email?: string;
  created_at?: string;
}

interface Stats {
  total_users?: number;
  total_projects?: number;
  total_log_entries?: number;
  total_detections?: number;
  [key: string]: unknown;
}

export default function AdminPage() {
  const { user } = useAuthStore();
  const router = useRouter();

  const [stats, setStats] = useState<Stats>({});
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [working, setWorking] = useState<number | null>(null);

  // Create form
  const [showCreate, setShowCreate] = useState(false);
  const [newUser, setNewUser] = useState("");
  const [newPass, setNewPass] = useState("");
  const [createError, setCreateError] = useState("");
  const [creating, setCreating] = useState(false);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [s, u] = await Promise.all([adminStats(), adminListUsers()]);
      setStats((s as Stats) ?? {});
      const raw = u as unknown;
      setUsers(Array.isArray(raw) ? (raw as User[]) : ((raw as {users?: User[]}).users ?? []));
    } catch (e) { setError(String(e)); }
    setLoading(false);
  }, []);

  useEffect(() => {
    if (user?.role !== "admin") { router.replace("/overview"); return; }
    const timer = window.setTimeout(() => {
      void loadAll();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [user, router, loadAll]);

  const handleCreate = async () => {
    if (!newUser.trim()) { setCreateError("Username required"); return; }
    if (newPass.length < 8) { setCreateError("Password must be at least 8 characters"); return; }
    setCreating(true); setCreateError("");
    try {
      await adminCreateAnalyst(newUser.trim(), newPass);
      setNewUser(""); setNewPass(""); setShowCreate(false);
      await loadAll();
    } catch (e) { setCreateError(String(e)); }
    setCreating(false);
  };

  const handleToggleActive = async (u: User) => {
    const uid = u.user_id ?? u.id;
    if (!uid) return;
    setWorking(uid);
    try {
      await adminSetUserActive(uid, !u.is_active);
      await loadAll();
    } catch {}
    setWorking(null);
  };

  const handleDelete = async (u: User) => {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return;
    const uid = u.user_id ?? u.id;
    if (!uid) return;
    setWorking(uid);
    try {
      await adminDeleteUser(uid);
      await loadAll();
    } catch {}
    setWorking(null);
  };

  if (user?.role !== "admin") return null;

  return (
    <div>
      <SectionHeader title="Admin" subtitle="User management and system statistics" />

      {error && <AlertBanner type="error" message={error} />}

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 24 }}>
        <MetricCard label="Total Users" value={(stats.total_users ?? 0).toString()} />
        <MetricCard label="Total Projects" value={(stats.total_projects ?? 0).toString()} />
        <MetricCard label="Log Entries" value={(stats.total_log_entries ?? 0).toLocaleString()} />
        <MetricCard label="Detections" value={(stats.total_detections ?? 0).toLocaleString()} accent="#ff8800" />
      </div>

      <Divider />

      {/* Create analyst */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase" }}>
          {users.length} User{users.length !== 1 ? "s" : ""}
        </div>
        <Btn variant="purple" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? "CANCEL" : "CREATE ANALYST"}
        </Btn>
      </div>

      {showCreate && (
        <div style={{ background: "#0d0d0d", border: "1px solid #2a1a3a", borderRadius: 4, padding: 16, marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: "#6b46c1", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>
            New Analyst Account
          </div>
          <TextInput label="Username *" value={newUser} onValueChange={setNewUser} placeholder="analyst_username" />
          <TextInput label="Password * (min 8 chars)" value={newPass} onValueChange={setNewPass} placeholder="••••••••" type="password" />
          {createError && <div style={{ color: "#cc4444", fontSize: 12, marginBottom: 8 }}>{createError}</div>}
          <Btn variant="purple" onClick={handleCreate} disabled={creating}>
            {creating ? <Spinner size={12} /> : "CREATE"}
          </Btn>
        </div>
      )}

      {/* User list */}
      {loading ? (
        <div style={{ textAlign: "center", padding: 40 }}><Spinner size={24} /></div>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
              {["Status", "Username", "Role", "Created", "Actions"].map((h) => (
                <th key={h} style={{ textAlign: "left", color: "#444", padding: "6px 10px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
              {users.map((u) => {
              const uid = u.user_id ?? u.id;
              const isMe = u.username === user?.username;
              const roleColor = u.role === "admin" ? "#6b46c1" : "#1d4ed8";
              return (
                <tr key={uid ?? u.username} style={{ borderBottom: "1px solid #111", opacity: working === uid ? 0.5 : 1 }}>
                  <td style={{ padding: "8px 10px" }}>
                    <StatusDot active={Boolean(u.is_active)} />
                  </td>
                  <td style={{ padding: "8px 10px", color: "#c0c0c0" }}>
                    {u.username}
                    {isMe && <span style={{ color: "#444", fontSize: 10, marginLeft: 6 }}>(you)</span>}
                  </td>
                  <td style={{ padding: "8px 10px" }}>
                    <Badge color={roleColor}>{u.role.toUpperCase()}</Badge>
                  </td>
                  <td style={{ padding: "8px 10px", color: "#444" }}>
                    {u.created_at ? new Date(u.created_at).toLocaleDateString() : "—"}
                  </td>
                  <td style={{ padding: "8px 10px" }}>
                    {!isMe && (
                      <div style={{ display: "flex", gap: 6 }}>
                        <Btn
                          variant="ghost"
                          onClick={() => handleToggleActive(u)}
                          disabled={working === u.user_id}
                        >
                          {u.is_active ? "DEACTIVATE" : "ACTIVATE"}
                        </Btn>
                        <Btn
                          variant="danger"
                          onClick={() => handleDelete(u)}
                          disabled={working === u.user_id}
                        >
                          DELETE
                        </Btn>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
