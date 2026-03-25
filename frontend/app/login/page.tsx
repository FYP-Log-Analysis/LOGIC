"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";

type LoginMode = null | "admin" | "analyst";

function CredentialForm({ role, onBack }: { role: "admin" | "analyst"; onBack: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const { setUser, setProjectSelectPending } = useAuthStore();

  const isAdmin = role === "admin";
  const accent = isAdmin ? "#6b46c1" : "#1d4ed8";
  const hintPw = isAdmin ? "admin123" : "analyst123";
  const hintUser = role;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) { setError("Enter username and password."); return; }
    setError("");
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error ?? "Login failed."); return; }

      const userRole = (data.role ?? "analyst").toLowerCase() as "admin" | "analyst" | "user";
      setUser({ username: data.username, role: userRole, userId: data.user_id, email: data.email ?? "" });
      if (userRole !== "admin") setProjectSelectPending(true);
      router.push(userRole === "admin" ? "/admin" : "/overview");
    } catch {
      setError("Could not contact server.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} style={{ width: "100%" }}>
      <div style={{ textAlign: "center", marginBottom: 20 }}>
        <span style={{
          background: accent, color: "#fff", fontSize: 9, letterSpacing: 3,
          textTransform: "uppercase", borderRadius: 2, padding: "3px 12px",
        }}>
          {isAdmin ? "ADMIN" : "ANALYST"} ACCESS
        </span>
      </div>
      <div style={{ fontSize: 10, letterSpacing: 2, color: "#555", textTransform: "uppercase", marginBottom: 14 }}>
        CREDENTIALS
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={{ display: "block", fontSize: 10, letterSpacing: 1, color: "#555", marginBottom: 5, textTransform: "uppercase" }}>Username</label>
        <input
          value={username}
          onChange={e => setUsername(e.target.value)}
          placeholder={hintUser}
          autoComplete="username"
          style={inputStyle}
        />
      </div>
      <div style={{ marginBottom: 20 }}>
        <label style={{ display: "block", fontSize: 10, letterSpacing: 1, color: "#555", marginBottom: 5, textTransform: "uppercase" }}>Password</label>
        <input
          value={password}
          onChange={e => setPassword(e.target.value)}
          type="password"
          placeholder="••••••••"
          autoComplete="current-password"
          style={inputStyle}
        />
      </div>

      {error && <div style={{ color: "#cc4444", fontSize: 12, marginBottom: 12 }}>{error}</div>}

      <button type="submit" disabled={loading} style={btnStyle(accent)}>
        {loading ? "AUTHENTICATING…" : "SIGN IN"}
      </button>

      <div style={{ marginTop: 12, fontSize: 11, color: "#333" }}>
        Demo: <code style={{ color: "#555" }}>{hintUser}</code> / <code style={{ color: "#555" }}>{hintPw}</code>
      </div>

      <br />
      <button type="button" onClick={onBack} style={{ ...btnStyle("#222"), background: "transparent", border: "1px solid #222", color: "#444" }}>
        Back
      </button>
    </form>
  );
}

const inputStyle: React.CSSProperties = {
  width: "100%",
  background: "#111",
  border: "1px solid #2a2a2a",
  borderRadius: 3,
  color: "#c0c0c0",
  fontFamily: "'SF Mono','Fira Code','Consolas',monospace",
  fontSize: 13,
  padding: "8px 12px",
  outline: "none",
  boxSizing: "border-box",
};

const btnStyle = (accent: string): React.CSSProperties => ({
  width: "100%",
  background: accent + "22",
  border: `1px solid ${accent}`,
  color: "#c0c0c0",
  borderRadius: 2,
  fontSize: 11,
  letterSpacing: 1,
  textTransform: "uppercase",
  padding: "10px 16px",
  fontFamily: "inherit",
  cursor: "pointer",
});

export default function LoginPage() {
  const [mode, setMode] = useState<LoginMode>(null);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", background: "#080808" }}>
      {/* Header */}
      <div style={{ textAlign: "center", marginBottom: 48 }}>
        <div style={{ fontSize: 28, letterSpacing: 8, color: "#e0e0e0", fontWeight: 200, fontFamily: "monospace" }}>LOGIC</div>
        <div style={{ fontSize: 10, letterSpacing: 4, color: "#333", marginTop: 6, textTransform: "uppercase" }}>
          Web Agent · Security Analysis
        </div>
      </div>

      <div style={{
        width: "100%", maxWidth: 400,
        background: "#0d0d0d", border: "1px solid #1e1e1e",
        borderRadius: 6, padding: "28px 32px",
      }}>
        {mode === null && (
          <>
            <div style={{ fontSize: 10, letterSpacing: 2, color: "#555", textTransform: "uppercase", textAlign: "center", marginBottom: 24 }}>
              SELECT ACCESS LEVEL
            </div>
            <div style={{ display: "flex", gap: 12 }}>
              <button onClick={() => setMode("admin")} style={{ ...roleBtn, borderColor: "#6b46c1" }}>
                <div style={{ fontSize: 9, letterSpacing: 2, color: "#6b46c1", textTransform: "uppercase" }}>ADMIN</div>
                <div style={{ fontSize: 10, color: "#444", marginTop: 4 }}>Full control</div>
              </button>
              <button onClick={() => setMode("analyst")} style={{ ...roleBtn, borderColor: "#1d4ed8" }}>
                <div style={{ fontSize: 9, letterSpacing: 2, color: "#1d4ed8", textTransform: "uppercase" }}>ANALYST</div>
                <div style={{ fontSize: 10, color: "#444", marginTop: 4 }}>Log analysis</div>
              </button>
            </div>
          </>
        )}

        {mode !== null && (
          <CredentialForm role={mode} onBack={() => setMode(null)} />
        )}
      </div>
    </div>
  );
}

const roleBtn: React.CSSProperties = {
  flex: 1,
  background: "#111",
  border: "1px solid",
  borderRadius: 4,
  padding: "16px",
  cursor: "pointer",
  textAlign: "center",
  transition: "all 0.15s",
};
