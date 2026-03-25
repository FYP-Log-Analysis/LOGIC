import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL ?? "http://localhost:4000";

export async function GET(req: NextRequest) {
  const token = req.cookies.get("auth_token")?.value;

  if (!token) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) {
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }

    const me = await res.json();
    return NextResponse.json({
      username: me.username,
      role: me.role ?? "analyst",
      user_id: me.user_id ?? me.id ?? 0,
      email: me.email ?? "",
    });
  } catch {
    return NextResponse.json({ error: "API unavailable" }, { status: 503 });
  }
}
