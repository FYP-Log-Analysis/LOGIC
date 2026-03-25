import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL ?? "http://localhost:4000";

export async function POST(req: NextRequest) {
  const { username, password } = await req.json();

  // FastAPI OAuth2 expects application/x-www-form-urlencoded
  const body = new URLSearchParams({ username, password });

  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
  } catch {
    return NextResponse.json(
      { error: "API unavailable" },
      { status: 503 },
    );
  }

  if (!res.ok) {
    let detail = "Login failed";
    try {
      const data = await res.json();
      detail = data?.detail ?? detail;
    } catch {}
    return NextResponse.json({ error: detail }, { status: res.status });
  }

  const data = await res.json();
  const token: string = data.access_token;

  if (!token) {
    return NextResponse.json({ error: "No token returned" }, { status: 500 });
  }

  // Fetch user info from FastAPI using the token
  let user = { username, role: "analyst", user_id: 0, email: "" };
  try {
    const meRes = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (meRes.ok) {
      const me = await meRes.json();
      user = {
        username: me.username ?? username,
        role: me.role ?? "analyst",
        user_id: me.user_id ?? me.id ?? 0,
        email: me.email ?? "",
      };
    }
  } catch {}

  const response = NextResponse.json(user, { status: 200 });

  // Store JWT in httpOnly cookie
  response.cookies.set({
    name: "auth_token",
    value: token,
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    // secure: true — enable in production behind HTTPS
    maxAge: 60 * 60 * 24, // 24 hours
  });

  return response;
}
