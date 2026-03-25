import { NextResponse } from "next/server";

function clearCookieResponse() {
  const response = NextResponse.redirect(new URL("/login", process.env.NEXT_PUBLIC_BASE_URL ?? "http://localhost:3000"));
  response.cookies.set({ name: "auth_token", value: "", httpOnly: true, path: "/", maxAge: 0 });
  return response;
}

// GET: used when navigating directly to /api/auth/logout
export async function GET() {
  return clearCookieResponse();
}

// POST: called programmatically by the client before redirecting to /login
export async function POST() {
  const response = NextResponse.json({ ok: true });
  response.cookies.set({
    name: "auth_token",
    value: "",
    httpOnly: true,
    path: "/",
    maxAge: 0,
  });
  return response;
}
