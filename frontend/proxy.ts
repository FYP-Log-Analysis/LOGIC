import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL ?? "http://localhost:4000";
const TOKEN_CACHE_TTL_MS = 15_000;
const TOKEN_CACHE_LIMIT = 200;
const tokenValidationCache = new Map<string, { valid: boolean; expiresAt: number }>();

function getCachedTokenValidity(token: string): boolean | null {
  const now = Date.now();
  const cached = tokenValidationCache.get(token);
  if (!cached) return null;
  if (cached.expiresAt <= now) {
    tokenValidationCache.delete(token);
    return null;
  }
  return cached.valid;
}

function setCachedTokenValidity(token: string, valid: boolean): void {
  const now = Date.now();
  tokenValidationCache.set(token, { valid, expiresAt: now + TOKEN_CACHE_TTL_MS });

  // Keep cache bounded in long-running dev sessions.
  if (tokenValidationCache.size > TOKEN_CACHE_LIMIT) {
    for (const [k, v] of tokenValidationCache) {
      if (v.expiresAt <= now) tokenValidationCache.delete(k);
    }
  }
}

/** Ask FastAPI whether the token is actually valid (covers signature + expiry). */
async function isTokenValid(token: string): Promise<boolean> {
  const cached = getCachedTokenValidity(token);
  if (cached !== null) return cached;

  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(3000),
    });
    setCachedTokenValidity(token, res.ok);
    return res.ok;
  } catch {
    setCachedTokenValidity(token, false);
    return false;
  }
}

const PROTECTED = [
  "/overview",
  "/projects",
  "/analysis",
  "/detections",
  "/behavioral",
  "/windows-analysis",
  "/windows-behavioral",
  "/log-statistics",
  "/ai-insights",
  "/pipeline",
  "/admin",
];

export async function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const token = req.cookies.get("auth_token")?.value;

  const isProtected = PROTECTED.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );

  // Not a route we manage — pass through immediately
  if (!isProtected && pathname !== "/login") {
    return NextResponse.next();
  }

  const valid = token ? await isTokenValid(token) : false;

  if (isProtected && !valid) {
    const res = NextResponse.redirect(new URL("/login", req.url));
    if (token) res.cookies.delete("auth_token"); // clear the stale cookie
    return res;
  }

  if (pathname === "/login" && valid) {
    return NextResponse.redirect(new URL("/overview", req.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/overview/:path*",
    "/projects/:path*",
    "/analysis/:path*",
    "/detections/:path*",
    "/behavioral/:path*",
    "/windows-analysis/:path*",
    "/windows-behavioral/:path*",
    "/log-statistics/:path*",
    "/ai-insights/:path*",
    "/pipeline/:path*",
    "/admin/:path*",
    "/login",
  ],
};
