/**
 * Base API fetch helper — proxies all requests through the Next.js catch-all
 * route handler at /api/proxy/[...path], which injects the httpOnly auth cookie
 * as a Bearer token to the FastAPI backend.
 */

export class ApiError extends Error {
  constructor(
    message: string,
    public status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const API_BASE = process.env.API_BASE_URL ?? "http://localhost:4000";

export async function apiFetch<T = unknown>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  // Strip leading slash so we don't double-slash
  const cleanPath = path.replace(/^\//, "");
  const res = await fetch(`/api/proxy/${cleanPath}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
  });

  if (res.status === 401) {
    if (typeof window !== "undefined") {
      // Clear the httpOnly cookie first so proxy.ts doesn't redirect back
      await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
      window.location.href = "/login";
    }
    throw new ApiError("Unauthorized", 401);
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.detail ?? body?.error ?? detail;
    } catch {}
    throw new ApiError(detail, res.status);
  }

  // 204 No Content
  if (res.status === 204) return {} as T;

  return res.json() as Promise<T>;
}

export async function apiGet<T = unknown>(path: string): Promise<T> {
  return apiFetch<T>(path, { method: "GET" });
}

export async function apiPost<T = unknown>(
  path: string,
  body?: unknown,
): Promise<T> {
  return apiFetch<T>(path, {
    method: "POST",
    body: body != null ? JSON.stringify(body) : undefined,
  });
}

export async function apiDelete<T = unknown>(path: string): Promise<T> {
  return apiFetch<T>(path, { method: "DELETE" });
}

/** Upload a file using multipart/form-data */
export async function apiUpload<T = unknown>(
  path: string,
  formData: FormData,
): Promise<T> {
  const cleanPath = path.replace(/^\//, "");
  const res = await fetch(`${API_BASE}/${cleanPath}`, {
    method: "POST",
    body: formData,
    credentials: "include",
    // Do NOT set Content-Type — browser sets it with boundary
  });

  if (res.status === 401) {
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new ApiError("Unauthorized", 401);
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.detail ?? body?.error ?? detail;
    } catch {}
    throw new ApiError(detail, res.status);
  }

  return res.json() as Promise<T>;
}

/** Check if the API is reachable */
export async function apiHealth(): Promise<boolean> {
  try {
    // Use /api/auth/me — returns 200 if up+authenticated, 401 if up+unauthenticated
    // Either way means the API is reachable
    const res = await fetch("/api/proxy/api/auth/me", { method: "GET" });
    return res.status !== 502 && res.status !== 503 && res.status !== 504;
  } catch {
    return false;
  }
}
