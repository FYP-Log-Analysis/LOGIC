import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL ?? "http://localhost:4000";

type Params = { path: string[] };

async function proxyRequest(
  req: NextRequest,
  params: Promise<Params>,
): Promise<NextResponse> {
  const { path } = await params;
  const token = req.cookies.get("auth_token")?.value;

  // Reconstruct the target URL, preserving query string
  const pathStr = (path ?? []).join("/");
  const search = req.nextUrl.searchParams.toString();
  const targetUrl = `${API_BASE}/${pathStr}${search ? `?${search}` : ""}`;

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();
    if (["host", "connection", "cookie"].includes(lowerKey)) return;
    headers.set(key, value);
  });
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const body = ["GET", "HEAD"].includes(req.method) ? undefined : req.body;

  let upstream: Response;
  try {
    upstream = await fetch(targetUrl, {
      method: req.method,
      headers,
      body,
      // Stream the incoming body through to FastAPI so large uploads do not
      // get buffered into memory by the proxy.
      // @ts-expect-error — Node 18+ fetch supports this
      duplex: "half",
    });
  } catch (err) {
    return NextResponse.json(
      { error: `API unreachable: ${String(err)}` },
      { status: 503 },
    );
  }

  // Stream the response body back to the client
  // (preserves SSE / chunked streaming for the chat endpoint)
  const responseHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    // Skip headers that Next.js manages
    if (!["transfer-encoding", "connection"].includes(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  });

  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export async function GET(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}

export async function POST(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}

export async function PUT(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}
