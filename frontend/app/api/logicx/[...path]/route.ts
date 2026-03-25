import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL ?? "http://localhost:4000";

type Params = { path: string[] };

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<Params> },
): Promise<NextResponse> {
  const { path } = await params;
  const targetUrl = `${API_BASE}/api/logicx/${path.join("/")}`;

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (["range", "if-none-match", "if-modified-since", "accept"].includes(lower)) {
      headers.set(key, value);
    }
  });

  let upstream: Response;
  try {
    upstream = await fetch(targetUrl, { method: "GET", headers });
  } catch (err) {
    return NextResponse.json(
      { error: `API unreachable: ${String(err)}` },
      { status: 503 },
    );
  }

  const responseHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    if (!["transfer-encoding", "connection"].includes(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  });

  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

/**
 * Public pass-through for POST /api/logicx/* -> FastAPI /api/logicx/*
 *
 * The LOGIC agent authenticates via X-Logic-Api-Key and forwards gzip NDJSON
 * payloads. Keep headers/query/body untouched so FastAPI receives the original
 * request and can validate/decompress safely.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<Params> },
): Promise<NextResponse> {
  const { path } = await params;
  const search = req.nextUrl.searchParams.toString();
  const targetUrl = `${API_BASE}/api/logicx/${path.join("/")}${search ? `?${search}` : ""}`;

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    if (["host", "connection", "cookie"].includes(key.toLowerCase())) return;
    headers.set(key, value);
  });

  let upstream: Response;
  try {
    upstream = await fetch(targetUrl, {
      method: "POST",
      headers,
      body: req.body,
      // Node 18+ fetch supports half-duplex streaming for request bodies.
      // @ts-expect-error non-standard but supported in Node 18+
      duplex: "half",
    });
  } catch (err) {
    return NextResponse.json(
      { error: `API unreachable: ${String(err)}` },
      { status: 503 },
    );
  }

  const responseHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    if (!["transfer-encoding", "connection"].includes(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  });

  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
}
