#!/usr/bin/env python3
"""Minimal Windows log sender for LOGIC ingest.

This script tails selected log files (or glob patterns) and sends appended lines to:
POST /api/logicx/ingest?project_id=<id>

Reliability scope is intentionally minimal:
- Fixed max retry attempts per batch
- No persistent offsets/state across restarts
- No exponential backoff
- No log rotation state tracking
- No offline spool queue
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from glob import glob
from typing import Dict, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tail log files and send lines to LOGIC ingest.")
    parser.add_argument("--api-url", required=True, help="Base API URL, e.g. https://example.com")
    parser.add_argument("--api-key", required=True, help="Project API key for X-Logic-Api-Key header")
    parser.add_argument("--project-id", required=True, help="Destination project UUID")
    parser.add_argument(
        "--log-path",
        action="append",
        required=True,
        help="Log file path or glob pattern. Repeat for multiple paths.",
    )
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--batch-size", type=int, default=200, help="Max records per request")
    parser.add_argument("--max-retries", type=int, default=3, help="Retry attempts per failed batch")
    parser.add_argument("--timeout-seconds", type=float, default=15.0, help="HTTP request timeout")
    parser.add_argument("--max-read-bytes", type=int, default=1024 * 1024, help="Max bytes read per file per cycle")
    parser.add_argument("--agent-version", default="2.0.0", help="agent_version field value")
    parser.add_argument(
        "--read-from-start",
        action="store_true",
        help="If set, start from beginning of existing files. Default starts at EOF.",
    )
    parser.add_argument(
        "--insecure-skip-tls-verify",
        action="store_true",
        help="Disable TLS certificate verification (not recommended).",
    )
    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")
    if args.max_retries < 0:
        parser.error("--max-retries must be >= 0")
    if args.poll_interval <= 0:
        parser.error("--poll-interval must be > 0")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be > 0")
    if args.max_read_bytes < 1:
        parser.error("--max-read-bytes must be >= 1")

    return args


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def expand_paths(patterns: List[str]) -> List[str]:
    files: set[str] = set()
    for pattern in patterns:
        for match in glob(pattern, recursive=True):
            if os.path.isfile(match):
                files.add(os.path.abspath(match))
    return sorted(files)


def send_batch(
    api_url: str,
    api_key: str,
    project_id: str,
    records: List[dict],
    timeout_seconds: float,
    max_retries: int,
    insecure_skip_tls_verify: bool,
) -> bool:
    if not records:
        return True

    endpoint = api_url.rstrip("/") + "/api/logicx/ingest?project_id=" + urllib.parse.quote(project_id)
    ndjson = "\n".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) for r in records).encode("utf-8")
    compressed = gzip.compress(ndjson)

    headers = {
        "X-Logic-Api-Key": api_key,
        "Content-Type": "application/x-ndjson",
        "Content-Encoding": "gzip",
    }

    context = None
    if insecure_skip_tls_verify and endpoint.lower().startswith("https://"):
        import ssl

        context = ssl._create_unverified_context()  # noqa: SLF001

    attempt = 0
    while attempt <= max_retries:
        attempt += 1
        req = urllib.request.Request(endpoint, data=compressed, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds, context=context) as resp:
                status = resp.getcode()
                body = resp.read(300).decode("utf-8", errors="replace")
            if status == 202:
                print(f"[OK] Sent {len(records)} records")
                return True
            print(f"[WARN] Attempt {attempt}/{max_retries + 1}: HTTP {status} {body}")
        except urllib.error.HTTPError as exc:
            body = exc.read(300).decode("utf-8", errors="replace") if exc.fp else ""
            print(f"[WARN] Attempt {attempt}/{max_retries + 1}: HTTP {exc.code} {body}")
        except Exception as exc:  # noqa: BLE001
            print(f"[WARN] Attempt {attempt}/{max_retries + 1}: {exc}")

        if attempt <= max_retries:
            time.sleep(1.0)

    print(f"[DROP] Dropping {len(records)} records after {max_retries + 1} attempts")
    return False


def read_new_lines(file_state: Dict[str, object], max_read_bytes: int) -> List[str]:
    path = str(file_state["path"])
    offset = int(file_state.get("offset", 0))
    partial = str(file_state.get("partial", ""))

    try:
        file_size = os.path.getsize(path)
    except OSError:
        return []

    if file_size < offset:
        # File truncated/recreated. Minimal reset behavior.
        offset = 0
        partial = ""

    if file_size == offset:
        file_state["offset"] = offset
        file_state["partial"] = partial
        return []

    to_read = min(max_read_bytes, file_size - offset)
    with open(path, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read(to_read)

    offset += len(chunk)
    text = partial + chunk.decode("utf-8", errors="replace")

    lines = text.splitlines(keepends=False)
    if text and not text.endswith(("\n", "\r")):
        partial = lines.pop() if lines else text
    else:
        partial = ""

    file_state["offset"] = offset
    file_state["partial"] = partial

    cleaned = [line.rstrip("\r") for line in lines if line.strip()]
    return cleaned


def main() -> int:
    args = parse_args()

    host = socket.gethostname()
    in_memory_state: Dict[str, Dict[str, object]] = {}

    print("Starting LOGIC log sender")
    print(f"API URL: {args.api_url}")
    print(f"Project ID: {args.project_id}")
    print(f"Patterns: {args.log_path}")
    print(f"Batch size: {args.batch_size}, max retries: {args.max_retries}")

    pending_records: List[dict] = []

    try:
        while True:
            files = expand_paths(args.log_path)
            if not files:
                print("[INFO] No files match current --log-path patterns")

            for path in files:
                state = in_memory_state.get(path)
                if state is None:
                    start_offset = 0
                    if not args.read_from_start:
                        try:
                            start_offset = os.path.getsize(path)
                        except OSError:
                            start_offset = 0
                    state = {"path": path, "offset": start_offset, "partial": ""}
                    in_memory_state[path] = state
                    print(f"[INFO] Tracking file: {path} (start_offset={start_offset})")

                new_lines = read_new_lines(state, args.max_read_bytes)
                if not new_lines:
                    continue

                now = utc_now_iso()
                for line in new_lines:
                    pending_records.append(
                        {
                            "host": host,
                            "file": path,
                            "log": line,
                            "date": now,
                            "agent_version": args.agent_version,
                        }
                    )

                while len(pending_records) >= args.batch_size:
                    batch = pending_records[: args.batch_size]
                    pending_records = pending_records[args.batch_size :]
                    send_batch(
                        api_url=args.api_url,
                        api_key=args.api_key,
                        project_id=args.project_id,
                        records=batch,
                        timeout_seconds=args.timeout_seconds,
                        max_retries=args.max_retries,
                        insecure_skip_tls_verify=args.insecure_skip_tls_verify,
                    )

            if pending_records:
                send_batch(
                    api_url=args.api_url,
                    api_key=args.api_key,
                    project_id=args.project_id,
                    records=pending_records,
                    timeout_seconds=args.timeout_seconds,
                    max_retries=args.max_retries,
                    insecure_skip_tls_verify=args.insecure_skip_tls_verify,
                )
                pending_records = []

            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("\nStopping log sender")
        return 0


if __name__ == "__main__":
    sys.exit(main())
