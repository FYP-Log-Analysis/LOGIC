# Replays normalised log entries against the OWASP ModSecurity CRS service and
# extracts rule match details from the JSON audit log.
#
# Flow: stream normalized_logs.json -> send each entry to crs-detector via HTTP
# with a unique X-Logic-TxId header -> wait for audit log flush -> parse NDJSON.
#
# Reads env vars: CRS_SERVICE_URL, CRS_AUDIT_LOG, CRS_BATCH_SIZE, CRS_FLUSH_WAIT.
# Degrades gracefully when the crs-detector container is not running.

import json
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import ijson
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_AUDIT = str(_PROJECT_ROOT / "data" / "crs_audit" / "audit.log")

CRS_SERVICE_URL = os.getenv("CRS_SERVICE_URL", "http://crs-detector:8080")
CRS_AUDIT_LOG = os.getenv("CRS_AUDIT_LOG", _DEFAULT_AUDIT)
CRS_BATCH_SIZE = int(os.getenv("CRS_BATCH_SIZE", "500"))
CRS_FLUSH_WAIT = float(os.getenv("CRS_FLUSH_WAIT", "10"))
CRS_TIMEOUT = float(os.getenv("CRS_TIMEOUT", "2"))
CRS_WORKERS = int(os.getenv("CRS_WORKERS", "20"))
_RESOLVED_CRS_SERVICE_URL: str | None = None

_TX_HEADER = "X-Logic-TxId"
_BODY_METHODS = {"POST", "PUT", "PATCH"}


def _parse_iso_ts(value: str | None) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            return datetime.fromisoformat(raw[:-1] + "+00:00")
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=1,
        backoff_factor=0.2,
        status_forcelist=[503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=CRS_WORKERS * 2)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _candidate_service_urls() -> list[str]:
    candidates = [CRS_SERVICE_URL]
    parsed = urlparse(CRS_SERVICE_URL)
    if parsed.hostname == "crs-detector":
        scheme = parsed.scheme or "http"
        fallback_port = parsed.port or 8080
        candidates.extend([
            f"{scheme}://localhost:{fallback_port}",
            f"{scheme}://127.0.0.1:{fallback_port}",
        ])
        if fallback_port != 8080:
            candidates.extend([
                f"{scheme}://localhost:8080",
                f"{scheme}://127.0.0.1:8080",
            ])
    return list(dict.fromkeys(candidates))


def get_crs_service_url() -> str:
    return _RESOLVED_CRS_SERVICE_URL or CRS_SERVICE_URL


def check_crs_available() -> bool:
    global _RESOLVED_CRS_SERVICE_URL
    for candidate in _candidate_service_urls():
        try:
            requests.head(candidate, timeout=3)
            if candidate != CRS_SERVICE_URL:
                logger.info(
                    "[CRS] Using fallback service URL %s instead of configured %s",
                    candidate,
                    CRS_SERVICE_URL,
                )
            _RESOLVED_CRS_SERVICE_URL = candidate
            return True
        except Exception:
            continue
    return False


def _build_request(entry: dict, tx_id: str) -> dict:
    method = (entry.get("http_method") or "GET").upper()
    path = entry.get("request_path") or "/"
    qs = entry.get("query_string") or ""
    ua = entry.get("user_agent") or "LOGIC-CRS-Replay/1.0"
    ip = entry.get("client_ip") or "127.0.0.1"
    referer = entry.get("referer") or ""

    base = get_crs_service_url().rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    if qs and not qs.startswith("?"):
        url = f"{base}{path}?{qs}"
    elif qs:
        url = f"{base}{path}{qs}"
    else:
        url = f"{base}{path}"

    headers = {
        _TX_HEADER: tx_id,
        "User-Agent": ua,
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
    }
    if referer and referer not in ("-", ""):
        headers["Referer"] = referer

    data = None
    if method in _BODY_METHODS:
        data = qs if qs else "logic=replay"
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "data": data,
        "timeout": CRS_TIMEOUT,
        "allow_redirects": False,
        "verify": False,
    }


def _replay_entries(entries: list[dict], session: requests.Session) -> dict[str, dict]:
    tx_map: dict[str, dict] = {tx_id: entry for tx_id, entry in ((str(uuid.uuid4()), e) for e in entries)}

    def _send(tx_id: str) -> None:
        kwargs = _build_request(tx_map[tx_id], tx_id)
        try:
            session.request(**kwargs)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=CRS_WORKERS) as pool:
        futures = {pool.submit(_send, tx_id): tx_id for tx_id in tx_map}
        for fut in as_completed(futures):
            fut.result()

    return tx_map


def _parse_audit_log(audit_path: str, tx_map: dict[str, dict], start_offset: int = 0) -> list[dict]:
    path = Path(audit_path)
    if not path.exists() or path.stat().st_size == 0:
        logger.warning("[CRS] Audit log not found or empty: %s", audit_path)
        return []

    matches: list[dict] = []
    lines_read = 0
    lines_error = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        if start_offset:
            fh.seek(start_offset)
        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            lines_read += 1
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError:
                lines_error += 1
                continue

            tx = record.get("transaction", {})
            req_headers = {}
            req_section = tx.get("request", {})
            if isinstance(req_section, dict):
                req_headers = req_section.get("headers", {}) or {}
                req_headers_lower = {k.lower(): v for k, v in req_headers.items()}
            else:
                req_headers_lower = {}

            tx_id = req_headers.get(_TX_HEADER) or req_headers_lower.get(_TX_HEADER.lower(), "")
            if not tx_id or tx_id not in tx_map:
                continue

            original_entry = tx_map[tx_id]
            messages = tx.get("messages", []) or []
            if not messages:
                continue

            tx_anomaly_score = 0
            if isinstance(tx.get("score"), dict):
                tx_anomaly_score = tx["score"].get("inbound", 0) or 0
            elif isinstance(tx.get("anomaly_score"), (int, float)):
                tx_anomaly_score = tx["anomaly_score"]

            for msg in messages:
                if not isinstance(msg, dict):
                    continue

                details = msg.get("details", {}) or {}
                rule_id = str(details.get("ruleId", "") or msg.get("ruleId", "") or "")
                message = details.get("message", "") or msg.get("message", "") or ""
                tags_raw = details.get("tags", []) or msg.get("tags", []) or []
                tags = tags_raw if isinstance(tags_raw, list) else [str(tags_raw)]

                paranoia_level = 1
                for tag in tags:
                    if isinstance(tag, str) and tag.startswith("paranoia-level/"):
                        try:
                            paranoia_level = int(tag.split("/")[1])
                        except (IndexError, ValueError):
                            pass

                try:
                    msg_score = float(details.get("severity", 0) or 0)
                except (TypeError, ValueError):
                    msg_score = 0.0

                anomaly_score = float(tx_anomaly_score) if tx_anomaly_score else msg_score
                crs_severity_raw = details.get("severity") or msg.get("severity") or ""

                matches.append(
                    {
                        "tx_id": tx_id,
                        "timestamp": original_entry.get("timestamp", ""),
                        "client_ip": original_entry.get("client_ip", ""),
                        "method": original_entry.get("http_method", ""),
                        "uri": original_entry.get("request_path", ""),
                        "rule_id": rule_id,
                        "message": message,
                        "crs_severity": str(crs_severity_raw),
                        "anomaly_score": anomaly_score,
                        "tags": json.dumps(tags),
                        "paranoia_level": paranoia_level,
                        "original_entry": original_entry,
                    }
                )

    logger.info(
        "[CRS] Parsed audit log: %d lines read, %d parse errors, %d rule matches found",
        lines_read,
        lines_error,
        len(matches),
    )
    return matches


def run_crs_detection(
    normalized_path: "Path | str",
    run_id: Optional[str] = None,
    start_ts: Optional[str] = None,
    end_ts: Optional[str] = None,
    diagnostics: dict | None = None,
) -> list[dict]:
    del run_id
    normalized_path = Path(normalized_path)

    if not check_crs_available():
        logger.warning(
            "[CRS] Skipped - crs-detector service is not reachable at %s. "
            "Is docker compose up crs-detector running? Pipeline continues without CRS results.",
            CRS_SERVICE_URL,
        )
        print("[CRS] SKIP - crs-detector unreachable")
        return []

    if not normalized_path.exists():
        logger.error("[CRS] Normalised log file not found: %s", normalized_path)
        return []

    active_service_url = get_crs_service_url()
    print(f"[CRS] Starting CRS replay against {active_service_url} ...")
    logger.info("[CRS] Normalised log: %s | audit log: %s", normalized_path, CRS_AUDIT_LOG)

    session = _build_session()
    all_tx_map: dict[str, dict] = {}
    batch: list[dict] = []
    scanned_entries = 0
    replay_entries = 0
    skipped_range = 0
    skipped_invalid = 0
    skipped_unparseable_ts = 0
    total_batches = 0
    seen_timestamps = 0

    start_dt = _parse_iso_ts(start_ts)
    end_dt = _parse_iso_ts(end_ts)

    audit_path = Path(CRS_AUDIT_LOG)
    audit_start_offset = audit_path.stat().st_size if audit_path.exists() else 0
    logger.info("[CRS] Audit log offset before replay: %d bytes", audit_start_offset)

    with open(normalized_path, "rb") as fh:
        for entry in ijson.items(fh, "item"):
            scanned_entries += 1
            if not isinstance(entry, dict):
                skipped_invalid += 1
                continue

            ts = entry.get("timestamp", "")
            if ts:
                seen_timestamps += 1
            entry_dt = _parse_iso_ts(ts) if ts else None

            if ts and entry_dt is None:
                skipped_unparseable_ts += 1

            if start_dt and entry_dt and entry_dt < start_dt:
                skipped_range += 1
                continue
            if end_dt and entry_dt and entry_dt > end_dt:
                skipped_range += 1
                continue

            batch.append(entry)
            replay_entries += 1

            if len(batch) >= CRS_BATCH_SIZE:
                tx_map = _replay_entries(batch, session)
                all_tx_map.update(tx_map)
                total_batches += 1
                print(f"[CRS]   Batch {total_batches}: replayed {len(batch)} entries ({replay_entries} total)")
                batch = []

    if batch:
        tx_map = _replay_entries(batch, session)
        all_tx_map.update(tx_map)
        total_batches += 1
        print(f"[CRS]   Batch {total_batches}: replayed {len(batch)} entries ({replay_entries} total)")

    logger.info(
        "[CRS] Replay eligibility: scanned=%d, replay_candidates=%d, skipped_range=%d, "
        "skipped_invalid=%d, unparseable_ts=%d, with_timestamp=%d",
        scanned_entries,
        replay_entries,
        skipped_range,
        skipped_invalid,
        skipped_unparseable_ts,
        seen_timestamps,
    )

    if diagnostics is not None:
        diagnostics.update(
            {
                "scanned_entries": scanned_entries,
                "replay_candidates": replay_entries,
                "skipped_range": skipped_range,
                "skipped_invalid": skipped_invalid,
                "unparseable_timestamps": skipped_unparseable_ts,
            }
        )

    if not all_tx_map:
        print("[CRS] No entries replayed.")
        logger.warning(
            "[CRS] No entries replayed after filtering. start_ts=%r end_ts=%r",
            start_ts,
            end_ts,
        )
        return []

    print(
        f"[CRS] Replay complete: {replay_entries} entries in {total_batches} batches. "
        f"Waiting {CRS_FLUSH_WAIT}s for audit log flush ..."
    )
    time.sleep(CRS_FLUSH_WAIT)

    matches = _parse_audit_log(CRS_AUDIT_LOG, all_tx_map, start_offset=audit_start_offset)

    unique_rules = len({m["rule_id"] for m in matches})
    unique_ips = len({m["client_ip"] for m in matches})
    print(
        f"[CRS] Detection complete:\n"
        f"[CRS]   Total matches   : {len(matches)}\n"
        f"[CRS]   Unique rules    : {unique_rules}\n"
        f"[CRS]   Unique IPs      : {unique_ips}\n"
        f"[CRS]   Paranoia level  : {os.getenv('CRS_PARANOIA_LEVEL', '1')}"
    )
    logger.info(
        "[CRS] Detection complete: %d matches, %d unique rules, %d unique ips",
        len(matches),
        unique_rules,
        unique_ips,
    )

    return matches
