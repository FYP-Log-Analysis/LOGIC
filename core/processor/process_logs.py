# Single streaming pass: reads intermediate.json for the upload, parses each line, normalises it,
# and writes normalized.json + compact behavioral aggregations to SQLite.
# Raw log rows are NOT stored in SQLite — the aggregation tables are far smaller
# and support all behavioral analysis and IP investigation features.
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import ijson

from core.processor.apache_norm import normalise_access_entry, normalise_nginx_error
from core.processor.evtx_norm import normalise_windows_event
from core.storage.sqlite_store import upsert_ip_geo

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT  = Path(__file__).resolve().parents[2]
PROJECTS_ROOT = PROJECT_ROOT / "data" / "projects"

_LOG_EVERY = 50_000


# Apache / Nginx Combined Log Format
COMBINED_RE = re.compile(
    r'(?P<ip>\S+)'
    r'\s+\S+'
    r'\s+(?P<user>\S+)'
    r'\s+\[(?P<time>[^\]]+)\]'
    r'\s+"(?P<method>\S+)'
    r'\s+(?P<path>\S+)'
    r'\s+(?P<protocol>[^"]+)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"'
    r'\s+"(?P<user_agent>[^"]*)")?'
)

# Nginx error log: 2024/01/15 12:34:56 [error] 1234#0: *1 message, client: 1.2.3.4
NGINX_ERROR_RE = re.compile(
    r'(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+\[(?P<level>\w+)\]'
    r'.*?client:\s*(?P<ip>[\d\.]+)?'
    r'.*?(?P<message>.+)'
)

TIMESTAMP_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # Apache/Nginx combined
    "%Y/%m/%d %H:%M:%S",       # Nginx error
    "%Y-%m-%dT%H:%M:%S%z",    # ISO 8601
    "%Y-%m-%dT%H:%M:%S.%fZ",  # EVTX timestamps with milliseconds
    "%Y-%m-%dT%H:%M:%SZ",     # EVTX timestamps in UTC
]


def _parse_timestamp(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""

    if raw.endswith("Z"):
        try:
            return datetime.fromisoformat(raw[:-1] + "+00:00").isoformat()
        except ValueError:
            pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw, fmt).isoformat()
        except ValueError:
            continue
    return raw


def _detect_server_type(source: str) -> str:
    s = source.lower()
    if s.endswith(".evtx") or s.endswith(".xml"):
        return "windows_event"
    if "nginx" in s:
        return "nginx"
    if "apache" in s or "httpd" in s:
        return "apache"
    return "apache"  # Combined Format default


def _parse_evtx_event(event: dict[str, Any], source: str) -> dict | None:
    event_id = event.get("event_id")
    try:
        if event_id is not None and str(event_id).isdigit():
            event_id = int(event_id)
    except Exception:
        pass

    return {
        "source": source,
        "log_type": "evtx",
        "timestamp": _parse_timestamp(event.get("timestamp") or ""),
        "event_id": event_id,
        "channel": event.get("channel"),
        "computer": event.get("computer"),
        "security_user": event.get("security_user"),
        "level": event.get("level"),
        "record_id": event.get("record_id"),
        "event_data": event.get("event_data") or {},
        "raw": event.get("raw") or json.dumps(event, ensure_ascii=False),
    }


def _parse_line(raw_line: Any, source: str, raw_event: dict | None = None) -> dict | None:
    if raw_event:
        return _parse_evtx_event(raw_event, source)

    if isinstance(raw_line, dict):
        return _parse_evtx_event(raw_line, source)

    if not isinstance(raw_line, str):
        return None

    m = COMBINED_RE.match(raw_line)
    if m:
        g = m.groupdict()
        return {
            "source":     source,
            "log_type":   "access",
            "ip":         g["ip"],
            "user":       g["user"] if g["user"] != "-" else None,
            "timestamp":  _parse_timestamp(g["time"]),
            "method":     g["method"].upper(),
            "path":       g["path"],
            "protocol":   g.get("protocol", "").strip(),
            "status":     int(g["status"]),
            "size":       int(g["size"]) if g["size"].isdigit() else 0,
            "referer":    g.get("referer") or None,
            "user_agent": g.get("user_agent") or None,
            "raw":        raw_line,
        }

    m = NGINX_ERROR_RE.match(raw_line)
    if m:
        g = m.groupdict()
        return {
            "source":    source,
            "log_type":  "error",
            "ip":        g.get("ip"),
            "timestamp": _parse_timestamp(g["time"]),
            "level":     g.get("level"),
            "message":   g.get("message", "").strip(),
            "raw":       raw_line,
        }

    return None


def _normalise(parsed: dict) -> dict | None:
    log_type    = parsed.get("log_type", "access")
    server_type = _detect_server_type(parsed.get("source", ""))

    if log_type == "evtx" or server_type == "windows_event":
        return normalise_windows_event(parsed)
    if log_type == "error":
        return normalise_nginx_error(parsed)
    return normalise_access_entry(parsed, server_type=server_type)


def _parse_filter_dt(ts_str: str | None) -> datetime | None:
    """Parse an ISO 8601 string into a timezone-aware datetime for range filtering."""
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def process_all(
    upload_id: str,
    project_id: str,
    time_from: str | None = None,
    time_to: str | None = None,
) -> int:
    """Parse and normalise all raw log entries for the given upload.

    Only entries whose timestamp falls within [time_from, time_to] are written
    to normalized.json when those bounds are provided.

    Reads  : data/projects/{project_id}/uploads/{upload_id}/intermediate.json
    Writes : data/projects/{project_id}/uploads/{upload_id}/normalized.json
    Deletes: intermediate.json after successful normalisation.
    """
    _filter_from = _parse_filter_dt(time_from)
    _filter_to   = _parse_filter_dt(time_to)
    if time_from or time_to:
        logger.info(f"Time-range filter active: {time_from} → {time_to}")

    upload_dir = PROJECTS_ROOT / project_id / "uploads" / upload_id
    src        = upload_dir / "intermediate.json"

    if not src.exists():
        logger.error(f"Raw entries not found: {src} — run ingestion first.")
        return 0

    out_dir  = upload_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "normalized.json"

    written = skipped = 0
    first   = True

    # ── In-memory behavioural aggregation accumulators ──────────────────────
    # These are written to compact SQLite tables at the end in a single
    # transaction, replacing per-batch bulk_insert_logs calls.
    _rate:     defaultdict = defaultdict(int)          # (ip, min_bucket) -> count
    _enum_c:   defaultdict = defaultdict(int)          # (ip, hour_bucket) -> total requests
    _enum_p:   defaultdict = defaultdict(set)          # (ip, hour_bucket) -> set(paths, ≤20)
    _status:   defaultdict = defaultdict(lambda: [0, 0])  # min_bucket -> [total, errors]
    _visitors: defaultdict = defaultdict(set)          # hour_bucket -> set(unique IPs)
    _hour_tot: defaultdict = defaultdict(int)          # hour_bucket -> total requests
    _ip_sum:   dict        = {}                        # ip -> summary dict
    _total_count = 0
    _min_ts: str | None  = None
    _max_ts: str | None  = None

    _geo_batch: set[str] = set()
    _seen_ips:  set[str] = set()

    with open(src, "rb") as fin, open(out_path, "w", encoding="utf-8") as fout:
        fout.write("[\n")
        for raw_entry in ijson.items(fin, "item"):
            source = raw_entry.get("source", "")
            raw_event = raw_entry.get("raw_event") if isinstance(raw_entry.get("raw_event"), dict) else None
            raw_payload: Any = raw_event if raw_event is not None else raw_entry.get("raw")
            parsed = _parse_line(raw_payload, source, raw_event=raw_event)
            if parsed is None:
                skipped += 1
                continue
            normalised = _normalise(parsed)
            if normalised is None:
                skipped += 1
                continue

            # ── Time-range filter ────────────────────────────────────────────
            if _filter_from or _filter_to:
                ts_str = normalised.get("timestamp") or ""
                if ts_str:
                    entry_dt = _parse_filter_dt(ts_str)
                    if entry_dt is not None:
                        if _filter_from and entry_dt < _filter_from:
                            skipped += 1
                            continue
                        if _filter_to and entry_dt > _filter_to:
                            skipped += 1
                            continue

            if not first:
                fout.write(",\n")
            fout.write(json.dumps(normalised, ensure_ascii=False))
            first        = False
            written     += 1
            _total_count += 1
            is_windows_event = normalised.get("server_type") == "windows_event"

            # ── Accumulate behavioural aggregation data ─────────────────────
            ts      = normalised.get("timestamp") or ""
            ip      = normalised.get("client_ip") or ""
            status  = normalised.get("status_code") or 0
            path    = normalised.get("path_clean") or normalised.get("request_path") or ""
            ua      = normalised.get("user_agent") or ""
            sc      = normalised.get("status_class") or ""

            if ts and not is_windows_event:
                if _min_ts is None or ts < _min_ts:
                    _min_ts = ts
                if _max_ts is None or ts > _max_ts:
                    _max_ts = ts
                min_bucket  = ts[:16]          # "2024-01-15T12:34"
                hour_bucket = ts[:13] + ":00"  # "2024-01-15T12:00"
                _status[min_bucket][0] += 1
                if status >= 400:
                    _status[min_bucket][1] += 1

                if ip:
                    _rate[(ip, min_bucket)] += 1
                    _enum_c[(ip, hour_bucket)] += 1
                    ep = _enum_p[(ip, hour_bucket)]
                    if path and len(ep) < 20:
                        ep.add(path)
                    _visitors[hour_bucket].add(ip)
                    _hour_tot[hour_bucket] += 1

            if ip and not is_windows_event:
                if ip not in _seen_ips:
                    _seen_ips.add(ip)
                    _geo_batch.add(ip)
                # Per-IP summary
                s = _ip_sum.get(ip)
                if s is None:
                    s = {
                        "count": 0, "first_ts": ts, "last_ts": ts,
                        "ua_ctr": Counter(), "status_ctr": Counter(), "path_ctr": Counter(),
                    }
                    _ip_sum[ip] = s
                s["count"] += 1
                if ts and ts < s["first_ts"]:
                    s["first_ts"] = ts
                if ts and ts > s["last_ts"]:
                    s["last_ts"] = ts
                if ua:
                    s["ua_ctr"][ua] += 1
                if sc:
                    s["status_ctr"][sc] += 1
                if path:
                    s["path_ctr"][path] += 1
                    # Prune to cap memory usage per IP (keep top 50, note count is approximate)
                    if len(s["path_ctr"]) > 200:
                        s["path_ctr"] = Counter(dict(s["path_ctr"].most_common(50)))

            if written % _LOG_EVERY == 0:
                logger.info(f"  … {written:,} entries processed")
        fout.write("\n]")

    # ── Flush GeoIP lookups ─────────────────────────────────────────────────
    if _geo_batch:
        try:
            upsert_ip_geo(list(_geo_batch))
        except Exception as exc:
            logger.warning(f"GeoIP batch upsert skipped: {exc}")

    # ── Write aggregations to JSON files ───────────────────────────────────
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)

        # log_summary.json
        with open(upload_dir / "log_summary.json", "w", encoding="utf-8") as fh:
            json.dump({
                "upload_id":       upload_id,
                "project_id":      project_id,
                "total_count":     _total_count,
                "min_ts":          _min_ts,
                "max_ts":          _max_ts,
                "unique_ip_count": len(_seen_ips),
            }, fh)

        # ip_summary.json
        ip_data: dict = {}
        for ip, s in _ip_sum.items():
            top_ua   = [{"user_agent": ua, "count": c} for ua, c in s["ua_ctr"].most_common(5)]
            top_path = [{"request_path": p, "count": c} for p, c in s["path_ctr"].most_common(10)]
            ip_data[ip] = {
                "request_count":       s["count"],
                "unique_paths":        len(s["path_ctr"]),
                "first_seen":          s["first_ts"],
                "last_seen":           s["last_ts"],
                "user_agents":         top_ua,
                "status_distribution": dict(s["status_ctr"]),
                "top_paths":           top_path,
            }
        with open(upload_dir / "ip_summary.json", "w", encoding="utf-8") as fh:
            json.dump({"upload_id": upload_id, "project_id": project_id, "ips": ip_data}, fh)

        # behavioral_stats.json
        rate_list = [
            {"client_ip": ip, "window_minute": mb, "request_count": cnt}
            for (ip, mb), cnt in _rate.items()
        ]
        enum_list = [
            {
                "client_ip":      ip,
                "window_hour":    hb,
                "distinct_paths": len(_enum_p.get((ip, hb), set())),
                "total_requests": tot,
                "sample_paths":   list(_enum_p.get((ip, hb), set())),
            }
            for (ip, hb), tot in _enum_c.items()
        ]
        status_list = [
            {"window_minute": mb, "total_requests": t[0], "error_count": t[1]}
            for mb, t in _status.items()
        ]
        visitor_list = [
            {"window_hour": hour, "unique_visitors": len(ip_set), "total_requests": _hour_tot.get(hour, 0)}
            for hour, ip_set in _visitors.items()
        ]
        with open(upload_dir / "behavioral_stats.json", "w", encoding="utf-8") as fh:
            json.dump({
                "upload_id":             upload_id,
                "project_id":            project_id,
                "rate_buckets":          rate_list,
                "path_enum_buckets":     enum_list,
                "status_trend_buckets":  status_list,
                "visitor_trend_buckets": visitor_list,
            }, fh)
    except Exception as exc:
        logger.warning(f"Aggregation file write failed: {exc}")

    logger.info(f"Processed {written:,} entries | Skipped {skipped}")
    logger.info(f"Saved → {out_path}")

    # Clean up the intermediate file so disk space isn't wasted
    if src.exists():
        try:
            src.unlink()
        except Exception as exc:
            logger.warning(f"Could not delete intermediate file {src}: {exc}")

    return written


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Process logs for a specific upload")
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--upload-id",  required=True)
    args = ap.parse_args()
    process_all(upload_id=args.upload_id, project_id=args.project_id)
