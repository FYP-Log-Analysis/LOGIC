# SQLite store for pipeline run history, upload status, user/project management,
# and GeoIP lookup cache. Detection results and behavioral aggregations live in
# per-upload JSON files (rule_matches.json, ip_summary.json, etc.).
# Database lives at data/logic.db
import json
import sqlite3
import logging
import shutil
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH      = PROJECT_ROOT / "data" / "logic.db"


@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # return dict-like rows
    conn.execute("PRAGMA journal_mode=WAL") # safe concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS pipeline_runs (
                run_id      TEXT PRIMARY KEY,
                source_file TEXT,
                file_size   INTEGER,
                started_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                finished_at TEXT,
                status      TEXT DEFAULT 'pending',
                entries     INTEGER,
                detections  INTEGER,
                anomalies   INTEGER,
                error_msg   TEXT
            );

            CREATE TABLE IF NOT EXISTS upload_status (
                upload_id   TEXT PRIMARY KEY,
                stage       TEXT DEFAULT 'uploading',
                status      TEXT DEFAULT 'pending',
                entry_count INTEGER DEFAULT 0,
                error_msg   TEXT,
                started_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                updated_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE TABLE IF NOT EXISTS ip_geo (
                client_ip              TEXT PRIMARY KEY,
                country_code           TEXT,
                country_name           TEXT,
                is_private_or_unknown  INTEGER DEFAULT 0,
                lookup_source          TEXT,
                updated_at             TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_ip_geo_country_code ON ip_geo(country_code);

            -- ── AUTH: users ─────────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE,
                email           TEXT    NOT NULL UNIQUE,
                hashed_password TEXT    NOT NULL,
                role            TEXT    NOT NULL DEFAULT 'user',
                is_active       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            -- ── AUTH: projects ───────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS projects (
                id          TEXT    PRIMARY KEY,
                name        TEXT    NOT NULL,
                description TEXT    DEFAULT '',
                owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at  TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                last_run_at TEXT,
                status      TEXT    DEFAULT 'active'
            );

            CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id);
        """)

        # Non-destructive column migrations
        _migrations = [
            "ALTER TABLE upload_status ADD COLUMN project_id TEXT",
            "ALTER TABLE upload_status ADD COLUMN filename    TEXT",
            "ALTER TABLE pipeline_runs ADD COLUMN project_id TEXT",
            "ALTER TABLE projects ADD COLUMN api_key TEXT",
            "ALTER TABLE projects ADD COLUMN agent_log_paths TEXT",
            "ALTER TABLE projects ADD COLUMN agent_config_updated_at TEXT",
            "ALTER TABLE projects ADD COLUMN project_type TEXT DEFAULT 'web'",
            "ALTER TABLE projects ADD COLUMN log_time_range_start TEXT",
            "ALTER TABLE projects ADD COLUMN log_time_range_end TEXT",
            "ALTER TABLE upload_status ADD COLUMN time_range_start TEXT",
            "ALTER TABLE upload_status ADD COLUMN time_range_end TEXT",
        ]
        for stmt in _migrations:
            try:
                conn.execute(stmt)
            except Exception:
                pass  # column already exists — SQLite has no ALTER TABLE IF NOT EXISTS

        _idx = [
            "CREATE INDEX IF NOT EXISTS idx_upl_project_id ON upload_status(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_run_project_id ON pipeline_runs(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_projects_api_key ON projects(api_key)",
            "CREATE INDEX IF NOT EXISTS idx_projects_type ON projects(project_type)",
        ]
        for stmt in _idx:
            try:
                conn.execute(stmt)
            except Exception:
                pass  # index already exists

    logger.info(f"SQLite database initialised: {DB_PATH}")


# ─────────────────────────────────────────────────────────────────────────────
# File-based query helpers (detection/behavioral data lives in per-upload JSON)
# ─────────────────────────────────────────────────────────────────────────────

PROJECTS_ROOT = PROJECT_ROOT / "data" / "projects"


def _load_all_matches(project_id: str | None, upload_id: str | None = None) -> list[dict]:
    """Load all rule matches from every rule_matches.json for a project."""
    if not project_id:
        return []
    ud = PROJECTS_ROOT / project_id / "uploads"
    if not ud.exists():
        return []
    matches: list[dict] = []
    pattern = f"{upload_id}/rule_matches.json" if upload_id else "*/rule_matches.json"
    for f in ud.glob(pattern):
        try:
            with open(f, encoding="utf-8") as fh:
                matches.extend(json.load(fh).get("matches", []))
        except Exception:
            pass
    return matches


def _load_log_summaries(project_id: str | None, upload_id: str | None = None) -> list[dict]:
    if not project_id:
        return []
    ud = PROJECTS_ROOT / project_id / "uploads"
    if not ud.exists():
        return []
    summaries: list[dict] = []
    pattern = f"{upload_id}/log_summary.json" if upload_id else "*/log_summary.json"
    for f in ud.glob(pattern):
        try:
            with open(f, encoding="utf-8") as fh:
                summaries.append(json.load(fh))
        except Exception:
            pass
    return summaries


def _load_ip_summaries(project_id: str | None, upload_id: str | None = None) -> dict:
    """Merge ip_summary.json files. Returns {ip -> aggregated stats}."""
    if not project_id:
        return {}
    ud = PROJECTS_ROOT / project_id / "uploads"
    if not ud.exists():
        return {}
    merged: dict = {}
    pattern = f"{upload_id}/ip_summary.json" if upload_id else "*/ip_summary.json"
    for f in ud.glob(pattern):
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
            for ip, s in data.get("ips", {}).items():
                ua_counts: dict[str, int] = {}
                for ua_entry in s.get("user_agents", []):
                    if not isinstance(ua_entry, dict):
                        continue
                    user_agent = ua_entry.get("user_agent")
                    if not user_agent:
                        continue
                    ua_counts[user_agent] = ua_counts.get(user_agent, 0) + int(ua_entry.get("count", 0) or 0)

                path_counts: dict[str, int] = {}
                for path_entry in s.get("top_paths", []):
                    if not isinstance(path_entry, dict):
                        continue
                    request_path = path_entry.get("request_path")
                    if not request_path:
                        continue
                    path_counts[request_path] = path_counts.get(request_path, 0) + int(path_entry.get("count", 0) or 0)

                status_counts = {
                    str(code): int(count or 0)
                    for code, count in (s.get("status_distribution", {}) or {}).items()
                }

                if ip not in merged:
                    merged[ip] = {
                        "request_count":       s.get("request_count", 0),
                        "unique_paths":        s.get("unique_paths", 0),
                        "first_seen":          s.get("first_seen"),
                        "last_seen":           s.get("last_seen"),
                        "user_agents":         ua_counts,
                        "status_distribution": status_counts,
                        "top_paths":           path_counts,
                    }
                else:
                    merged[ip]["request_count"] += s.get("request_count", 0)
                    merged[ip]["unique_paths"]   = max(merged[ip]["unique_paths"], s.get("unique_paths", 0))
                    if s.get("first_seen") and (not merged[ip]["first_seen"] or s["first_seen"] < merged[ip]["first_seen"]):
                        merged[ip]["first_seen"] = s["first_seen"]
                    if s.get("last_seen") and (not merged[ip]["last_seen"] or s["last_seen"] > merged[ip]["last_seen"]):
                        merged[ip]["last_seen"] = s["last_seen"]
                    for user_agent, count in ua_counts.items():
                        merged[ip]["user_agents"][user_agent] = merged[ip]["user_agents"].get(user_agent, 0) + count
                    for code, count in status_counts.items():
                        merged[ip]["status_distribution"][code] = merged[ip]["status_distribution"].get(code, 0) + count
                    for request_path, count in path_counts.items():
                        merged[ip]["top_paths"][request_path] = merged[ip]["top_paths"].get(request_path, 0) + count
        except Exception:
            pass
    return merged


def _load_behavioral_key(project_id: str | None, key: str, upload_id: str | None = None) -> list:
    """Load and merge a specific bucket list from behavioral_stats.json files."""
    if not project_id:
        return []
    ud = PROJECTS_ROOT / project_id / "uploads"
    if not ud.exists():
        return []
    result: list = []
    pattern = f"{upload_id}/behavioral_stats.json" if upload_id else "*/behavioral_stats.json"
    for f in ud.glob(pattern):
        try:
            with open(f, encoding="utf-8") as fh:
                result.extend(json.load(fh).get(key, []))
        except Exception:
            pass
    return result


def _load_normalized_entries(project_id: str | None, upload_id: str | None = None) -> list[dict]:
    if not project_id:
        return []
    ud = PROJECTS_ROOT / project_id / "uploads"
    if not ud.exists():
        return []

    import ijson

    entries: list[dict] = []
    pattern = f"{upload_id}/normalized.json" if upload_id else "*/normalized.json"
    for f in ud.glob(pattern):
        try:
            with open(f, "rb") as fh:
                entries.extend(ijson.items(fh, "item"))
        except Exception:
            pass
    return entries


def insert_detection(match: dict, run_id: str | None = None) -> None:
    pass  # detection results are now stored in rule_matches.json files


def bulk_insert_detections(matches: list[dict], run_id: str | None = None, project_id: str | None = None) -> int:
    return 0  # no-op: detection results live in rule_matches.json


def _latest_completed_upload(project_id: str) -> str | None:
    """Return the most-recent completed upload_id for a project, or the most recent overall."""
    with _get_conn() as conn:
        # Try completed first
        row = conn.execute(
            "SELECT upload_id FROM upload_status "
            "WHERE project_id = ? AND stage = 'saved' AND status = 'complete' "
            "ORDER BY started_at DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        if row:
            return row[0]
        # Fall back to any upload
        row = conn.execute(
            "SELECT upload_id FROM upload_status "
            "WHERE project_id = ? ORDER BY started_at DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        return row[0] if row else None


def query_logs(
    limit:      int = 5000,
    project_id: str | None = None,
    upload_id:  str | None = None,
) -> list[dict]:
    """Stream normalised log entries from the per-upload JSON file.

    When upload_id is omitted but project_id is provided, the latest
    completed upload is resolved automatically.
    Returns an empty list when the file cannot be located.
    """
    import ijson

    if not project_id:
        logger.warning("query_logs: project_id is required")
        return []

    resolved_upload = upload_id or _latest_completed_upload(project_id)
    if not resolved_upload:
        logger.warning("query_logs: no uploads found for project=%s", project_id)
        return []

    p = PROJECT_ROOT / "data" / "projects" / project_id / "uploads" / resolved_upload / "normalized.json"
    if not p.exists():
        logger.warning("query_logs: no normalised log file for project=%s upload=%s", project_id, resolved_upload)
        return []

    results: list[dict] = []
    try:
        with open(p, "rb") as fh:
            for entry in ijson.items(fh, "item"):
                results.append(entry)
                if len(results) >= limit:
                    break
    except Exception as exc:
        logger.warning("query_logs: could not read %s: %s", p, exc)
    return results


def query_detections(
    severity:   str | None = None,
    rule_id:    str | None = None,
    client_ip:  str | None = None,
    project_id: str | None = None,
    upload_id:  str | None = None,
    start_ts:   str | None = None,
    end_ts:     str | None = None,
    limit:      int = 500,
    offset:     int = 0,
) -> tuple[list[dict], int]:
    """Return (rows, total) from file-based rule_matches.json files."""

    def _parse_iso_ts(ts: str | None) -> datetime | None:
        raw = (ts or "").strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    def _in_range(ts: str | None, start: datetime | None, end: datetime | None) -> bool:
        dt = _parse_iso_ts(ts)
        if dt is None:
            return False
        if start and dt < start:
            return False
        if end and dt > end:
            return False
        return True

    matches = _load_all_matches(project_id, upload_id)
    if severity:
        matches = [m for m in matches if (m.get("severity") or "").lower() == severity.lower()]
    if rule_id:
        matches = [m for m in matches if m.get("rule_id") == rule_id]
    if client_ip:
        matches = [m for m in matches if m.get("client_ip") == client_ip]

    start_dt = _parse_iso_ts(start_ts)
    end_dt = _parse_iso_ts(end_ts)
    if start_dt or end_dt:
        matches = [m for m in matches if _in_range(m.get("timestamp"), start_dt, end_dt)]

    matches.sort(
        key=lambda m: _parse_iso_ts(m.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return matches[offset : offset + limit], len(matches)


def _insert_ip_geo_rows(conn: sqlite3.Connection, rows: list[tuple]) -> None:
    conn.executemany(
        """
        INSERT INTO ip_geo
            (client_ip, country_code, country_name, is_private_or_unknown, lookup_source, updated_at)
        VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        ON CONFLICT(client_ip) DO UPDATE SET
            country_code = excluded.country_code,
            country_name = excluded.country_name,
            is_private_or_unknown = excluded.is_private_or_unknown,
            lookup_source = excluded.lookup_source,
            updated_at = excluded.updated_at
        """,
        rows,
    )


def upsert_ip_geo(client_ips: list[str]) -> int:
    if not client_ips:
        return 0

    from core.enrichment.geoip import lookup_ip_country

    unique_ips = sorted({ip.strip() for ip in client_ips if ip and ip.strip()})
    if not unique_ips:
        return 0

    placeholders = ",".join(["?"] * len(unique_ips))
    with _get_conn() as conn:
        existing = {
            row[0]
            for row in conn.execute(
                f"SELECT client_ip FROM ip_geo WHERE client_ip IN ({placeholders})",
                unique_ips,
            ).fetchall()
        }
        missing = [ip for ip in unique_ips if ip not in existing]
        if not missing:
            return 0

        rows = []
        for client_ip in missing:
            geo = lookup_ip_country(client_ip)
            rows.append(
                (
                    client_ip,
                    geo.get("country_code"),
                    geo.get("country_name"),
                    1 if geo.get("is_private_or_unknown") else 0,
                    geo.get("lookup_source"),
                )
            )
        _insert_ip_geo_rows(conn, rows)
    logger.info("Upserted %d GeoIP records", len(rows))
    return len(rows)


def ensure_ip_geo(client_ip: str | None) -> dict | None:
    if not client_ip:
        return None

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM ip_geo WHERE client_ip = ?",
            (client_ip,),
        ).fetchone()
        if row:
            return dict(row)

    upsert_ip_geo([client_ip])

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM ip_geo WHERE client_ip = ?",
            (client_ip,),
        ).fetchone()
    return dict(row) if row else None


def backfill_ip_geo(limit: int = 5000) -> int:
    """Enrich IPs found in ip_summary.json files that are missing from ip_geo."""
    all_ips: set[str] = set()
    if PROJECTS_ROOT.exists():
        for f in PROJECTS_ROOT.glob("*/uploads/*/ip_summary.json"):
            try:
                with open(f, encoding="utf-8") as fh:
                    all_ips.update(json.load(fh).get("ips", {}).keys())
            except Exception:
                pass
    if not all_ips:
        return 0
    all_ips_list = sorted(all_ips)[:limit]
    placeholders = ",".join(["?"] * len(all_ips_list))
    with _get_conn() as conn:
        existing = {
            row[0]
            for row in conn.execute(
                f"SELECT client_ip FROM ip_geo WHERE client_ip IN ({placeholders})",
                all_ips_list,
            ).fetchall()
        }
    missing = [ip for ip in all_ips_list if ip not in existing]
    return upsert_ip_geo(missing) if missing else 0


def get_geo_summary(limit: int = 10, project_id: str | None = None) -> dict:
    # Ensure IPs from uploads are in the ip_geo cache
    backfill_ip_geo()

    # Aggregate detection counts per IP from rule_matches.json files
    matches = _load_all_matches(project_id)
    ip_counts:   dict[str, int]       = {}
    ip_severity: dict[str, dict]      = {}
    for m in matches:
        ip = m.get("client_ip")
        if not ip:
            continue
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        sev = (m.get("severity") or "unknown").lower()
        if ip not in ip_severity:
            ip_severity[ip] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        ip_severity[ip][sev] = ip_severity[ip].get(sev, 0) + 1

    # Fetch geo for known IPs
    if ip_counts:
        all_ips = list(ip_counts.keys())
        ph = ",".join(["?"] * len(all_ips))
        with _get_conn() as conn:
            geo_rows = conn.execute(
                f"SELECT client_ip, country_code, country_name, is_private_or_unknown "
                f"FROM ip_geo WHERE client_ip IN ({ph})",
                all_ips,
            ).fetchall()
        geo_map = {r["client_ip"]: dict(r) for r in geo_rows}
    else:
        geo_map = {}

    # Aggregate by country
    country_agg: dict[str, dict] = {}
    for ip, count in ip_counts.items():
        geo     = geo_map.get(ip, {})
        cc      = geo.get("country_code") or "ZZ"
        cn      = geo.get("country_name") or "Unknown"
        is_priv = int(geo.get("is_private_or_unknown") or 1)
        if is_priv:
            cc = "ZZ"; cn = "Private / Unknown"
        if cc not in country_agg:
            country_agg[cc] = {
                "country_code":          cc,
                "country_name":          cn,
                "is_private_or_unknown": is_priv,
                "detection_count":       0,
                "unique_ips":            set(),
                "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
            }
        country_agg[cc]["detection_count"] += count
        country_agg[cc]["unique_ips"].add(ip)
        sev_data = ip_severity.get(ip, {})
        for sev in ("critical", "high", "medium", "low"):
            country_agg[cc][f"{sev}_count"] += sev_data.get(sev, 0)

    countries = []
    for v in country_agg.values():
        c = dict(v)
        c["unique_ips"] = len(v["unique_ips"])
        countries.append(c)
    countries.sort(key=lambda x: -x["detection_count"])

    geolocated = [c for c in countries if c["country_code"] != "ZZ" and not c["is_private_or_unknown"]]
    unknown    = [c for c in countries if c["country_code"] == "ZZ" or c["is_private_or_unknown"]]

    total_det  = sum(c["detection_count"] for c in countries)
    geo_det    = sum(c["detection_count"] for c in geolocated)
    unk_det    = sum(c["detection_count"] for c in unknown)
    top_country  = geolocated[0] if geolocated else None
    coverage_pct = round((geo_det / total_det) * 100, 1) if total_det else 0.0

    return {
        "countries_impacted":      len(geolocated),
        "total_detections":        total_det,
        "geolocated_detections":   geo_det,
        "unknown_detections":      unk_det,
        "coverage_pct":            coverage_pct,
        "top_source_country":      top_country,
        "countries":               geolocated,
        "top_countries":           geolocated[:limit],
        "backfilled_ip_count":     0,
    }


def get_stats(project_id: str | None = None) -> dict:
    matches = _load_all_matches(project_id)
    by_severity: dict[str, int] = {}
    ip_ctr:      dict[str, int] = {}
    for m in matches:
        sev = (m.get("severity") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        ip = m.get("client_ip")
        if ip:
            ip_ctr[ip] = ip_ctr.get(ip, 0) + 1
    top_ips = sorted(ip_ctr.items(), key=lambda x: -x[1])[:10]
    return {
        "total_detections":       len(matches),
        "detections_by_severity": by_severity,
        "top_offending_ips":      [{"client_ip": ip, "hit_count": c} for ip, c in top_ips],
    }


def get_ip_summary(client_ip: str, project_id: str | None = None) -> dict:
    """Return aggregated stats for a single IP from ip_summary.json files."""
    geo = ensure_ip_geo(client_ip)
    ips = _load_ip_summaries(project_id)
    s   = ips.get(client_ip)
    if s:
        return {
            "client_ip":           client_ip,
            "country_code":        geo.get("country_code") if geo else None,
            "country_name":        geo.get("country_name") if geo else "Unknown",
            **s,
        }
    return {
        "client_ip":           client_ip,
        "country_code":        geo.get("country_code") if geo else None,
        "country_name":        geo.get("country_name") if geo else "Unknown",
        "request_count":       0,
        "unique_paths":        0,
        "first_seen":          None,
        "last_seen":           None,
        "user_agents":         [],
        "status_distribution": {},
        "top_paths":           [],
    }


def insert_pipeline_run(run_id: str, source_file: str = "", file_size: int = 0) -> None:
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO pipeline_runs (run_id, source_file, file_size, status) VALUES (?, ?, ?, 'pending')",
            (run_id, source_file, file_size),
        )


def update_pipeline_run(
    run_id: str,
    status: str,
    entries:    int | None = None,
    detections: int | None = None,
    anomalies:  int | None = None,
    error_msg:  str | None = None,
) -> None:
    """Update status and result counts for an existing pipeline run."""
    with _get_conn() as conn:
        conn.execute("""
            UPDATE pipeline_runs
               SET status      = ?,
                   finished_at = strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                   entries     = COALESCE(?, entries),
                   detections  = COALESCE(?, detections),
                   anomalies   = COALESCE(?, anomalies),
                   error_msg   = COALESCE(?, error_msg)
             WHERE run_id = ?
        """, (status, entries, detections, anomalies, error_msg, run_id))


def get_pipeline_runs(limit: int = 50) -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_pipeline_run(run_id: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM pipeline_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return dict(row) if row else None


def bulk_insert_logs(entries: list[dict], upload_id: str | None = None, project_id: str | None = None) -> int:
    return 0  # no-op: raw log entries are not stored in the database


def insert_behavioral_aggregations(
    upload_id:       str | None,
    project_id:      str | None,
    summary:         dict,
    rate_buckets:    dict,
    enum_buckets_c:  dict,
    enum_buckets_p:  dict,
    status_buckets:  dict,
    visitor_buckets: dict,
    hour_totals:     dict,
    ip_summaries:    dict,
) -> None:
    pass  # no-op: aggregations are written to JSON files by process_logs.py


def get_log_time_range(project_id: str | None = None) -> dict:
    summaries = _load_log_summaries(project_id)
    if not summaries:
        return {"min_timestamp": None, "max_timestamp": None, "total_logs": 0}
    min_ts = min((s["min_ts"] for s in summaries if s.get("min_ts")), default=None)
    max_ts = max((s["max_ts"] for s in summaries if s.get("max_ts")), default=None)
    total  = sum(s.get("total_count", 0) for s in summaries)
    return {"min_timestamp": min_ts, "max_timestamp": max_ts, "total_logs": total}


def get_log_count() -> int:
    total = 0
    if PROJECTS_ROOT.exists():
        for f in PROJECTS_ROOT.glob("*/uploads/*/log_summary.json"):
            try:
                with open(f, encoding="utf-8") as fh:
                    total += json.load(fh).get("total_count", 0)
            except Exception:
                pass
    return total


def insert_upload_status(
    upload_id:  str,
    project_id: str | None = None,
    filename:   str | None = None,
    time_from:  str | None = None,
    time_to:    str | None = None,
) -> None:
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO upload_status (upload_id, project_id, filename, time_range_start, time_range_end, stage, status) "
            "VALUES (?, ?, ?, ?, ?, 'uploading', 'running')",
            (upload_id, project_id, filename, time_from, time_to),
        )


def get_uploads_for_project(project_id: str) -> list[dict]:
    """Return all upload records for a given project, newest first."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT upload_id, filename, stage, status, entry_count, started_at, updated_at "
            "FROM upload_status WHERE project_id = ? ORDER BY started_at DESC",
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def update_upload_status(
    upload_id:   str,
    stage:       str,
    status:      str,
    entry_count: int | None = None,
    error_msg:   str | None = None,
) -> None:
    """Update the current stage and status for an upload."""
    with _get_conn() as conn:
        conn.execute("""
            UPDATE upload_status
               SET stage       = ?,
                   status      = ?,
                   entry_count = COALESCE(?, entry_count),
                   error_msg   = COALESCE(?, error_msg),
                   updated_at  = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE upload_id = ?
        """, (stage, status, entry_count, error_msg, upload_id))


def get_upload_status(upload_id: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM upload_status WHERE upload_id = ?", (upload_id,)
        ).fetchone()
    return dict(row) if row else None


def delete_upload_for_project(project_id: str, upload_id: str) -> int:
    """Delete a specific upload status row scoped to a project.

    Returns the number of deleted rows (0 or 1).
    """
    with _get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM upload_status WHERE project_id = ? AND upload_id = ?",
            (project_id, upload_id),
        )
    return int(cur.rowcount or 0)


def bulk_insert_crs_matches(matches: list[dict], run_id: str | None = None, project_id: str | None = None) -> int:
    return 0  # no-op: CRS matches are written to rule_matches.json by rule_pipeline.py


def query_crs_matches(
    client_ip:  str | None = None,
    rule_id:    str | None = None,
    min_score:  float | None = None,
    limit:      int = 500,
    offset:     int = 0,
) -> list[dict]:
    return []  # CRS matches now live in rule_matches.json files


def get_crs_stats() -> dict:
    return {
        "total_crs_matches": 0,
        "unique_crs_rules":  0,
        "unique_crs_ips":    0,
        "max_anomaly_score": 0.0,
        "top_crs_rules":     [],
        "top_crs_ips":       [],
    }


# ── Behavioral alerts ─────────────────────────────────────────────────────────

def bulk_insert_behavioral_alerts(alerts: list[dict], project_id: str | None = None) -> int:
    return 0  # no-op: behavioral analysis now writes behavioral_results.json directly


def get_behavioral_alerts(
    alert_type: str | None = None,
    client_ip:  str | None = None,
    project_id: str | None = None,
    start_ts:   str | None = None,
    end_ts:     str | None = None,
    limit:      int = 1000,
    offset:     int = 0,
) -> list[dict]:
    """Fetch behavioral alerts from behavioral_results.json files."""
    results_path = PROJECTS_ROOT / (project_id or "") / "detection_results" / "behavioral_results.json"
    all_alerts: list[dict] = []
    candidates = [results_path] if project_id else list(PROJECTS_ROOT.glob("*/detection_results/behavioral_results.json"))
    for p in candidates:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
            pid = p.parent.parent.name
            for key in ("request_rate_spikes", "url_enumeration", "status_code_spikes", "visitor_rates"):
                for item in data.get(key, []):
                    all_alerts.append({**item, "alert_type": key, "project_id": pid})
        except Exception:
            pass

    filtered = all_alerts
    if alert_type:
        filtered = [a for a in filtered if a.get("alert_type") == alert_type]
    if client_ip:
        filtered = [a for a in filtered if a.get("client_ip") == client_ip]
    if start_ts:
        filtered = [a for a in filtered if (a.get("window_start") or "") >= start_ts]
    if end_ts:
        filtered = [a for a in filtered if (a.get("window_start") or "") <= end_ts]
    return filtered[offset: offset + limit]


def get_behavioral_summary() -> dict:
    """Aggregate alert counts per type from behavioral_results.json files."""
    all_alerts = get_behavioral_alerts()
    by_type: dict[str, int] = {}
    ip_counts: dict[str, int] = {}
    for a in all_alerts:
        at = a.get("alert_type", "unknown")
        by_type[at] = by_type.get(at, 0) + 1
        ip = a.get("client_ip")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    return {
        "total_behavioral_alerts": len(all_alerts),
        "by_type":                 by_type,
        "top_ips":                 [{"client_ip": ip, "alert_count": cnt} for ip, cnt in top_ips],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Users
# ─────────────────────────────────────────────────────────────────────────────

def get_user_count() -> int:
    with _get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(
    username:        str,
    email:           str,
    hashed_password: str,
    role:            str = "user",
) -> dict:
    """Insert a new user and return the created row as a dict."""
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, email, hashed_password, role) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, role),
        )
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
    return dict(row)


def get_user_by_username(username: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_email(email: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, username, email, role, is_active, created_at "
            "FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def set_user_active(user_id: int, is_active: int) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE users SET is_active = ? WHERE id = ?", (is_active, user_id)
        )


def set_user_role(user_id: int, role: str) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (role, user_id)
        )


def delete_user(user_id: int) -> None:
    with _get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ─────────────────────────────────────────────────────────────────────────────
# Projects
# ─────────────────────────────────────────────────────────────────────────────

def create_project(project_id: str, name: str, description: str, owner_id: int, project_type: str = "web") -> dict:
    """Create a project record (web or windows) and return it as a dict."""
    if project_type not in ("web", "windows"):
        raise ValueError(f"Invalid project_type '{project_type}'. Must be 'web' or 'windows'.")
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, name, description, owner_id, project_type) VALUES (?, ?, ?, ?, ?)",
            (project_id, name, description, owner_id, project_type),
        )
        row = conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
    return dict(row)


def get_project(project_id: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
    return dict(row) if row else None


def list_projects_for_user(owner_id: int, project_type: str | None = None) -> list[dict]:
    """List projects for a user, optionally filtered by type."""
    with _get_conn() as conn:
        if project_type:
            rows = conn.execute(
                "SELECT * FROM projects WHERE owner_id = ? AND project_type = ? ORDER BY created_at DESC",
                (owner_id, project_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM projects WHERE owner_id = ? ORDER BY created_at DESC",
                (owner_id,),
            ).fetchall()
    return [dict(r) for r in rows]


def list_all_projects() -> list[dict]:
    """Admin view — all projects with owner username."""
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT p.*, u.username AS owner_username
               FROM projects p
               LEFT JOIN users u ON p.owner_id = u.id
               ORDER BY p.created_at DESC""",
        ).fetchall()
    return [dict(r) for r in rows]


def _list_projects_with_type(project_id: str | None = None) -> list[dict]:
    with _get_conn() as conn:
        if project_id:
            rows = conn.execute(
                "SELECT id, project_type FROM projects WHERE id = ?",
                (project_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, project_type FROM projects ORDER BY created_at DESC",
            ).fetchall()
    return [dict(r) for r in rows]


def _read_rule_matches_detector(path: Path) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        detector = data.get("detector")
        return str(detector).lower() if detector else None
    except Exception:
        return None


def scan_mixed_project_artifacts(project_id: str | None = None) -> dict:
    """Scan projects for artifacts that conflict with their immutable project_type."""
    projects = _list_projects_with_type(project_id)
    issues: list[dict] = []
    category_counts: dict[str, int] = {}

    def add_issue(pid: str, ptype: str, category: str, path: Path) -> None:
        category_counts[category] = category_counts.get(category, 0) + 1
        issues.append(
            {
                "project_id": pid,
                "project_type": ptype,
                "category": category,
                "path": str(path),
            }
        )

    for project in projects:
        pid = project["id"]
        ptype = (project.get("project_type") or "web").lower()
        base = PROJECTS_ROOT / pid
        if not base.exists():
            continue

        for f in base.glob("uploads/*/windows_sigma_matches.json"):
            if ptype == "web":
                add_issue(pid, ptype, "windows_sigma_artifact_in_web_project", f)

        for f in base.glob("uploads/*/windows_ml_anomalies.json"):
            if ptype == "web":
                add_issue(pid, ptype, "windows_ml_artifact_in_web_project", f)

        for f in base.glob("uploads/*/rule_matches.json"):
            detector = _read_rule_matches_detector(f)
            if detector == "sigma" and ptype == "web":
                add_issue(pid, ptype, "sigma_rule_matches_in_web_project", f)
            if detector == "crs" and ptype == "windows":
                add_issue(pid, ptype, "crs_rule_matches_in_windows_project", f)

        behavioral_file = base / "detection_results" / "behavioral_results.json"
        if ptype == "windows" and behavioral_file.exists():
            add_issue(pid, ptype, "web_behavioral_artifact_in_windows_project", behavioral_file)

    return {
        "status": "ok",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "projects_scanned": len(projects),
        "projects_with_issues": len({i["project_id"] for i in issues}),
        "issue_count": len(issues),
        "categories": category_counts,
        "issues": issues,
    }


def cleanup_mixed_project_artifacts(
    project_id: str | None = None,
    dry_run: bool = True,
    archive: bool = True,
) -> dict:
    """Remove or archive mixed artifacts detected by scan_mixed_project_artifacts."""
    report = scan_mixed_project_artifacts(project_id=project_id)
    issues = report.get("issues", [])

    unique_paths = sorted({i.get("path") for i in issues if i.get("path")})
    actions: list[dict] = []
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_root = PROJECTS_ROOT / "_cleanup_archive" / ts

    for raw in unique_paths:
        src = Path(str(raw))
        if not src.exists() or not src.is_file():
            actions.append({"path": str(src), "action": "skipped_missing"})
            continue

        if dry_run:
            actions.append({
                "path": str(src),
                "action": "would_archive" if archive else "would_delete",
            })
            continue

        if archive:
            try:
                rel = src.relative_to(PROJECTS_ROOT)
                dst = archive_root / rel
            except Exception:
                dst = archive_root / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            actions.append({"path": str(src), "action": "archived", "archived_to": str(dst)})
        else:
            src.unlink(missing_ok=True)
            actions.append({"path": str(src), "action": "deleted"})

    return {
        "status": "ok",
        "mode": "dry_run" if dry_run else "apply",
        "archive": archive,
        "scan": report,
        "action_count": len(actions),
        "actions": actions,
    }


def delete_project(project_id: str) -> None:
    """Delete a project and all its associated DB rows (JSON data removed by caller)."""
    with _get_conn() as conn:
        conn.execute("DELETE FROM upload_status WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM pipeline_runs WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM ip_geo WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))


def update_project_last_run(project_id: str) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE projects SET last_run_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') "
            "WHERE id = ?",
            (project_id,),
        )


def get_project_stats(project_id: str) -> dict:
    """Quick summary counts scoped to a project (file-based)."""
    summaries = _load_log_summaries(project_id)
    log_count = sum(s.get("total_count", 0) for s in summaries)
    matches = _load_all_matches(project_id)
    det_count = len(matches)
    crs_count = sum(1 for m in matches if m.get("source") == "crs")
    return {
        "log_entries": log_count,
        "detections":  det_count,
        "crs_matches": crs_count,
    }


def set_project_api_key(project_id: str, api_key: str) -> None:
    """Store (or replace) the agent API key for a project."""
    with _get_conn() as conn:
        conn.execute(
            "UPDATE projects SET api_key = ? WHERE id = ?",
            (api_key, project_id),
        )


def get_project_agent_log_paths(project_id: str) -> list[str]:
    """Return configured agent log paths for a project (empty list when unset)."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT agent_log_paths FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()

    if not row:
        return []

    raw = row[0]
    if not raw:
        return []

    try:
        values = json.loads(raw)
    except Exception:
        return []

    if not isinstance(values, list):
        return []

    cleaned: list[str] = []
    for item in values:
        if not isinstance(item, str):
            continue
        path = item.strip()
        if path and path not in cleaned:
            cleaned.append(path)
    return cleaned


def set_project_agent_log_paths(project_id: str, log_paths: list[str]) -> None:
    """Store per-project agent log paths and set an update timestamp."""
    normalized = [p.strip() for p in log_paths if isinstance(p, str) and p.strip()]
    payload = json.dumps(normalized)
    with _get_conn() as conn:
        conn.execute(
            "UPDATE projects "
            "SET agent_log_paths = ?, agent_config_updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') "
            "WHERE id = ?",
            (payload, project_id),
        )


def get_project_by_api_key(api_key: str) -> dict | None:
    """Look up a project by its agent API key. Returns None if not found."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM projects WHERE api_key = ?",
            (api_key,),
        ).fetchone()
    return dict(row) if row else None


# ─────────────────────────────────────────────────────────────────────────────
# Server-side aggregations for dashboard (avoids client-side truncation)
# ─────────────────────────────────────────────────────────────────────────────

def get_overview_stats(
    project_id: str | None = None,
    upload_id:  str | None = None,
    start_ts:   str | None = None,
    end_ts:     str | None = None,
) -> dict:
    """Return dashboard overview data computed from JSON files."""

    def _parse_iso_ts(ts: str | None) -> datetime | None:
        raw = (ts or "").strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    def _in_range(ts: str | None, start: datetime | None, end: datetime | None) -> bool:
        dt = _parse_iso_ts(ts)
        if dt is None:
            return False
        if start and dt < start:
            return False
        if end and dt > end:
            return False
        return True

    # ── Log summary stats ─────────────────────────────────────────────────
    summaries = _load_log_summaries(project_id, upload_id)
    ip_summaries = _load_ip_summaries(project_id, upload_id)
    fallback_entries: list[dict] = []

    if summaries:
        total_logs = sum(s.get("total_count", 0) for s in summaries)
        all_min = [s["min_ts"] for s in summaries if s.get("min_ts")]
        all_max = [s["max_ts"] for s in summaries if s.get("max_ts")]
        min_ts_val = min(all_min) if all_min else None
        max_ts_val = max(all_max) if all_max else None
    else:
        fallback_entries = _load_normalized_entries(project_id, upload_id)
        timestamps = [entry.get("timestamp") for entry in fallback_entries if entry.get("timestamp")]
        total_logs = len(fallback_entries)
        min_ts_val = min(timestamps) if timestamps else None
        max_ts_val = max(timestamps) if timestamps else None

    if ip_summaries:
        unique_ips = len(ip_summaries)
    else:
        if not fallback_entries:
            fallback_entries = _load_normalized_entries(project_id, upload_id)
        unique_ips = len({entry.get("client_ip") for entry in fallback_entries if entry.get("client_ip")})

    # ── Detection stats (from rule_matches.json) ──────────────────────────
    matches = _load_all_matches(project_id, upload_id)
    start_dt = _parse_iso_ts(start_ts)
    end_dt = _parse_iso_ts(end_ts)
    if start_dt or end_dt:
        matches = [m for m in matches if _in_range(m.get("timestamp"), start_dt, end_dt)]

    total_det = len(matches)
    # Count unique log entries that triggered at least one rule.
    # A log entry is identified by (timestamp, client_ip, method, path).
    unique_flagged_entries = len({
        (m.get("timestamp", ""), m.get("client_ip", ""), m.get("method", ""), m.get("path", ""))
        for m in matches
    })

    severity_breakdown: dict[str, int] = {}
    rule_hits: dict[str, dict] = {}
    ip_hits: dict[str, int] = {}
    hourly_tl: dict[str, dict[str, int]] = {}
    success_count = 0

    for m in matches:
        sev = (m.get("severity") or "unknown").lower()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        rid = m.get("rule_id", "")
        if rid not in rule_hits:
            rule_hits[rid] = {"rule_id": rid, "rule_title": m.get("rule_title", ""), "severity": sev, "hit_count": 0}
        rule_hits[rid]["hit_count"] += 1

        ip = m.get("client_ip", "")
        ip_hits[ip] = ip_hits.get(ip, 0) + 1

        ts = m.get("timestamp", "")
        if ts and len(ts) >= 13:
            hour = ts[:13] + ":00"
            hourly_tl.setdefault(hour, {})[sev] = hourly_tl.get(hour, {}).get(sev, 0) + 1

        sc = m.get("status_code")
        if sc and 200 <= int(sc) < 300:
            success_count += 1

    top_rules = sorted(rule_hits.values(), key=lambda x: -x["hit_count"])[:10]
    top_ips = [{"client_ip": ip, "hit_count": cnt} for ip, cnt in sorted(ip_hits.items(), key=lambda x: -x[1])[:10]]
    attack_success_rate = round((success_count / total_det) * 100, 1) if total_det else 0.0

    recent_alerts = sorted(
        [m for m in matches if (m.get("severity") or "").lower() in ("critical", "high")],
        key=lambda x: (x.get("timestamp") or ""),
        reverse=True,
    )[:20]

    return {
        "total_logs":              total_logs,
        "min_timestamp":           min_ts_val,
        "max_timestamp":           max_ts_val,
        "unique_ips":              unique_ips,
        "total_detections":        total_det,
        "unique_flagged_entries":  unique_flagged_entries,
        "unique_rules":            len(rule_hits),
        "severity_breakdown":      severity_breakdown,
        "top_ips":                 top_ips,
        "top_rules":               top_rules,
        "hourly_timeline":         hourly_tl,
        "attack_success_rate":     attack_success_rate,
        "recent_alerts":           recent_alerts,
    }


def get_detection_aggregations(
    project_id: str | None = None,
    upload_id:  str | None = None,
    start_ts:   str | None = None,
    end_ts:     str | None = None,
) -> dict:
    """Return pre-computed detection aggregations for the Detections page (file-based)."""

    def _parse_iso_ts(ts: str | None) -> datetime | None:
        raw = (ts or "").strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    def _in_range(ts: str | None, start: datetime | None, end: datetime | None) -> bool:
        dt = _parse_iso_ts(ts)
        if dt is None:
            return False
        if start and dt < start:
            return False
        if end and dt > end:
            return False
        return True

    matches = _load_all_matches(project_id, upload_id)
    start_dt = _parse_iso_ts(start_ts)
    end_dt = _parse_iso_ts(end_ts)
    if start_dt or end_dt:
        matches = [m for m in matches if _in_range(m.get("timestamp"), start_dt, end_dt)]

    severity: dict[str, int] = {}
    rule_hits: dict[str, dict] = {}
    ip_hits: dict[str, int] = {}
    path_hits: dict[str, int] = {}
    methods: dict[str, int] = {}
    status_dist: dict[str, int] = {}
    hourly_tl: dict[str, dict[str, int]] = {}

    for m in matches:
        sev = (m.get("severity") or "unknown").lower()
        severity[sev] = severity.get(sev, 0) + 1

        rid = m.get("rule_id", "")
        if rid not in rule_hits:
            rule_hits[rid] = {"rule_id": rid, "rule_title": m.get("rule_title", ""), "severity": sev, "hit_count": 0}
        rule_hits[rid]["hit_count"] += 1

        ip = m.get("client_ip", "")
        ip_hits[ip] = ip_hits.get(ip, 0) + 1

        path = m.get("path") or m.get("uri", "")
        if path:
            path_hits[path] = path_hits.get(path, 0) + 1

        method = m.get("method") or "unknown"
        methods[method] = methods.get(method, 0) + 1

        sc = m.get("status_code")
        if sc is not None:
            try:
                c = int(sc)
                cls = "2xx" if 200 <= c < 300 else "3xx" if 300 <= c < 400 else "4xx" if 400 <= c < 500 else "5xx" if 500 <= c < 600 else "other"
            except (ValueError, TypeError):
                cls = "other"
            status_dist[cls] = status_dist.get(cls, 0) + 1

        ts = m.get("timestamp", "")
        if ts and len(ts) >= 13:
            hour = ts[:13] + ":00"
            bucket = hourly_tl.setdefault(hour, {})
            bucket[sev] = bucket.get(sev, 0) + 1

    return {
        "total_detections":    len(matches),
        "severity_breakdown":  severity,
        "top_rules":           sorted(rule_hits.values(), key=lambda x: -x["hit_count"])[:10],
        "top_ips":             [{"client_ip": ip, "hit_count": c} for ip, c in sorted(ip_hits.items(), key=lambda x: -x[1])[:10]],
        "top_paths":           [{"path": p, "hit_count": c} for p, c in sorted(path_hits.items(), key=lambda x: -x[1])[:10]],
        "method_distribution": methods,
        "status_distribution": status_dist,
        "hourly_timeline":     hourly_tl,
    }


def get_log_statistics(
    project_id: str | None = None,
    upload_id:  str | None = None,
) -> dict:
    """Return pre-computed log statistics from JSON files."""
    summaries  = _load_log_summaries(project_id, upload_id)
    ip_summaries = _load_ip_summaries(project_id, upload_id)
    rate_buckets = _load_behavioral_key(project_id, "rate_buckets", upload_id)

    if not summaries and not ip_summaries and not rate_buckets:
        entries = _load_normalized_entries(project_id, upload_id)
        ip_agg: dict[str, int] = {}
        path_agg: dict[str, int] = {}
        ua_agg: dict[str, int] = {}
        status_classes: dict[str, int] = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
        hourly_heatmap: dict[int, int] = {}

        for entry in entries:
            client_ip = entry.get("client_ip")
            if client_ip:
                ip_agg[client_ip] = ip_agg.get(client_ip, 0) + 1

            request_path = entry.get("path_clean") or entry.get("request_path") or entry.get("path")
            if request_path:
                path_agg[request_path] = path_agg.get(request_path, 0) + 1

            user_agent = entry.get("user_agent")
            if user_agent:
                ua_agg[user_agent] = ua_agg.get(user_agent, 0) + 1

            status_code = entry.get("status_code")
            try:
                code = int(status_code)
                cls = "2xx" if 200 <= code < 300 else "3xx" if 300 <= code < 400 else "4xx" if 400 <= code < 500 else "5xx" if 500 <= code < 600 else "other"
            except (TypeError, ValueError):
                cls = str(entry.get("status_class") or "other")
                if cls not in status_classes:
                    cls = "other"
            status_classes[cls] = status_classes.get(cls, 0) + 1

            timestamp = entry.get("timestamp") or ""
            if timestamp and len(timestamp) >= 13:
                try:
                    hour = int(timestamp[11:13])
                    hourly_heatmap[hour] = hourly_heatmap.get(hour, 0) + 1
                except (ValueError, IndexError):
                    pass

        bot_keywords = {"bot", "crawler", "spider", "scraper", "wget", "curl", "python", "java", "go-http", "libwww"}
        bot_count = sum(c for ua, c in ua_agg.items() if any(kw in ua.lower() for kw in bot_keywords))
        human_count = sum(c for ua, c in ua_agg.items() if not any(kw in ua.lower() for kw in bot_keywords))

        return {
            "total_entries":   len(entries),
            "unique_ips":      len(ip_agg),
            "hourly_heatmap":  hourly_heatmap,
            "top_ips":         [{"client_ip": ip, "request_count": c} for ip, c in sorted(ip_agg.items(), key=lambda x: -x[1])[:10]],
            "top_paths":       [{"request_path": p, "count": c} for p, c in sorted(path_agg.items(), key=lambda x: -x[1])[:10]],
            "top_user_agents": [{"user_agent": ua, "count": c} for ua, c in sorted(ua_agg.items(), key=lambda x: -x[1])[:10]],
            "status_classes":  status_classes,
            "bot_count":       bot_count,
            "human_count":     human_count,
        }

    total_entries = sum(s.get("total_count", 0) for s in summaries)

    # Unique IPs from ip_summary.json files
    ip_agg: dict[str, int] = {}
    path_agg: dict[str, int] = {}
    ua_agg: dict[str, int] = {}
    status_classes: dict[str, int] = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}

    for ip, info in ip_summaries.items():
        ip_agg[ip] = ip_agg.get(ip, 0) + int(info.get("request_count", 0) or 0)
        for path, count in (info.get("top_paths", {}) or {}).items():
            path_agg[path] = path_agg.get(path, 0) + int(count or 0)
        for user_agent, count in (info.get("user_agents", {}) or {}).items():
            ua_agg[user_agent] = ua_agg.get(user_agent, 0) + int(count or 0)
        for code, count in (info.get("status_distribution", {}) or {}).items():
            normalized_code = str(code)
            if normalized_code in status_classes:
                status_classes[normalized_code] += int(count or 0)
                continue
            try:
                numeric_code = int(normalized_code)
                if 200 <= numeric_code < 300:
                    status_classes["2xx"] += int(count or 0)
                elif 300 <= numeric_code < 400:
                    status_classes["3xx"] += int(count or 0)
                elif 400 <= numeric_code < 500:
                    status_classes["4xx"] += int(count or 0)
                elif 500 <= numeric_code < 600:
                    status_classes["5xx"] += int(count or 0)
                else:
                    status_classes["other"] += int(count or 0)
            except ValueError:
                status_classes["other"] += int(count or 0)

    top_ips = [{"client_ip": ip, "request_count": c} for ip, c in sorted(ip_agg.items(), key=lambda x: -x[1])[:10]]
    top_paths_list = [{"request_path": p, "count": c} for p, c in sorted(path_agg.items(), key=lambda x: -x[1])[:10]]
    top_uas_list = [{"user_agent": ua, "count": c} for ua, c in sorted(ua_agg.items(), key=lambda x: -x[1])[:10]]

    # Hourly heatmap from behavioral_stats.json rate_buckets
    hourly_heatmap: dict[int, int] = {}
    for bucket in rate_buckets:
        ts = bucket.get("window_minute", "")
        if ts and len(ts) >= 13:
            try:
                h = int(ts[11:13])
                hourly_heatmap[h] = hourly_heatmap.get(h, 0) + bucket.get("request_count", 0)
            except (ValueError, IndexError):
                pass

    # Bot heuristic from UAs
    bot_keywords = {"bot", "crawler", "spider", "scraper", "wget", "curl", "python", "java", "go-http", "libwww"}
    bot_count = sum(c for ua, c in ua_agg.items() if any(kw in ua.lower() for kw in bot_keywords))
    human_count = sum(c for ua, c in ua_agg.items() if not any(kw in ua.lower() for kw in bot_keywords))

    return {
        "total_entries":   total_entries,
        "unique_ips":      len(ip_agg),
        "hourly_heatmap":  hourly_heatmap,
        "top_ips":         top_ips,
        "top_paths":       top_paths_list,
        "top_user_agents": top_uas_list,
        "status_classes":  status_classes,
        "bot_count":       bot_count,
        "human_count":     human_count,
    }

