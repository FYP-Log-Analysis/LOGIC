"""
Behavioral traffic analysis — detects volumetric & slow/low-volume attack patterns
by reading per-upload behavioral_stats.json files written by the processing pipeline.

Detections:
  1. Request-rate spikes   — high request count from a single IP in a short window
  2. URL enumeration       — single IP hitting many distinct paths (scanning)
  3. Status-code spikes    — time windows with an unusually high error (4xx/5xx) ratio
  4. Visitor-rate anomalies— hours where unique visitor count is statistically abnormal
"""
from __future__ import annotations

import json
import logging
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import ijson

logger = logging.getLogger(__name__)

PROJECT_ROOT   = Path(__file__).resolve().parents[2]
_PROJECTS_ROOT = PROJECT_ROOT / "data" / "projects"

# ── Default thresholds ─────────────────────────────────────────────────────────────────
RATE_WINDOW_MINUTES  = 1
RATE_THRESHOLD       = 60
ENUM_WINDOW_HOURS    = 1
ENUM_THRESHOLD       = 50
STATUS_WINDOW_MINUTES = 5
STATUS_ERROR_RATIO   = 0.50
VISITOR_ZSCORE       = 2.0


# ── File-scanning helpers ───────────────────────────────────────────────────────────────

def _scan_behavioral_stats(project_id: str | None, key: str) -> list:
    """Load and merge a specific bucket list from all uploads for a project."""
    if not project_id:
        return []
    uploads_dir = _PROJECTS_ROOT / project_id / "uploads"
    if not uploads_dir.exists():
        return []
    result: list = []
    for f in uploads_dir.glob("*/behavioral_stats.json"):
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
            result.extend(data.get(key, []))
        except Exception:
            pass
    return result


def _scan_all_behavioral_stats(project_id: str | None) -> dict[str, list]:
    """Load all behavioral buckets from a project's uploads in one pass."""
    keys = [
        "rate_buckets",
        "path_enum_buckets",
        "status_trend_buckets",
        "visitor_trend_buckets",
    ]
    merged: dict[str, list] = {k: [] for k in keys}
    if not project_id:
        return merged
    uploads_dir = _PROJECTS_ROOT / project_id / "uploads"
    if not uploads_dir.exists():
        return merged

    upload_dirs = [p for p in uploads_dir.iterdir() if p.is_dir()]
    for udir in upload_dirs:
        stats_path = udir / "behavioral_stats.json"
        if not stats_path.exists():
            normalized_path = udir / "normalized.json"
            if normalized_path.exists():
                generated = _build_behavioral_stats_from_normalized(normalized_path)
                if any(generated.values()):
                    try:
                        payload = {
                            "upload_id": udir.name,
                            "project_id": project_id,
                            **generated,
                        }
                        with open(stats_path, "w", encoding="utf-8") as fh:
                            json.dump(payload, fh)
                    except Exception:
                        pass

        if not stats_path.exists():
            continue
        try:
            with open(stats_path, encoding="utf-8") as fh:
                data = json.load(fh)
            for k in keys:
                merged[k].extend(data.get(k, []))
        except Exception:
            continue
    return merged


def _build_behavioral_stats_from_normalized(normalized_path: Path) -> dict[str, list]:
    """Generate behavioral bucket arrays from normalized.json for legacy uploads."""
    rate: dict[tuple[str, str], int] = defaultdict(int)
    enum_count: dict[tuple[str, str], int] = defaultdict(int)
    enum_paths: dict[tuple[str, str], set[str]] = defaultdict(set)
    status: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    visitors: dict[str, set[str]] = defaultdict(set)
    hour_totals: dict[str, int] = defaultdict(int)

    try:
        with open(normalized_path, "rb") as fh:
            for e in ijson.items(fh, "item"):
                if e.get("server_type") == "windows_event":
                    continue
                ts = e.get("timestamp") or ""
                ip = e.get("client_ip") or ""
                if not ts or not ip:
                    continue
                min_bucket = ts[:16]
                hour_bucket = ts[:13] + ":00"
                path = e.get("path_clean") or e.get("request_path") or ""
                status_code = int(e.get("status_code") or 0)

                rate[(ip, min_bucket)] += 1
                enum_count[(ip, hour_bucket)] += 1
                if path and len(enum_paths[(ip, hour_bucket)]) < 20:
                    enum_paths[(ip, hour_bucket)].add(path)
                status[min_bucket][0] += 1
                if status_code >= 400:
                    status[min_bucket][1] += 1
                visitors[hour_bucket].add(ip)
                hour_totals[hour_bucket] += 1
    except Exception:
        return {
            "rate_buckets": [],
            "path_enum_buckets": [],
            "status_trend_buckets": [],
            "visitor_trend_buckets": [],
        }

    return {
        "rate_buckets": [
            {"client_ip": ip, "window_minute": mb, "request_count": c}
            for (ip, mb), c in rate.items()
        ],
        "path_enum_buckets": [
            {
                "client_ip": ip,
                "window_hour": hb,
                "distinct_paths": len(enum_paths.get((ip, hb), set())),
                "total_requests": c,
                "sample_paths": list(enum_paths.get((ip, hb), set())),
            }
            for (ip, hb), c in enum_count.items()
        ],
        "status_trend_buckets": [
            {"window_minute": mb, "total_requests": v[0], "error_count": v[1]}
            for mb, v in status.items()
        ],
        "visitor_trend_buckets": [
            {"window_hour": hb, "unique_visitors": len(ips), "total_requests": hour_totals.get(hb, 0)}
            for hb, ips in visitors.items()
        ],
    }


# ── 1. Request-rate spikes ───────────────────────────────────────────────────────────────

def compute_request_rate_spikes(
    window_minutes: int   = RATE_WINDOW_MINUTES,
    threshold:      int   = RATE_THRESHOLD,
    start_ts:       str | None = None,
    end_ts:         str | None = None,
    project_id:     str | None = None,
    buckets:        list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    bkts = buckets if buckets is not None else _scan_behavioral_stats(project_id, "rate_buckets")
    if not bkts:
        return []
    if start_ts:
        bkts = [b for b in bkts if b["window_minute"] >= start_ts[:16]]
    if end_ts:
        bkts = [b for b in bkts if b["window_minute"] <= end_ts[:16]]
    if not bkts:
        return []

    if window_minutes == 1:
        results = [
            {
                "client_ip":      b["client_ip"],
                "window_start":   b["window_minute"],
                "request_count":  b["request_count"],
                "threshold_used": threshold,
                "window_minutes": window_minutes,
                "is_anomaly":     True,
            }
            for b in bkts
            if b["request_count"] >= threshold
        ]
    else:
        agg: dict[tuple, int] = {}
        for b in bkts:
            try:
                dt_part, hm = b["window_minute"].split("T")
                h, m = hm.split(":")
                wider_m = (int(m) // window_minutes) * window_minutes
                bucket  = f"{dt_part}T{h}:{wider_m:02d}"
            except Exception:
                bucket = b["window_minute"]
            key = (b["client_ip"], bucket)
            agg[key] = agg.get(key, 0) + b["request_count"]
        results = [
            {
                "client_ip":      ip,
                "window_start":   bucket,
                "request_count":  count,
                "threshold_used": threshold,
                "window_minutes": window_minutes,
                "is_anomaly":     True,
            }
            for (ip, bucket), count in agg.items()
            if count >= threshold
        ]

    results.sort(key=lambda x: -x["request_count"])
    return results[:500]


# ── 2. URL enumeration (scanning) ─────────────────────────────────────────────────────

def compute_url_enumeration(
    window_hours: int = ENUM_WINDOW_HOURS,
    threshold:    int = ENUM_THRESHOLD,
    start_ts:     str | None = None,
    end_ts:       str | None = None,
    project_id:   str | None = None,
    buckets:      list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    bkts = buckets if buckets is not None else _scan_behavioral_stats(project_id, "path_enum_buckets")
    if not bkts:
        return []
    if start_ts:
        bkts = [b for b in bkts if b["window_hour"] >= start_ts[:13] + ":00"]
    if end_ts:
        bkts = [b for b in bkts if b["window_hour"] <= end_ts[:13] + ":00"]
    if not bkts:
        return []

    if window_hours == 1:
        results = [
            {
                "client_ip":       b["client_ip"],
                "window_start":    b["window_hour"],
                "distinct_paths":  b["distinct_paths"],
                "total_requests":  b["total_requests"],
                "sample_paths":    b.get("sample_paths", []),
                "threshold_used":  threshold,
                "window_hours":    window_hours,
                "is_anomaly":      True,
            }
            for b in bkts
            if b["distinct_paths"] >= threshold
        ]
    else:
        agg_dp: dict[tuple, int] = {}
        agg_tr: dict[tuple, int] = {}
        for b in bkts:
            try:
                dt_part, h_part = b["window_hour"].split("T")
                h_int   = int(h_part[:2])
                wider_h = (h_int // window_hours) * window_hours
                bucket  = f"{dt_part}T{wider_h:02d}:00"
            except Exception:
                bucket = b["window_hour"]
            key = (b["client_ip"], bucket)
            agg_dp[key] = agg_dp.get(key, 0) + b["distinct_paths"]
            agg_tr[key] = agg_tr.get(key, 0) + b["total_requests"]
        results = [
            {
                "client_ip":       ip,
                "window_start":    bucket,
                "distinct_paths":  dp,
                "total_requests":  agg_tr.get((ip, bucket), 0),
                "sample_paths":    [],
                "threshold_used":  threshold,
                "window_hours":    window_hours,
                "is_anomaly":      True,
            }
            for (ip, bucket), dp in agg_dp.items()
            if dp >= threshold
        ]

    results.sort(key=lambda x: -x["distinct_paths"])
    return results[:500]


# ── 3. Status-code spike windows ───────────────────────────────────────────────────────

def compute_status_code_spikes(
    window_minutes:        int   = STATUS_WINDOW_MINUTES,
    error_ratio_threshold: float = STATUS_ERROR_RATIO,
    start_ts:              str | None = None,
    end_ts:                str | None = None,
    project_id:            str | None = None,
    buckets:               list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    bkts = buckets if buckets is not None else _scan_behavioral_stats(project_id, "status_trend_buckets")
    if not bkts:
        return []
    if start_ts:
        bkts = [b for b in bkts if b["window_minute"] >= start_ts[:16]]
    if end_ts:
        bkts = [b for b in bkts if b["window_minute"] <= end_ts[:16]]
    if not bkts:
        return []

    agg: dict[str, list] = {}
    for b in bkts:
        if window_minutes == 1:
            bucket = b["window_minute"]
        else:
            try:
                dt_part, hm = b["window_minute"].split("T")
                h, m = hm.split(":")
                wider_m = (int(m) // window_minutes) * window_minutes
                bucket  = f"{dt_part}T{h}:{wider_m:02d}"
            except Exception:
                bucket = b["window_minute"]
        if bucket not in agg:
            agg[bucket] = [0, 0]
        agg[bucket][0] += b["total_requests"]
        agg[bucket][1] += b["error_count"]

    results = []
    for bucket, (total, errors) in agg.items():
        if total >= 5:
            ratio = errors / total
            if ratio >= error_ratio_threshold:
                results.append({
                    "window_start":     bucket,
                    "total_requests":   total,
                    "error_count":      errors,
                    "error_ratio":      round(ratio, 4),
                    "top_status_codes": {},
                    "threshold_used":   error_ratio_threshold,
                    "window_minutes":   window_minutes,
                    "is_anomaly":       True,
                })
    results.sort(key=lambda x: (-x["error_ratio"], -x["total_requests"]))
    return results[:500]


# ── 4. Visitor-rate anomalies ─────────────────────────────────────────────────────────────

def compute_visitor_rate_anomalies(
    z_threshold: float = VISITOR_ZSCORE,
    start_ts:    str | None = None,
    end_ts:      str | None = None,
    project_id:  str | None = None,
    buckets:     list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    bkts = buckets if buckets is not None else _scan_behavioral_stats(project_id, "visitor_trend_buckets")
    if not bkts:
        return []
    if start_ts:
        bkts = [b for b in bkts if b["window_hour"] >= start_ts[:13] + ":00"]
    if end_ts:
        bkts = [b for b in bkts if b["window_hour"] <= end_ts[:13] + ":00"]
    if not bkts:
        return []

    bkts.sort(key=lambda b: b["window_hour"])
    counts = [b["unique_visitors"] for b in bkts]

    if len(counts) < 3:
        return [
            {
                "hour":            b["window_hour"],
                "unique_visitors": b["unique_visitors"],
                "total_requests":  b["total_requests"],
                "mean_visitors":   None,
                "std_visitors":    None,
                "z_score":         None,
                "flag":            "insufficient_data",
            }
            for b in bkts
        ]

    mean_v = statistics.mean(counts)
    std_v  = statistics.pstdev(counts)

    results = []
    for b in bkts:
        z    = (b["unique_visitors"] - mean_v) / std_v if std_v > 0 else 0.0
        flag = "normal"
        if z >= z_threshold:
            flag = "high_visitor_rate"
        elif z <= -z_threshold:
            flag = "low_visitor_rate"
        results.append({
            "hour":            b["window_hour"],
            "unique_visitors": b["unique_visitors"],
            "total_requests":  b["total_requests"],
            "mean_visitors":   round(mean_v, 2),
            "std_visitors":    round(std_v, 2),
            "z_score":         round(z, 4),
            "flag":            flag,
            "is_anomaly":      flag not in ("normal", "insufficient_data"),
        })
    return results


# ── Entry point ─────────────────────────────────────────────────────────────────────

def run_behavioral_analysis(
    rate_window_minutes:    int   = RATE_WINDOW_MINUTES,
    rate_threshold:         int   = RATE_THRESHOLD,
    enum_window_hours:      int   = ENUM_WINDOW_HOURS,
    enum_threshold:         int   = ENUM_THRESHOLD,
    status_window_minutes:  int   = STATUS_WINDOW_MINUTES,
    status_error_ratio:     float = STATUS_ERROR_RATIO,
    visitor_zscore:         float = VISITOR_ZSCORE,
    start_ts:               str | None = None,
    end_ts:                 str | None = None,
    project_id:             str | None = None,
) -> dict[str, Any]:
    """Run all four behavioral detections, persist results, return summary dict."""
    logger.info("Starting behavioral analysis …")

    all_buckets = _scan_all_behavioral_stats(project_id)

    rate_spikes     = compute_request_rate_spikes(rate_window_minutes, rate_threshold, start_ts, end_ts, project_id, all_buckets["rate_buckets"])
    url_enum        = compute_url_enumeration(enum_window_hours, enum_threshold, start_ts, end_ts, project_id, all_buckets["path_enum_buckets"])
    status_spikes   = compute_status_code_spikes(status_window_minutes, status_error_ratio, start_ts, end_ts, project_id, all_buckets["status_trend_buckets"])
    visitor_rates   = compute_visitor_rate_anomalies(visitor_zscore, start_ts, end_ts, project_id, all_buckets["visitor_trend_buckets"])

    flagged_visitors = [v for v in visitor_rates if v.get("flag") not in ("normal", "insufficient_data")]

    result = {
        "generated_at":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "start_ts":            start_ts,
        "end_ts":              end_ts,
        "thresholds": {
            "rate_window_minutes":   rate_window_minutes,
            "rate_threshold":        rate_threshold,
            "enum_window_hours":     enum_window_hours,
            "enum_threshold":        enum_threshold,
            "status_window_minutes": status_window_minutes,
            "status_error_ratio":    status_error_ratio,
            "visitor_zscore":        visitor_zscore,
        },
        "summary": {
            "total_rate_spikes":           len(rate_spikes),
            "total_url_enumerators":       len(url_enum),
            "total_status_spikes":         len(status_spikes),
            "total_rate_spike_windows":    len(rate_spikes),
            "total_enumeration_alerts":    len(url_enum),
            "total_status_spike_windows":  len(status_spikes),
            "total_visitor_anomaly_hours": len(flagged_visitors),
        },
        "request_rate_spikes": rate_spikes,
        "url_enumeration":     url_enum,
        "status_code_spikes":  status_spikes,
        "visitor_rates":       visitor_rates,
    }

    # Persist results JSON
    if project_id:
        results_path = PROJECT_ROOT / "data" / "projects" / project_id / "detection_results" / "behavioral_results.json"
        results_path.parent.mkdir(parents=True, exist_ok=True)
        with open(results_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        logger.info(f"Behavioral results written to {results_path}")
    else:
        logger.warning("No project_id provided — skipping results file persistence")

    return result

