from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import ijson

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _SKLEARN_AVAILABLE = True
except Exception:
    _SKLEARN_AVAILABLE = False

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_ROOT = PROJECT_ROOT / "data" / "projects"


def _parse_dt(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _iter_windows_events(normalized_path: Path):
    with open(normalized_path, "rb") as fh:
        for entry in ijson.items(fh, "item"):
            if entry.get("server_type") == "windows_event":
                yield entry


def _window_key(dt: datetime, window_minutes: int) -> str:
    minute = (dt.minute // window_minutes) * window_minutes
    bucket = dt.replace(minute=minute, second=0, microsecond=0)
    return bucket.isoformat()


def _extract_features(events: list[dict[str, Any]]) -> dict[str, Any]:
    channels = Counter()
    computers = set()
    users = set()
    event_ids = Counter()
    source_ips = set()

    for event in events:
        if event.get("channel"):
            channels[str(event["channel"])] += 1
        if event.get("computer"):
            computers.add(str(event["computer"]))
        if event.get("auth_user"):
            users.add(str(event["auth_user"]))
        if event.get("event_id") is not None:
            event_ids[str(event["event_id"])] += 1
        if event.get("client_ip"):
            source_ips.add(str(event["client_ip"]))

    return {
        "event_count": len(events),
        "unique_event_ids": len(event_ids),
        "security_events": channels.get("Security", 0),
        "system_events": channels.get("System", 0),
        "powershell_events": channels.get("Windows PowerShell", 0) + channels.get("Microsoft-Windows-PowerShell/Operational", 0),
        "unique_computers": len(computers),
        "unique_users": len(users),
        "unique_source_ips": len(source_ips),
    }


def _anomaly_severity(anomaly_score: float | None, is_anomalous: bool) -> str:
    if not is_anomalous or anomaly_score is None:
        return "low"
    if anomaly_score <= -0.20:
        return "critical"
    if anomaly_score <= -0.10:
        return "high"
    return "medium"


def run_windows_ml_analysis(
    project_id: str,
    upload_id: str,
    window_minutes: int = 5,
    start_ts: str | None = None,
    end_ts: str | None = None,
    contamination: float = 0.1,
) -> dict[str, Any]:
    upload_dir = PROJECTS_ROOT / project_id / "uploads" / upload_id
    normalized_path = upload_dir / "normalized.json"
    out_path = upload_dir / "windows_ml_anomalies.json"

    if not normalized_path.exists():
        return {"total_windows": 0, "anomalous_windows": 0, "status": "skipped:no_normalized"}

    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    start_dt = _parse_dt(start_ts)
    end_dt = _parse_dt(end_ts)
    for event in _iter_windows_events(normalized_path):
        ts = _parse_dt(event.get("timestamp"))
        if ts is None:
            continue
        if start_dt and ts < start_dt:
            continue
        if end_dt and ts > end_dt:
            continue
        buckets[_window_key(ts, window_minutes)].append(event)

    if not buckets:
        payload = {
            "project_id": project_id,
            "upload_id": upload_id,
            "window_minutes": window_minutes,
            "total_windows": 0,
            "anomalous_windows": 0,
            "windows": [],
            "status": "skipped:no_windows_events",
        }
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return {"total_windows": 0, "anomalous_windows": 0, "status": "skipped:no_windows_events"}

    rows: list[dict[str, Any]] = []
    for window_start, events in sorted(buckets.items()):
        feature_row = _extract_features(events)
        feature_row["window_start"] = window_start
        rows.append(feature_row)

    if not _SKLEARN_AVAILABLE or len(rows) < 20:
        windows = [
            {
                **row,
                "anomaly_score": None,
                "is_anomalous": False,
                "anomaly_severity": "low",
            }
            for row in rows
        ]
        payload = {
            "project_id": project_id,
            "upload_id": upload_id,
            "window_minutes": window_minutes,
            "total_windows": len(rows),
            "anomalous_windows": 0,
            "windows": windows,
            "status": "ok:insufficient_baseline" if len(rows) < 20 else "ok:sklearn_unavailable",
            "model": {
                "type": "isolation_forest",
                "scaled_features": False,
                "contamination": float(contamination),
                "min_windows_required": 20,
            },
        }
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return {
            "total_windows": len(rows),
            "anomalous_windows": 0,
            "status": payload["status"],
        }

    matrix = [
        [
            r["event_count"],
            r["unique_event_ids"],
            r["security_events"],
            r["system_events"],
            r["powershell_events"],
            r["unique_computers"],
            r["unique_users"],
            r["unique_source_ips"],
        ]
        for r in rows
    ]

    safe_contamination = float(contamination)
    if not (0.0 < safe_contamination < 0.5):
        safe_contamination = 0.1

    scaled_matrix = StandardScaler().fit_transform(matrix)
    model = IsolationForest(
        n_estimators=100,
        contamination=safe_contamination,
        random_state=42,
    )
    model.fit(scaled_matrix)
    scores = model.decision_function(scaled_matrix)
    labels = model.predict(scaled_matrix)

    windows = []
    anomalous = 0
    for idx, row in enumerate(rows):
        is_anomalous = labels[idx] == -1
        anomaly_score = float(scores[idx])
        if is_anomalous:
            anomalous += 1
        windows.append(
            {
                **row,
                "anomaly_score": anomaly_score,
                "is_anomalous": bool(is_anomalous),
                "anomaly_severity": _anomaly_severity(anomaly_score, bool(is_anomalous)),
            }
        )

    payload = {
        "project_id": project_id,
        "upload_id": upload_id,
        "window_minutes": window_minutes,
        "total_windows": len(rows),
        "anomalous_windows": anomalous,
        "windows": windows,
        "status": "ok",
        "model": {
            "type": "isolation_forest",
            "scaled_features": True,
            "contamination": safe_contamination,
            "min_windows_required": 20,
        },
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    return {
        "total_windows": len(rows),
        "anomalous_windows": anomalous,
        "status": "ok",
    }
