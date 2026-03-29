from __future__ import annotations

from typing import Any


_SOURCE_IP_KEYS = [
    "IpAddress",
    "SourceIp",
    "SourceAddress",
    "ClientAddress",
    "WorkstationName",
]


def _pick_source_ip(event_data: dict[str, Any]) -> str | None:
    for key in _SOURCE_IP_KEYS:
        val = event_data.get(key)
        if isinstance(val, str) and val.strip() and val != "-":
            return val.strip()
    return None


def _to_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def normalise_windows_event(entry: dict[str, Any]) -> dict[str, Any]:
    event_data = entry.get("event_data") or {}
    if not isinstance(event_data, dict):
        event_data = {}

    event_id = _to_int(entry.get("event_id"))

    return {
        "source": entry.get("source"),
        "log_type": "evtx",
        "server_type": "windows_event",
        "timestamp": entry.get("timestamp"),
        "client_ip": _pick_source_ip(event_data),
        "auth_user": entry.get("security_user") or event_data.get("TargetUserName"),
        "event_id": event_id,
        "channel": entry.get("channel"),
        "computer": entry.get("computer"),
        "record_id": _to_int(entry.get("record_id")),
        "level": entry.get("level"),
        "event_data": event_data,
        "category": "windows_event",
        "raw": entry.get("raw"),
    }
