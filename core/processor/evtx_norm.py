from __future__ import annotations

from typing import Any


_SOURCE_IP_KEYS = [
    "IpAddress",
    "SourceIp",
    "SourceAddress",
    "ClientAddress",
    "SourceNetworkAddress",
    "RemoteAddress",
    "Address",
]

_PLACEHOLDER_VALUES = {
    "",
    "-",
    "--",
    "null",
    "none",
    "n/a",
}

# NXLog transport keys add noise but no detection value.
_DROP_EVENT_DATA_KEYS = {
    "SourceModuleName",
    "SourceModuleType",
}

_SECURITY_FIELD_CANDIDATES: dict[str, list[str]] = {
    "subject_user": ["SubjectUserName", "SubjectUserSid", "AccountName"],
    "target_user": ["TargetUserName", "NewTargetUserName", "TargetUserSid"],
    "workstation_name": ["WorkstationName"],
    "process_name": ["ProcessName", "Image", "Application", "CallerProcessName"],
    "process_id": ["ProcessId", "ProcessID", "ClientProcessId", "CallerProcessId"],
    "parent_process_name": ["ParentProcessName", "ParentImage"],
    "command_line": ["CommandLine", "ProcessCommandLine", "ImagePath"],
    "logon_type": ["LogonType"],
    "logon_id": ["SubjectLogonId", "LogonId"],
    "target_logon_id": ["TargetLogonId"],
    "status": ["Status", "ReturnCode"],
    "sub_status": ["SubStatus"],
    "service_name": ["ServiceName"],
    "task_name": ["TaskName"],
    "object_name": ["ObjectName", "ObjectValueName", "TargetObject"],
}


def _pick_source_ip(event_data: dict[str, Any]) -> str | None:
    for key in _SOURCE_IP_KEYS:
        val = event_data.get(key)
        if isinstance(val, str) and val.strip() and val.strip().lower() not in _PLACEHOLDER_VALUES:
            return val.strip()
    return None


def _clean_value(value: Any) -> Any:
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned.lower() in _PLACEHOLDER_VALUES:
            return None
        return cleaned
    if isinstance(value, list):
        cleaned_list = [v for v in (_clean_value(item) for item in value) if v is not None]
        return cleaned_list or None
    return value


def _clean_event_data(event_data: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in event_data.items():
        if key in _DROP_EVENT_DATA_KEYS:
            continue
        cleaned_value = _clean_value(value)
        if cleaned_value is None:
            continue
        cleaned[key] = cleaned_value
    return cleaned


def _pick_first(event_data: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        value = _clean_value(event_data.get(key))
        if value is not None:
            return value
    return None


def _extract_message(entry: dict[str, Any]) -> str | None:
    message = _clean_value(entry.get("message"))
    if isinstance(message, str):
        return message

    raw = entry.get("raw")
    if isinstance(raw, str):
        first_line = raw.splitlines()[0].strip() if raw else ""
        if first_line and not first_line.startswith("{"):
            return first_line[:400]
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
    event_data = _clean_event_data(event_data)

    event_id = _to_int(entry.get("event_id"))
    auth_user = (
        _clean_value(entry.get("security_user"))
        or _pick_first(event_data, ["TargetUserName", "SubjectUserName", "AccountName"])
    )

    extracted_fields = {
        field: _pick_first(event_data, candidates)
        for field, candidates in _SECURITY_FIELD_CANDIDATES.items()
    }

    return {
        "source": entry.get("source"),
        "log_type": "evtx",
        "server_type": "windows_event",
        "timestamp": entry.get("timestamp"),
        "client_ip": _pick_source_ip(event_data),
        "auth_user": auth_user,
        "event_id": event_id,
        "channel": entry.get("channel"),
        "computer": entry.get("computer"),
        "record_id": _to_int(entry.get("record_id")),
        "level": entry.get("level"),
        "message": _extract_message(entry),
        "event_data": event_data,
        **extracted_fields,
        "category": "windows_event",
        "raw": entry.get("raw"),
    }
