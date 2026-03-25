from __future__ import annotations

import os
from typing import Any

import yaml

FIELD_MAP = {
    "EventID": "event_id",
    "Channel": "channel",
    "Computer": "computer",
}


def load_sigma_rules(rules_folder: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    if not os.path.isdir(rules_folder):
        return rules

    for folder, _, files in os.walk(rules_folder):
        for filename in files:
            if not filename.endswith((".yml", ".yaml")):
                continue

            file_path = os.path.join(folder, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    rule = yaml.safe_load(fh) or {}
                if isinstance(rule, dict):
                    rule["source_file"] = file_path
                    rules.append(rule)
            except Exception:
                continue
    return rules


def _field_value(event: dict[str, Any], sigma_field: str) -> Any:
    mapped = FIELD_MAP.get(sigma_field)
    if mapped:
        return event.get(mapped)

    if sigma_field.startswith("EventData."):
        key = sigma_field.split(".", 1)[1]
        event_data = event.get("event_data") or {}
        if isinstance(event_data, dict):
            return event_data.get(key)
        return None

    return event.get(sigma_field) or event.get(sigma_field.lower())


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def check_if_event_matches_selection(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    for sigma_field, expected_value in selection.items():
        actual_value = _normalize_scalar(_field_value(event, sigma_field))
        expected_value = _normalize_scalar(expected_value)
        if actual_value != expected_value:
            return False
    return True


def check_if_event_matches_rule(event: dict[str, Any], rule: dict[str, Any]) -> bool:
    detection = rule.get("detection", {})
    selection = detection.get("selection")
    condition = detection.get("condition")
    if condition != "selection" or selection is None or not isinstance(selection, dict):
        return False
    return check_if_event_matches_selection(event, selection)


def run_sigma_pipeline(log_events: list[dict[str, Any]], rules_folder: str) -> dict[str, Any]:
    rules = load_sigma_rules(rules_folder)
    matches: list[dict[str, Any]] = []
    matched_rule_ids: set[str] = set()

    for event in log_events:
        for rule in rules:
            if not check_if_event_matches_rule(event, rule):
                continue

            rule_id = str(rule.get("id", "unknown"))
            matched_rule_ids.add(rule_id)
            matches.append(
                {
                    "rule_id": f"SIGMA-{rule_id}",
                    "rule_title": f"[SIGMA] {rule.get('title', 'Unnamed Rule')}",
                    "severity": str(rule.get("level", "medium")).lower(),
                    "client_ip": event.get("client_ip"),
                    "timestamp": event.get("timestamp"),
                    "computer": event.get("computer"),
                    "event_id": event.get("event_id"),
                    "channel": event.get("channel"),
                    "entry": event,
                    "detector": "sigma",
                }
            )

    return {
        "matches": matches,
        "matched_rules": sorted(matched_rule_ids),
        "total_matches": len(matches),
        "sigma_matches": len(matches),
    }
