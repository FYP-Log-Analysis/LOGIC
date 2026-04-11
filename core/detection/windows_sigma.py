from __future__ import annotations

import os
import re
from fnmatch import fnmatch
from typing import Any, Callable

import yaml

FIELD_MAP = {
    "EventID": "event_id",
    "Channel": "channel",
    "Computer": "computer",
}

_CONDITION_OF_RE = re.compile(r"(?<!\S)(1|all)\s+of\s+([A-Za-z0-9_*]+)(?!\S)", re.IGNORECASE)


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

    event_data = event.get("event_data") or {}
    if not isinstance(event_data, dict):
        event_data = {}

    key_name = sigma_field
    if sigma_field.startswith("EventData."):
        key_name = sigma_field.split(".", 1)[1]

    for candidate in (key_name, key_name.lower()):
        if candidate in event:
            return event.get(candidate)

    for k, value in event_data.items():
        if str(k).lower() == key_name.lower():
            return value

    return None


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def _string_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _expected_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _match_equality(actual: Any, expected: Any) -> bool:
    normalized_expected = [_normalize_scalar(v) for v in _expected_list(expected)]
    if isinstance(actual, list):
        normalized_actual = [_normalize_scalar(v) for v in actual]
        return any(item in normalized_expected for item in normalized_actual)
    normalized_actual = _normalize_scalar(actual)
    return any(normalized_actual == candidate for candidate in normalized_expected)


def _match_text_operator(actual: Any, expected: Any, operator: str, require_all: bool) -> bool:
    actual_values = [s.lower() for s in _string_values(actual)]
    expected_values = [str(v).lower() for v in _expected_list(expected)]
    if not actual_values or not expected_values:
        return False

    def _token_match(actual_text: str, token: str) -> bool:
        if operator == "contains":
            return token in actual_text
        if operator == "startswith":
            return actual_text.startswith(token)
        if operator == "endswith":
            return actual_text.endswith(token)
        return False

    if require_all:
        return all(any(_token_match(actual_text, token) for actual_text in actual_values) for token in expected_values)
    return any(_token_match(actual_text, token) for actual_text in actual_values for token in expected_values)


def _match_regex(actual: Any, expected: Any) -> bool:
    patterns = [str(v) for v in _expected_list(expected)]
    values = _string_values(actual)
    if not patterns or not values:
        return False
    for pattern in patterns:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        if any(regex.search(value) for value in values):
            return True
    return False


def _match_field_condition(event: dict[str, Any], sigma_field: str, expected_value: Any) -> bool:
    parts = sigma_field.split("|")
    field_name = parts[0]
    modifiers = {part.lower() for part in parts[1:]}

    actual_value = _field_value(event, field_name)
    if actual_value is None:
        return False

    require_all = "all" in modifiers
    if "contains" in modifiers:
        return _match_text_operator(actual_value, expected_value, "contains", require_all)
    if "startswith" in modifiers:
        return _match_text_operator(actual_value, expected_value, "startswith", require_all)
    if "endswith" in modifiers:
        return _match_text_operator(actual_value, expected_value, "endswith", require_all)
    if "re" in modifiers:
        return _match_regex(actual_value, expected_value)
    return _match_equality(actual_value, expected_value)


def _match_selection(event: dict[str, Any], selection: Any) -> bool:
    if isinstance(selection, dict):
        for sigma_field, expected_value in selection.items():
            if not _match_field_condition(event, sigma_field, expected_value):
                return False
        return True
    if isinstance(selection, list):
        return any(_match_selection(event, item) for item in selection)
    return False


def _resolve_selector_names(pattern: str, selector_results: dict[str, bool]) -> list[str]:
    if "*" in pattern:
        return [name for name in selector_results if fnmatch(name, pattern)]
    return [pattern] if pattern in selector_results else []


def _evaluate_condition(condition: str, selector_results: dict[str, bool]) -> bool:
    expression = condition.strip()
    if not expression:
        return False

    def _replace_of_clause(match: re.Match[str]) -> str:
        quantifier = match.group(1).lower()
        pattern = match.group(2)
        names = _resolve_selector_names(pattern, selector_results)
        if not names:
            return "False"
        values = [selector_results[name] for name in names]
        return str(any(values) if quantifier == "1" else all(values))

    expression = _CONDITION_OF_RE.sub(_replace_of_clause, expression)

    for name in sorted(selector_results.keys(), key=len, reverse=True):
        expression = re.sub(rf"\b{re.escape(name)}\b", str(selector_results[name]), expression)

    expression = re.sub(r"\s+", " ", expression).strip()
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expression)
    allowed = {"True", "False", "and", "or", "not"}
    if any(token not in allowed for token in tokens):
        return False

    try:
        return bool(eval(expression, {"__builtins__": {}}, {}))
    except Exception:
        return False


def _sigma_severity_v2(rule: dict[str, Any]) -> tuple[str, dict]:
    """Apply risk-based severity mapping for Sigma rules, similar to CRS."""
    level = str(rule.get("level", "medium")).lower()
    severity = level if level in ("critical", "high", "medium", "low") else "medium"
    
    details: dict[str, str | int] = {
        "base_severity": severity,
        "rule_level": level,
    }
    
    # Upgrade severity for high-risk attack types
    tags = [str(t).lower() for t in (rule.get("tags", []) if isinstance(rule.get("tags"), list) else [])]
    title = str(rule.get("title", "")).lower()
    haystack = " ".join(tags + [title])
    
    high_risk_tokens = (
        "execution", "persistence", "privilege_escalation", "defense_evasion",
        "credential_access", "lateral_movement", "command_and_control",
        "mimikatz", "powershell", "ransomware", "backdoor", "exploit"
    )
    
    has_high_risk = any(token in haystack for token in high_risk_tokens)
    
    if has_high_risk and severity == "medium":
        severity = "high"
        details["tag_adjustment"] = "upgrade_to_high"
    
    return severity, details


def check_if_event_matches_selection(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    return _match_selection(event, selection)


def check_if_event_matches_rule(event: dict[str, Any], rule: dict[str, Any]) -> bool:
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        return False

    condition = str(detection.get("condition", "")).strip()
    selectors = {
        key: value
        for key, value in detection.items()
        if key != "condition"
    }
    if not selectors:
        return False

    if not condition:
        if "selection" in selectors:
            return _match_selection(event, selectors["selection"])
        return False

    selector_results = {
        name: _match_selection(event, selector)
        for name, selector in selectors.items()
    }
    return _evaluate_condition(condition, selector_results)


def run_sigma_pipeline(
    log_events: list[dict[str, Any]],
    rules_folder: str,
    should_cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    from core.detection.mitre_mapping import enrich_sigma_match_with_mitre
    
    rules = load_sigma_rules(rules_folder)
    matches: list[dict[str, Any]] = []
    matched_rule_ids: set[str] = set()

    for event_idx, event in enumerate(log_events):
        if should_cancel and event_idx % 100 == 0 and should_cancel():
            return {
                "matches": matches,
                "matched_rules": sorted(matched_rule_ids),
                "total_matches": len(matches),
                "sigma_matches": len(matches),
                "cancelled": True,
                "processed_events": event_idx,
                "total_events": len(log_events),
            }

        for rule in rules:
            if not check_if_event_matches_rule(event, rule):
                continue

            rule_id = str(rule.get("id", "unknown"))
            matched_rule_ids.add(rule_id)
            
            # Calculate both legacy and v2 severity
            legacy_severity = str(rule.get("level", "medium")).lower()
            severity_v2, mapping_details = _sigma_severity_v2(rule)
            
            match = {
                "rule_id": f"SIGMA-{rule_id}",
                "rule_title": f"[SIGMA] {rule.get('title', 'Unnamed Rule')}",
                "severity": severity_v2,
                "severity_legacy": legacy_severity,
                "severity_v2": severity_v2,
                "severity_mapping_version": 2,
                "severity_v2_details": mapping_details,
                "client_ip": event.get("client_ip"),
                "timestamp": event.get("timestamp"),
                "computer": event.get("computer"),
                "event_id": event.get("event_id"),
                "channel": event.get("channel"),
                "entry": event,
                "detector": "sigma",
            }
            
            # Enrich with MITRE ATT&CK mapping
            match = enrich_sigma_match_with_mitre(match, rule)
            matches.append(match)

    return {
        "matches": matches,
        "matched_rules": sorted(matched_rule_ids),
        "total_matches": len(matches),
        "sigma_matches": len(matches),
    }
