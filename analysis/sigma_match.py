"""
Sigma rule matching functions for log events
"""

FIELD_MAP = {
    "EventID": "event_id",
    "Channel": "channel",
    "Computer": "computer"
}

def check_if_event_matches_selection(event, selection):
    """
    Returns True if all fields in selection match the event.
    Returns False if any field does not match or is missing.
    """
    for sigma_field, expected_value in selection.items():
        our_field = FIELD_MAP.get(sigma_field)
        if our_field is None:
            return False
        actual_value = event.get(our_field)
        if isinstance(actual_value, str) and actual_value.isdigit():
            actual_value = int(actual_value)
        if actual_value != expected_value:
            return False
    return True

def check_if_event_matches_rule(event, rule):
    """
    Returns True if event matches the Sigma rule's selection and condition.
    Only supports rules with condition == 'selection'.
    """
    detection = rule.get("detection", {})
    selection = detection.get("selection")
    condition = detection.get("condition")
    if condition != "selection":
        return False
    if selection is None:
        return False
    return check_if_event_matches_selection(event, selection)
