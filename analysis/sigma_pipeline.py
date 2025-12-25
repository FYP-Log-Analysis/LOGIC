import os
try:
    from analysis.sigma_load import load_sigma_rules
    from analysis.sigma_match import check_if_event_matches_rule
except ImportError:
    from sigma_load import load_sigma_rules
    from sigma_match import check_if_event_matches_rule

def run_sigma_pipeline(log_events, rules_folder):
    rules = load_sigma_rules(rules_folder)
    match_count = 0
    for event in log_events:
        for rule in rules:
            if check_if_event_matches_rule(event, rule):
                match_count += 1
                print(f"ALERT #{match_count}: Rule: {rule.get('title', 'Unnamed Rule')} Computer: {event.get('computer')} Event ID: {event.get('event_id')} Timestamp: {event.get('timestamp')} Severity: {rule.get('level', 'unknown')}")

def main():
    import json
    events_file = "data/processed/normalized/Security_normalized.json"
    rules_folder = "analysis/detection/sigma/rules"
    if not os.path.exists(events_file):
        print("Error: Events file not found at", events_file)
        return
    if not os.path.exists(rules_folder):
        print("Error: Rules directory not found at", rules_folder)
        return
    with open(events_file, 'r', encoding='utf-8') as f:
        log_events = json.load(f)
    run_sigma_pipeline(log_events, rules_folder)

if __name__ == "__main__":
    main()
