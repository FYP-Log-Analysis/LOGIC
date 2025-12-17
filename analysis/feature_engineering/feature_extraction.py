import json
import math
from pathlib import Path
from collections import Counter

# Files and settings for extracting features from our time windows
INPUT_FILE = "execution_windows.json"
OUTPUT_FILE = "features.json"

# These are the core Windows processes we expect to see running normally
CORE_SYSTEM_PROCESSES = {
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "autochk.exe"
}

def normalize_process(process_path):
    """Just grab the executable name from a full path and make it lowercase for consistency."""
    if process_path is None:
        return None
    return process_path.split("\\")[-1].lower()


def calculate_entropy(process_counter):
    """Calculate how diverse the process activity is using Shannon entropy."""
    total = sum(process_counter.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in process_counter.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy

def extract_features(window):
    events = window.get("events", [])

    processes = []
    parent_processes = []
    users = []
    computers = []

    registry_event_count = 0
    system32_exec_count = 0
    non_system_exec_count = 0
    self_parent_count = 0
    chain_depths = []

    # Go through each event and extract the data we care about
    for event in events:
        process_raw = event.get("process")
        parent_raw = event.get("parent_process")

        user = event.get("user_sid")
        computer = event.get("computer")

        if user is not None:
            users.append(user)

        if computer is not None:
            computers.append(computer)

        # Registry events are weird - handle them separately
        if process_raw == "Registry":
            registry_event_count += 1
            continue

        process_name = normalize_process(process_raw)
        parent_name = normalize_process(parent_raw)

        if process_name is not None:
            processes.append(process_name)

        if parent_name is not None:
            parent_processes.append(parent_name)

        # See if this process is running from the Windows system folder
        if process_raw and "\\windows\\system32\\" in process_raw.lower():
            system32_exec_count += 1
        else:
            non_system_exec_count += 1

        # Figure out roughly how deep this process chain is
        depth = 1
        if parent_name is not None:
            depth += 1
            if parent_name == process_name:
                self_parent_count += 1

        chain_depths.append(depth)

    # Count how many times each process appears
    process_counter = Counter(processes)
    total_process_events = sum(process_counter.values())

    # See how many of these are core system processes
    core_process_count = 0
    for process_name, count in process_counter.items():
        if process_name in CORE_SYSTEM_PROCESSES:
            core_process_count += count

    # Pack all our calculated features into a nice dictionary
    features = {
        "window_start": window.get("window_start"),
        "window_end": window.get("window_end"),
        "event_count": window.get("event_count", len(events)),
        "process_event_count": total_process_events,
        "unique_process_count": len(process_counter),
        "unique_parent_process_count": len(set(parent_processes)),
        "unique_user_count": len(set(users)),
        "unique_computer_count": len(set(computers)),
        "system32_exec_count": system32_exec_count,
        "non_system_exec_count": non_system_exec_count,
        "registry_event_count": registry_event_count,
        "avg_chain_depth": (
            sum(chain_depths) / len(chain_depths)
            if len(chain_depths) > 0 else 0
        ),
        "max_chain_depth": max(chain_depths) if len(chain_depths) > 0 else 0,
        "self_parent_count": self_parent_count,
        "repeated_process_count": sum(
            1 for count in process_counter.values() if count > 1
        ),
        "process_entropy": calculate_entropy(process_counter),
        "core_process_ratio": (
            core_process_count / total_process_events
            if total_process_events > 0 else 0
        ),
        "non_core_process_count": total_process_events - core_process_count
    }

    return features

def main():
    base_path = Path(__file__).parent

    with open(base_path / INPUT_FILE, "r") as file:
        windows = json.load(file)

    all_features = []
    for window in windows:
        feature_row = extract_features(window)
        all_features.append(feature_row)

    with open(base_path / OUTPUT_FILE, "w") as file:
        json.dump(all_features, file, indent=2)

    print("Feature extraction completed.")
    print("Total windows processed:", len(all_features))
    print("Output file:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
