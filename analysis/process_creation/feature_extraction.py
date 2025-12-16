import json
import math
from pathlib import Path
from collections import Counter

INPUT_FILE = "execution_windows.json"
OUTPUT_FILE = "features.json"

CORE_SYSTEM_PROCESSES = {
    "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe",
    "lsass.exe", "autochk.exe"
}


def normalize_process(proc):
    if not proc:
        return None
    return proc.split("\\")[-1].lower()


def shannon_entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def extract_features(window):
    events = window.get("events", [])

    processes = []
    parents = []
    users = []
    computers = []

    registry_count = 0
    system32_count = 0
    non_system_count = 0
    self_parent_count = 0
    chain_depths = []

    for e in events:
        proc_raw = e.get("process")
        parent_raw = e.get("parent_process")

        user = e.get("user_sid")
        computer = e.get("computer")

        if user:
            users.append(user)
        if computer:
            computers.append(computer)

        # Registry pseudo-events
        if proc_raw == "Registry":
            registry_count += 1
            continue

        proc = normalize_process(proc_raw)
        parent = normalize_process(parent_raw)

        if proc:
            processes.append(proc)

        if parent:
            parents.append(parent)

        # System32 vs non-system
        if proc_raw and "\\windows\\system32\\" in proc_raw.lower():
            system32_count += 1
        else:
            non_system_count += 1

        # Chain depth approximation
        depth = 1
        if parent:
            depth += 1
            if parent == proc:
                self_parent_count += 1
        chain_depths.append(depth)

    process_counter = Counter(processes)

    core_count = sum(
        count for proc, count in process_counter.items()
        if proc in CORE_SYSTEM_PROCESSES
    )

    total_proc_events = sum(process_counter.values())

    return {
        "window_start": window.get("window_start"),
        "window_end": window.get("window_end"),
        "event_count": window.get("event_count", len(events)),
        "process_event_count": total_proc_events,
        "unique_process_count": len(process_counter),
        "unique_parent_process_count": len(set(parents)),
        "unique_user_count": len(set(users)),
        "unique_computer_count": len(set(computers)),
        "system32_exec_count": system32_count,
        "non_system_exec_count": non_system_count,
        "registry_event_count": registry_count,
        "avg_chain_depth": (
            sum(chain_depths) / len(chain_depths)
            if chain_depths else 0
        ),
        "max_chain_depth": max(chain_depths) if chain_depths else 0,
        "self_parent_count": self_parent_count,
        "repeated_process_count": sum(
            1 for c in process_counter.values() if c > 1
        ),
        "process_entropy": shannon_entropy(process_counter),
        "core_process_ratio": (
            core_count / total_proc_events
            if total_proc_events else 0
        ),
        "non_core_process_count": (
            total_proc_events - core_count
        )
    }


def main():
    base = Path(__file__).parent

    with open(base / INPUT_FILE, "r") as f:
        windows = json.load(f)

    features = [extract_features(w) for w in windows]

    with open(base / OUTPUT_FILE, "w") as f:
        json.dump(features, f, indent=2)

    print(f"[+] Extracted {len(features)} feature rows")
    print(f"[+] Output written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()