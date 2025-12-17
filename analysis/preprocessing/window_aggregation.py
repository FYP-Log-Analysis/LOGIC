import json
from datetime import datetime, timedelta

# File paths and settings for our time window analysis
INPUT_FILE = "process_execution_events.json"
OUTPUT_FILE = "execution_windows.json"

WINDOW_SIZE_MINUTES = 5

# Load up all the process events we filtered earlier
with open(INPUT_FILE, "r") as f:
    events = json.load(f)

print("Total process events:", len(events))

# Turn all those timestamp strings into proper datetime objects so we can work with them
for event in events:
    event["dt"] = datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )

# Put everything in chronological order
events.sort(key=lambda x: x["dt"])

# Now we'll group events into 5-minute time windows to see activity patterns
windows = []

current_window_events = []
current_window_start = events[0]["dt"]
current_window_end = current_window_start + timedelta(minutes=WINDOW_SIZE_MINUTES)

for event in events:
    event_time = event["dt"]

    # Does this event belong in our current window?
    if event_time < current_window_end:
        current_window_events.append(event)
    else:
        # Clean up events before saving (remove the temp datetime objects)
        clean_events = []
        for e in current_window_events:
            e_copy = e.copy()
            e_copy.pop("dt", None)
            clean_events.append(e_copy)

        # Save completed window
        windows.append({
            "window_start": current_window_start.isoformat(),
            "window_end": current_window_end.isoformat(),
            "event_count": len(clean_events),
            "events": clean_events
        })

        # Begin the next window with this event
        current_window_start = event_time
        current_window_end = current_window_start + timedelta(minutes=WINDOW_SIZE_MINUTES)
        current_window_events = [event]

# Don't forget to save the last window too
clean_events = []
for e in current_window_events:
    e_copy = e.copy()
    e_copy.pop("dt", None)
    clean_events.append(e_copy)

windows.append({
    "window_start": current_window_start.isoformat(),
    "window_end": current_window_end.isoformat(),
    "event_count": len(clean_events),
    "events": clean_events
})

# Write out all our time windows for the next analysis step
with open(OUTPUT_FILE, "w") as f:
    json.dump(windows, f, indent=2)

print("Total windows created:", len(windows))
print("Saved to", OUTPUT_FILE)
