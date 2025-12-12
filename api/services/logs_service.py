import os
import json

BASE_DIR = os.path.join("data", "processed", "normalized")

def load_all_logs():
    logs = []
    for filename in os.listdir(BASE_DIR):
        if filename.endswith("_normalized.json"):
            with open(os.path.join(BASE_DIR, filename)) as f:
                logs.extend(json.load(f))
    return logs

def load_logs_by_type(log_type: str):
    filename = f"{log_type}_normalized.json"

    file_path = os.path.join(BASE_DIR, filename)

    if not os.path.exists(file_path):
        return {"error": f"No logs found for type '{log_type}'"}

    with open(file_path) as f:
        return json.load(f)
