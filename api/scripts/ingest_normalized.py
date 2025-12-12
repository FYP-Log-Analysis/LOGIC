import json
import glob
from datetime import datetime

from main import SessionLocal
from models.normalized_log import NormalizedLog


def load_logs():
    db = SessionLocal()

    path = "/app/data/processed/normalized/*.json"
    files = glob.glob(path)

    print(f"Found {len(files)} files to load.")

    for file in files:
        print(f"Loading {file}...")
        with open(file, "r") as f:
            logs = json.load(f)

        for log in logs:
            ts_string = log.get("timestamp")
            if not ts_string:
                continue

            timestamp = datetime.fromisoformat(ts_string.replace("Z", "+00:00"))

            db_entry = NormalizedLog(
                timestamp=timestamp,
                event_id=log.get("event_id"),
                source=log.get("source"),
                user_name=log.get("user"),
                computer=log.get("computer"),
                process_path=log.get("process_path"),
                command_line=log.get("command_line"),
                category=log.get("category"),
                summary=log.get("summary"),
                raw=log
            )

            db.add(db_entry)

        db.commit()

    db.close()
    print("Uploaded all logs.")

if __name__ == "__main__":
    load_logs()
