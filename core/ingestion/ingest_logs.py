# Reads raw log files (.log, .gz, .txt, .evtx, .xml) from the upload's raw directory and
# writes them as structured JSON to the upload's intermediate.json.
import gzip
import json
import logging
from pathlib import Path

from core.ingestion.evtx_ingest import event_to_raw_line, read_evtx_file

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def read_log_file(file_path: Path) -> list[str]:
    lines = []
    try:
        if file_path.suffix == ".gz":
            with gzip.open(file_path, "rt", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        else:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        logger.info(f"Read {len(lines):,} lines from {file_path.name}")
    except Exception as exc:
        logger.error(f"Failed to read {file_path}: {exc}")
    return [line.rstrip("\n") for line in lines if line.strip()]


def ingest_all(
    project_id: str,
    upload_id: str,
    raw_logs_dir: str | None = None,
) -> list[dict]:
    """Read all log files for an upload and write them to the upload's intermediate.json.

    Args:
        project_id: The project this upload belongs to.
        upload_id:  The unique upload identifier.
        raw_logs_dir: Override the raw-files directory (used by CLI / tests).
    """
    upload_dir = PROJECT_ROOT / "data" / "projects" / project_id / "uploads" / upload_id
    source_dir = Path(raw_logs_dir) if raw_logs_dir else upload_dir / "raw"
    source_dir.mkdir(parents=True, exist_ok=True)
    upload_dir.mkdir(parents=True, exist_ok=True)

    entries   = []
    log_files = sorted(
        f for f in source_dir.iterdir()
        if f.is_file() and f.suffix.lower() in {".log", ".gz", ".txt", ".evtx", ".xml"}
    )

    if not log_files:
        logger.warning(f"No log files found in {source_dir}")
        return entries

    for log_file in log_files:
        if log_file.suffix.lower() in {".evtx", ".xml"}:
            for event in read_evtx_file(log_file):
                entries.append({
                    "source": log_file.name,
                    "raw": event_to_raw_line(event),
                    "raw_event": event,
                })
            continue

        for line in read_log_file(log_file):
            entries.append({"source": log_file.name, "raw": line})

    out_path = upload_dir / "intermediate.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh)

    logger.info(f"Total entries ingested: {len(entries):,}")
    logger.info(f"Saved raw entries → {out_path}")
    return entries
