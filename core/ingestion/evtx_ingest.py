import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    _EVTX_AVAILABLE = True
except Exception:
    _EVTX_AVAILABLE = False

logger = logging.getLogger(__name__)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_event_xml(xml_string: str) -> dict | None:
    try:
        root = ET.fromstring(xml_string)
        system = root.find("e:System", NS)
        if system is None:
            return None

        event_data = root.find("e:EventData", NS)
        record: dict = {
            "event_id": system.findtext("e:EventID", None, NS),
            "version": system.findtext("e:Version", None, NS),
            "level": system.findtext("e:Level", None, NS),
            "task": system.findtext("e:Task", None, NS),
            "opcode": system.findtext("e:Opcode", None, NS),
            "keywords": system.findtext("e:Keywords", None, NS),
            "timestamp": (
                system.find("e:TimeCreated", NS).attrib.get("SystemTime")
                if system.find("e:TimeCreated", NS) is not None else None
            ),
            "record_id": system.findtext("e:EventRecordID", None, NS),
            "computer": system.findtext("e:Computer", None, NS),
            "channel": system.findtext("e:Channel", None, NS),
            "security_user": (
                system.find("e:Security", NS).attrib.get("UserID")
                if system.find("e:Security", NS) is not None else None
            ),
            "event_data": {},
        }

        if event_data is not None:
            for child in event_data:
                name = child.attrib.get("Name", child.tag)
                record["event_data"][name] = child.text

        return record
    except Exception:
        return None


def _read_evtx_binary(file_path: Path) -> list[dict]:
    if not _EVTX_AVAILABLE:
        raise RuntimeError(
            "python-evtx is not installed. Install dependency 'python-evtx' to ingest .evtx files."
        )

    events: list[dict] = []
    with Evtx(str(file_path)) as evtx_log:
        for xml_event, _ in evtx_file_xml_view(evtx_log):
            event = _parse_event_xml(xml_event)
            if event:
                events.append(event)
    return events


def _read_evtx_xml(file_path: Path) -> list[dict]:
    events: list[dict] = []
    inside_event = False
    buffer: list[str] = []

    with open(file_path, "r", encoding="utf-8", errors="replace") as infile:
        for line in infile:
            stripped = line.strip()
            if stripped.startswith("<Event "):
                inside_event = True
                buffer = [line]
                continue

            if inside_event:
                buffer.append(line)

            if stripped == "</Event>":
                inside_event = False
                xml_block = "".join(buffer)
                event = _parse_event_xml(xml_block)
                if event:
                    events.append(event)

    return events


def read_evtx_file(file_path: Path) -> list[dict]:
    suffix = file_path.suffix.lower()
    if suffix == ".evtx":
        events = _read_evtx_binary(file_path)
    elif suffix == ".xml":
        events = _read_evtx_xml(file_path)
    else:
        return []

    logger.info("Read %d Windows events from %s", len(events), file_path.name)
    return events


def event_to_raw_line(event: dict) -> str:
    return json.dumps(event, ensure_ascii=False)
