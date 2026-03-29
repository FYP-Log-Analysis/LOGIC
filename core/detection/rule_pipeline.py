# Rule-based detection engine:
# - OWASP ModSecurity CRS for web logs
# - Sigma rules for windows_event records

import json
import logging
import tempfile
from pathlib import Path

import ijson

try:
    from core.detection.crs_processor import run_crs_detection, check_crs_available
    _CRS_IMPORTABLE = True
except Exception as _e:
    _CRS_IMPORTABLE = False
    logging.getLogger(__name__).warning(f"[CRS] crs_processor unavailable: {_e}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT  = Path(__file__).resolve().parents[2]
PROJECTS_ROOT = PROJECT_ROOT / "data" / "projects"
SIGMA_RULES_DIR = PROJECT_ROOT / "data" / "sigma_rules"

_SEVERITY_RANK = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _stream_filtered_entries(src_path: Path, predicate) -> tuple[Path | None, int]:
    count = 0
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    tmp_path = Path(tmp.name)
    with tmp:
        tmp.write("[\n")
        first = True
        with open(src_path, "rb") as fh:
            for entry in ijson.items(fh, "item"):
                if not predicate(entry):
                    continue
                if not first:
                    tmp.write(",\n")
                tmp.write(json.dumps(entry, ensure_ascii=False))
                first = False
                count += 1
        tmp.write("\n]")
    if count == 0:
        tmp_path.unlink(missing_ok=True)
        return None, 0
    return tmp_path, count


def _load_windows_entries(src_path: Path) -> list[dict]:
    entries: list[dict] = []
    with open(src_path, "rb") as fh:
        for entry in ijson.items(fh, "item"):
            if entry.get("server_type") == "windows_event":
                entries.append(entry)
    return entries


def _crs_severity(score: float) -> str:
    if score >= 10: return "critical"
    if score >= 5:  return "high"
    if score >= 2:  return "medium"
    return "low"


def _normalise_severity(value: str | None) -> str:
    sev = (value or "unknown").strip().lower()
    return sev if sev in _SEVERITY_RANK else "unknown"


def _max_severity(a: str, b: str) -> str:
    aa = _normalise_severity(a)
    bb = _normalise_severity(b)
    return aa if _SEVERITY_RANK[aa] >= _SEVERITY_RANK[bb] else bb


def _min_severity(a: str, b: str) -> str:
    aa = _normalise_severity(a)
    bb = _normalise_severity(b)
    return aa if _SEVERITY_RANK[aa] <= _SEVERITY_RANK[bb] else bb


def _parse_crs_tags(tags_raw) -> list[str]:
    if isinstance(tags_raw, list):
        return [str(t).strip().lower() for t in tags_raw if str(t).strip()]
    if isinstance(tags_raw, str):
        raw = tags_raw.strip()
        if not raw:
            return []
        if raw.startswith("[") and raw.endswith("]"):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    return [str(t).strip().lower() for t in parsed if str(t).strip()]
            except Exception:
                pass
        return [s.strip().lower() for s in raw.split(",") if s.strip()]
    return []


def _contains_any(haystack: str, needles: tuple[str, ...]) -> bool:
    return any(n in haystack for n in needles)


def _crs_severity_v2(cm: dict) -> tuple[str, dict]:
    score = float(cm.get("anomaly_score") or 0)
    severity = _crs_severity(score)
    details: dict[str, str | int | float] = {
        "base_severity": severity,
        "anomaly_score": score,
    }

    paranoia_level = cm.get("paranoia_level")
    try:
        pl = int(paranoia_level)
    except (TypeError, ValueError):
        pl = 1
    details["paranoia_level"] = pl

    if pl >= 3 and score >= 2:
        severity = _max_severity(severity, "high")
        details["pl_adjustment"] = "upgrade_to_high"

    tags = _parse_crs_tags(cm.get("tags"))
    msg = str(cm.get("message") or "").lower()
    haystack = " ".join(tags + [msg])

    high_risk_tokens = (
        "attack-sqli",
        "attack-rce",
        "attack-xss",
        "attack-injection",
        "attack-lfi",
        "attack-rfi",
        "attack-protocol",
        "sql injection",
        "command injection",
        "remote file inclusion",
        "xss",
        "path traversal",
    )
    scanner_tokens = (
        "attack-reputation-scanner",
        "scanner",
        "bot",
        "crawler",
        "spider",
        "reputation",
    )

    has_high_risk = _contains_any(haystack, high_risk_tokens)
    has_scanner = _contains_any(haystack, scanner_tokens)

    if has_high_risk:
        severity = _max_severity(severity, "high")
        details["tag_adjustment"] = "upgrade_to_high"

    # Cap scanner-only findings to medium unless stronger risk signals exist.
    if has_scanner and not has_high_risk:
        severity = _min_severity(severity, "medium")
        details["scanner_cap"] = "max_medium"

    return severity, details


def _crs_to_rule_match(cm: dict) -> dict:
    # Map the raw CRS result dict into the unified rule_matches.json format
    orig = cm.get("original_entry") or {}
    anomaly_score = float(cm.get("anomaly_score") or 0)
    legacy_severity = _crs_severity(anomaly_score)
    severity_v2, mapping_details = _crs_severity_v2(cm)
    return {
        "rule_id":       f"CRS-{cm.get('rule_id', 'unknown')}",
        "rule_title":    f"[CRS] {cm.get('message', 'ModSecurity Rule')}",
        "severity":      severity_v2,  # FIXED: Use v2 mapping with risk analysis
        "severity_legacy": legacy_severity,
        "severity_v2":   severity_v2,
        "severity_mapping_version": 2,
        "severity_v2_details": mapping_details,
        "client_ip":     cm.get("client_ip") or orig.get("client_ip", "N/A"),
        "timestamp":     cm.get("timestamp") or orig.get("timestamp", "N/A"),
        "method":        cm.get("method") or orig.get("http_method"),
        "path":          cm.get("uri") or orig.get("request_path"),
        "status_code":   orig.get("status_code"),
        "user_agent":    orig.get("user_agent"),
        "entry":         orig,
        "anomaly_score": anomaly_score,
        "paranoia_level": cm.get("paranoia_level"),
        "crs_tags":      cm.get("tags", "[]"),
    }


def _write_results(
    matches: list,
    crs_count: int,
    sigma_count: int,
    out_path: Path,
    detector: str,
    detector_status: str,
    warning: str | None = None,
) -> dict:
    rule_ids = list({m["rule_id"] for m in matches})
    results_data = {
        "matches":       matches,
        "matched_rules": rule_ids,
        "total_matches": len(matches),
        "crs_matches":   crs_count,
        "sigma_matches": sigma_count,
        "detector":      detector,
        "detector_status": detector_status,
        "severity_mapping": {
            "active_default": "severity_v2",  # FIXED: Reflects v2 is now active
            "legacy_field": "severity_legacy",
            "v2_field": "severity_v2",
            "version": 2,
        },
    }
    if warning:
        results_data["warning"] = warning
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results_data, fh, indent=2)
    return results_data


def run_rule_pipeline_from_file(
    normalised_path,
    rules_folder=None,   # kept for backward compat — unused (CRS only)
    start_ts:   str | None = None,
    end_ts:     str | None = None,
    project_id: str | None = None,
    upload_id:  str | None = None,
) -> dict:
    """Detect which project type we're analyzing and enforce strict separation.
    WEB projects use CRS only. WINDOWS projects use Sigma only."""
    normalised_path = Path(normalised_path)
    if not normalised_path.exists():
        logger.error(f"Normalised logs not found: {normalised_path} — run processor first.")
        return {"matches": [], "matched_rules": [], "total_matches": 0, "crs_matches": 0}

    if project_id and upload_id:
        out_dir = PROJECTS_ROOT / project_id / "uploads" / upload_id
    elif project_id:
        out_dir = normalised_path.parent
    else:
        out_dir = normalised_path.parent
    out_path = out_dir / "rule_matches.json"
    matches: list[dict] = []
    crs_count = 0
    sigma_count = 0
    detector = "unknown"
    statuses: list[str] = []
    warnings: list[str] = []

    # Determine project type and enforce strict separation
    project_type = None
    if project_id:
        from core.storage.sqlite_store import get_project
        proj = get_project(project_id)
        if proj:
            project_type = proj.get("project_type", "web")
        else:
            logger.warning(f"Project {project_id} not found; defaulting to WEB")
            project_type = "web"
    else:
        # Auto-detect from content if no project_id given
        windows_entries = _load_windows_entries(normalised_path)
        project_type = "windows" if windows_entries else "web"
        logger.info(f"[AutoDetect] Project type: {project_type}")

    logger.info(f"[Pipeline] Processing {project_type.upper()} project")

    # ── STRICT SEPARATION: WEB projects use CRS only ───────────────────────
    if project_type == "web":
        detector = "crs"
        crs_service_up = _CRS_IMPORTABLE and check_crs_available()
        
        # Extract ONLY web logs (not windows_event)
        web_json_path, web_count = _stream_filtered_entries(
            normalised_path,
            lambda e: e.get("server_type") != "windows_event",
        )

        if web_count > 0:
            if crs_service_up and web_json_path is not None:
                try:
                    logger.info("[CRS] Running OWASP ModSecurity CRS detection …")
                    crs_diag: dict = {}
                    raw = run_crs_detection(
                        normalized_path=web_json_path,
                        start_ts=start_ts,
                        end_ts=end_ts,
                        diagnostics=crs_diag,
                    )
                    if raw:
                        matches.extend([_crs_to_rule_match(cm) for cm in raw])
                        crs_count = len(raw)
                        logger.info("[CRS] %d matches found.", crs_count)
                    else:
                        logger.info("[CRS] 0 matches.")
                        replay_candidates = int(crs_diag.get("replay_candidates", 0))
                        skipped_range = int(crs_diag.get("skipped_range", 0))
                        if replay_candidates == 0 and web_count > 0:
                            warnings.append(
                                "CRS replay queued 0 entries despite web logs being present; "
                                f"check analysis time filters (skipped_range={skipped_range})."
                            )
                        elif replay_candidates > 0:
                            warnings.append(
                                "CRS replay ran but produced 0 rule matches for current log set."
                            )
                    statuses.append("crs:ok")
                except Exception as exc:
                    logger.warning("[CRS] Detection step failed: %s", exc)
                    statuses.append("crs:error")
                    warnings.append(f"CRS detection failed: {exc}.")
            else:
                logger.warning("[CRS] Service unreachable - CRS detection skipped.")
                statuses.append("crs:unavailable")
                warnings.append("CRS service unreachable; web log detection skipped.")
        else:
            logger.warning("[CRS] No web logs found in normalized.json")
            statuses.append("crs:nologs")

        if web_json_path is not None:
            web_json_path.unlink(missing_ok=True)

    # ── STRICT SEPARATION: WINDOWS projects use Sigma only ──────────────────
    elif project_type == "windows":
        detector = "sigma"
        windows_entries = _load_windows_entries(normalised_path)
        
        if windows_entries:
            try:
                from core.detection.windows_sigma import run_sigma_pipeline
                logger.info("[SIGMA] Running Windows Sigma rule detection…")
                sigma_result = run_sigma_pipeline(windows_entries, str(SIGMA_RULES_DIR))
                sigma_matches = sigma_result.get("matches", [])
                sigma_count = len(sigma_matches)
                matches.extend(sigma_matches)
                statuses.append("sigma:ok")
                logger.info("[SIGMA] %d matches found.", sigma_count)
            except Exception as exc:
                logger.warning("[SIGMA] Detection step failed: %s", exc)
                statuses.append("sigma:error")
                warnings.append(f"Sigma detection failed: {exc}.")
        else:
            logger.warning("[SIGMA] No Windows events found in normalized.json")
            statuses.append("sigma:nologs")

    detector_status = ",".join(statuses)
    warning = " ".join(warnings) if warnings else None
    return _write_results(matches, crs_count, sigma_count, out_path, detector, detector_status, warning)


def run_rule_pipeline(log_entries, rules_folder=None) -> dict:
    # In-memory variant — log_entries accepted for API compatibility; CRS always reads from disk
    raise RuntimeError(
        "run_rule_pipeline() requires project_id and upload_id. "
        "Use run_rule_pipeline_from_file(normalised_path, project_id=..., upload_id=...) instead."
    )
