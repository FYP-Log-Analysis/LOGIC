# Sends threat detection data to Groq Cloud (llama-3.3-70b-versatile) for AI analysis.
# Requires the GROQ_API_KEY environment variable to be set.
import asyncio
import logging
from typing import Dict
import json

from groq import Groq
import os

logger = logging.getLogger(__name__)


def _get_client() -> Groq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Export it before starting the API."
        )
    return Groq(api_key=api_key)


def _build_summary(detection_data: Dict) -> str:
    matches  = detection_data.get("matches", [])
    severity_counts: Dict[str, int] = {}
    rule_counts:     Dict[str, int] = {}
    ips: set = set()

    for m in matches:
        # NOTE: The 'severity' field in matches is already normalized by _normalise_match_severity()
        # to reflect the active severity field (severity_v2 by default)
        sev = m.get("severity", "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        rule = m.get("rule_title", "Unknown")
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        if m.get("client_ip"):
            ips.add(m["client_ip"])

    lines = [
        f"Total Detections      : {len(matches)}",
        f"Unique Rules Triggered: {len(detection_data.get('matched_rules', []))}",
        f"Unique Source IPs     : {len(ips)}",
        "",
        "Severity Breakdown:",
    ]
    for sev in ["critical", "high", "medium", "low"]:
        cnt = severity_counts.get(sev, 0)
        if cnt:
            lines.append(f"  {sev.upper()}: {cnt}")

    lines += ["", "Top Triggered Rules:"]
    for rule, cnt in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
        lines.append(f"  - {rule}: {cnt} match(es)")

    top_ips = sorted(
        [(ip, sum(1 for m in matches if m.get("client_ip") == ip)) for ip in ips],
        key=lambda x: -x[1],
    )[:5]
    if top_ips:
        lines += ["", "Top Offending IPs:"]
        for ip, cnt in top_ips:
            lines.append(f"  - {ip}: {cnt} match(es)")

    return "\n".join(lines)


def analyse_detection_results(detection_data: Dict) -> Dict:
    try:
        summary = _build_summary(detection_data)
        client  = _get_client()

        system_prompt = (
            "You are a web application security expert. "
            "Analyse the provided web server threat detection results and provide:\n"
            "1. Key attack patterns and techniques observed\n"
            "2. Top 3 most critical findings\n"
            "3. Risk assessment (Critical/High/Medium/Low)\n"
            "4. Recommended immediate actions\n"
            "5. Long-term hardening recommendations\n"
            "Be concise, technical, and actionable."
        )
        user_prompt = (
            f"Analyse these web server security detections:\n\n{summary}\n\n"
            "Provide a comprehensive threat analysis."
        )

        logger.info("Calling Groq API for bulk threat analysis …")
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=1024,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
        )

        return {
            "status":   "success",
            "model":    "llama-3.3-70b-versatile",
            "backend":  "groq",
            "analysis": response.choices[0].message.content,
            "detection_summary": {
                "total_matches":  detection_data.get("total_matches", 0),
                "unique_rules":   len(detection_data.get("matched_rules", [])),
            },
        }
    except Exception as exc:
        logger.error(f"LLM analysis failed: {exc}", exc_info=True)
        return {"status": "error", "error_message": str(exc), "analysis": None}


def analyse_specific_match(match_data: Dict) -> Dict:
    try:
        client = _get_client()
        entry  = match_data.get("entry", {})
        # NOTE: The 'severity' field is already normalized by _normalise_match_severity()
        # to reflect the active severity field (severity_v2 by default)
        user_prompt = (
            f"Analyse this web server security detection:\n\n"
            f"Rule     : {match_data.get('rule_title')}\n"
            f"Severity : {match_data.get('severity')}\n"
            f"Source IP: {match_data.get('client_ip')}\n"
            f"Method   : {match_data.get('method')}\n"
            f"Path     : {match_data.get('path')}\n"
            f"Status   : {match_data.get('status_code')}\n"
            f"UA       : {entry.get('user_agent')}\n"
            f"Timestamp: {match_data.get('timestamp')}\n\n"
            "In 3-4 sentences: what attack does this indicate, why is it important, "
            "and what should be done?"
        )
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=512,
            messages=[
                {"role": "system", "content": "You are a web security analyst."},
                {"role": "user",   "content": user_prompt},
            ],
        )
        return {
            "status":   "success",
            "backend":  "groq",
            "analysis": response.choices[0].message.content,
            "rule_id":  match_data.get("rule_id"),
        }
    except Exception as exc:
        logger.error(f"Specific match analysis failed: {exc}", exc_info=True)
        return {"status": "error", "error_message": str(exc)}


# ── Async wrappers ────────────────────────────────────────────────────────────
# These run the blocking Groq SDK calls in a thread pool so they don't block
# the FastAPI event loop (important under concurrent requests).

async def async_analyse_detection_results(detection_data: Dict) -> Dict:
    """Non-blocking wrapper around analyse_detection_results."""
    return await asyncio.to_thread(analyse_detection_results, detection_data)


async def async_analyse_specific_match(match_data: Dict) -> Dict:
    """Non-blocking wrapper around analyse_specific_match."""
    return await asyncio.to_thread(analyse_specific_match, match_data)


def analyse_windows_event(event_data: Dict) -> Dict:
    """Explain one Windows event record with concise analyst-oriented guidance."""
    try:
        client = _get_client()
        event_payload = dict(event_data or {})
        event_blob = json.dumps(event_payload, ensure_ascii=False, default=str)
        if len(event_blob) > 16000:
            event_blob = event_blob[:16000] + "\n... [truncated]"

        system_prompt = (
            "You are a Windows Security analyst. "
            "Explain the event in concise, actionable terms for SOC triage."
        )
        user_prompt = (
            "Analyze this Windows event and respond in Markdown with these sections:\n"
            "1) What happened\n"
            "2) Why it matters\n"
            "3) Benign vs suspicious indicators\n"
            "4) Recommended next checks\n\n"
            f"Event JSON:\n{event_blob}"
        )

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=700,
            temperature=0.2,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )

        return {
            "status": "success",
            "backend": "groq",
            "model": "llama-3.3-70b-versatile",
            "analysis": response.choices[0].message.content,
        }
    except Exception as exc:
        logger.error("Windows event analysis failed: %s", exc, exc_info=True)
        return {"status": "error", "error_message": str(exc)}


async def async_analyse_windows_event(event_data: Dict) -> Dict:
    """Non-blocking wrapper around analyse_windows_event."""
    return await asyncio.to_thread(analyse_windows_event, event_data)
