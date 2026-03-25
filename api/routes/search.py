from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from api.routes.projects import _normalize_project_id
from core.storage.sqlite_store import (
    get_geo_summary,
    get_stats,
    get_ip_summary,
    query_detections,
    get_overview_stats,
    get_detection_aggregations,
    get_log_statistics,
)
from api.deps import UserInDB, get_current_user

router = APIRouter(prefix="/search", tags=["Search & Grafana"])


def _assert_project_type(project_id: str | None, required_type: str) -> None:
    if not project_id:
        return
    project_id = _normalize_project_id(project_id)
    from core.storage.sqlite_store import get_project

    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")
    if project.get("project_type") != required_type:
        raise HTTPException(
            status_code=400,
            detail=(
                f"This endpoint is for {required_type.upper()} projects. "
                f"The project '{project_id}' is a {project.get('project_type', 'unknown').upper()} project."
            ),
        )


@router.get("/detections")
def get_detections(
    severity:   str | None = Query(None, description="Filter by severity: critical/high/medium/low"),
    rule_id:    str | None = Query(None, description="Filter by rule ID"),
    client_ip:  str | None = Query(None, description="Filter by source IP"),
    project_id: str | None = Query(None, description="Scope to a specific project"),
    upload_id:  str | None = Query(None, description="Scope to a specific upload"),
    start_ts:   str | None = Query(None, description="Earliest timestamp (ISO 8601)"),
    end_ts:     str | None = Query(None, description="Latest timestamp (ISO 8601)"),
    limit:      int        = Query(100, le=50000),
    offset:     int        = Query(0),
    _user:      UserInDB   = Depends(get_current_user),
) -> dict[str, Any]:
    _assert_project_type(project_id, "web")
    rows, total = query_detections(
        severity=severity, rule_id=rule_id, client_ip=client_ip,
        project_id=project_id, upload_id=upload_id,
        start_ts=start_ts, end_ts=end_ts,
        limit=limit, offset=offset,
    )
    return {"count": total, "results": rows}


@router.get("/stats")
def get_summary_stats(
    project_id: str | None = Query(None, description="Scope to a specific project"),
    _user:      UserInDB   = Depends(get_current_user),
) -> dict[str, Any]:
    _assert_project_type(project_id, "web")
    return get_stats(project_id=project_id)


@router.get("/geography/summary")
def get_geography_summary(
    limit:      int        = Query(10, ge=1, le=50),
    project_id: str | None = Query(None, description="Scope to a specific project"),
    _user:      UserInDB   = Depends(get_current_user),
) -> dict[str, Any]:
    _assert_project_type(project_id, "web")
    return get_geo_summary(limit=limit, project_id=project_id)


@router.get("/ip-summary/{client_ip}")
def get_ip_summary_endpoint(
    client_ip:  str,
    project_id: str | None = Query(None, description="Scope to a specific project"),
    _user:      UserInDB   = Depends(get_current_user),
) -> dict[str, Any]:
    _assert_project_type(project_id, "web")
    return get_ip_summary(client_ip, project_id=project_id)


@router.get("/overview")
def get_overview(
    project_id: str | None = Query(None, description="Scope to a specific project"),
    upload_id:  str | None = Query(None, description="Scope to a specific upload"),
    start_ts:   str | None = Query(None, description="Earliest timestamp (ISO 8601)"),
    end_ts:     str | None = Query(None, description="Latest timestamp (ISO 8601)"),
    _user:      UserInDB   = Depends(get_current_user),
) -> dict[str, Any]:
    """Return all dashboard overview data, computed server-side."""
    return get_overview_stats(
        project_id=project_id, upload_id=upload_id,
        start_ts=start_ts, end_ts=end_ts,
    )


@router.get("/detection-aggregations")
def get_detection_aggs(
    project_id: str | None = Query(None, description="Scope to a specific project"),
    upload_id:  str | None = Query(None, description="Scope to a specific upload"),
    start_ts:   str | None = Query(None, description="Earliest timestamp (ISO 8601)"),
    end_ts:     str | None = Query(None, description="Latest timestamp (ISO 8601)"),
    _user:      UserInDB   = Depends(get_current_user),
) -> dict[str, Any]:
    """Return pre-computed detection aggregations for the Detections page."""
    _assert_project_type(project_id, "web")
    return get_detection_aggregations(
        project_id=project_id, upload_id=upload_id,
        start_ts=start_ts, end_ts=end_ts,
    )


# Grafana plugin: "SimpleJSON" (grafana-simple-json-datasource)
# Expose at /api/search/grafana/*

grafana = APIRouter(prefix="/search/grafana", tags=["Grafana SimpleJSON"])


@grafana.get("/")
def grafana_health() -> str:
    return "OK"


@grafana.post("/search")
def grafana_search() -> list[str]:
    return [
        "detections_total",
        "critical_detections",
        "high_detections",
        "detections_by_severity",
        "top_offending_ips",
    ]


@grafana.post("/query")
def grafana_query(body: dict[str, Any]) -> list[dict[str, Any]]:
    # Accept an optional project_id in the Grafana query body for project-scoped stats
    project_id = body.get("project_id") or None
    stats   = get_stats(project_id=project_id)
    now_ms  = int(time.time() * 1000)
    results = []

    for target_obj in body.get("targets", []):
        target = target_obj.get("target", "")

        if target == "detections_total":
            results.append({
                "target": "Total Detections",
                "datapoints": [[stats["total_detections"], now_ms]],
            })


        elif target == "critical_detections":
            count = stats["detections_by_severity"].get("critical", 0)
            results.append({
                "target": "Critical Detections",
                "datapoints": [[count, now_ms]],
            })

        elif target == "high_detections":
            count = stats["detections_by_severity"].get("high", 0)
            results.append({
                "target": "High Detections",
                "datapoints": [[count, now_ms]],
            })

        elif target == "detections_by_severity":
            results.append({
                "columns": [
                    {"text": "Severity", "type": "string"},
                    {"text": "Count",    "type": "number"},
                ],
                "rows": [
                    [sev, cnt]
                    for sev, cnt in stats["detections_by_severity"].items()
                ],
                "type": "table",
            })

        elif target == "top_offending_ips":
            results.append({
                "columns": [
                    {"text": "IP Address", "type": "string"},
                    {"text": "Hit Count",  "type": "number"},
                ],
                "rows": [
                    [row["client_ip"], row["hit_count"]]
                    for row in stats["top_offending_ips"]
                ],
                "type": "table",
            })

    return results


@grafana.post("/annotations")
def grafana_annotations(body: dict[str, Any]) -> list:
    return []
