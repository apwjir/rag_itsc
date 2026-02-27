from typing import Any, Dict, List, Optional, Literal
from fastapi import APIRouter, Depends, Query

from app.core.deps import get_current_user
from app.services.risk_calculate import calculate_top_weighted_risks
from app.db.es_client import es, INDEX_NAME
from app.db.es_filters import build_organization_filter
from app.services.risk_calculate import calculate_top_weighted_risks
from app.db.es_filters import build_time_range_filter, resolve_calendar_interval

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/threat-types")
async def threat_type_distribution(
    limit: int = Query(50, ge=1, le=500),
    for_filter: bool = Query(False),
    organizations: Optional[List[str]] = Query(None),
    user: Any = Depends(get_current_user),
):
    filters = build_organization_filter(organizations)

    body: Dict[str, Any] = {
        "size": 0,
        "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        "aggs": {
            "threat_types": {
                "terms": {
                    "field": "CategoryEN.keyword",
                    "size": limit,
                    "order": {"_key": "asc"} if for_filter else {"_count": "desc"},
                }
            }
        },
    }

    res = es.search(index=INDEX_NAME, body=body)
    buckets = res["aggregations"]["threat_types"]["buckets"]

    data = [{"name": b["key"], "value": b["doc_count"]} for b in buckets]

    if for_filter:
        options = [
            {"value": b["key"], "label": b["key"]}
            for b in buckets
            if str(b["key"]).strip()
        ]
        return {"filters": {"organizations": organizations or []}, "data": options}

    return {
        "limit": limit,
        "totalCategories": len(buckets),
        "filters": {"organizations": organizations or []},
        "data": data,
    }


@router.get("/severity")
async def severity_distribution(
    organizations: Optional[List[str]] = Query(None),
    user: Any = Depends(get_current_user),
):
    filters = build_organization_filter(organizations)

    body: Dict[str, Any] = {
        "size": 0,
        "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        "aggs": {
            "raw_severity": {
                "terms": {"field": "PiorityEN.keyword", "size": 20}
            }
        },
    }

    res = es.search(index=INDEX_NAME, body=body)
    buckets = res["aggregations"]["raw_severity"]["buckets"]

    severity_map = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Information": 0}

    for b in buckets:
        key = str(b["key"] or "")
        count = b["doc_count"]

        if key.startswith("Critical"):
            severity_map["Critical"] += count
        elif key.startswith("High"):
            severity_map["High"] += count
        elif key.startswith("Medium"):
            severity_map["Medium"] += count
        elif key.startswith("Low"):
            severity_map["Low"] += count
        elif key.startswith("Information"):
            severity_map["Information"] += count

    data = [{"name": k, "value": v} for k, v in severity_map.items() if v > 0]

    return {
        "filters": {"organizations": organizations or []},
        "total": sum(severity_map.values()),
        "data": data,
    }


@router.get("/organizations")
async def organizations_options(
    limit: int = Query(500, ge=1, le=5000),
    user: Any = Depends(get_current_user),
):
    body: Dict[str, Any] = {
        "size": 0,
        "aggs": {
            "orgs": {
                "terms": {
                    "field": "OrganizationMaskEn.keyword",
                    "size": limit,
                    "order": {"_key": "asc"},
                }
            }
        },
    }

    res = es.search(index=INDEX_NAME, body=body)
    buckets = res["aggregations"]["orgs"]["buckets"]

    options = [
        {"value": b["key"], "label": b["key"]}
        for b in buckets
        if str(b["key"]).strip()
    ]

    return {"total": len(options), "data": options}

@router.get("/top-risks")
async def get_top_risks(
    limit: int = Query(None),
    user: str = Depends(get_current_user)
):
    data = await calculate_top_weighted_risks(limit=limit)
    return {
        "status": "success",
        "data": data
    }

@router.get("/incident-trends")
async def incident_trends(
    range: Literal["7d", "30d", "custom"] = Query("7d"),
    from_date: str | None = Query(None, alias="from"),
    to_date: str | None = Query(None, alias="to"),
    user: str = Depends(get_current_user),
):
    time_filter = build_time_range_filter(range, from_date, to_date)
    interval = resolve_calendar_interval(range, from_date, to_date)

    filters = []
    if time_filter:
        filters.append(time_filter)

    # CreateDate is stored as text (e.g. "2025-11-27T10:20:08+00:00").
    # date_histogram requires a proper date type, so we define a runtime field.
    # IMPORTANT: text fields have no doc values, so we must use params._source
    # instead of doc['CreateDate'] (doc[] always returns empty for text fields).
    runtime_mappings = {
        "CreateDate_parsed": {
            "type": "date",
            "script": {
                "lang": "painless",
                "source": (
                    "String d = params._source['CreateDate'];"
                    "if (d != null && !d.isEmpty()) {"
                    "  try {"
                    "    emit(ZonedDateTime.parse(d).toInstant().toEpochMilli());"
                    "  } catch (Exception e) {}"
                    "}"
                ),
            },
        }
    }

    date_histogram_config: dict = {
        "field": "CreateDate_parsed",   # ← runtime date field, not the raw text
        "calendar_interval": interval,
        "format": "yyyy-MM-dd",
        "min_doc_count": 0,
    }

    # Only add extended_bounds when actual dates are provided
    if from_date and to_date:
        date_histogram_config["extended_bounds"] = {
            "min": from_date,
            "max": to_date,
        }

    body = {
        "size": 0,
        "runtime_mappings": runtime_mappings,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "by_date": {
                "date_histogram": date_histogram_config,
                "aggs": {
                    "resolved": {"filter": {"term": {"StatusId": 5}}},
                    "critical": {"filter": {"term": {"PiorityId": 1}}},
                },
            }
        },
    }

    res = es.search(index=INDEX_NAME, body=body)

    return {
        "interval": interval,
        "data": [
            {
                "date": b["key_as_string"],
                "incidents": b["doc_count"],
                "resolved": b["resolved"]["doc_count"],
                "critical": b["critical"]["doc_count"],
            }
            for b in res["aggregations"]["by_date"]["buckets"]
        ],
    }