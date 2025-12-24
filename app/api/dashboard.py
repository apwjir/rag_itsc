from fastapi import APIRouter, Depends, Query
from app.core.deps import get_current_user
from app.db.es_client import es, INDEX_NAME

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)

@router.get("/threat-types")
async def threat_type_distribution(
    limit: int = Query(10, ge=1, le=50),
    user: str = Depends(get_current_user)
):
    body = {
        "size": 0,
        "aggs": {
            "threat_types": {
                "terms": {
                    "field": "CategoryEN.keyword",
                    "size": limit,                  # ⭐ ใช้ limit
                    "order": { "_count": "desc" }
                }
            }
        }
    }

    res = es.search(index=INDEX_NAME, body=body)

    buckets = res["aggregations"]["threat_types"]["buckets"]

    data = [
        {
            "name": b["key"],
            "value": b["doc_count"]
        }
        for b in buckets
    ]

    return {
        "limit": limit,
        "totalCategories": len(buckets),
        "data": data
    }

@router.get("/severity")
async def severity_distribution(
    user: str = Depends(get_current_user)
):
    body = {
        "size": 0,
        "aggs": {
            "raw_severity": {
                "terms": {
                    "field": "PiorityEN.keyword",
                    "size": 20
                }
            }
        }
    }

    res = es.search(index=INDEX_NAME, body=body)
    buckets = res["aggregations"]["raw_severity"]["buckets"]

    # -------------------------
    # Map → Severity Levels
    # -------------------------
    severity_map = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Information": 0,
    }

    for b in buckets:
        key = b["key"]
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

    data = [
        { "name": k, "value": v }
        for k, v in severity_map.items()
        if v > 0
    ]

    return {
        "total": sum(v for v in severity_map.values()),
        "data": data
    }
