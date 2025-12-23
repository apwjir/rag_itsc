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