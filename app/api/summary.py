from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
import json
from app.db.es_client import es, INDEX_NAME
from app.core.deps import get_current_user
from app.db.es_filters import normalize_date 

router = APIRouter(
    prefix="/summary", 
    tags=["Summary"]
)

@router.get("/logs/with-update-date")
async def get_logs_with_update_date(
    limit: int = Query(50),
    search_after: Optional[str] = None,
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    user: str = Depends(get_current_user)
):
    filters = [
        {"exists": {"field": "UpdateDate"}},
        {"exists": {"field": "CreateDate"}},
        {"bool": {"must_not": [{"terms": {"PiorityEN.keyword": ["INFORMATION", "Information", "information"]}}]}}
    ]

    # Filter by CreateDate (receive time) — normalize to full ISO 8601 to match stored format
    if date_from or date_to:
        r = {}
        if date_from:
            r["gte"] = normalize_date(date_from)
        if date_to:
            r["lte"] = normalize_date(date_to, end_of_day=True)
        filters.append({"range": {"CreateDate_parsed": r}})

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

    body = {
        "size": limit,
        "track_total_hits": True,
        "runtime_mappings": runtime_mappings,
        "query": {"bool": {"filter": filters}},
        "sort": [{"IncidentsId": "desc"}, {"_id": "desc"}]
    }

    if search_after:
        try:
            body["search_after"] = json.loads(search_after)
        except (json.JSONDecodeError, ValueError):
            pass  # invalid cursor — ignore and return first page

    try:
        res = es.search(index=INDEX_NAME, body=body)
        hits = res["hits"]["hits"]
        total = res["hits"]["total"]["value"]

        data = [{"id": h["_id"], **h["_source"]} for h in hits]
        next_cursor = json.dumps(hits[-1]["sort"]) if hits else None

        return {
            "status": "success",
            "count": total,
            "data": data,
            "next_cursor": next_cursor
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs/time")
async def get_all_time_stats(
    # 1. เพิ่ม Query Parameters สำหรับรับค่า Filter จากหน้าบ้าน
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    priority: Optional[List[str]] = Query(None),
    incident_id: Optional[str] = Query(None),
    category: Optional[List[str]] = Query(None),
    user: str = Depends(get_current_user)
):
    # Base filters: exclude Information priority only.
    # NOTE: UpdateDate/CreateDate null checks are handled per-document in Python,
    # NOT as exists filters — strict exists filters would exclude docs where
    # UpdateDate failed normalization (set to null) even if most data is valid.
    filters = [
        {"bool": {
            "must_not": [
                {"terms": {"PiorityEN.keyword": ["INFORMATION", "Information", "information"]}}
            ]
        }}
    ]

    # Filter by CreateDate (receive time) — normalize_date ensures proper ISO 8601
    # format with timezone so string comparison against stored values is correct.
    if date_from or date_to:
        date_range = {}
        if date_from:
            date_range["gte"] = normalize_date(date_from)
        if date_to:
            date_range["lte"] = normalize_date(date_to, end_of_day=True)
        filters.append({"range": {"CreateDate_parsed": date_range}})

    # กรองตามชื่อ Priority (ถ้ามีเลือกหลายอัน)
    if priority:
        filters.append({"terms": {"PiorityEN.keyword": priority}})

    # ค้นหาตาม Incident ID
    if incident_id:
        try:
            filters.append({"term": {"IncidentsId": int(incident_id)}})
        except ValueError:
            pass
        
    # กรองตามหมวดหมู่ (Category)
    if category:
        filters.append({"terms": {"Category.keyword": category}})

    from datetime import datetime

    durations: dict[str, list[float]] = {}

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

    search_body = {
        "size": 1000,
        "runtime_mappings": runtime_mappings,
        "query": {"bool": {"filter": filters}},
        "_source": ["UpdateDate", "CreateDate", "PiorityEN"],
        "sort": [{"_doc": "asc"}],   # stable sort for pagination
    }

    # Paginate through all matching docs using search_after
    page_count = 0
    total_processed = 0
    last_sort = None

    while True:
        if last_sort:
            search_body["search_after"] = last_sort

        try:
            res = es.search(index=INDEX_NAME, body=search_body)
        except Exception as e:
            print(f"[/logs/time] ES search error: {e}")
            raise HTTPException(status_code=500, detail=str(e))

        hits = res["hits"]["hits"]
        if not hits:
            break

        page_count += 1
        last_sort = hits[-1]["sort"]

        for hit in hits:
            src = hit["_source"]
            priority   = str(src.get("PiorityEN") or "").strip()
            update_raw = src.get("UpdateDate")
            create_raw = src.get("CreateDate")

            total_processed += 1

            if not priority or not update_raw or not create_raw:
                continue

            try:
                end_dt   = datetime.fromisoformat(update_raw)
                start_dt = datetime.fromisoformat(create_raw)
                duration_min = abs((end_dt - start_dt).total_seconds()) / 60.0

                durations.setdefault(priority, []).append(duration_min)
            except Exception as parse_err:
                print(f"[/logs/time] Date parse error: {parse_err} | update={update_raw!r} create={create_raw!r}")
                continue

    print(f"[/logs/time] pages={page_count}, docs={total_processed}, priorities={list(durations.keys())}")

    stats = {
        p: {
            "avg":   round(sum(d) / len(d), 2) if d else 0.0,
            "count": len(d),
        }
        for p, d in durations.items()
        if d
    }

    return {"status": "success", "stats": stats}