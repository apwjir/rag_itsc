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
    priority: Optional[List[str]] = Query(None),
    incident_id: Optional[str] = Query(None),
    category: Optional[List[str]] = Query(None),
    user: str = Depends(get_current_user)
):
    # 2. สร้างรายการ Filter
    filters = [
        {"exists": {"field": "UpdateDate"}},
        {"exists": {"field": "CreateDate"}},
        {"bool": {"must_not": [{"terms": {"PiorityEN.keyword": ["INFORMATION", "Information", "information"]}}]}}
    ]

    # 3. เพิ่ม Dynamic Filters ตามที่หน้าบ้านส่งมา
    if date_from or date_to:
        r = {}
        if date_from: r["gte"] = date_from
        if date_to: r["lte"] = f"{date_to}T23:59:59"
        filters.append({"range": {"CreateDate": r}})

    if priority:
        priority_clauses = [{"wildcard": {"PiorityEN.keyword": {"value": f"*{p}*", "case_insensitive": True}}} for p in priority]
        filters.append({"bool": {"should": priority_clauses, "minimum_should_match": 1}})

    if incident_id:
        try:
            filters.append({"term": {"IncidentsId": int(incident_id)}})
        except ValueError:
            pass # ถ้าไม่ใช่ตัวเลข ไม่ต้องกรองเพื่อให้ไม่พัง
        
    if category:
        category_clauses = [{"wildcard": {"CategoryEN.keyword": {"value": f"*{c}*", "case_insensitive": True}}} for c in category]
        filters.append({"bool": {"should": category_clauses, "minimum_should_match": 1}})

    # 4. สร้าง Query Body สำหรับตาราง
    body = {
        "size": limit,
        "query": {"bool": {"filter": filters}},
        "sort": [{"UpdateDate.keyword": "desc"}, {"_id": "asc"}]
    }

    if search_after:
        body["search_after"] = search_after.split("|")

    try:
        res = es.search(index=INDEX_NAME, body=body)
        hits = res["hits"]["hits"]
        total = res["hits"]["total"]["value"]

        data = [h["_source"] for h in hits]
        next_cursor = "|".join(hits[-1]["sort"]) if hits else None

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
    # 2. สร้างรายการ Filter พื้นฐาน (เหมือนเดิม)
    filters = [
        {"exists": {"field": "UpdateDate"}},
        {"exists": {"field": "CreateDate"}},
        {"bool": {
            "must_not": [
                {"terms": {"PiorityEN.keyword": ["INFORMATION", "Information", "information"]}}
            ]
        }}
    ]

    # 3. เพิ่ม Dynamic Filters ตามที่รับมาจากหน้าบ้าน
    # กรองตามช่วงวันที่ (CreateDate)
    if date_from or date_to:
        date_range = {}
        if date_from: date_range["gte"] = date_from
        if date_to: date_range["lte"] = f"{date_to}T23:59:59" # รวมเวลาจนถึงสิ้นวัน
        filters.append({"range": {"CreateDate": date_range}})

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

    painless_script = """
        if (doc['UpdateDate.keyword'].size() > 0 && doc['CreateDate'].size() > 0) {
            try {
                String rawEnd = doc['UpdateDate.keyword'].value;
                
                String cleanEnd = rawEnd.replace('T', ' ').trim();
                if (cleanEnd.length() > 19) cleanEnd = cleanEnd.substring(0, 19);
                
                DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                long endMs = LocalDateTime.parse(cleanEnd, fmt)
                    .atZone(ZoneId.of("UTC")).toInstant().toEpochMilli();
                
                long startMs = doc['CreateDate'].value.toInstant().toEpochMilli();
                
                return (double)Math.abs(endMs - startMs) / 60000.0;
            } catch (Exception e) { return null; }
        }
        return null;
    """

    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": filters # 🚀 4. ใช้รายการ filters ที่สร้างแบบ Dynamic
            }
        },
        "aggs": {
            "by_priority": {
                "terms": {"field": "PiorityEN.keyword"},
                "aggs": {
                    "avg_duration": {
                        "avg": {
                            "script": {
                                "lang": "painless",
                                "source": painless_script
                            }
                        }
                    }
                }
            }
        }
    }

    try:
        res = es.search(index=INDEX_NAME, body=body)
        aggs = res.get("aggregations", res.get("aggs", {}))
        buckets = aggs.get("by_priority", {}).get("buckets", [])
        
        stats = {}
        for b in buckets:
            avg_val = b.get("avg_duration", {}).get("value")
            stats[b["key"]] = {
                "avg": round(float(avg_val), 2) if avg_val is not None else 0.0,
                "count": b["doc_count"]
            }
        
        return {"status": "success", "stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))