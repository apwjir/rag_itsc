from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Query
from elasticsearch import helpers
import pandas as pd
import io
import numpy as np
import uuid
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from pydantic import BaseModel

from app.core.deps import get_current_user
from app.db.es_client import es, INDEX_NAME
from app.db.es_filters import normalize_date

router = APIRouter()

# --- Pydantic Models ---
class MitigationItem(BaseModel):
    method_id: int
    action: str
    reason: str

class RelatedThreatItem(BaseModel):
    mitre_id: str
    name: str

class AIAnalysisUpdate(BaseModel):
    mitigation_plan: List[MitigationItem]
    related_threats: List[RelatedThreatItem]

PRIORITY_MAP = {
    "high": 2,
    "medium": 3,
    "low": 4,
}

# --- Route Upload ---
@router.post("/upload-log/")
async def upload_log(file: UploadFile = File(...), user: str = Depends(get_current_user)):
    filename = file.filename.lower()

    if not (filename.endswith('.csv') or filename.endswith('.xlsx')):
        raise HTTPException(status_code=400, detail="Only .csv (UTF-8) and .xlsx files are supported.")

    try:
        contents = await file.read()

        if filename.endswith(".csv"):
            try:
                # Always try UTF-8 first (policy)
                df = pd.read_csv(io.BytesIO(contents), encoding="utf-8-sig")
            except UnicodeDecodeError:
                import chardet
                detected = chardet.detect(contents)
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"CSV encoding '{detected.get('encoding')}' is not supported. "
                        "Please save the file as UTF-8 (CSV UTF-8) or upload an XLSX file."
                    ),
                )

        else:  # .xlsx
            df = pd.read_excel(io.BytesIO(contents), engine="openpyxl")


        df = df.where(pd.notnull(df), None)

        # --- Check for existing IncidentsId in Elasticsearch ---
        if "IncidentsId" not in df.columns:
            raise HTTPException(
                status_code=400,
                detail="CSV must contain an 'IncidentsId' column for duplicate checking."
            )

        incoming_ids = df["IncidentsId"].dropna().unique().tolist()

        existing_ids: set = set()
        if incoming_ids:
            # Query ES in batches of 1000, using scan to guarantee all matches are returned
            for i in range(0, len(incoming_ids), 1000):
                batch = incoming_ids[i:i + 1000]
                for hit in helpers.scan(
                    es,
                    index="cmu-incidents-fastapi",
                    query={"query": {"terms": {"IncidentsId": batch}}},
                    _source=["IncidentsId"],
                ):
                    existing_ids.add(hit["_source"].get("IncidentsId"))

        skipped_count = 0
        actions = []
        for _, row in df.iterrows():
            doc = row.to_dict()

            # Skip if this IncidentsId already exists in ES
            incident_id = doc.get("IncidentsId")
            if incident_id in existing_ids:
                skipped_count += 1
                continue
            
            generated_uid = str(uuid.uuid4())

            doc["ingested_at"] = datetime.now(timezone(timedelta(hours=7))).replace(microsecond=0).isoformat()
            
            try:
                doc["CreateDate"] = normalize_date(
                    doc.get("CreateDate"),
                    allow_now_if_missing=False,
                )
            except ValueError as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid CreateDate format at row {_ + 2}: '{doc.get('CreateDate')}'. "
                           f"Supported formats: YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS, "
                           f"YYYY-MM-DDTHH:MM:SS+00:00, MM/DD/YYYY."
                )
            
            try:
                doc["UpdateDate"] = normalize_date(
                    doc.get("UpdateDate"),
                    allow_now_if_missing=False,
                )
            except Exception as e:
                print(f"UpdateDate normalize failed: {doc.get('UpdateDate')} → {e}")
                doc["UpdateDate"] = None
            
            doc['ai_analysis'] = None
            doc["ai_status"] = "pending"
            doc["ai_generated_at"] = None

            actions.append({
                "_index": "cmu-incidents-fastapi",
                "_id": generated_uid, 
                "_source": doc
            })

        if not es.ping():
             raise Exception("Cannot connect to Elasticsearch at localhost:9200")

        success = 0
        if actions:
            success, failed = helpers.bulk(
                es, actions,
                chunk_size=2000,
                raise_on_error=False,
            )
        
        return {
            "status": "success",
            "total_rows_in_file": len(df),
            "inserted_count": success,
            "skipped_duplicates": skipped_count,
            "note": f"Imported successfully. {skipped_count} duplicate(s) skipped by IncidentsId."
        }

    except Exception as e:
        print(f"!!! CRITICAL ERROR !!!: {str(e)}") 
        raise HTTPException(status_code=500, detail=f"Server Error: {str(e)}")

# --- Route Update AI Analysis ---
@router.put("/log/update-ai/{uid}")
async def update_ai_analysis(uid: str, ai_data: AIAnalysisUpdate, user: str = Depends(get_current_user)):
    """
    อัปเดตข้อมูล AI Analysis (Mitigation Plan & Related Threats) โดยใช้ UID
    """
    try:
        if not es.exists(index="cmu-incidents-fastapi", id=uid):
             raise HTTPException(status_code=404, detail="Log ID not found")

        update_body = {
            "doc": {
                "ai_analysis": ai_data.dict()
            }
        }

        es.update(index="cmu-incidents-fastapi", id=uid, body=update_body)

        return {
            "status": "success",
            "message": "AI Analysis updated successfully",
            "uid": uid,
            "updated_data": ai_data
        }

    except Exception as e:
        print(f"Update Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/search-logs/")
async def search_logs(
    keyword: Optional[str] = None,
    limit: int = Query(50, le=200),
    search_after: Optional[str] = None,
    user: str = Depends(get_current_user),
):
    if not keyword:
        query = {"match_all": {}}
    else:
        query = {
            "multi_match": {
                "query": keyword,
                "fields": [
                    "IncidentSubject",
                    "IncidentMessage",
                    "TicketId",
                    "uid"
                ],
                "fuzziness": "AUTO"
            }
        }

    body = {
        "query": query,
        "size": limit,
        "track_total_hits": False,
        "sort": [
            {"ingested_at": "desc"},
            {"_id": "desc"}
        ]
    }

    if search_after:
        try:
            body["search_after"] = json.loads(search_after)
        except json.JSONDecodeError:
            fixed = search_after.replace('\\"', '"')
            body["search_after"] = json.loads(fixed)

    res = es.search(
        index=INDEX_NAME,
        body=body
    )

    hits = res["hits"]["hits"]
    items = [
        {
            "id": h["_id"],
            **h["_source"]
        }
        for h in hits
    ]

    next_cursor = None
    if hits:
        next_cursor = json.dumps(hits[-1]["sort"])

    return {
        "data": items,
        "next_cursor": next_cursor,
        "count": len(items)
    } 

@router.get("/logs/unanalysis")
async def get_unanalysis_logs(
    limit: int = Query(50, ge=1, le=50),
    search_after: Optional[str] = None,
    search: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    priority: Optional[List[str]] = Query(None),
    priority_id: Optional[List[int]] = Query(None),
    category: Optional[List[str]] = Query(None),
    incident_id: Optional[str] = Query(None),
    user: str = Depends(get_current_user),
):
    filters = []
    must = []
    must_not = [
        {"exists": {"field": "ai_generated_at"}},
        {"term": {"PiorityId": 6}},
    ]

    if search and search.strip():
        must.append({
            "multi_match": {
                "query": search.strip(),
                "fields": ["IncidentSubject", "IncidentMessage"],
                "fuzziness": "AUTO",
            }
        })

    if date_from or date_to:
        r = {}
        if date_from:
            r["gte"] = normalize_date(date_from)
        if date_to:
            r["lte"] = normalize_date(date_to, end_of_day=True)

        filters.append({"range": {"CreateDate": r}})

    if priority_id or priority:
        should = []
        if priority_id:
            should.append({"terms": {"PiorityId": priority_id}})
        if priority:
            for p in priority:
                s = str(p).strip()
                should.append({"prefix": {"PiorityEN.keyword": s}})
        filters.append({"bool": {"should": should, "minimum_should_match": 1}})

    if category:
        filters.append({"terms": {"CategoryEN.keyword": category}})

    if incident_id:
        s = str(incident_id).strip()
        if s.isdigit():
            filters.append({"term": {"IncidentsId": int(s)}})
        else:
            filters.append({"term": {"IncidentsId.keyword": s}})

    body = {
        "query": {"bool": {"must": must, "filter": filters, "must_not": must_not}},
        "size": limit,
        "track_total_hits": False,
        "sort": [{"IncidentsId": "desc"}, {"_id": "desc"}],
    }

    if search_after:
        body["search_after"] = json.loads(search_after)

    res = es.search(index="cmu-incidents-fastapi", body=body)
    hits = res["hits"]["hits"]
    items = [{"id": h["_id"], **h["_source"]} for h in hits]
    next_cursor = json.dumps(hits[-1]["sort"]) if hits else None
    return {"data": items, "next_cursor": next_cursor}


@router.get("/logs/analyzed")
async def get_analyzed_logs(
    limit: int = Query(50, le=200),
    search_after: Optional[str] = None,
    search: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    priority: Optional[List[str]] = Query(None),
    priority_id: Optional[List[int]] = Query(None),
    category: Optional[List[str]] = Query(None),
    incident_id: Optional[str] = Query(None),
    user: str = Depends(get_current_user)
):
    filters = [{"exists": {"field": "ai_generated_at"}}]
    must = []
    must_not = [{"exists": {"field": "soc_action.selected_method_id"}},{"term": {"PiorityId": 6}}]

    if search and search.strip():
        must.append({
            "multi_match": {
                "query": search.strip(),
                "fields": ["IncidentSubject", "IncidentMessage"],
                "fuzziness": "AUTO",
            }
        })

    if date_from or date_to:
        r = {}
        if date_from:
            r["gte"] = normalize_date(date_from)
        if date_to:
            r["lte"] = normalize_date(date_to, end_of_day=True)
        filters.append({"range": {"CreateDate": r}})

    if priority_id or priority:
        should = []
        if priority_id:
            should.append({"terms": {"PiorityId": priority_id}})
        if priority:
            for p in priority:
                s = str(p).strip()
                should.append({"prefix": {"PiorityEN.keyword": s}})
        filters.append({"bool": {"should": should, "minimum_should_match": 1}})

    if category:
        filters.append({"terms": {"CategoryEN.keyword": category}})

    if incident_id:
        s = str(incident_id).strip()
        if s.isdigit():
            filters.append({"term": {"IncidentsId": int(s)}})
        else:
            filters.append({"term": {"IncidentsId.keyword": s}})

    body = {
        "query": {"bool": {"must": must, "filter": filters, "must_not": must_not}},
        "size": limit,
        "track_total_hits": False,
        "sort": [{"IncidentsId": "desc"}, {"_id": "desc"}],
    }

    if search_after:
        body["search_after"] = json.loads(search_after)

    res = es.search(index=INDEX_NAME, body=body)

    hits = res["hits"]["hits"]
    items = [{"id": h["_id"], **h["_source"]} for h in hits]
    next_cursor = json.dumps(hits[-1]["sort"]) if hits else None

    return {
        "data": items,
        "next_cursor": next_cursor
    }

@router.get("/logs/summary")
async def get_logs_summary(user: str = Depends(get_current_user)):
    try:
        total = es.count(index=INDEX_NAME)["count"]

        analyzed = es.count(
            index=INDEX_NAME,
            body={
                "query": {
                    "exists": {
                        "field": "ai_generated_at"
                    }
                }
            }
        )["count"]

        unanalyzed = total - analyzed

        return {
            "total": total,
            "analyzed": analyzed,
            "unanalyzed": unanalyzed
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/logs/summary/analysis")
async def summary_analysis(user: str = Depends(get_current_user)):
    analyzed_pending_soc = es.count(
        index=INDEX_NAME,
        body={
            "query": {
                "bool": {
                    "must": [
                        { "exists": { "field": "ai_generated_at" } }
                    ],
                    "must_not": [
                        { "exists": { "field": "soc_action.selected_method_id" } },
                        { "term": {"PiorityId": 6} }
                    ]
                }
            }
        }
    )["count"]

    return {
        "analyzed_pending_soc": analyzed_pending_soc
    }

@router.get("/logs/summary/unanalysis")
async def summary_unanalysis(user: str = Depends(get_current_user)):
    unanalyzed = es.count(
        index=INDEX_NAME,
        body={
            "query": {
                "bool": {
                    "must_not": [
                        { "exists": { "field": "ai_generated_at" } },
                        { "term": {"PiorityId": 6} }
                    ]
                }
            }
        }
    )["count"]

    return {
        "unanalyzed": unanalyzed
    }

@router.get("/logs/summary/soc")
async def summary_soc(user: str = Depends(get_current_user)):
    responded = es.count(
        index=INDEX_NAME,
        body={
            "query": {
                "exists": {
                    "field": "soc_action.selected_method_id"
                }
            }
        }
    )["count"]

    avg_rating = es.search(
        index=INDEX_NAME,
        body={
            "size": 0,
            "query": {
                "exists": { "field": "soc_action.rating" }
            },
            "aggs": {
                "avg_rating": {
                    "avg": { "field": "soc_action.rating" }
                }
            }
        }
    )["aggregations"]["avg_rating"]["value"]

    return {
        "responded": responded,
        "avg_rating": round(avg_rating, 2) if avg_rating else None
    }

    
@router.get("/logs/soc-actioned")
async def get_soc_actioned_logs(
    limit: int = Query(50, le=200),
    search_after: Optional[str] = None,
    user: str = Depends(get_current_user),
):
    body = {
        "query": {
            "exists": {
                "field": "soc_action.selected_method_id"
            }
        },
        "size": limit,
        "track_total_hits": False,
        "sort": [
            {"soc_action.selected_at": "desc"},
            {"_id": "desc"}
        ]
    }

    if search_after:
        body["search_after"] = json.loads(search_after)

    res = es.search(index=INDEX_NAME, body=body)

    hits = res["hits"]["hits"]
    items = [{"id": h["_id"], **h["_source"]} for h in hits]

    next_cursor = json.dumps(hits[-1]["sort"]) if hits else None

    return {
        "data": items,
        "next_cursor": next_cursor
    }

@router.get("/dashboard/summary")
async def dashboard_summary(user: str = Depends(get_current_user)):
    total = es.count(index=INDEX_NAME)["count"]

    pending_analysis = es.count(
        index=INDEX_NAME,
        body={
            "query": {
                "bool": {
                    "must_not": [
                        { "exists": { "field": "ai_generated_at" } }
                    ]
                }
            }
        }
    )["count"]

    resolved = es.count(
        index=INDEX_NAME,
        body={
            "query": {
                "exists": {
                    "field": "soc_action.selected_method_id"
                }
            }
        }
    )["count"]

    critical = es.count(
        index=INDEX_NAME,
        body={
            "query": {
                "match_phrase": {
                    "PiorityEN": "High"
                }
            }
        }
    )["count"]

    today = datetime.utcnow().date().isoformat()

    new_today = es.count(
        index=INDEX_NAME,
        body={
            "query": {
                "range": {
                    "ingested_at": {
                        "gte": today,
                        "lte": "now"
                    }
                }
            }
        }
    )["count"]

    return {
        "totalIncidents": total,
        "pendingAnalysis": pending_analysis,
        "resolvedCases": resolved,
        "criticalAlerts": critical,
        "newToday": new_today,
    }


# --- Route Get by TicketId ---
@router.get("/log/ticket/{ticket_id}")
async def get_log_by_ticket_id(ticket_id: str, user: str = Depends(get_current_user)):
    body = {
        "query": {
            "term": {
                "TicketId.keyword": ticket_id 
            }
        }
    }
    try:
        res = es.search(index="cmu-incidents-fastapi", body=body)
        hits = res['hits']['hits']
        if len(hits) > 0:
            return hits[0]['_source']
        else:
            raise HTTPException(status_code=404, detail="Log not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Route Get by UID ---
@router.get("/log/uid/{uid}")
async def get_log_by_uid(uid: str, user: str = Depends(get_current_user)):
    try:
        res = es.get(index="cmu-incidents-fastapi", id=uid)
        return res['_source']
    except Exception as e:
        raise HTTPException(status_code=404, detail="Log not found")

# --- Route Delete All ---
@router.delete("/delete-all-logs/")
async def delete_all_logs(user: str = Depends(get_current_user)):
    try:
        if es.indices.exists(index="cmu-incidents-fastapi"):
            es.delete_by_query(
                index="cmu-incidents-fastapi", 
                body={"query": {"match_all": {}}}
            )
        return {"status": "success", "message": "Deleted all logs"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
