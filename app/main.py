from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware 
from elasticsearch import Elasticsearch, helpers
from contextlib import asynccontextmanager # ต้องใช้ตัวนี้สำหรับ Lifespan
import pandas as pd
import io
import numpy as np
import uuid
import json
from datetime import datetime
from typing import Optional, List, Dict, Any 
from pydantic import BaseModel
from app.services.ai_engine import ai_engine_instance,AIEngineError
import qdrant_client
from app.api.auth import router as auth_router 
from app.core.deps import get_current_user
from app.api.auto_analyze import router as auto_analyze_router
from app.api.soc_action import router as soc_action_router
from app.db.es_client import es, INDEX_NAME
from app.api.dashboard import router as dashboard_router

from app.services.auto_worker import run_auto_worker
from threading import Thread, Event
stop_event = Event()
worker_thread: Thread | None = None

# --- Lifespan Manager ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker_thread
    print("🚀 Server Starting... Initializing AI Engine...")
    
    # --- 🔍 แก้เป็นบรรทัดนี้ครับ ---
    print(f"🔎 DEBUG: Module Path = {qdrant_client}") 
    # (ถ้ามันโหลดถูกที่ ต้องมีคำว่า 'site-packages' ใน Path ที่แสดงออกมา)
    
    # --- ส่วนเช็ค search method เก็บไว้เหมือนเดิม ---
    try:
        ai_engine_instance.init_models()

        stop_event.clear()

        if not worker_thread or not worker_thread.is_alive():
            worker_thread = Thread(
                target=run_auto_worker,
                args=(stop_event,),
                daemon=True,
            )
            worker_thread.start()
            print("Auto worker thread started")
        else:
            print("ℹ️ Auto worker thread already running")

        if ai_engine_instance.client is None:
            print("Qdrant not connected")
        else:
            print("Qdrant client OK")

    except Exception as e:
        print(f"💥 Error during init: {e}")
    yield

    stop_event.set()
    if worker_thread and worker_thread.is_alive():
        worker_thread.join(timeout=5)
    print("🛑 Server Stopping...")
    
app = FastAPI(lifespan=lifespan)

# เชื่อมต่อ Elasticsearch
# es = Elasticsearch("http://localhost:9200")
# INDEX_NAME = "cmu-incidents-fastapi"

# --- Function 1: แปลงวันที่ ---
def parse_date_from_ticket(ticket_id):
    try:
        if ticket_id is None or (isinstance(ticket_id, float) and np.isnan(ticket_id)):
             return datetime.now().isoformat()

        date_part = str(ticket_id).split('-')[0]
        
        if not date_part.isdigit() or len(date_part) < 4:
             return datetime.now().isoformat()

        year = int(date_part[:4])
        rest = date_part[4:]
        
        if len(rest) == 3:
            month = int(rest[0])
            day = int(rest[1:])
        elif len(rest) == 4:
            month = int(rest[:2])
            day = int(rest[2:])
        else:
            if rest and int(rest) > 1231:
                 month = int(rest[0])
                 day = int(rest[1:])
            elif rest:
                 month = int(rest[:2])
                 day = int(rest[2:])
            else:
                 return datetime.now().isoformat()
                 
        return datetime(year, month, day).isoformat()
    except Exception as e:
        print(f"Date Parse Error: {e}") 
        return datetime.now().isoformat()

def map_ai_engine_error(e: Exception):
    # ✅ ถ้าเป็น AIEngineError ให้ map ตาม code ได้เลย
    if isinstance(e, AIEngineError):
        if e.code == "EXPIRED_API_KEY":
            return HTTPException(
                status_code=401,
                detail={
                    "error": "EXPIRED_API_KEY",
                    "message": str(e),
                    "provider_message": getattr(e, "provider_message", ""),
                },
            )
        if e.code == "RATE_LIMIT":
            return HTTPException(
                status_code=429,
                detail={
                    "error": "RATE_LIMIT",
                    "message": str(e),
                    "provider_message": getattr(e, "provider_message", ""),
                },
            )

        return HTTPException(
            status_code=500,
            detail={
                "error": e.code,
                "message": str(e),
                "provider_message": getattr(e, "provider_message", ""),
            },
        )

    # --- fallback เดิมของคุณ (กรณี error แปลก ๆ) ---
    msg = str(e)
    if "expired_api_key" in msg or ("Invalid API Key" in msg and "Error code: 401" in msg):
        return HTTPException(
            status_code=401,
            detail={
                "error": "EXPIRED_API_KEY",
                "message": "AI provider API key expired/invalid. Please update API key.",
                "provider_message": msg,
            },
        )

    if "Error code: 429" in msg or "rate limit" in msg.lower():
        return HTTPException(
            status_code=429,
            detail={
                "error": "RATE_LIMIT",
                "message": "AI provider rate limited. Please retry later.",
                "provider_message": msg,
            },
        )

    return HTTPException(
        status_code=500,
        detail={
            "error": "AI_PROCESSING_ERROR",
            "message": "AI processing failed.",
            "provider_message": msg,
        },
    )

# --- Pydantic Models (สำหรับรับข้อมูล Update) ---
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

#--- CORS Middleware ---
origins = [
    "http://localhost:5173",  # ← Vite frontend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,  # ← สำคัญสำหรับ Cookies ของ JWT Session
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Include Auth Router ---
app.include_router(auth_router, prefix="/auth", tags=["Auth"])

# --- Include Auto Analyze Router ---
app.include_router(auto_analyze_router, tags=["Auto Analysis"])

# --- Include SOC Select Action Router ---
app.include_router(soc_action_router)

# --- Include Dashboard Router ---
app.include_router(dashboard_router)

# --- Route Upload ---
@app.post("/upload-log/")
async def upload_log_csv(file: UploadFile = File(...), user: str = Depends(get_current_user)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="ขอเป็นไฟล์ CSV เท่านั้นครับ")

    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))

        df = df.where(pd.notnull(df), None)
        
        actions = []
        for _, row in df.iterrows():
            doc = row.to_dict()
            
            # 1. สร้าง UID
            generated_uid = str(uuid.uuid4())

            # 2. แปลงวันที่
            doc['@timestamp'] = parse_date_from_ticket(doc.get('TicketId'))
            
            # 3. ใส่โครงสร้าง AI (เริ่มแรกเป็นค่าว่าง)
            doc['ai_analysis'] = None
            doc["ai_status"] = "pending"
            doc["ai_generated_at"] = None

            # 4. เตรียมข้อมูลสำหรับ Bulk Insert
            actions.append({
                "_index": "cmu-incidents-fastapi",
                "_id": generated_uid, 
                "_source": doc
            })

        if not es.ping():
             raise Exception("Cannot connect to Elasticsearch at localhost:9200")

        success, failed = helpers.bulk(es, actions)
        
        return {
            "status": "success",
            "total_rows_processed": len(df), # จำนวนแถวที่เหลือหลังจากการกรอง
            "inserted_count": success,
            "note": "Imported successfully (Filtered out 'Admin Information Sharing')"
        }

    except Exception as e:
        print(f"!!! CRITICAL ERROR !!!: {str(e)}") 
        raise HTTPException(status_code=500, detail=f"Server Error: {str(e)}")

# --- Route Update AI Analysis (NEW) ---
@app.put("/log/update-ai/{uid}")
async def update_ai_analysis(uid: str, ai_data: AIAnalysisUpdate, user: str = Depends(get_current_user)):
    """
    อัปเดตข้อมูล AI Analysis (Mitigation Plan & Related Threats) โดยใช้ UID
    """
    try:
        # 1. เช็คก่อนว่ามีข้อมูลไหม
        if not es.exists(index="cmu-incidents-fastapi", id=uid):
             raise HTTPException(status_code=404, detail="Log ID not found")

        # 2. เตรียมข้อมูลสำหรับ Update (Elasticsearch Partial Update)
        update_body = {
            "doc": {
                "ai_analysis": ai_data.dict() # แปลง Pydantic model เป็น Dictionary
            }
        }

        # 3. สั่ง Update
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
    
@app.get("/search-logs/")
async def search_logs(
    keyword: Optional[str] = None,
    limit: int = Query(50, le=200),
    search_after: Optional[str] = None,
    user: str = Depends(get_current_user),
):
    # 1️⃣ สร้าง query
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

    # 2️⃣ สร้าง body หลัก
    body = {
        "query": query,
        "size": limit,
        "track_total_hits": False,
        "sort": [
            {"@timestamp": "desc"},
            {"uid.keyword": "desc"}  # unique tie-breaker
        ],
    }

    if search_after:
        try:
            body["search_after"] = json.loads(search_after)
        except json.JSONDecodeError:
            # กรณี "\"uuid\"" หลุดมา
            fixed = search_after.replace('\\"', '"')
            body["search_after"] = json.loads(fixed)

    # 4️⃣ ยิง Elasticsearch
    res = es.search(
        index=INDEX_NAME,
        body=body
    )

    # 5️⃣ เตรียม response
    hits = res["hits"]["hits"]
    logs = [hit["_source"] for hit in hits]
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

PRIORITY_MAP = {
    "high": 2,
    "medium": 3,
    "low": 4,
}

@app.get("/logs/unanalysis")
async def get_unanalysis_logs(
    limit: int = Query(50, ge=1, le=50),
    search_after: Optional[str] = None,
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    priority: Optional[List[str]] = Query(None),
    priority_id: Optional[List[int]] = Query(None),
    category: Optional[List[str]] = Query(None),
    incident_id: Optional[str] = Query(None),
    user: str = Depends(get_current_user),
):
    filters = []
    must_not = [{"exists": {"field": "ai_generated_at"}}]

    if date_from or date_to:
        r = {}
        if date_from: r["gte"] = date_from
        if date_to: r["lte"] = date_to
        filters.append({"range": {"@timestamp": r}})

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
        "query": {"bool": {"filter": filters, "must_not": must_not}},
        "size": limit,
        "track_total_hits": False,
        "sort": [{"@timestamp": "desc"}, {"_id": "desc"}],
    }

    if search_after:
        body["search_after"] = json.loads(search_after)

    res = es.search(index="cmu-incidents-fastapi", body=body)
    hits = res["hits"]["hits"]
    items = [{"id": h["_id"], **h["_source"]} for h in hits]
    next_cursor = json.dumps(hits[-1]["sort"]) if hits else None
    return {"data": items, "next_cursor": next_cursor}


@app.get("/logs/analyzed")
async def get_analyzed_logs(
    limit: int = Query(50, le=200),
    search_after: Optional[str] = None,
    user: str = Depends(get_current_user)
):
    body = {
        "query": {
            "bool": {
                "must": [
                    { "exists": { "field": "ai_generated_at" } }
                ],
                "must_not": [
                    { "exists": { "field": "soc_action.selected_method_id" } }
                ]
            }
        },
        "size": limit,
        "track_total_hits": False,
        "sort": [
            {"@timestamp": "desc"},
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

@app.get("/logs/summary")
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
    
@app.get("/logs/summary/analysis")
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
                        { "exists": { "field": "soc_action.selected_method_id" } }
                    ]
                }
            }
        }
    )["count"]

    return {
        "analyzed_pending_soc": analyzed_pending_soc
    }

@app.get("/logs/summary/unanalysis")
async def summary_unanalysis(user: str = Depends(get_current_user)):
    unanalyzed = es.count(
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

    return {
        "unanalyzed": unanalyzed
    }

@app.get("/logs/summary/soc")
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

    
@app.get("/logs/soc-actioned")
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

@app.get("/dashboard/summary")
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
                    "@timestamp": {
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
@app.get("/log/ticket/{ticket_id}")
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
@app.get("/log/uid/{uid}")
async def get_log_by_uid(uid: str, user: str = Depends(get_current_user)):
    try:
        res = es.get(index="cmu-incidents-fastapi", id=uid)
        return res['_source']
    except Exception as e:
        raise HTTPException(status_code=404, detail="Log not found")

# --- Route Delete All ---
@app.delete("/delete-all-logs/")
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

# Generate AI Analysis by UID
@app.post("/generate-ai/{uid}")
async def generate_ai_analysis(uid: str, user: str = Depends(get_current_user)):
    """
    1. รับ UID
    2. ดึงข้อมูล Log จาก Elasticsearch
    3. ส่งเข้า RAG (AI Engine)
    4. เอาผลลัพธ์กลับมา Update ลง Elasticsearch
    """
    print(f"⚡ Request received: Generate AI for UID {uid}")

    # 1. ดึงข้อมูลจาก Elasticsearch
    try:
        if not es.exists(index=INDEX_NAME, id=uid):
            raise HTTPException(status_code=404, detail="Log ID not found")
            
        doc = es.get(index=INDEX_NAME, id=uid)
        source = doc['_source']
        
        # ดึงฟิลด์ที่ต้องใช้ในการวิเคราะห์
        cat = str(source.get('CategoryEN', 'Unknown'))
        subj = str(source.get('IncidentSubject', ''))
        msg = str(source.get('IncidentMessage', ''))

        es.update(index=INDEX_NAME, id=uid, body={"doc": {"ai_status": "processing"}})
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Elasticsearch Error: {str(e)}")

    # 2. เรียกใช้ AI Engine (RAG)
    try:
        # ฟังก์ชันนี้จะไปค้น Qdrant และถาม Gemini ให้
        ai_result = ai_engine_instance.analyze_incident(cat, subj, msg)
        
        # ai_result จะหน้าตาแบบนี้:
        # {
        #    "mitigation_plan": [...],
        #    "related_threats": [...]
        # }

        if (
            not isinstance(ai_result, dict)
            or "mitigation_plan" not in ai_result
            or "related_threats" not in ai_result
        ):
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "AI_PROCESSING_ERROR",
                    "message": "AI returned invalid result",
                    "provider_message": str(ai_result),
                },
            )
    except Exception as e:
        es.update(
            index=INDEX_NAME,
            id=uid,
            body={
                "doc": {
                    "ai_status": "failed",
                    "ai_generated_at": None,
                    "ai_analysis": None,
                }
            },
        )
        raise map_ai_engine_error(e)

    # 3. อัปเดตข้อมูลกลับลง Elasticsearch
    try: 
        update_body = {
            "doc": {
                "ai_analysis": ai_result,  # เขียนทับ field ai_analysis เดิม
                "ai_status": "auto_generated",
                "ai_generated_at": datetime.now().isoformat() # (Optional) แปะเวลาที่ gen ไว้ด้วย
            }
        }
        es.update(index=INDEX_NAME, id=uid, body=update_body)
        
        return {
            "status": "success",
            "uid": uid,
            "message": "AI Analysis generated and updated successfully",
            "data": ai_result # ส่งผลลัพธ์กลับไปให้ดูด้วยเลย
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update Elasticsearch: {str(e)}")

@app.get("/ai/health")
async def ai_health(user: str = Depends(get_current_user)):
    try:
        return {"status": "ok"}
    except Exception as e:
        raise map_ai_engine_error(e)
