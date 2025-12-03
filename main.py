from fastapi import FastAPI, UploadFile, File, HTTPException
from elasticsearch import Elasticsearch, helpers
from contextlib import asynccontextmanager # ต้องใช้ตัวนี้สำหรับ Lifespan
import pandas as pd
import io
import numpy as np
import uuid 
from datetime import datetime
from typing import Optional, List, Dict, Any 
from pydantic import BaseModel
import config
from ai_engine import ai_engine_instance  

# --- Lifespan Manager ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. โหลด Model AI และเชื่อมต่อ Qdrant เมื่อ Server start (ทำแค่ครั้งเดียว)
    print("🚀 Server Starting... Initializing AI Engine...")
    ai_engine_instance.init_models()
    yield
    # Cleanup (ถ้ามี)
    print("🛑 Server Stopping...")

app = FastAPI(lifespan=lifespan)

# เชื่อมต่อ Elasticsearch
es = Elasticsearch("http://localhost:9200")
INDEX_NAME = "cmu-incidents-fastapi"

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

# --- Function 2: โครงสร้าง AI เริ่มต้น ---
def get_empty_ai_structure():
    return {
        "mitigation_plan": [], 
        "related_threats": []  
    }

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

# --- Route Upload ---
@app.post("/upload-log/")
async def upload_log_csv(file: UploadFile = File(...)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="ขอเป็นไฟล์ CSV เท่านั้นครับ")

    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
        
        # --- Filter out Admin Information Sharing ---
        # กรองข้อมูลก่อน Clean Data เพื่อลดจำนวน row ที่ไม่จำเป็น
        if 'CategoryEN' in df.columns:
             df = df[df['CategoryEN'] != 'Admin Information Sharing']

        df = df.where(pd.notnull(df), None)
        
        actions = []
        for _, row in df.iterrows():
            doc = row.to_dict()
            
            # 1. สร้าง UID
            generated_uid = str(uuid.uuid4())
            doc['uid'] = generated_uid

            # 2. แปลงวันที่
            doc['@timestamp'] = parse_date_from_ticket(doc.get('TicketId'))
            
            # 3. ใส่โครงสร้าง AI (เริ่มแรกเป็นค่าว่าง)
            doc['ai_analysis'] = get_empty_ai_structure()

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
async def update_ai_analysis(uid: str, ai_data: AIAnalysisUpdate):
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

# --- Route Search ---
@app.get("/search-logs/")
async def search_logs(keyword: Optional[str] = None, limit: int = 10, skip: int = 0):
    if not keyword:
        body = {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc"}}]}
    else:
        body = {
            "query": {
                "multi_match": {
                    "query": keyword,
                    "fields": ["IncidentSubject", "IncidentMessage", "TicketId", "uid"],
                    "fuzziness": "AUTO"
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

    try:
        res = es.search(index="cmu-incidents-fastapi", body=body, size=limit, from_=skip)
        hits = res['hits']['hits']
        results = [hit['_source'] for hit in hits]
        return {"total": res['hits']['total']['value'], "data": results}
    except Exception as e:
        return {"error": str(e)}

# --- Route Get by TicketId ---
@app.get("/log/ticket/{ticket_id}")
async def get_log_by_ticket_id(ticket_id: str):
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
async def get_log_by_uid(uid: str):
    try:
        res = es.get(index="cmu-incidents-fastapi", id=uid)
        return res['_source']
    except Exception as e:
        raise HTTPException(status_code=404, detail="Log not found")

# --- Route Delete All ---
@app.delete("/delete-all-logs/")
async def delete_all_logs():
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
async def generate_ai_analysis(uid: str):
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
        
    except Exception as e:
        print(f"AI Engine Error: {e}")
        raise HTTPException(status_code=500, detail=f"AI Processing Error: {str(e)}")

    # 3. อัปเดตข้อมูลกลับลง Elasticsearch
    try:
        update_body = {
            "doc": {
                "ai_analysis": ai_result,  # เขียนทับ field ai_analysis เดิม
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