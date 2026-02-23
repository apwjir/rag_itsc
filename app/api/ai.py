from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timedelta
import json

from app.core.deps import get_current_user
from app.services.ai_engine import ai_engine_instance, AIEngineError
from app.db.es_client import es, INDEX_NAME

router = APIRouter()


def map_ai_engine_error(e: Exception):
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

    # --- fallback (กรณี error แปลก ๆ) ---
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


# Generate AI Analysis by UID
@router.post("/generate-ai/{uid}")
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
        
        cat = str(source.get('CategoryEN', 'Unknown'))
        subj = str(source.get('IncidentSubject', ''))
        msg = str(source.get('IncidentMessage', ''))

        es.update(index=INDEX_NAME, id=uid, body={"doc": {"ai_status": "processing"}})
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Elasticsearch Error: {str(e)}")

    # 2. เรียกใช้ AI Engine (RAG)
    try:
        ai_result = ai_engine_instance.analyze_incident(cat, subj, msg)

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
                "ai_analysis": ai_result,
                "ai_status": "auto_generated",
                "ai_generated_at": datetime.now().isoformat()
            }
        }
        es.update(index=INDEX_NAME, id=uid, body=update_body)
        
        return {
            "status": "success",
            "uid": uid,
            "message": "AI Analysis generated and updated successfully",
            "data": ai_result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update Elasticsearch: {str(e)}")

@router.get("/ai/health")
async def ai_health(user: str = Depends(get_current_user)):
    try:
        return {"status": "ok"}
    except Exception as e:
        raise map_ai_engine_error(e)

# --- Generate Cybersecurity Threat Intelligence Suggestion ---
@router.post("/generate-suggestion/")
async def generate_suggestion(user: str = Depends(get_current_user)):
    """
    Fetch logs from the past 1 year, send to LLM for cybersecurity
    threat intelligence analysis (stateless — does not store result).
    """
    print("⚡ Request received: Generate Threat Suggestion")

    # 1. Query ES for logs from the past 1 year
    try:
        one_year_ago = (datetime.now() - timedelta(days=365)).isoformat()

        body = {
            "size": 100,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"CreateDate": {"gte": one_year_ago}}},
                    ]
                }
            },
            "sort": [{"CreateDate": "desc"}],
            "_source": [
                "IncidentsId", "CategoryEN", "PiorityEN",
                "IncidentSubject", "IncidentMessage", "CreateDate",
            ],
        }

        res = es.search(index=INDEX_NAME, body=body)
        hits = res["hits"]["hits"]

        if not hits:
            raise HTTPException(
                status_code=404,
                detail="No logs found within the past 1 year.",
            )

        # 2. Format logs for LLM consumption
        log_lines = []
        for h in hits:
            s = h["_source"]
            log_lines.append(
                f"[{s.get('CreateDate', 'N/A')}] "
                f"Priority={s.get('PiorityEN', 'N/A')} | "
                f"Category={s.get('CategoryEN', 'N/A')} | "
                f"Subject={s.get('IncidentSubject', '')} | "
                f"Message={str(s.get('IncidentMessage', ''))[:300]}"
            )

        log_text = "\n".join(log_lines)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to query logs: {str(e)}",
        )

    # 3. Call AI Engine
    try:
        suggestion = ai_engine_instance.generate_suggestion(log_text)

        return {
            "status": "success",
            "logs_analyzed": len(hits),
            "suggestion": suggestion,
        }

    except Exception as e:
        raise map_ai_engine_error(e)
