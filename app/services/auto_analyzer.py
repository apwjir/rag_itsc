import time
from datetime import datetime
from elasticsearch import Elasticsearch
from app.services.ai_engine import ai_engine_instance

INDEX_NAME = "cmu-incidents-fastapi"

MAX_AUTO_ANALYZE = 5        # จำกัดจำนวน
AI_SLEEP_SEC = 2            # กัน rate limit

def auto_analyze_pending_logs(es: Elasticsearch):
    """
    วิเคราะห์ log ที่ ai_status = pending แบบจำกัดจำนวน
    """
    query = {
        "query": {
            "term": {
                "ai_status": "pending"
            }
        },
        "size": MAX_AUTO_ANALYZE,
        "sort": [{"@timestamp": "desc"}]
    }

    res = es.search(index=INDEX_NAME, body=query)
    hits = res["hits"]["hits"]

    for hit in hits:
        uid = hit["_id"]
        source = hit["_source"]

        try:
            # mark processing
            es.update(
                index=INDEX_NAME,
                id=uid,
                body={"doc": {"ai_status": "processing"}}
            )

            cat = str(source.get("CategoryEN", "Unknown"))
            subj = str(source.get("IncidentSubject", ""))
            msg = str(source.get("IncidentMessage", ""))

            ai_result = ai_engine_instance.analyze_incident(cat, subj, msg)

            es.update(
                index=INDEX_NAME,
                id=uid,
                body={
                    "doc": {
                        "ai_analysis": ai_result,
                        "ai_status": "auto_generated",
                        "ai_generated_at": datetime.now().isoformat()
                    }
                }
            )

            time.sleep(AI_SLEEP_SEC)

        except Exception as e:
            es.update(
                index=INDEX_NAME,
                id=uid,
                body={
                    "doc": {
                        "ai_status": "failed",
                        "ai_error": str(e)
                    }
                }
            )
