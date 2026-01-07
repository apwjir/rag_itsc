import json
import time
from threading import Event

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.db.models.auto_analyze_setting import AutoAnalyzeSetting
from app.db.es_client import es, INDEX_NAME
from app.services.ai_engine import ai_engine_instance


def load_setting(db: Session) -> AutoAnalyzeSetting | None:
    return db.query(AutoAnalyzeSetting).first()


def fetch_pending_logs(limit: int):
    # pending = ไม่มี ai_generated_at และ ai_status ไม่ใช่ processing
    body = {
        "query": {
            "bool": {
                "must_not": [{"exists": {"field": "ai_generated_at"}}],
                "filter": [
                    {"bool": {"must_not": [{"term": {"ai_status.keyword": "processing"}}]}}
                ]
            }
        },
        "size": limit,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
    }
    res = es.search(index=INDEX_NAME, body=body)
    return res["hits"]["hits"]


def mark_processing(doc_id: str) -> bool:
    # ทำแบบง่าย: update ให้เป็น processing ก่อน
    # ถ้าอยากกันชนงานชนกันจริง ๆ ค่อยทำ optimistic concurrency ทีหลัง
    es.update(index=INDEX_NAME, id=doc_id, body={"doc": {"ai_status": "processing"}})
    return True


def mark_done(doc_id: str, ai_result: dict):
    es.update(
        index=INDEX_NAME,
        id=doc_id,
        body={
            "doc": {
                "ai_analysis": ai_result,
                "ai_status": "auto_generated",
                "ai_generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        },
    )


def mark_failed(doc_id: str, err: str):
    es.update(
        index=INDEX_NAME,
        id=doc_id,
        body={"doc": {"ai_status": "failed", "ai_error": err}},
    )


def run_auto_worker(stop_event: Event):
    """
    Worker loop:
    - อ่าน setting จาก DB
    - ถ้า enabled -> ดึง pending logs -> analyze เป็น batch
    - sleep interval_sec หลังจบ batch
    """
    while not stop_event.is_set():
        db = SessionLocal()
        try:
            setting = load_setting(db)
            if not setting or not setting.enabled:
                time.sleep(5)
                continue

            batch_size = max(1, min(int(setting.batch_size), 5))
            interval_sec = max(2, min(int(setting.interval_sec), 60))

            hits = fetch_pending_logs(limit=batch_size)
            if not hits:
                time.sleep(5)
                continue

            for h in hits:
                if stop_event.is_set():
                    break

                doc_id = h["_id"]
                src = h["_source"]

                try:
                    mark_processing(doc_id)

                    cat = str(src.get("CategoryEN", "Unknown"))
                    subj = str(src.get("IncidentSubject", ""))
                    msg = str(src.get("IncidentMessage", ""))

                    ai_result = ai_engine_instance.analyze_incident(cat, subj, msg)
                    if not isinstance(ai_result, dict):
                        raise Exception(f"AI returned invalid: {ai_result}")

                    mark_done(doc_id, ai_result)

                except Exception as e:
                    err = str(e)
                    mark_failed(doc_id, err)

                    if "429" in err or "rate limit" in err.lower():
                        time.sleep(30)

            time.sleep(interval_sec)

        finally:
            db.close()

    print("🛑 Auto worker stopped")
