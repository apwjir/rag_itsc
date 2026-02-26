from fastapi import APIRouter
from app.db.es_client import es  

router = APIRouter()

@router.get("/health")
async def health_check():
    try:
        if not es.ping():
            raise Exception("Elasticsearch not reachable")

        return {"ok": True}
    except Exception:
        return {"ok": False}