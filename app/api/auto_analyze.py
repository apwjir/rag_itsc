from fastapi import APIRouter, Depends, BackgroundTasks
from elasticsearch import Elasticsearch
from app.core.deps import get_current_user
from app.services.auto_analyzer import auto_analyze_pending_logs

router = APIRouter()

@router.post("/auto-analyze")
async def trigger_auto_analyze(
    background_tasks: BackgroundTasks,
    user: str = Depends(get_current_user)
):
    from app.main import es   # reuse ES client

    background_tasks.add_task(auto_analyze_pending_logs, es)

    return {
        "status": "started",
        "message": "Auto analysis started (limited)"
    }