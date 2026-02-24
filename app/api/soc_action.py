from app.db.models.user import User
import json
from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel
from typing import Optional

from app.core.deps import get_current_user
from app.db.es_client import es, INDEX_NAME

BANGKOK_TZ = timezone(timedelta(hours=7))

router = APIRouter(prefix="/soc", tags=["SOC Action"])

class SOCActionRequest(BaseModel):
    selected_method_id: int
    selected_action: str
    rating: Optional[int] = None
    comment: Optional[str] = None

@router.put("/action/{uid}")
async def select_soc_action(
    uid: str,
    body: SOCActionRequest,
    user: User = Depends(get_current_user)
):
    if not es.exists(index=INDEX_NAME, id=uid):
        raise HTTPException(status_code=404, detail="Log not found")

    if body.rating is None:
        raise HTTPException(status_code=400, detail="Please enter a rating")

    if not (1 <= body.rating <= 5):
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")

    now_bangkok = datetime.now(BANGKOK_TZ).strftime("%Y-%m-%dT%H:%M:%S+07:00")

    soc_action_doc = {
        "selected_method_id": body.selected_method_id,
        "selected_action": body.selected_action,
        "comment": body.comment,
        "rating": body.rating,
        "selected_by": user.username,
        "selected_by_id": user.id,    
        "selected_by_role": user.role,    
        "selected_at": now_bangkok,
    }

    # Check if UpdateDate already exists
    existing_doc = es.get(index=INDEX_NAME, id=uid, _source=["UpdateDate"])
    existing_update_date = existing_doc.get("_source", {}).get("UpdateDate")

    update_body = {"soc_action": soc_action_doc}

    if not existing_update_date:
        update_body["UpdateDate"] = now_bangkok

    es.update(
        index=INDEX_NAME,
        id=uid,
        body={"doc": update_body}
    )

    return {
        "status": "success",
        "uid": uid,
        "soc_action": soc_action_doc
    }