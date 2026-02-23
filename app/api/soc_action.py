from app.db.models.user import User
import json
from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime
from pydantic import BaseModel
from typing import Optional

from app.core.deps import get_current_user
from app.db.es_client import es, INDEX_NAME

router = APIRouter(prefix="/soc", tags=["SOC Action"])

# ---------
# Request Schema
# ---------
class SOCActionRequest(BaseModel):
    selected_method_id: int
    selected_action: str
    rating: Optional[int] = None
    comment: Optional[str] = None


# ------------------
# API: SOC เลือก mitigation + ให้คะแนน AI
# ------------------
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

    soc_action_doc = {
        "selected_method_id": body.selected_method_id,
        "selected_action": body.selected_action,
        "comment": body.comment,
        "rating": body.rating,
        "selected_by": user.username,
        "selected_by_id": user.id,    
        "selected_by_role": user.role,    
        "selected_at": datetime.now().isoformat(),
    }

    es.update(
        index=INDEX_NAME,
        id=uid,
        body={"doc": {"soc_action": soc_action_doc}}
    )

    return {
        "status": "success",
        "uid": uid,
        "soc_action": soc_action_doc
    }