from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.db.session import get_db
from app.db.models.auto_analyze_setting import AutoAnalyzeSetting

router = APIRouter(prefix="/auto", tags=["Auto Analysis"])

class AutoSettingOut(BaseModel):
    enabled: bool
    batch_size: int
    interval_sec: int

class AutoSettingUpdate(BaseModel):
    enabled: bool | None = None
    batch_size: int | None = Field(default=None, ge=1, le=5)
    interval_sec: int | None = Field(default=None, ge=1, le=60)

def get_or_create_setting(db: Session) -> AutoAnalyzeSetting:
    row = db.query(AutoAnalyzeSetting).first()
    if not row:
        row = AutoAnalyzeSetting(enabled=False, batch_size=1, interval_sec=4)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row

@router.get("/settings", response_model=AutoSettingOut)
def get_settings(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = get_or_create_setting(db)
    return AutoSettingOut(
        enabled=row.enabled,
        batch_size=row.batch_size,
        interval_sec=row.interval_sec,
    )

@router.put("/settings", response_model=AutoSettingOut)
def update_settings(
    payload: AutoSettingUpdate,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = get_or_create_setting(db)

    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.batch_size is not None:
        row.batch_size = payload.batch_size
    if payload.interval_sec is not None:
        row.interval_sec = payload.interval_sec

    db.commit()
    db.refresh(row)

    return AutoSettingOut(
        enabled=row.enabled,
        batch_size=row.batch_size,
        interval_sec=row.interval_sec,
    )
