from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Literal, Optional
from sqlalchemy.exc import IntegrityError

from app.db.session import get_db
from app.db.models.user import User
from app.core.security import hash_password
from app.core.deps import get_current_user, require_admin

router = APIRouter(prefix="/users", tags=["Users"])

UserRole = Literal["admin", "member"]

# ---------- Schemas ----------
class UserOut(BaseModel):
    id: int
    username: str
    role: UserRole

    class Config:
        from_attributes = True  # pydantic v2 (ถ้า v1 ใช้ orm_mode=True)

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)
    role: UserRole = "member"

class UserUpdate(BaseModel):
    # admin แก้ได้: role / password
    role: Optional[UserRole] = None
    password: Optional[str] = Field(default=None, min_length=6, max_length=128)

# ---------- Routes ----------
@router.get("", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return db.query(User).order_by(User.id.desc()).all()

@router.post("", response_model=UserOut)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    username = payload.username.strip()

    u = User(
        username=username,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(u)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username already exists")

    db.refresh(u)
    return u

@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    
    if payload.role is not None:
        
        if admin.id == user_id and payload.role != "admin":
            raise HTTPException(status_code=400, detail="Cannot change your own role")

        if u.role == "admin" and payload.role != "admin":
            admin_count = db.query(User).filter(User.role == "admin").count()
            if admin_count <= 1:
                raise HTTPException(status_code=400, detail="System must have at least 1 admin")

        u.role = payload.role

    if payload.password is not None:
        u.hashed_password = hash_password(payload.password)

    db.commit()
    db.refresh(u)
    return u

@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if u.role == "admin":
        admin_count = db.query(User).filter(User.role == "admin").count()
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="System must have at least 1 admin")

    db.delete(u)
    db.commit()
    return {"status": "success"}

