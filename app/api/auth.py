from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from decouple import config
from jose import jwt, JWTError

from app.db.session import get_db
from app.db.models.user import User
from app.core.security import verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from app.core.deps import get_current_user 

router = APIRouter()

SECRET_KEY = config("SECRET_KEY")
ALGORITHM = config("ALGORITHM")

class LoginRequest(BaseModel):
    username: str
    password: str

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

@router.post("/login")
def login(
    data: LoginRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, data.username, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user.username})

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",     
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return {
        "status": "success",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        }
    }

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(
        key="access_token",
        httponly=True,
        secure=False,
        samesite="lax",
    )

    return {"status": "logged_out"}

@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        }
    }
