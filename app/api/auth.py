from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from decouple import config
from jose import jwt, JWTError

from app.db.session import get_db
from app.db.models.user import User
from app.core.security import verify_password, create_access_token

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


# @router.post("/login")
# def login(data: LoginRequest, db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.username == data.username).first()

#     if not user or not verify_password(data.password, user.hashed_password):
#         raise HTTPException(status_code=401, detail="Invalid credentials")

#     token = create_access_token({"sub": user.username})

#     return {"access_token": token, "token_type": "bearer"}

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
        secure=False,        # local only
        samesite="lax",      # <<< สำคัญ ต้องแก้
        max_age=60 * 60,
    )

    return {
        "status": "success",
        "user": {"username": user.username}
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
def get_me(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        return {"user": {"username": username}}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

