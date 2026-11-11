from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.database.session import get_db
from app.models.tables import User
from app.services.crypto import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    email: str = Field(min_length=4, max_length=255)
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=4, max_length=255)
    password: str = Field(min_length=1, max_length=128)


def _user_dict(user: User) -> dict:
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


@router.get("/bootstrap-status")
async def bootstrap_status(db: AsyncSession = Depends(get_db)) -> dict:
    count = (await db.execute(select(func.count(User.id)))).scalar_one()
    return {"has_users": count > 0, "user_count": count}


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)) -> dict:
    email_norm = payload.email.strip().lower()
    existing = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email is already registered")

    total_users = (await db.execute(select(func.count(User.id)))).scalar_one()
    role = "admin" if total_users == 0 else "developer"

    user = User(
        name=payload.name.strip(),
        email=email_norm,
        password_hash=hash_password(payload.password),
        role=role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(user.id, user.email)
    return {"access_token": token, "token_type": "bearer", "user": _user_dict(user)}


@router.post("/login")
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> dict:
    email_norm = payload.email.strip().lower()
    user = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(user.id, user.email)
    return {"access_token": token, "token_type": "bearer", "user": _user_dict(user)}


@router.get("/me")
async def me(user: User = Depends(get_current_user)) -> dict:
    return {"user": _user_dict(user)}
