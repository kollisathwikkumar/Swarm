from __future__ import annotations

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database.session import get_db
from app.models.tables import ConnectedAccount, User
from app.services.crypto import decode_access_token, decrypt_secret, hash_password

bearer_scheme = HTTPBearer(auto_error=False)

WORKSPACE_EMAIL = "workspace@reviewboard.local"


async def get_or_create_workspace_user(db: AsyncSession) -> User:
    res = await db.execute(select(User).order_by(User.created_at.asc()).limit(1))
    user = res.scalar_one_or_none()
    if user:
        return user
    user = User(
        email=WORKSPACE_EMAIL,
        name="ReviewBoard Workspace",
        password_hash=hash_password("local-workspace-no-auth"),
        role="admin",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if credentials and credentials.credentials:
        try:
            payload = decode_access_token(credentials.credentials)
            user_id = payload.get("sub")
            if user_id:
                res = await db.execute(select(User).where(User.id == user_id))
                user = res.scalar_one_or_none()
                if user:
                    return user
        except Exception:
            pass
    return await get_or_create_workspace_user(db)


async def resolve_github_token(user_id: str, db: AsyncSession) -> str:
    res = await db.execute(
        select(ConnectedAccount)
        .where(ConnectedAccount.user_id == user_id, ConnectedAccount.provider == "github")
        .order_by(ConnectedAccount.updated_at.desc())
    )
    acct = res.scalars().first()
    if acct and acct.encrypted_access_token:
        decrypted = decrypt_secret(acct.encrypted_access_token)
        if decrypted:
            return decrypted
    return get_settings().github_token.strip()
