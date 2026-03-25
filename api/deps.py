"""
api/deps.py — FastAPI dependency helpers
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Provides:
  • JWT token creation / verification (python-jose)
  • get_current_user  Depends() — validates Bearer token, returns UserInDB
  • require_admin     Depends() — raises 403 if user.role != 'admin'

All routes that require authentication add:
    current_user: UserInDB = Depends(get_current_user)

Admin-only routes add:
    _admin: UserInDB = Depends(require_admin)
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from core.storage.sqlite_store import get_user_by_id

# ── Config ────────────────────────────────────────────────────────────────────

_secret = os.getenv("JWT_SECRET_KEY")
if not _secret:
    import sys
    # In production the env var MUST be set. For local dev we fall back to a
    # clearly-labelled insecure default and print a loud warning.
    _secret = "dev-insecure-secret-CHANGE-BEFORE-PRODUCTION"
    print(
        "\n[SECURITY WARNING] JWT_SECRET_KEY is not set. "
        "Using an insecure default — set JWT_SECRET_KEY in your .env file before deploying.\n",
        file=sys.stderr,
    )

SECRET_KEY  = _secret
ALGORITHM   = "HS256"
# Token expiry — 480 min (8 h) default; override with JWT_EXPIRE_MINUTES env var
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# ── Pydantic models ───────────────────────────────────────────────────────────

class UserInDB(BaseModel):
    id:         int
    username:   str
    email:      str
    role:       str           # 'admin' | 'analyst' (legacy: 'user' treated as 'analyst')
    is_active:  int           # 1 = active, 0 = deactivated


class TokenData(BaseModel):
    user_id: Optional[int] = None


# ── Token helpers ─────────────────────────────────────────────────────────────

def create_access_token(user_id: int, username: str, role: str) -> str:
    """
    Create a signed JWT containing user_id, username, and role.
    Expires after ACCESS_TOKEN_EXPIRE_MINUTES (default 480 = 8 hrs).
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub":      str(user_id),
        "username": username,
        "role":     role,
        "exp":      expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ── Dependencies ──────────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
) -> UserInDB:
    """
    Decode the Bearer token and return the corresponding user from the DB.
    Raises HTTP 401 on any validation failure (expired, tampered, not found).
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token_value = token or request.cookies.get("auth_token")
    if not token_value:
        raise credentials_exception

    try:
        payload  = jwt.decode(token_value, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str | None = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        raise credentials_exception

    row = get_user_by_id(user_id)
    if not row:
        raise credentials_exception

    user = UserInDB(**row)
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )
    return user


async def require_admin(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    """Raises HTTP 403 unless the authenticated user has role='admin'."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user


async def require_analyst(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    """
    Raises HTTP 403 unless the authenticated user has role='analyst' or 'user'
    (legacy alias).  Admins are intentionally excluded from analyst-only routes
    to enforce the role separation defined in the target architecture.
    """
    if current_user.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint is for analyst accounts only.",
        )
    return current_user


async def require_analyst_or_admin(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    """
    Allow both analyst/user roles AND admin.
    Use this for routes that any authenticated user (regardless of role) may call.
    """
    return current_user


async def get_optional_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
) -> Optional[UserInDB]:
    """
    Like get_current_user but returns None instead of raising 401.
    Used by endpoints that support both JWT and API key authentication.
    """
    try:
        return await get_current_user(request, token)
    except HTTPException:
        return None
