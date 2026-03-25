"""
api/routes/auth.py — Registration, Login, Me
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
POST /api/auth/register   — create account (first user auto-promoted to admin)
POST /api/auth/login      — OAuth2 password form → JWT Bearer token
GET  /api/auth/me         — return current user info
"""

from __future__ import annotations

import logging
import bcrypt as _bcrypt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from core.storage.sqlite_store import (
    create_user,
    get_user_by_username,
    get_user_by_email,
    get_user_count,
)
from api.deps import UserInDB, create_access_token, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


def _hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()


def _verify(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── Request / Response models ──────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email:    str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    username:     str
    role:         str
    user_id:      int


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/register", status_code=201)
async def register(req: RegisterRequest) -> dict:
    """
    Create a new user account.
    • Username and e-mail must be unique.
    • The FIRST user ever registered is automatically given role='admin'.
    """
    # Basic field validation
    req.username = req.username.strip()
    req.email    = req.email.strip().lower()

    if len(req.username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters.")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")

    if get_user_by_username(req.username):
        raise HTTPException(409, f"Username '{req.username}' is already taken.")
    if get_user_by_email(req.email):
        raise HTTPException(409, f"E-mail '{req.email}' is already registered.")

    # First user becomes admin automatically; all others are analysts
    role = "admin" if get_user_count() == 0 else "analyst"

    user = create_user(
        username        = req.username,
        email           = req.email,
        hashed_password = _hash(req.password),
        role            = role,
    )

    logger.info("New user registered: %s (role=%s)", req.username, role)
    return {
        "user_id":  user["id"],
        "username": user["username"],
        "email":    user["email"],
        "role":     user["role"],
        "message":  "Account created." + (" You have been granted admin rights." if role == "admin" else " Welcome, analyst."),
    }


@router.post("/login", response_model=TokenResponse)
async def login(form: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    """
    OAuth2 password flow — returns a JWT Bearer token.
    Accepts username OR e-mail in the 'username' field.
    """
    identifier = form.username.strip()

    # Support login with either username or email
    user_row = get_user_by_username(identifier) or get_user_by_email(identifier.lower())

    if not user_row or not _verify(form.password, user_row["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user_row["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )

    token = create_access_token(
        user_id  = user_row["id"],
        username = user_row["username"],
        role     = user_row["role"],
    )
    logger.info("User logged in: %s", user_row["username"])
    return TokenResponse(
        access_token = token,
        username     = user_row["username"],
        role         = user_row["role"],
        user_id      = user_row["id"],
    )


@router.get("/me")
async def me(current_user: UserInDB = Depends(get_current_user)) -> dict:
    """Return the current authenticated user's profile."""
    return {
        "user_id":  current_user.id,
        "username": current_user.username,
        "email":    current_user.email,
        "role":     current_user.role,
    }
