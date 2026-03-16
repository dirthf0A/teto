"""Authentication, authorization, and RBAC.

Roles (hierarchical):
  admin    — full access: manage users, orgs, billing, all scans
  analyst  — read/write scans and findings, read assets, no user mgmt
  viewer   — read-only: assets, findings, reports (no scan triggers)

Role hierarchy: admin > analyst > viewer
Each role inherits permissions of lower roles.

Auth methods:
  1. JWT Bearer token  (OAuth2PasswordBearer)
  2. X-API-Key header  (ApiKeyHeader)

Token payload: {"sub": email, "exp": timestamp}
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.db import SessionLocal
from app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme  = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

# Permissions each role grants (cumulative — higher role includes all lower)
ROLE_PERMISSIONS = {
    "viewer": {
        "read:assets", "read:findings", "read:alerts", "read:scans",
        "read:reports", "read:dashboard",
    },
    "analyst": {
        "read:assets", "read:findings", "read:alerts", "read:scans",
        "read:reports", "read:dashboard",
        "write:scans", "write:findings", "write:alerts",
        "read:templates",
    },
    "admin": {
        "read:assets",   "write:assets",
        "read:findings", "write:findings",
        "read:alerts",   "write:alerts",
        "read:scans",    "write:scans",
        "read:reports",  "write:reports",
        "read:dashboard",
        "read:templates", "write:templates",
        "manage:users",  "manage:org",  "manage:billing",
        "admin:system",
    },
}

ROLE_HIERARCHY = ["viewer", "analyst", "admin"]


def role_has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())


def role_gte(role: str, minimum: str) -> bool:
    """Check if role is >= minimum in hierarchy."""
    try:
        return ROLE_HIERARCHY.index(role) >= ROLE_HIERARCHY.index(minimum)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Password + token
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(subject: str, expires_minutes: Optional[int] = None) -> str:
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes or config.get_jwt_exp_minutes())
    return jwt.encode({"sub": subject, "exp": expire}, config.get_jwt_secret(), algorithm="HS256")


# ---------------------------------------------------------------------------
# User lookup
# ---------------------------------------------------------------------------

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.execute(select(User).where(User.email == email)).scalars().first()


def get_user_by_api_key(db: Session, api_key: str) -> Optional[User]:
    return db.execute(select(User).where(User.api_key == api_key)).scalars().first()


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = get_user_by_email(db, email)
    if not user or not user.password_hash:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


# ---------------------------------------------------------------------------
# FastAPI dependency — current user
# ---------------------------------------------------------------------------

def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Depends(api_key_header),
    db: Session = Depends(get_db),
) -> User:
    # API key auth
    if api_key:
        user = get_user_by_api_key(db, api_key)
        if user:
            if not user.is_active:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
            return user

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(token, config.get_jwt_secret(), algorithms=["HS256"])
        subject = payload.get("sub")
        if not subject:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    user = get_user_by_email(db, subject)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    return user


# ---------------------------------------------------------------------------
# FastAPI dependency — role-based access control
# ---------------------------------------------------------------------------

def require_role(*roles: str):
    """Require user to have one of the specified roles.

    Usage: current_user: User = Depends(require_role("admin", "analyst"))
    """
    def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {' or '.join(roles)}. Your role: {user.role}",
            )
        return user
    return _check


def require_permission(permission: str):
    """Require user to have a specific permission (role-based).

    Usage: current_user: User = Depends(require_permission("write:scans"))
    """
    def _check(user: User = Depends(get_current_user)) -> User:
        if not role_has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}",
            )
        return user
    return _check


def require_min_role(minimum_role: str):
    """Require user to be at minimum_role level or above in hierarchy.

    Usage: current_user: User = Depends(require_min_role("analyst"))
    → allows analyst and admin, rejects viewer
    """
    def _check(user: User = Depends(get_current_user)) -> User:
        if not role_gte(user.role, minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Minimum role required: {minimum_role}. Your role: {user.role}",
            )
        return user
    return _check
