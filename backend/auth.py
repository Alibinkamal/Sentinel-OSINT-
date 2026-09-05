"""
JWT auth + RBAC enforcement.
Issue tokens on login, verify on protected routes, and gate routes by permission.
"""
import time
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from config import JWT_SECRET, JWT_ALG, JWT_TTL_HOURS
import db
import permissions as perm

_bearer = HTTPBearer(auto_error=False)


def issue_token(user: dict) -> str:
    now = int(time.time())
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + JWT_TTL_HOURS * 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def identity(user_row: dict) -> dict:
    """Public identity object shipped to the client — includes resolved perms."""
    role = user_row["role"]
    return {
        "username": user_row["username"],
        "role": role,
        "role_label": perm.ROLES.get(role, {}).get("label", role),
        "level": perm.role_level(role),
        "permissions": sorted(perm.perms_for(role)),
    }


def current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    u = db.get_user(payload.get("sub"))
    if not u:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown user")
    return identity(u)


def require_perm(permission: str):
    """Dependency factory: 403 unless the caller's role grants `permission`."""
    def _dep(user: dict = Depends(current_user)) -> dict:
        if permission not in user.get("permissions", []):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"Permission '{permission}' required")
        return user
    return _dep
