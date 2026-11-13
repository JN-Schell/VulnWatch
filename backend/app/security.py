import hashlib
import secrets
import time

from fastapi import Depends, HTTPException, Request
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.config import get_settings
from app.db import get_db, utcnow
from app.models import AuditEvent, Permission, RateBucket, RiskPolicy, Role, Session, SyncState, User

passwords = PasswordHash.recommended()
DUMMY_HASH = passwords.hash("nonexistent-account-timing-placeholder")
ROLE_PERMISSIONS = {
    "admin": ["read", "write", "admin", "audit"],
    "analyst": ["read", "write"],
    "viewer": ["read"],
}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def audit(db, actor_id, action, target, details=None):
    db.add(AuditEvent(actor_id=actor_id, action=action, target=str(target), details=details or {}))


def bootstrap(db):
    for name in {name for values in ROLE_PERMISSIONS.values() for name in values}:
        if not db.scalar(select(Permission).where(Permission.name == name)):
            db.add(Permission(name=name))
    db.flush()
    for name, permissions in ROLE_PERMISSIONS.items():
        if not db.scalar(select(Role).where(Role.name == name)):
            db.add(
                Role(
                    name=name,
                    permissions=list(db.scalars(select(Permission).where(Permission.name.in_(permissions)))),
                )
            )
    if not db.get(RiskPolicy, 1):
        db.add(RiskPolicy(id=1))
    if not db.get(SyncState, 1):
        db.add(SyncState(id=1))
    db.commit()


def check_origin(request):
    origin = request.headers.get("origin")
    if origin not in get_settings().trusted_origins:
        raise HTTPException(403, "Trusted Origin header required")


def current_user(request: Request, db=Depends(get_db)):
    token = request.cookies.get("vw_session", "")
    session = db.get(Session, digest(token)) if token and len(token) <= 100 else None
    user = db.get(User, session.user_id) if session and session.expires_at > utcnow() else None
    if not user or not user.active:
        raise HTTPException(401, "Authentication required")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        check_origin(request)
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf_token):
            raise HTTPException(403, "Invalid CSRF token")
    request.state.auth_session = session
    return user


def require(permission):
    def authorized(user=Depends(current_user)):
        if permission not in {entry.name for entry in user.role.permissions}:
            raise HTTPException(403, "Insufficient permissions")
        return user

    return authorized


def consume_rate(db, key, limit, seconds=60):
    window = int(time.time()) // seconds
    insert = sqlite_insert if db.bind.dialect.name == "sqlite" else pg_insert
    statement = insert(RateBucket).values(key=digest(key), window=window, count=1)
    statement = statement.on_conflict_do_update(
        index_elements=["key", "window"], set_={"count": RateBucket.count + 1}
    ).returning(RateBucket.count)
    count = db.scalar(statement)
    db.commit()
    if count > limit:
        raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": str(seconds)})
