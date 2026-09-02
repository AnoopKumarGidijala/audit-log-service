from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import UserRecord, settings
from app.core.roles import Role

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


@dataclass(frozen=True)
class CurrentUser:
    """The identity established by authentication for the current request:
    who they are, and the role/tenant that authorization decisions (see
    app.core.authorization) are made from. Resolving this is
    authentication's job; deciding whether this identity is *allowed* to
    perform a given operation is a separate, later step - kept in its own
    module deliberately (see docs/authorization-design.md).
    """

    username: str
    role: Role
    tenant_id: str | None


def authenticate_user(username: str, password: str) -> UserRecord | None:
    """Check credentials against the configured user store
    (Settings.auth_users) and return the matching user record, or None if
    the credentials don't match any configured user.
    """
    user = next((u for u in settings.auth_users if u.username == username), None)
    if user is None or user.password != password:
        return None
    return user


def create_access_token(user: UserRecord) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "tenantId": user.tenant_id,
        "exp": expire,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    """Authentication only: establishes who is making the request from the
    bearer token, with no opinion on what they're allowed to do (see
    app.core.authorization.require_roles for that).
    """
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except jwt.InvalidTokenError:
        raise credentials_error

    username = payload.get("sub")
    role_value = payload.get("role")
    if username is None or role_value is None:
        raise credentials_error

    try:
        role = Role(role_value)
    except ValueError:
        raise credentials_error

    return CurrentUser(username=username, role=role, tenant_id=payload.get("tenantId"))
