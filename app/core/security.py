from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import UserRecord, settings
from app.core.passwords import verify_password, verify_unknown_user_password
from app.core.roles import Role

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# A fixed constant, not a setting: see the comment on Settings.secret_key
# in app/core/config.py for why the algorithm must never be
# configuration-driven. Both encode and decode use this single value, and
# decode is called with algorithms=[JWT_ALGORITHM] - a one-element allow
# list - so a token claiming any other algorithm (including "none") is
# rejected by PyJWT before its signature is even considered.
JWT_ALGORITHM: Final[str] = "HS256"

# The one error response for every authentication failure - missing token,
# malformed token, expired token, bad signature, wrong issuer/audience,
# wrong algorithm, unknown username, wrong password. Deliberately
# undifferentiated: which specific check failed is an implementation
# detail an attacker could use to narrow down what to try next (e.g.
# distinguishing "no such user" from "wrong password" enables username
# enumeration), so none of that detail leaves this module. See
# docs/auth-hardening-design.md.
_CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


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

    Passwords are never compared directly (see app/core/passwords.py) -
    always via a verify() call, and a call is made (against a dummy hash)
    even when the username doesn't exist, so a login attempt for a
    nonexistent user takes about as long as one for a real user with the
    wrong password. Without this, the two cases are trivially
    distinguishable by response time, which would let an attacker
    enumerate valid usernames without ever guessing a password.
    """
    user = next((u for u in settings.auth_users if u.username == username), None)
    if user is None:
        verify_unknown_user_password(password)
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def create_access_token(user: UserRecord) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "tenantId": user.tenant_id,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    """Authentication only: establishes who is making the request from the
    bearer token, with no opinion on what they're allowed to do (see
    app.core.authorization.require_roles for that).

    algorithms=[JWT_ALGORITHM] restricts PyJWT to accepting only that one
    algorithm - a token signed (or claiming to be signed) any other way is
    rejected outright. issuer/audience are validated so a token minted for
    some other purpose, even if it happens to be signed with the same key,
    doesn't get treated as a login to this service. Expiry (exp) is
    validated by PyJWT automatically and is never disabled here. Every
    failure mode - expired, malformed, wrong signature, wrong issuer/
    audience, wrong algorithm, or a well-formed token for a since-removed
    user - collapses to the same generic 401 (see _CREDENTIALS_ERROR)."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[JWT_ALGORITHM],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
    except jwt.InvalidTokenError:
        raise _CREDENTIALS_ERROR

    username = payload.get("sub")
    role_value = payload.get("role")
    if username is None or role_value is None:
        raise _CREDENTIALS_ERROR

    try:
        role = Role(role_value)
    except ValueError:
        raise _CREDENTIALS_ERROR

    return CurrentUser(username=username, role=role, tenant_id=payload.get("tenantId"))
