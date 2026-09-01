from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def authenticate_user(username: str, password: str) -> bool:
    """Check credentials against the single configured user.

    A prototype-scoped stand-in for user management: one username/password
    pair from settings (see docs/assumptions.md), not a user store.
    """
    return username == settings.auth_username and password == settings.auth_password


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def get_current_subject(token: str = Depends(oauth2_scheme)) -> str:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except jwt.InvalidTokenError:
        raise credentials_error

    subject = payload.get("sub")
    if subject is None:
        raise credentials_error
    return subject
