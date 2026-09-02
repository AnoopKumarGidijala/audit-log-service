import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.rate_limit import enforce_login_rate_limit
from app.core.security import authenticate_user, create_access_token
from app.core.security_logging import log_security_event
from app.schemas.auth import Token

router = APIRouter(tags=["auth"])


@router.post("/auth/token", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    _rate_limit: None = Depends(enforce_login_rate_limit),
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if user is None:
        # Deliberately logs only the attempted username, never the
        # password - see docs/security-logging-design.md. Doesn't
        # distinguish "no such user" from "wrong password" here either,
        # for the same reason the HTTP response itself doesn't (see
        # docs/auth-hardening-design.md) - that distinction would be
        # exactly as useful to an attacker reading logs as it would be in
        # the response.
        log_security_event(
            "auth.login.failure", level=logging.WARNING, username=form_data.username
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(user)
    log_security_event("auth.login.success", username=user.username, role=user.role.value)
    return Token(access_token=access_token)
