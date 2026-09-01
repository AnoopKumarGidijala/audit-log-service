from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.security import authenticate_user, create_access_token
from app.schemas.auth import Token

router = APIRouter(tags=["auth"])


@router.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(subject=form_data.username)
    return Token(access_token=access_token)
