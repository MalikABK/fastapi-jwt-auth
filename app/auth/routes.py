from fastapi import APIRouter, Depends, HTTPException, Body, status, Request, Header
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session
from jose import jwt, JWTError
from slowapi import Limiter
from slowapi.util import get_remote_address
import os

from app.core.config import settings
from app.database import get_session
from app.models.user import User, UserCreate, UserPublic
from app.auth.service import create_user, authenticate_user
from app.auth.jwt import create_access_token, decode_access_token

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Conditionally apply rate limiting based on environment at runtime
def limiter_decorator(limit_str):
    def decorator(func):
        if os.getenv("ENVIRONMENT") == "test":
            # No rate limiting in test environment
            return func
        else:
            # Apply rate limiting in non-test environments
            return limiter.limit(limit_str)(func)
    return decorator

router = APIRouter(tags=["auth"])

@router.post("/signup", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
@limiter_decorator("5/minute")  # Limit signup attempts
def signup(
    request: Request,
    user_in: UserCreate,
    session: Session = Depends(get_session),
):
    """
    Create a new user with hashed password and return public info.
    """
    user = create_user(session=session, user_in=user_in)
    return user

@router.post("/token")
@limiter_decorator("10/minute")  # Limit login attempts
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """
    Authenticate user and return access + refresh tokens.
    """
    tokens = authenticate_user(
        session=session,
        email=form_data.username,
        password=form_data.password,
    )

    return tokens


@router.post("/refresh")
@limiter_decorator("30/minute")  # Limit refresh token attempts
def refresh_token(
    request: Request,
    refresh_token: str = Body(..., embed=True),
    session: Session = Depends(get_session),
):
    """
    Validate refresh token and issue a new access token.
    """
    try:
        payload = jwt.decode(
            refresh_token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Validate stored refresh token
    if user.refresh_token != refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

    access_token = create_access_token(subject=str(user.id))
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
@limiter_decorator("10/minute")  # Limit logout attempts
def logout(
    request: Request,
    refresh_token: str = Body(..., embed=True),
    access_token: str = Header(None, description="Access token to be blacklisted"),
    session: Session = Depends(get_session),
):
    """
    Invalidate refresh token for the user and optionally blacklist the access token.
    """
    try:
        payload = jwt.decode(
            refresh_token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Validate that the provided refresh token matches the one stored for the user
    if user.refresh_token != refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Clear refresh token
    user.refresh_token = None

    # If access token is provided, blacklist it
    if access_token:
        from app.auth.service import blacklist_access_token
        blacklist_access_token(session=session, token=access_token, user_id=user_id)

    session.add(user)
    session.commit()

    return {"msg": "Logged out successfully"}
