# app/auth/mfa_routes.py
# Routes for multi-factor authentication functionality

from fastapi import APIRouter, Depends, HTTPException, Body, status, Request
from sqlmodel import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
import os

from app.database import get_session
from app.auth.mfa_service import (
    generate_mfa_setup_info, enable_mfa_for_user, 
    disable_mfa_for_user, verify_totp_code, authenticate_with_mfa
)
from app.auth.jwt import get_current_user
from app.models.user import User

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

router = APIRouter(tags=["mfa"])

@router.post("/mfa/setup")
def setup_mfa(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Generate MFA setup information for the current user.
    """
    return generate_mfa_setup_info(session=session, user_id=current_user.id)


@router.post("/mfa/enable")
def enable_mfa(
    request: Request,
    password: str = Body(..., embed=True),
    totp_code: str = Body(..., embed=True),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Enable MFA for the current user after verifying password and TOTP code.
    """
    return enable_mfa_for_user(
        session=session,
        user_id=current_user.id,
        password=password,
        totp_code=totp_code
    )


@router.post("/mfa/disable")
def disable_mfa(
    request: Request,
    password: str = Body(..., embed=True),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Disable MFA for the current user after verifying password.
    """
    return disable_mfa_for_user(
        session=session,
        user_id=current_user.id,
        password=password
    )


@router.post("/mfa/verify")
def verify_mfa(
    request: Request,
    totp_code: str = Body(..., embed=True),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Verify a TOTP code for the current user.
    """
    is_valid = verify_totp_code(
        session=session,
        user_id=current_user.id,
        totp_code=totp_code
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code"
        )

    return {"msg": "TOTP code verified successfully"}


@router.post("/auth/token-with-mfa")
def login_with_mfa(
    request: Request,
    email: str = Body(..., embed=True),
    password: str = Body(..., embed=True),
    totp_code: str = Body(..., embed=True),
    session: Session = Depends(get_session)
):
    """
    Authenticate user with both password and TOTP code.
    """
    return authenticate_with_mfa(
        session=session,
        email=email,
        password=password,
        totp_code=totp_code
    )