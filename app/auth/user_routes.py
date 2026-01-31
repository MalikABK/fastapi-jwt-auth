# app/auth/user_routes.py
# Routes for extended user management functionality

from fastapi import APIRouter, Depends, HTTPException, Body, status, Request
from sqlmodel import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
import os

from app.core.config import settings
from app.database import get_session
from app.models.user import UserPublic, UserUpdate
from app.auth.user_management_service import UserProfileUpdate, PasswordResetRequest, PasswordReset, EmailVerificationRequest, AccountDeletionRequest
from app.auth.user_management_service import (
    update_user_profile, request_password_reset, reset_password,
    verify_email, delete_account, generate_email_verification_token
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

router = APIRouter(tags=["user-management"])

@router.get("/users/me", response_model=UserPublic)
def get_current_user_extended(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Get current user's extended profile information.
    """
    # Return the current user as UserPublic format
    return current_user


@router.patch("/users/me", response_model=UserPublic)
@limiter_decorator("20/hour")
def update_current_user_profile(
    request: Request,
    profile_update: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Update current user's profile information.
    """
    return update_user_profile(
        session=session,
        user_id=current_user.id,
        profile_update=profile_update
    )


@router.post("/auth/request-password-reset")
def request_password_reset_endpoint(
    request: Request,
    password_reset_request: PasswordResetRequest = Body(...),
    session: Session = Depends(get_session)
):
    """
    Request password reset - sends reset link to user's email.
    """
    return request_password_reset(session=session, request=password_reset_request)


@router.post("/auth/reset-password")
def reset_password_endpoint(
    request: Request,
    reset_data: PasswordReset = Body(...),
    session: Session = Depends(get_session)
):
    """
    Reset password using the provided token.
    """
    return reset_password(session=session, reset_data=reset_data)


@router.post("/auth/verify-email")
def verify_email_endpoint(
    request: Request,
    verification_data: EmailVerificationRequest = Body(...),
    session: Session = Depends(get_session)
):
    """
    Verify user's email using the provided token.
    """
    return verify_email(session=session, verification_data=verification_data)


@router.post("/auth/generate-verification-token")
def generate_verification_token_endpoint(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Generate a new email verification token and send to user's email.
    """
    return generate_email_verification_token(
        session=session,
        user_id=current_user.id
    )


@router.delete("/users/me")
def delete_current_account(
    request: Request,
    deletion_request: AccountDeletionRequest = Body(...),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Delete the current user's account after verifying password.
    """
    return delete_account(
        session=session,
        user_id=current_user.id,
        deletion_request=deletion_request
    )