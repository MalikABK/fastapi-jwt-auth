# app/auth/auth_extended_service.py
# Extended authentication service with support for new user management features

import logging
from sqlmodel import Session, select
from fastapi import HTTPException, status
from app.models.user_extended import UserExtended, UserCreate
from app.models.token_blacklist import TokenBlacklist
from app.auth.security import hash_password, verify_password
from typing import Dict
from app.auth.jwt import create_access_token, create_refresh_token
from datetime import datetime, timedelta, timezone
from app.core.config import settings
import secrets

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_extended_user(*, session: Session, user_in: UserCreate) -> UserExtended:
    logger.info(f"Creating extended user with email: {user_in.email}")

    # 1. Check if user already exists
    statement = select(UserExtended).where(UserExtended.email == user_in.email)
    existing_user = session.exec(statement).first()

    if existing_user:
        logger.warning(f"Attempt to create user with existing email: {user_in.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # 2. Hash password
    hashed_password = hash_password(user_in.password)

    # 3. Generate email verification token
    verification_token = secrets.token_urlsafe(32)
    verification_expires = datetime.utcnow() + timedelta(hours=24)  # 24-hour expiry

    # 4. Create UserExtended object
    user = UserExtended(
        email=user_in.email,
        hashed_password=hashed_password,
        full_name=user_in.full_name,
        email_verification_token=verification_token,
        email_verification_expires=verification_expires
    )

    # 5. Persist to database
    try:
        session.add(user)
        session.commit()
        session.refresh(user)
        logger.info(f"Successfully created extended user with ID: {user.id}")
        
        # Send verification email (mock implementation)
        send_verification_email(user.email, verification_token)
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to create extended user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create user: {str(e)}"
        )

    return user


def authenticate_extended_user(
    *, session: Session, email: str, password: str
) -> Dict[str, str]:
    """
    Authenticate an extended user and return both access and refresh tokens.
    Raises HTTPException on failure.
    """
    logger.info(f"Authenticating extended user: {email}")
    statement = select(UserExtended).where(UserExtended.email == email)
    user = session.exec(statement).first()

    # Check if user exists and account is not locked
    if user:
        logger.debug(f"User found, checking account status for: {email}")
        
        # Check if account is temporarily locked
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            logger.warning(f"Account is locked for user: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is temporarily locked due to multiple failed login attempts",
            )

        # Check if email is verified (optional - depends on your requirements)
        if not user.is_verified:
            logger.warning(f"Unverified email attempted login: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email not verified. Please verify your email address.",
            )

        # Check password
        if verify_password(password, user.hashed_password):
            logger.info(f"Successful authentication for user: {email}")
            # Reset failed attempts on successful login
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.locked_until = None
        else:
            # Increment failed login attempts
            user.failed_login_attempts += 1
            logger.warning(f"Failed login attempt #{user.failed_login_attempts} for user: {email}")

            # Lock account after max attempts for configured duration
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.account_lockout_duration_minutes)
                logger.warning(f"Account locked for user: {email} due to multiple failed attempts")

            session.add(user)
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )
    else:
        logger.warning(f"Authentication attempt for non-existent user: {email}")
        # Even if user doesn't exist, we still want to increment a counter-like behavior
        # to prevent timing attacks, but for non-existent users we just return error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        logger.warning(f"Inactive user attempted login: {email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    # Generate tokens
    access_token = create_access_token(subject=str(user.id))
    refresh_token = create_refresh_token(subject=str(user.id))

    # Optional: store refresh token for revocation support
    user.refresh_token = refresh_token
    session.add(user)
    session.commit()
    logger.info(f"Tokens generated for user: {email}")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


def blacklist_access_token(*, session: Session, token: str, user_id: int, reason: str = "User logged out") -> None:
    """
    Add an access token to the blacklist to invalidate it before expiration.
    """
    logger.info(f"Blacklisting access token for user ID: {user_id}, reason: {reason}")

    # Decode the token to get its expiration time
    from jose import jwt
    from app.core.config import settings

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        exp = payload.get("exp")
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc) if exp else datetime.now(timezone.utc) + timedelta(minutes=30)

        # Create a new TokenBlacklist entry
        blacklisted_token = TokenBlacklist(
            token=token,
            user_id=user_id,
            token_type="access",
            expires_at=expires_at,
            reason=reason
        )

        session.add(blacklisted_token)
        session.commit()
        logger.info(f"Successfully blacklisted token for user ID: {user_id}")
    except Exception as e:
        logger.error(f"Error decoding token for blacklisting: {str(e)}")
        # If we can't decode the token, still try to add it to blacklist
        # Set a reasonable default expiration (30 minutes from now)
        blacklisted_token = TokenBlacklist(
            token=token,
            user_id=user_id,
            token_type="access",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            reason=reason
        )

        session.add(blacklisted_token)
        session.commit()
        logger.info(f"Token added to blacklist with default expiration for user ID: {user_id}")


def send_verification_email(email: str, verification_token: str):
    """
    Mock function to send verification email
    In a real application, you would implement actual email sending
    """
    logger.info(f"Mock: Sending verification email to {email} with token {verification_token}")