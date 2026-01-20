import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt, JWTError
from fastapi import HTTPException, status, Depends
from app.core.config import settings
from app.models.user import User
from app.models.token_blacklist import TokenBlacklist
from app.database import get_session
from sqlmodel import Session, select
from fastapi.security import OAuth2PasswordBearer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_access_token(subject: str | Any) -> str:
    try:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.access_token_expire_minutes
        )

        to_encode = {
            "exp": expire,
            "sub": str(subject),
            "iat": datetime.now(timezone.utc),  # issued at time
            "type": "access",
        }

        encoded_jwt = jwt.encode(
            to_encode,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )

        logger.info(f"Access token created for subject: {subject}")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating access token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during token creation"
        )

def is_token_blacklisted(token: str, session: Session) -> bool:
    """
    Check if a token is blacklisted in the database.
    """
    statement = select(TokenBlacklist).where(TokenBlacklist.token == token)
    blacklisted_token = session.exec(statement).first()
    return blacklisted_token is not None


def decode_access_token(token: str, session: Session) -> str:
    try:
        logger.debug(f"Decoding access token: {token[:10]}...")
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        user_id: str | None = payload.get("sub")
        token_type: str | None = payload.get("type")

        if user_id is None or token_type != "access":
            logger.warning(f"Invalid token payload - user_id: {user_id}, token_type: {token_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )

        # Check blacklist
        if is_token_blacklisted(token, session):
            logger.warning(f"Attempt to use blacklisted token for user: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )

        logger.debug(f"Successfully decoded token for user: {user_id}")
        return user_id

    except JWTError as e:
        logger.warning(f"JWT decode error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    except Exception as e:
        logger.error(f"Unexpected error during token decoding: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during token validation"
        )



def create_refresh_token(subject: str | int) -> str:
    try:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_expire_days
        )

        to_encode = {
            "exp": expire,
            "sub": str(subject),
            "iat": datetime.now(timezone.utc),
            "type": "refresh",
        }

        encoded_jwt = jwt.encode(
            to_encode,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )

        logger.info(f"Refresh token created for subject: {subject}")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating refresh token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during token creation"
        )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    """
    Validates the access token, fetches the user from DB,
    and ensures the user is active.
    """
    try:
        user_id_str = decode_access_token(token, session)
        user_id = int(user_id_str)
    except (JWTError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    user = session.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user

def get_current_active_superuser(current_user: User = Depends(get_current_user)) -> User:
    """
    Ensures that the current user is a superuser/admin.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges")
    return current_user
