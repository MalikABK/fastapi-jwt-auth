# app/auth/api_key_service.py
# Service for API key management functionality

from sqlmodel import SQLModel, Field, Session, select
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from fastapi import HTTPException, status
import secrets
from enum import Enum
from app.database import engine
from app.models.user import User


class ApiKeyScope(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    ALL = "all"


class ApiKey(SQLModel, table=True):
    """
    Model to store API keys for service-to-service authentication
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    key_hash: str = Field(unique=True, index=True)  # Hashed API key
    name: str = Field(max_length=100)  # Name/description of the API key
    user_id: int = Field(index=True)  # User who owns the API key
    scopes: str = Field(default='["read"]')  # Scopes granted to this API key as JSON string
    created_at: datetime = Field(default_factory=datetime.utcnow)  # When key was created
    expires_at: Optional[datetime] = None  # When key expires (optional)
    last_used_at: Optional[datetime] = None  # When key was last used
    is_active: bool = True  # Whether key is still active
    rate_limit: Optional[int] = 1000  # Requests per hour limit (optional)


def generate_api_key() -> str:
    """
    Generate a new API key
    """
    return f"sk-{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for secure storage
    """
    from hashlib import sha256
    return sha256(api_key.encode()).hexdigest()


def create_api_key(
    *,
    session: Session,
    user_id: int,
    name: str,
    scopes: List[str],
    expires_in_days: Optional[int] = None,
    rate_limit: Optional[int] = 1000
) -> tuple[ApiKey, str]:
    """
    Create a new API key for a user
    """
    import json

    # Generate a new API key
    raw_api_key = generate_api_key()
    key_hash = hash_api_key(raw_api_key)

    # Calculate expiration if specified
    expires_at = None
    if expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    # Convert scopes list to JSON string
    scopes_json = json.dumps(scopes)

    # Create the API key record
    api_key_record = ApiKey(
        key_hash=key_hash,
        name=name,
        user_id=user_id,
        scopes=scopes_json,
        expires_at=expires_at,
        is_active=True,
        rate_limit=rate_limit
    )

    try:
        session.add(api_key_record)
        session.commit()
        session.refresh(api_key_record)
        return api_key_record, raw_api_key
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create API key: {str(e)}"
        )


def get_api_key_by_hash(*, session: Session, key_hash: str) -> Optional[ApiKey]:
    """
    Get an API key by its hash
    """
    statement = select(ApiKey).where(
        ApiKey.key_hash == key_hash,
        ApiKey.is_active == True
    )
    api_key = session.exec(statement).first()
    return api_key


def get_api_keys_for_user(*, session: Session, user_id: int) -> List[ApiKey]:
    """
    Get all API keys for a user
    """
    import json

    statement = select(ApiKey).where(ApiKey.user_id == user_id)
    api_keys = session.exec(statement).all()

    # Convert scopes JSON strings back to lists
    for key in api_keys:
        try:
            key.scopes = json.loads(key.scopes)
        except json.JSONDecodeError:
            key.scopes = ["read"]  # Default fallback

    return api_keys


def update_api_key_last_used(*, session: Session, key_hash: str) -> bool:
    """
    Update the last used timestamp for an API key
    """
    api_key = get_api_key_by_hash(session=session, key_hash=key_hash)
    if not api_key:
        return False
    
    api_key.last_used_at = datetime.utcnow()
    try:
        session.add(api_key)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False


def revoke_api_key(*, session: Session, key_hash: str) -> bool:
    """
    Revoke an API key by setting it as inactive
    """
    api_key = get_api_key_by_hash(session=session, key_hash=key_hash)
    if not api_key:
        return False
    
    api_key.is_active = False
    try:
        session.add(api_key)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False


def revoke_all_user_api_keys(*, session: Session, user_id: int) -> int:
    """
    Revoke all API keys for a user
    """
    statement = select(ApiKey).where(
        ApiKey.user_id == user_id,
        ApiKey.is_active == True
    )
    api_keys = session.exec(statement).all()
    
    revoked_count = 0
    for api_key in api_keys:
        api_key.is_active = False
        session.add(api_key)
        revoked_count += 1
    
    try:
        session.commit()
        return revoked_count
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke API keys: {str(e)}"
        )


def check_api_key_scopes(*, api_key: ApiKey, required_scopes: List[str]) -> bool:
    """
    Check if an API key has the required scopes
    """
    import json

    # Parse scopes from JSON string
    try:
        scopes_list = json.loads(api_key.scopes)
    except json.JSONDecodeError:
        scopes_list = []

    # If the API key has "all" scope, it has all permissions
    if "all" in scopes_list:
        return True

    # Check if all required scopes are present in the API key's scopes
    for scope in required_scopes:
        if scope not in scopes_list:
            return False

    return True


def rotate_api_key(*, session: Session, key_hash: str) -> tuple[ApiKey, str]:
    """
    Rotate an API key (create a new one with same properties, revoke old one)
    """
    old_api_key = get_api_key_by_hash(session=session, key_hash=key_hash)
    if not old_api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    # Revoke the old key
    revoke_api_key(session=session, key_hash=key_hash)
    
    # Create a new key with the same properties
    new_api_key, raw_key = create_api_key(
        session=session,
        user_id=old_api_key.user_id,
        name=f"{old_api_key.name} (Rotated)",
        scopes=old_api_key.scopes,
        expires_in_days=(old_api_key.expires_at - datetime.utcnow()).days if old_api_key.expires_at else None,
        rate_limit=old_api_key.rate_limit
    )
    
    return new_api_key, raw_key


def cleanup_expired_api_keys(*, session: Session) -> int:
    """
    Clean up expired API keys from the database
    """
    statement = select(ApiKey).where(
        ApiKey.expires_at < datetime.utcnow(),
        ApiKey.is_active == True
    )
    expired_keys = session.exec(statement).all()
    
    cleaned_count = 0
    for expired_key in expired_keys:
        expired_key.is_active = False
        session.add(expired_key)
        cleaned_count += 1
    
    try:
        session.commit()
        return cleaned_count
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clean up API keys: {str(e)}"
        )