# app/auth/api_key_routes.py
# Routes for API key management functionality

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlmodel import Session
from typing import List, Optional
from datetime import timedelta

from app.database import get_session
from app.auth.api_key_service import (
    create_api_key, get_api_keys_for_user, update_api_key_last_used,
    revoke_api_key, revoke_all_user_api_keys, check_api_key_scopes,
    rotate_api_key, cleanup_expired_api_keys, ApiKey, ApiKeyScope
)
from app.auth.jwt import get_current_user
from app.models.user import User


router = APIRouter(tags=["api-keys"])


@router.post("/api-keys/create", response_model=dict)
def create_api_key_endpoint(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
    name: str = Query(..., min_length=1, max_length=100, description="Name/description for the API key"),
    scopes: List[ApiKeyScope] = Query([ApiKeyScope.READ], description="Scopes granted to this API key"),
    expires_in_days: Optional[int] = Query(None, ge=1, le=365, description="Days until expiration (optional)"),
    rate_limit: int = Query(1000, ge=1, description="Requests per hour limit")
):
    """
    Create a new API key for the current user.
    """
    # Convert scopes to strings
    scope_strings = [scope.value for scope in scopes]
    
    api_key_record, raw_api_key = create_api_key(
        session=session,
        user_id=current_user.id,
        name=name,
        scopes=scope_strings,
        expires_in_days=expires_in_days,
        rate_limit=rate_limit
    )
    
    # Log the API key creation
    from app.auth.audit_service import log_audit_event, AuditEventType
    log_audit_event(
        session=session,
        user_id=current_user.id,
        event_type=AuditEventType.PERMISSION_GRANTED,
        details={
            "action": "api_key_created",
            "key_name": name,
            "scopes": scope_strings,
            "expires_in_days": expires_in_days
        }
    )
    
    return {
        "api_key": raw_api_key,
        "key_id": api_key_record.id,
        "name": api_key_record.name,
        "scopes": api_key_record.scopes,
        "expires_at": api_key_record.expires_at,
        "rate_limit": api_key_record.rate_limit,
        "msg": "API key created successfully. Save this key now as it won't be shown again!"
    }


@router.get("/api-keys/my-keys", response_model=List[dict])
def get_my_api_keys(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Get all API keys for the current user.
    """
    api_keys = get_api_keys_for_user(session=session, user_id=current_user.id)
    
    return [
        {
            "id": key.id,
            "name": key.name,
            "scopes": key.scopes,
            "created_at": key.created_at,
            "expires_at": key.expires_at,
            "last_used_at": key.last_used_at,
            "is_active": key.is_active,
            "rate_limit": key.rate_limit
        }
        for key in api_keys
    ]


@router.post("/api-keys/revoke/{key_id}")
def revoke_api_key_endpoint(
    key_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Revoke an API key for the current user.
    """
    # Get the API key to check ownership
    statement = select(ApiKey).where(ApiKey.id == key_id)
    api_key = session.exec(statement).first()
    
    if not api_key or api_key.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or does not belong to user"
        )
    
    success = revoke_api_key(session=session, key_hash=api_key.key_hash)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to revoke API key"
        )
    
    # Log the API key revocation
    from app.auth.audit_service import log_audit_event, AuditEventType
    log_audit_event(
        session=session,
        user_id=current_user.id,
        event_type=AuditEventType.PERMISSION_REVOKED,
        details={
            "action": "api_key_revoked",
            "key_id": key_id,
            "key_name": api_key.name
        }
    )
    
    return {"msg": "API key revoked successfully"}


@router.post("/api-keys/revoke-all")
def revoke_all_my_api_keys(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Revoke all API keys for the current user.
    """
    count = revoke_all_user_api_keys(session=session, user_id=current_user.id)
    
    # Log the API key revocation
    from app.auth.audit_service import log_audit_event, AuditEventType
    log_audit_event(
        session=session,
        user_id=current_user.id,
        event_type=AuditEventType.PERMISSION_REVOKED,
        details={
            "action": "all_api_keys_revoked",
            "count": count
        }
    )
    
    return {"msg": f"All {count} API keys revoked successfully"}


@router.post("/api-keys/rotate/{key_id}", response_model=dict)
def rotate_api_key_endpoint(
    key_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Rotate an API key (create a new one with same properties, revoke old one).
    """
    # Get the API key to check ownership
    statement = select(ApiKey).where(ApiKey.id == key_id)
    api_key = session.exec(statement).first()
    
    if not api_key or api_key.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or does not belong to user"
        )
    
    new_api_key, raw_key = rotate_api_key(session=session, key_hash=api_key.key_hash)
    
    # Log the API key rotation
    from app.auth.audit_service import log_audit_event, AuditEventType
    log_audit_event(
        session=session,
        user_id=current_user.id,
        event_type=AuditEventType.PERMISSION_GRANTED,
        details={
            "action": "api_key_rotated",
            "old_key_id": key_id,
            "new_key_id": new_api_key.id,
            "key_name": new_api_key.name
        }
    )
    
    return {
        "api_key": raw_key,
        "key_id": new_api_key.id,
        "name": new_api_key.name,
        "scopes": new_api_key.scopes,
        "expires_at": new_api_key.expires_at,
        "rate_limit": new_api_key.rate_limit,
        "msg": "API key rotated successfully. Save this key now as it won't be shown again!"
    }


@router.post("/api-keys/cleanup-expired")
def cleanup_expired_api_keys_endpoint(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Clean up expired API keys.
    """
    count = cleanup_expired_api_keys(session=session)
    return {"msg": f"Cleaned up {count} expired API keys"}