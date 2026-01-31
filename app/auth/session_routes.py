# app/auth/session_routes.py
# Routes for session management functionality

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session
from typing import List

from app.database import get_session
from app.auth.session_service import (
    create_session, get_active_sessions, get_session_by_id,
    update_session_activity, terminate_session, 
    terminate_all_user_sessions, cleanup_expired_sessions,
    get_session_stats, UserSession
)
from app.auth.jwt import get_current_user
from app.models.user import User


router = APIRouter(tags=["sessions"])


@router.post("/sessions/create")
def create_user_session(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Create a new session for the current user.
    """
    # Extract client information
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # In a real implementation, you might compute a device fingerprint
    device_fingerprint = f"{user_agent}_{ip_address}"
    
    user_session = create_session(
        session=session,
        user_id=current_user.id,
        device_fingerprint=device_fingerprint,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    return {
        "session_id": user_session.session_id,
        "expires_at": user_session.expires_at,
        "msg": "Session created successfully"
    }


@router.get("/sessions/active", response_model=List[dict])
def get_user_active_sessions(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Get all active sessions for the current user.
    """
    user_sessions = get_active_sessions(session=session, user_id=current_user.id)
    
    return [
        {
            "session_id": s.session_id,
            "device_fingerprint": s.device_fingerprint,
            "ip_address": s.ip_address,
            "user_agent": s.user_agent,
            "created_at": s.created_at,
            "last_activity": s.last_activity,
            "expires_at": s.expires_at
        }
        for s in user_sessions
    ]


@router.get("/sessions/stats")
def get_user_session_stats(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Get session statistics for the current user.
    """
    stats = get_session_stats(session=session, user_id=current_user.id)
    return stats


@router.post("/sessions/terminate/{session_id}")
def terminate_specific_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Terminate a specific session for the current user.
    """
    # Verify that the session belongs to the current user
    user_session = get_session_by_id(session=session, session_id=session_id)
    if not user_session or user_session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or does not belong to user"
        )
    
    success = terminate_session(session=session, session_id=session_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to terminate session"
        )
    
    return {"msg": "Session terminated successfully"}


@router.post("/sessions/terminate-all")
def terminate_all_user_sessions_endpoint(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Terminate all sessions for the current user.
    """
    count = terminate_all_user_sessions(session=session, user_id=current_user.id)
    return {"msg": f"All {count} sessions terminated successfully"}


@router.post("/sessions/update-activity/{session_id}")
def update_session_activity_endpoint(
    session_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Update the activity timestamp for a session.
    """
    # Verify that the session belongs to the current user
    user_session = get_session_by_id(session=session, session_id=session_id)
    if not user_session or user_session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or does not belong to user"
        )
    
    success = update_session_activity(session=session, session_id=session_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update session activity"
        )
    
    return {"msg": "Session activity updated successfully"}


@router.post("/sessions/cleanup-expired")
def cleanup_expired_sessions_endpoint(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Clean up expired sessions (admin only).
    """
    # Only allow admins to clean up sessions globally
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can clean up all expired sessions"
        )
    
    count = cleanup_expired_sessions(session=session)
    return {"msg": f"Cleaned up {count} expired sessions"}