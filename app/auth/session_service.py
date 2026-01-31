# app/auth/session_service.py
# Service for session management functionality

from sqlmodel import SQLModel, Field, Session, select
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from fastapi import HTTPException, status
import uuid
from app.database import engine
from app.models.user import User


class UserSession(SQLModel, table=True):
    """
    Model to store active user sessions
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(unique=True, index=True)  # Unique session identifier
    user_id: int = Field(index=True)  # Reference to the user
    device_fingerprint: Optional[str] = None  # Device identification
    ip_address: Optional[str] = None  # IP address of the session
    user_agent: Optional[str] = None  # Browser/device info
    created_at: datetime = Field(default_factory=datetime.utcnow)  # When session was created
    last_activity: datetime = Field(default_factory=datetime.utcnow)  # Last activity timestamp
    expires_at: datetime  # When session expires
    is_active: bool = True  # Whether session is still active


def create_session(
    *,
    session: Session,
    user_id: int,
    device_fingerprint: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> UserSession:
    """
    Create a new session for a user
    """
    # Generate a unique session ID
    session_id = str(uuid.uuid4())

    # Calculate session expiration (based on config or default to 24 hours)
    expires_at = datetime.utcnow() + timedelta(hours=24)

    # Create the session record
    user_session = UserSession(
        session_id=session_id,
        user_id=user_id,
        device_fingerprint=device_fingerprint,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at
    )

    try:
        session.add(user_session)
        session.commit()
        session.refresh(user_session)
        return user_session
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create session: {str(e)}"
        )


def get_active_sessions(*, session: Session, user_id: int) -> List[UserSession]:
    """
    Get all active sessions for a user
    """
    statement = select(UserSession).where(
        UserSession.user_id == user_id,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow()
    )
    user_sessions = session.exec(statement).all()
    return user_sessions


def get_session_by_id(*, session: Session, session_id: str) -> Optional[UserSession]:
    """
    Get a session by its ID
    """
    statement = select(UserSession).where(
        UserSession.session_id == session_id,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow()
    )
    user_session = session.exec(statement).first()
    return user_session


def update_session_activity(*, session: Session, session_id: str) -> bool:
    """
    Update the last activity timestamp for a session
    """
    user_session = get_session_by_id(session=session, session_id=session_id)
    if not user_session:
        return False
    
    user_session.last_activity = datetime.utcnow()
    try:
        session.add(user_session)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False


def terminate_session(*, session: Session, session_id: str) -> bool:
    """
    Terminate a specific session
    """
    user_session = get_session_by_id(session=session, session_id=session_id)
    if not user_session:
        return False
    
    user_session.is_active = False
    try:
        session.add(user_session)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False


def terminate_all_user_sessions(*, session: Session, user_id: int) -> int:
    """
    Terminate all sessions for a user (except the current one if needed)
    """
    statement = select(UserSession).where(
        UserSession.user_id == user_id,
        UserSession.is_active == True
    )
    user_sessions = session.exec(statement).all()
    
    terminated_count = 0
    for user_session in user_sessions:
        user_session.is_active = False
        session.add(user_session)
        terminated_count += 1
    
    try:
        session.commit()
        return terminated_count
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to terminate sessions: {str(e)}"
        )


def cleanup_expired_sessions(*, session: Session) -> int:
    """
    Clean up expired sessions from the database
    """
    statement = select(UserSession).where(
        UserSession.expires_at < datetime.utcnow()
    )
    expired_sessions = session.exec(statement).all()
    
    cleaned_count = 0
    for expired_session in expired_sessions:
        session.delete(expired_session)
        cleaned_count += 1
    
    try:
        session.commit()
        return cleaned_count
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clean up sessions: {str(e)}"
        )


def get_session_stats(*, session: Session, user_id: int) -> Dict:
    """
    Get statistics about user sessions
    """
    # Total sessions
    total_statement = select(UserSession).where(UserSession.user_id == user_id)
    total_sessions = session.exec(total_statement).all()
    
    # Active sessions
    active_statement = select(UserSession).where(
        UserSession.user_id == user_id,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow()
    )
    active_sessions = session.exec(active_statement).all()
    
    # Recent sessions (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_statement = select(UserSession).where(
        UserSession.user_id == user_id,
        UserSession.created_at > week_ago
    )
    recent_sessions = session.exec(recent_statement).all()
    
    return {
        "total_sessions": len(total_sessions),
        "active_sessions": len(active_sessions),
        "recent_sessions": len(recent_sessions),
        "unique_devices": len(set(s.device_fingerprint for s in total_sessions if s.device_fingerprint)),
        "unique_ips": len(set(s.ip_address for s in total_sessions if s.ip_address))
    }