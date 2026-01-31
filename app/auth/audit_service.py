# app/auth/audit_service.py
# Service for audit logging and compliance functionality

from sqlmodel import SQLModel, Field, Session, select
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum
from fastapi import HTTPException, status
from app.database import engine
from app.models.user import User


class AuditEventType(str, Enum):
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_SIGNUP = "user_signup"
    USER_PROFILE_UPDATE = "user_profile_update"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    SESSION_CREATED = "session_created"
    SESSION_TERMINATED = "session_terminated"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    FAILED_LOGIN = "failed_login"
    ACCOUNT_LOCKED = "account_locked"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_BLACKLISTED = "token_blacklisted"
    ACCOUNT_DELETED = "account_deleted"
    EMAIL_VERIFIED = "email_verified"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"


class AuditLog(SQLModel, table=True):
    """
    Model to store audit logs for compliance and security monitoring
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, index=True)  # Nullable for system events
    user_email: Optional[str] = Field(default=None, index=True)  # For tracking non-logged in events
    event_type: AuditEventType = Field(sa_column_kwargs={"name": "event_type"})
    ip_address: Optional[str] = None  # IP address of the request
    user_agent: Optional[str] = None  # Browser/device info
    details: Optional[str] = Field(default=None)  # Additional event details as JSON string
    timestamp: datetime = Field(default_factory=datetime.utcnow)  # When the event occurred
    success: bool = True  # Whether the action was successful
    resource_id: Optional[int] = None  # ID of the resource affected (if applicable)


def log_audit_event(
    *,
    session: Session,
    user_id: Optional[int] = None,
    user_email: Optional[str] = None,
    event_type: AuditEventType,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict] = None,
    success: bool = True,
    resource_id: Optional[int] = None
) -> AuditLog:
    """
    Log an audit event
    """
    import json

    # Convert details dict to JSON string
    details_str = None
    if details:
        details_str = json.dumps(details)

    # Get user email if user_id is provided and email not provided
    if user_id and not user_email:
        user = session.get(User, user_id)
        if user:
            user_email = user.email

    audit_log = AuditLog(
        user_id=user_id,
        user_email=user_email,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details_str,
        success=success,
        resource_id=resource_id
    )

    try:
        session.add(audit_log)
        session.commit()
        session.refresh(audit_log)
        return audit_log
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to log audit event: {str(e)}"
        )


def get_audit_logs(
    *,
    session: Session,
    user_id: Optional[int] = None,
    event_type: Optional[AuditEventType] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0
) -> List[AuditLog]:
    """
    Retrieve audit logs with optional filters
    """
    import json

    statement = select(AuditLog)

    if user_id:
        statement = statement.where(AuditLog.user_id == user_id)

    if event_type:
        statement = statement.where(AuditLog.event_type == event_type)

    if start_date:
        statement = statement.where(AuditLog.timestamp >= start_date)

    if end_date:
        statement = statement.where(AuditLog.timestamp <= end_date)

    statement = statement.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)

    audit_logs = session.exec(statement).all()

    # Convert details JSON strings back to dicts
    for log in audit_logs:
        if log.details:
            try:
                log.details = json.loads(log.details)
            except json.JSONDecodeError:
                log.details = {}

    return audit_logs


def get_user_audit_logs(
    *,
    session: Session,
    user_id: int,
    event_types: Optional[List[AuditEventType]] = None,
    limit: int = 50
) -> List[AuditLog]:
    """
    Get audit logs for a specific user
    """
    import json

    statement = select(AuditLog).where(AuditLog.user_id == user_id)

    if event_types:
        statement = statement.where(AuditLog.event_type.in_(event_types))

    statement = statement.order_by(AuditLog.timestamp.desc()).limit(limit)

    audit_logs = session.exec(statement).all()

    # Convert details JSON strings back to dicts
    for log in audit_logs:
        if log.details:
            try:
                log.details = json.loads(log.details)
            except json.JSONDecodeError:
                log.details = {}

    return audit_logs


def get_failed_login_attempts(
    *,
    session: Session,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    hours_back: int = 24
) -> List[AuditLog]:
    """
    Get failed login attempts within a specified time period
    """
    import json

    start_time = datetime.utcnow() - timedelta(hours=hours_back)

    statement = select(AuditLog).where(
        AuditLog.event_type == AuditEventType.FAILED_LOGIN,
        AuditLog.timestamp >= start_time,
        AuditLog.success == False
    )

    if user_id:
        statement = statement.where(AuditLog.user_id == user_id)

    if ip_address:
        statement = statement.where(AuditLog.ip_address == ip_address)

    statement = statement.order_by(AuditLog.timestamp.desc())

    failed_attempts = session.exec(statement).all()

    # Convert details JSON strings back to dicts
    for log in failed_attempts:
        if log.details:
            try:
                log.details = json.loads(log.details)
            except json.JSONDecodeError:
                log.details = {}

    return failed_attempts


def get_compliance_report(
    *,
    session: Session,
    start_date: datetime,
    end_date: datetime
) -> Dict:
    """
    Generate a compliance report for a date range
    """
    # Total events in the period
    total_events_stmt = select(AuditLog).where(
        AuditLog.timestamp >= start_date,
        AuditLog.timestamp <= end_date
    )
    total_events = session.exec(total_events_stmt).all()
    
    # Count by event type
    event_counts = {}
    for event in total_events:
        event_type = event.event_type.value
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
    
    # Count successful vs failed events
    successful_count = sum(1 for event in total_events if event.success)
    failed_count = len(total_events) - successful_count
    
    # Unique users who had activity
    unique_users = set(event.user_id for event in total_events if event.user_id is not None)
    
    # High-risk events (failed logins, account deletions, etc.)
    high_risk_events = [
        event for event in total_events
        if event.event_type in [
            AuditEventType.FAILED_LOGIN,
            AuditEventType.ACCOUNT_LOCKED,
            AuditEventType.ACCOUNT_DELETED,
            AuditEventType.TOKEN_BLACKLISTED
        ]
    ]
    
    return {
        "period": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat()
        },
        "summary": {
            "total_events": len(total_events),
            "successful_events": successful_count,
            "failed_events": failed_count,
            "unique_users": len(unique_users)
        },
        "event_counts": event_counts,
        "high_risk_events": len(high_risk_events),
        "top_ip_addresses": {},  # Would require additional processing
        "recommendations": []  # Would be populated based on analysis
    }


def cleanup_old_audit_logs(
    *,
    session: Session,
    older_than_days: int = 90
) -> int:
    """
    Clean up audit logs older than specified days
    """
    cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)
    
    old_logs_stmt = select(AuditLog).where(AuditLog.timestamp < cutoff_date)
    old_logs = session.exec(old_logs_stmt).all()
    
    deleted_count = 0
    for log in old_logs:
        session.delete(log)
        deleted_count += 1
    
    try:
        session.commit()
        return deleted_count
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clean up audit logs: {str(e)}"
        )