# app/auth/audit_routes.py
# Routes for audit logging and compliance functionality

from fastapi import APIRouter, Depends, Request, Query
from sqlmodel import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.database import get_session
from app.auth.audit_service import (
    log_audit_event, get_audit_logs, get_user_audit_logs,
    get_failed_login_attempts, get_compliance_report,
    cleanup_old_audit_logs, AuditEventType, AuditLog
)
from app.auth.jwt import get_current_user, get_current_active_superuser
from app.models.user import User


router = APIRouter(tags=["audit"])


@router.get("/audit/logs", response_model=List[dict])
def get_audit_logs_endpoint(
    current_user: User = Depends(get_current_active_superuser),  # Only admins can view all logs
    session: Session = Depends(get_session),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    event_type: Optional[AuditEventType] = Query(None, description="Filter by event type"),
    start_date: Optional[datetime] = Query(None, description="Filter by start date"),
    end_date: Optional[datetime] = Query(None, description="Filter by end date"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination")
):
    """
    Get audit logs with optional filters (admin only).
    """
    audit_logs = get_audit_logs(
        session=session,
        user_id=user_id,
        event_type=event_type,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset
    )
    
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "user_email": log.user_email,
            "event_type": log.event_type.value,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "details": log.details,
            "timestamp": log.timestamp,
            "success": log.success,
            "resource_id": log.resource_id
        }
        for log in audit_logs
    ]


@router.get("/audit/logs/my-activity", response_model=List[dict])
def get_my_audit_logs(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
    limit: int = Query(50, ge=1, le=1000, description="Number of records to return")
):
    """
    Get audit logs for the current user.
    """
    audit_logs = get_user_audit_logs(
        session=session,
        user_id=current_user.id,
        limit=limit
    )
    
    return [
        {
            "id": log.id,
            "event_type": log.event_type.value,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "details": log.details,
            "timestamp": log.timestamp,
            "success": log.success,
            "resource_id": log.resource_id
        }
        for log in audit_logs
    ]


@router.get("/audit/failed-login-attempts", response_model=List[dict])
def get_failed_login_attempts_endpoint(
    current_user: User = Depends(get_current_active_superuser),  # Only admins
    session: Session = Depends(get_session),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    ip_address: Optional[str] = Query(None, description="Filter by IP address"),
    hours_back: int = Query(24, ge=1, le=168, description="Hours back to look for failed attempts")
):
    """
    Get failed login attempts (admin only).
    """
    failed_attempts = get_failed_login_attempts(
        session=session,
        user_id=user_id,
        ip_address=ip_address,
        hours_back=hours_back
    )
    
    return [
        {
            "id": attempt.id,
            "user_id": attempt.user_id,
            "user_email": attempt.user_email,
            "ip_address": attempt.ip_address,
            "user_agent": attempt.user_agent,
            "timestamp": attempt.timestamp,
            "details": attempt.details
        }
        for attempt in failed_attempts
    ]


@router.get("/audit/compliance-report")
def get_compliance_report_endpoint(
    current_user: User = Depends(get_current_active_superuser),  # Only admins
    session: Session = Depends(get_session),
    days_back: int = Query(30, ge=1, le=365, description="Number of days back for the report")
):
    """
    Generate a compliance report (admin only).
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    
    report = get_compliance_report(
        session=session,
        start_date=start_date,
        end_date=end_date
    )
    
    return report


@router.post("/audit/log-event")
def log_custom_audit_event(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
    event_type: AuditEventType = Query(..., description="Type of audit event"),
    details: Optional[str] = Query(None, description="Additional details as JSON string"),
    success: bool = Query(True, description="Whether the action was successful")
):
    """
    Log a custom audit event.
    """
    import json
    
    # Parse details if provided
    details_dict = {}
    if details:
        try:
            details_dict = json.loads(details)
        except json.JSONDecodeError:
            pass  # Use empty dict if invalid JSON
    
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    log_entry = log_audit_event(
        session=session,
        user_id=current_user.id,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details_dict,
        success=success
    )
    
    return {
        "msg": "Audit event logged successfully",
        "log_id": log_entry.id
    }


@router.post("/audit/cleanup-old-logs")
def cleanup_old_audit_logs_endpoint(
    current_user: User = Depends(get_current_active_superuser),  # Only admins
    session: Session = Depends(get_session),
    older_than_days: int = Query(90, ge=1, description="Delete logs older than this many days")
):
    """
    Clean up old audit logs (admin only).
    """
    deleted_count = cleanup_old_audit_logs(
        session=session,
        older_than_days=older_than_days
    )
    
    return {
        "msg": f"Cleaned up {deleted_count} old audit logs",
        "deleted_count": deleted_count
    }