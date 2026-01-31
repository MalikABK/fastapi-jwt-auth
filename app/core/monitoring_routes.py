# app/core/monitoring_routes.py
# Monitoring and health check routes

from fastapi import APIRouter, Request
from typing import Dict, Any
import time
import psutil
import os
from datetime import datetime

from app.core.metrics import get_metrics
from app.database import engine
from app.auth.audit_service import AuditLog
from sqlmodel import select
from app.auth.session_service import UserSession
from starlette.responses import Response


router = APIRouter(tags=["monitoring"])


@router.get("/health/monitoring")
async def health_check_monitoring():
    """
    Basic health check endpoint for monitoring
    """
    return {
        "status": "healthy",
        "service": "fastapi-jwt-auth",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/health/extended")
async def extended_health_check():
    """
    Extended health check with more detailed information
    """
    # Check database connectivity
    try:
        with engine.connect() as conn:
            result = conn.execute("SELECT 1")
            db_connected = result.fetchone() is not None
    except Exception:
        db_connected = False

    # Get system information
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')

    # Get recent audit log count
    try:
        from app.database import get_session
        session_gen = get_session()
        session = next(session_gen)
        from datetime import timedelta
        from datetime import datetime, timezone

        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        recent_audits = session.exec(
            select(AuditLog).where(
                AuditLog.timestamp > one_hour_ago  # Last hour
            )
        ).all()
        recent_audit_count = len(recent_audits)
        session.close()
    except Exception:
        recent_audit_count = 0

    # Get active session count
    try:
        from app.database import get_session
        session_gen = get_session()
        session = next(session_gen)
        active_sessions = session.exec(
            select(UserSession).where(
                UserSession.is_active == True,
                UserSession.expires_at > datetime.now(timezone.utc)
            )
        ).all()
        active_session_count = len(active_sessions)
        session.close()
    except Exception:
        active_session_count = 0

    return {
        "status": "healthy",
        "service": "fastapi-jwt-auth",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {
            "database": {
                "status": "ok" if db_connected else "error",
                "connected": db_connected
            },
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_info.percent,
                "disk_percent": (disk_usage.used / disk_usage.total) * 100
            },
            "activity": {
                "recent_audit_logs": recent_audit_count,
                "active_sessions": active_session_count
            }
        }
    }


@router.get("/metrics")
async def metrics_endpoint():
    """
    Prometheus metrics endpoint
    """
    metrics_data, content_type = get_metrics()
    return Response(content=metrics_data, media_type=content_type)


@router.get("/status")
async def status_page():
    """
    Status page with service information
    """
    uptime_start = getattr(status_page, 'start_time', None)
    if not uptime_start:
        uptime_start = time.time()
        status_page.start_time = uptime_start

    uptime = time.time() - uptime_start

    return {
        "service": "fastapi-jwt-auth",
        "version": "1.0.0",
        "uptime_seconds": round(uptime, 2),
        "timestamp": datetime.utcnow().isoformat(),
        "environment": os.getenv("ENVIRONMENT", "development")
    }


@router.get("/status/system")
async def system_status():
    """
    System resource status
    """
    return {
        "cpu": {
            "percent": psutil.cpu_percent(interval=1),
            "count": psutil.cpu_count()
        },
        "memory": {
            "percent": psutil.virtual_memory().percent,
            "total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "available_gb": round(psutil.virtual_memory().available / (1024**3), 2)
        },
        "disk": {
            "percent": psutil.disk_usage('/').percent,
            "total_gb": round(psutil.disk_usage('/').total / (1024**3), 2),
            "free_gb": round(psutil.disk_usage('/').free / (1024**3), 2)
        },
        "process": {
            "pid": os.getpid(),
            "memory_mb": round(psutil.Process().memory_info().rss / (1024**2), 2)
        }
    }