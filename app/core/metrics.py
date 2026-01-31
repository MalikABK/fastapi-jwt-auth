# app/core/metrics.py
# Metrics and monitoring functionality

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
from datetime import datetime
import time
from typing import Optional
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

ACTIVE_USERS = Gauge(
    'active_users',
    'Number of active users'
)

AUTHENTICATION_ATTEMPTS = Counter(
    'authentication_attempts_total',
    'Total authentication attempts',
    ['result']  # success, failure
)

FAILED_LOGIN_ATTEMPTS = Counter(
    'failed_login_attempts_total',
    'Total failed login attempts',
    ['user_id', 'ip_address']
)

API_KEY_USAGE = Counter(
    'api_key_usage_total',
    'Total API key usage',
    ['key_id', 'user_id']
)

SESSION_COUNT = Gauge(
    'active_sessions',
    'Number of active sessions'
)

DB_CONNECTIONS = Gauge(
    'db_connections',
    'Number of database connections in use'
)


class MetricsMiddleware:
    """
    Middleware to collect metrics for HTTP requests
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        request = Request(scope)
        start_time = time.time()

        # Store original send function to intercept response
        response_status = None

        async def custom_send(message):
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = message["status"]
            return await send(message)

        # Call the next middleware/app
        await self.app(scope, receive, custom_send)

        # Record metrics after the request completes
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response_status or 500
        ).inc()

        duration = time.time() - start_time
        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)


def increment_auth_attempts(result: str):
    """
    Increment authentication attempt counter
    """
    AUTHENTICATION_ATTEMPTS.labels(result=result).inc()


def increment_failed_login(user_id: Optional[str], ip_address: str):
    """
    Increment failed login attempt counter
    """
    user_label = user_id or "unknown"
    FAILED_LOGIN_ATTEMPTS.labels(user_id=user_label, ip_address=ip_address).inc()


def increment_api_key_usage(key_id: str, user_id: str):
    """
    Increment API key usage counter
    """
    API_KEY_USAGE.labels(key_id=key_id, user_id=user_id).inc()


def update_active_users(count: int):
    """
    Update the gauge for active users
    """
    ACTIVE_USERS.set(count)


def update_active_sessions(count: int):
    """
    Update the gauge for active sessions
    """
    SESSION_COUNT.set(count)


def update_db_connections(count: int):
    """
    Update the gauge for database connections
    """
    DB_CONNECTIONS.set(count)


def get_metrics():
    """
    Get the current metrics in Prometheus format
    """
    return generate_latest(), CONTENT_TYPE_LATEST


# Initialize metrics with default values
def init_metrics():
    """
    Initialize metrics with default values
    """
    ACTIVE_USERS.set(0)
    SESSION_COUNT.set(0)
    DB_CONNECTIONS.set(0)
    logger.info("Metrics initialized")


# Call init_metrics to set initial values
init_metrics()