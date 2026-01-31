from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from app.core.config import settings
from app.database import engine
from sqlmodel import SQLModel, Session
from app.models.token_blacklist import TokenBlacklist  # Import to register the model
from app.models.user import User  # Import to register the user model
from app.auth.session_service import UserSession  # Import to register the session model
from app.auth.audit_service import AuditLog  # Import to register the audit log model
from app.auth.api_key_service import ApiKey  # Import to register the API key model
from app.core.cache import init_cache, close_cache
from app.core.metrics import MetricsMiddleware
import logging
import os

# Initialize rate limiter (will be used conditionally based on environment)
limiter = Limiter(key_func=get_remote_address)

from app.auth.routes import router as auth_router
from app.auth.user_routes import router as user_router
from app.auth.mfa_routes import router as mfa_router
from app.auth.rbac_routes import router as rbac_router
from app.auth.session_routes import router as session_router
from app.auth.audit_routes import router as audit_router
from app.auth.api_key_routes import router as api_key_router
from app.core.monitoring_routes import router as monitoring_router
from app.tasks.routes import router as tasks_router
from app.ai.routes import router as ai_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan to handle startup and shutdown events."""
    # Startup
    print("Creating tables...")
    SQLModel.metadata.create_all(bind=engine)

    # Create initial superuser if none exists
    from sqlmodel import select
    from app.models.user import User, UserRole
    from app.auth.security import hash_password
    import os

    # Check if a superuser already exists
    with Session(engine) as session:
        existing_superuser = session.exec(
            select(User).where(User.is_superuser == True)
        ).first()

        if not existing_superuser:
            # Create the initial superuser
            superuser_email = os.getenv("SUPERUSER_EMAIL", "admin@example.com")
            superuser_password = os.getenv("SUPERUSER_PASSWORD", "AdminPass123!")

            superuser = User(
                email=superuser_email,
                hashed_password=hash_password(superuser_password),
                full_name="Administrator",
                role=UserRole.SUPERUSER,
                is_superuser=True,
                is_active=True,
                is_verified=True  # Mark as verified since it's created by admin
            )

            session.add(superuser)
            session.commit()
            print(f"Initial superuser created: {superuser_email}")

    await init_cache()
    yield
    # Shutdown
    print("Shutting down...")
    await close_cache()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="Production-ready JWT Authentication Service",
        lifespan=lifespan,
    )

    # Conditionally set up rate limiter
    if os.getenv("ENVIRONMENT") == "test":
        # No rate limiting in test environment
        app.state.limiter = None
    else:
        app.state.limiter = limiter
        # Adapter to match FastAPI's ExceptionHandler signature (expects RateLimitExceeded)
        def _rate_limit_handler(request, exc: RateLimitExceeded):
            return _rate_limit_exceeded_handler(request, exc)

        app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
    # Add CORS middleware
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.frontend_url.split(",") if settings.frontend_url else [],  # Configure based on your needs
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add metrics middleware
    app.add_middleware(MetricsMiddleware)

    # Add security headers middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response: Response = await call_next(request)
            # Basic security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

            # Additional security headers
            # Allow necessary sources for Swagger UI while maintaining security
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
                "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "
                "img-src 'self' data: https:; "
                "connect-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
                "frame-ancestors 'none';"
            )
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

            return response

    app.add_middleware(SecurityHeadersMiddleware)

    # Include routers
    app.include_router(auth_router, prefix="/auth", tags=["auth"])
    app.include_router(user_router, prefix="", tags=["user-management"])
    app.include_router(mfa_router, prefix="", tags=["mfa"])
    app.include_router(rbac_router, prefix="", tags=["rbac"])
    app.include_router(session_router, prefix="", tags=["sessions"])
    app.include_router(audit_router, prefix="", tags=["audit"])
    app.include_router(api_key_router, prefix="", tags=["api-keys"])
    app.include_router(monitoring_router, prefix="", tags=["monitoring"])
    app.include_router(tasks_router, prefix="/tasks", tags=["tasks"])
    app.include_router(ai_router, prefix="", tags=["ai-security"])

    # Add health check endpoint
    @app.get("/health", tags=["health"])
    async def health_check():
        return {"status": "healthy", "service": "fastapi-jwt-auth"}

    return app


app = create_app()


