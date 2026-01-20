from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from app.core.config import settings
from app.database import engine
from sqlmodel import SQLModel
from app.models.token_blacklist import TokenBlacklist  # Import to register the model
import logging
import os

# Initialize rate limiter (will be used conditionally based on environment)
limiter = Limiter(key_func=get_remote_address)

from app.auth.routes import router as auth_router
from app.tasks.routes import router as tasks_router
from app.ai.routes import router as ai_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan to handle startup and shutdown events."""
    # Startup
    print("Creating tables...")
    SQLModel.metadata.create_all(bind=engine)
    yield
    # Shutdown
    print("Shutting down...")


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
        allow_origins=["*"],  # Configure based on your needs
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
    app.include_router(tasks_router, prefix="/tasks", tags=["tasks"])
    app.include_router(ai_router, prefix="", tags=["ai-security"])

    # Add health check endpoint
    @app.get("/health", tags=["health"])
    async def health_check():
        return {"status": "healthy", "service": "fastapi-jwt-auth"}

    return app


app = create_app()


