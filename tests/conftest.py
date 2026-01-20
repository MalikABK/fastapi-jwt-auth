"""Test configuration file for pytest"""

import pytest
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, Session
from contextlib import asynccontextmanager
from unittest.mock import patch

from app.core.config import settings
from main import create_app
from app.database import engine, get_session
from app.models.user import User
from app.models.token_blacklist import TokenBlacklist


# Set test environment
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-that-is-at-least-32-chars-long-for-testing"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"


@pytest.fixture
def test_engine():
    """Create a test database engine."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Create all tables
    SQLModel.metadata.create_all(bind=test_engine)
    return test_engine


@pytest.fixture
def test_db_session(test_engine):
    """Create a test database session."""
    with Session(test_engine) as session:
        yield session


@pytest.fixture
def test_client(test_engine):
    """Create a test client for the FastAPI app."""
    # Temporarily patch the get_session dependency to use the test engine
    def override_get_session():
        with Session(test_engine) as session:
            yield session

    app = create_app()

    # Override the get_session dependency
    app.dependency_overrides[get_session] = override_get_session

    with TestClient(app) as client:
        yield client


@pytest.fixture
def auth_headers(test_client):
    """Helper fixture to get authentication headers for a test user."""
    # Create a test user first
    user_data = {
        "email": "test@example.com",
        "password": "TestPassword123!",
        "full_name": "Test User"
    }

    response = test_client.post("/auth/signup", json=user_data)
    assert response.status_code == 201

    # Login to get tokens
    login_response = test_client.post(
        "/auth/token",
        data={
            "username": "test@example.com",
            "password": "TestPassword123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]

    return {"Authorization": f"Bearer {access_token}"}


def pytest_configure(config):
    """Configure pytest settings."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security-focused tests"
    )