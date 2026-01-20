import os
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-that-is-at-least-32-chars-long-for-testing"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, Session
from contextlib import asynccontextmanager

from app.core.config import settings
from main import create_app
from app.database import get_session
from app.models.user import User
from app.models.token_blacklist import TokenBlacklist


def get_test_session():
    """Create a test database session."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Create all tables
    SQLModel.metadata.create_all(bind=test_engine)

    with Session(test_engine) as session:
        yield session


@pytest.fixture(scope="session")
def test_client():
    """Create a test client for the FastAPI app."""
    # Temporarily patch the get_session dependency
    def override_get_session():
        yield from get_test_session()

    app = create_app()

    # Override the get_session dependency
    app.dependency_overrides[get_session] = override_get_session

    with TestClient(app) as client:
        yield client


def test_debug():
    """Debug test to see what's happening."""
    # Temporarily patch the get_session dependency
    def override_get_session():
        yield from get_test_session()

    app = create_app()

    # Override the get_session dependency
    app.dependency_overrides[get_session] = override_get_session

    with TestClient(app) as client:
        print("Making signup request...")
        response = client.post(
            "/auth/signup",
            json={
                "email": "lockout@example.com",
                "password": "ValidPass123!",
                "full_name": "Lockout Test User"
            }
        )
        print(f"Status: {response.status_code}")
        print(f"Response text: {response.text}")
        try:
            print(f"Response JSON: {response.json()}")
        except:
            print("Could not parse JSON response")


if __name__ == "__main__":
    test_debug()