"""
Basic tests for the FastAPI JWT Authentication Service
"""

import pytest
from fastapi.testclient import TestClient
from main import create_app
import os

# Set environment for testing
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-that-is-at-least-32-chars-long-for-testing"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

app = create_app()

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    """Test that health endpoint works"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "fastapi-jwt-auth"


def test_app_starts(client):
    """Test that the app starts without errors"""
    response = client.get("/")
    # Should return 404 for root path since no route is defined
    assert response.status_code == 404


def test_signup_endpoint_exists(client):
    """Test that signup endpoint exists"""
    # Should return 422 for missing data rather than 404
    response = client.post("/auth/signup")
    assert response.status_code == 422  # Unprocessable Entity due to missing body


def test_token_endpoint_exists(client):
    """Test that token endpoint exists"""
    # Should return 401 for invalid credentials rather than 404
    response = client.post("/auth/token")
    assert response.status_code == 401  # Unauthorized due to missing form data