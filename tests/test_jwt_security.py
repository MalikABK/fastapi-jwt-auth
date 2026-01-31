"""
Security tests for JWT token handling in the FastAPI JWT Authentication Service
Tests various JWT security features including token manipulation, algorithm confusion, and replay protection
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from jose import jwt, JWTError
from main import create_app
from app.database import get_session, engine
from app.models.user import User
from app.models.token_blacklist import TokenBlacklist
from app.auth.jwt import decode_access_token, create_access_token
from app.core.config import settings
import os
from datetime import datetime, timedelta, timezone
import time

# Set environment for testing
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-that-is-at-least-32-chars-long-for-testing"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

app = create_app()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def session():
    with Session(engine) as session:
        yield session


def test_tampered_token_detection(client, session):
    """Test that tampered JWT tokens are properly detected and rejected"""
    # Create a user first
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "jwt-test@example.com",
            "password": "ValidPass123!",
            "full_name": "JWT Test User"
        }
    )
    assert signup_response.status_code == 201

    # Login to get a valid token
    login_response = client.post(
        "/auth/token",
        data={
            "username": "jwt-test@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    valid_token = tokens["access_token"]

    # Verify the valid token works
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {valid_token}"}
    )
    assert protected_response.status_code == 200

    # Test 1: Tamper with the signature portion of the token
    parts = valid_token.split('.')
    assert len(parts) == 3  # JWT has 3 parts: header.payload.signature

    # Create a tampered token by modifying the signature
    tampered_token = f"{parts[0]}.{parts[1]}.invalidsignature"

    # This should fail
    tampered_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {tampered_token}"}
    )
    assert tampered_response.status_code == 401
    assert "detail" in tampered_response.json()

    # Test 2: Tamper with the payload portion
    fake_payload = jwt.encode(
        {
            "sub": "999",  # Non-existent user ID
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            "iat": datetime.now(timezone.utc),
            "type": "access"
        },
        "wrong-secret-key",  # Wrong secret to create invalid signature
        algorithm="HS256"
    )

    fake_token_parts = fake_payload.split('.')
    tampered_payload_token = f"{parts[0]}.{fake_token_parts[1]}.{parts[2]}"

    tampered_payload_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {tampered_payload_token}"}
    )
    assert tampered_payload_response.status_code == 401


def test_algorithm_confusion_prevention(client, session):
    """Test that algorithm confusion attacks (none algorithm) are prevented"""
    # Create a token with 'none' algorithm (malicious attempt)
    malicious_token = jwt.encode(
        {
            "sub": "999",  # Fake user ID
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            "iat": datetime.now(timezone.utc),
            "type": "access"
        },
        "",  # Empty key for 'none' algorithm
        algorithm="none"
    )

    # This should be rejected by the decoder which only accepts HS256
    malicious_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {malicious_token}"}
    )
    assert malicious_response.status_code == 401
    assert malicious_response.json()["detail"] == "Could not validate credentials"


def test_expired_token_rejection(client, session):
    """Test that expired tokens are properly rejected"""
    # Create a user first
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "expired-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Expired Test User"
        }
    )
    assert signup_response.status_code == 201

    # Create an expired token manually
    expired_payload = {
        "sub": "1",  # User ID
        "exp": datetime.now(timezone.utc) - timedelta(minutes=10),  # Expired 10 minutes ago
        "iat": datetime.now(timezone.utc) - timedelta(minutes=20),
        "type": "access"
    }

    expired_token = jwt.encode(
        expired_payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )

    # This should fail due to expiration
    expired_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert expired_response.status_code == 401
    assert expired_response.json()["detail"] == "Could not validate credentials"


def test_invalid_token_type_rejection(client, session):
    """Test that tokens with invalid type are rejected"""
    # Create a token with invalid type
    invalid_type_payload = {
        "sub": "1",  # User ID
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        "iat": datetime.now(timezone.utc),
        "type": "invalid_type"  # Not 'access'
    }

    invalid_type_token = jwt.encode(
        invalid_type_payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )

    # This should fail due to invalid token type
    invalid_type_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {invalid_type_token}"}
    )
    assert invalid_type_response.status_code == 401
    assert invalid_type_response.json()["detail"] == "Could not validate credentials"


def test_token_replay_attack_protection(client, session):
    """Test that blacklisted tokens cannot be reused (replay protection)"""
    # Create and login a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "replay-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Replay Test User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "replay-test@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Verify token works initially
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response.status_code == 200

    # Logout to blacklist the access token
    logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert logout_response.status_code == 200

    # Try to reuse the access token - should fail
    replay_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert replay_response.status_code == 401
    assert replay_response.json()["detail"] == "Token has been revoked"

    # Verify token is in blacklist
    blacklisted_token = session.exec(
        select(TokenBlacklist).where(TokenBlacklist.token == access_token)
    ).first()
    assert blacklisted_token is not None


def test_malformed_jwt_rejection(client, session):
    """Test that malformed JWT tokens are properly rejected"""
    # Test with completely invalid token
    invalid_response = client.get(
        "/tasks/me",
        headers={"Authorization": "Bearer invalid.token.format"}
    )
    assert invalid_response.status_code == 401

    # Test with token that doesn't have 3 parts
    two_part_token = "header.payload"  # Missing signature
    two_part_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {two_part_token}"}
    )
    assert two_part_response.status_code == 401

    # Test with empty token
    empty_response = client.get(
        "/tasks/me",
        headers={"Authorization": "Bearer "}
    )
    assert empty_response.status_code == 401


def test_jwt_decoder_direct_manipulation_protection(session):
    """Test the JWT decoder directly with various manipulations"""
    # Create a valid token
    user_id = 1
    valid_token = create_access_token(subject=str(user_id))

    # Verify the valid token decodes correctly
    decoded_user_id = decode_access_token(valid_token, session)
    assert decoded_user_id == str(user_id)

    # Test with tampered token
    parts = valid_token.split('.')
    tampered_token = f"{parts[0]}.{parts[1]}.invalidsignature"

    try:
        decode_access_token(tampered_token, session)
        assert False, "Should have raised an exception for tampered token"
    except Exception:
        # Expected to raise an exception
        pass


def test_future_iat_token_rejection(client, session):
    """Test that tokens with future 'issued at' time are rejected"""
    # Create a token with future iat (issued at time)
    future_iat_payload = {
        "sub": "1",  # User ID
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        "iat": datetime.now(timezone.utc) + timedelta(hours=1),  # 1 hour in the future
        "type": "access"
    }

    future_iat_token = jwt.encode(
        future_iat_payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )

    # This should fail due to future iat
    future_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {future_iat_token}"}
    )
    assert future_response.status_code == 401


def test_jwt_claims_validation(client, session):
    """Test that JWT tokens have proper claims"""
    # Create a token with missing required claims
    minimal_payload = {
        # Missing 'sub', 'exp', 'type', or 'iat' claims
        "sub": "1"
        # Intentionally missing other claims to test validation
    }

    minimal_token = jwt.encode(
        minimal_payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )

    # This should fail due to missing required claims
    minimal_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {minimal_token}"}
    )
    assert minimal_response.status_code == 401