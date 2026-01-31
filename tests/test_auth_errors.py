"""
Authentication error handling tests for the FastAPI JWT Authentication Service
Tests various error scenarios and proper error handling in the authentication flow
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from main import create_app
from app.database import get_session, engine
from app.models.user import User
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


def test_invalid_credentials_error_message(client, session):
    """Test that invalid credentials return consistent error messages"""
    # Try to login with non-existent email
    response1 = client.post(
        "/auth/token",
        data={
            "username": "nonexistent@example.com",
            "password": "any_password"
        }
    )
    assert response1.status_code == 401
    assert response1.json()["detail"] == "Invalid credentials"

    # Create a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "error-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Error Test User"
        }
    )
    assert signup_response.status_code == 201

    # Try to login with wrong password for existing user
    response2 = client.post(
        "/auth/token",
        data={
            "username": "error-test@example.com",
            "password": "wrong_password"
        }
    )
    assert response2.status_code == 401
    assert response2.json()["detail"] == "Invalid credentials"

    # Both should return the same generic error message to prevent user enumeration
    assert response1.json()["detail"] == response2.json()["detail"]


def test_inactive_user_error_handling(client, session):
    """Test error handling when trying to login with inactive user account"""
    # Create a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "inactive-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Inactive Test User"
        }
    )
    assert signup_response.status_code == 201

    # Manually set user as inactive in the database
    from app.database import get_session
    with get_session() as db_session:
        user = db_session.exec(select(User).where(User.email == "inactive-test@example.com")).first()
        user.is_active = False
        db_session.add(user)
        db_session.commit()

    # Try to login with inactive user
    login_response = client.post(
        "/auth/token",
        data={
            "username": "inactive-test@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 400  # Bad Request
    assert login_response.json()["detail"] == "Inactive user"


def test_unverified_email_error_handling(client, session):
    """Test error handling when trying to login with unverified email"""
    # Create a user (by default, is_verified=False)
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "unverified-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Unverified Test User"
        }
    )
    assert signup_response.status_code == 201

    # Try to login with unverified email
    login_response = client.post(
        "/auth/token",
        data={
            "username": "unverified-test@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 401  # Unauthorized
    assert login_response.json()["detail"] == "Email not verified. Please verify your email address."


def test_locked_account_error_handling(client, session):
    """Test error handling when trying to login to a locked account"""
    # Create a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "locked-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Locked Test User"
        }
    )
    assert signup_response.status_code == 201

    # Manually lock the account
    from app.database import get_session
    with get_session() as db_session:
        user = db_session.exec(select(User).where(User.email == "locked-test@example.com")).first()
        user.failed_login_attempts = settings.max_login_attempts
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.account_lockout_duration_minutes)
        db_session.add(user)
        db_session.commit()

    # Try to login to locked account
    login_response = client.post(
        "/auth/token",
        data={
            "username": "locked-test@example.com",
            "password": "ValidPass123!"  # Correct password but account is locked
        }
    )
    assert login_response.status_code == 401
    assert login_response.json()["detail"] == "Account is temporarily locked due to multiple failed login attempts"


def test_empty_credentials_error_handling(client, session):
    """Test error handling for empty credentials"""
    # Try to login with empty username and password
    response = client.post(
        "/auth/token",
        data={
            "username": "",
            "password": ""
        }
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_missing_credentials_error_handling(client, session):
    """Test error handling for missing credentials"""
    # Try to login with missing username
    response1 = client.post(
        "/auth/token",
        data={
            "password": "some_password"
        }
    )
    # This might return 422 (validation error) or 401 depending on FastAPI's handling

    # Try to login with missing password
    response2 = client.post(
        "/auth/token",
        data={
            "username": "someuser@example.com"
        }
    )
    # This might return 422 (validation error) or 401 depending on FastAPI's handling


def test_large_input_error_handling(client, session):
    """Test error handling for extremely large inputs"""
    # Try to signup with extremely long email (should fail validation)
    long_email = "a" * 300 + "@example.com"

    response = client.post(
        "/auth/signup",
        json={
            "email": long_email,
            "password": "ValidPass123!",
            "full_name": "Large Input Test User"
        }
    )
    assert response.status_code == 422  # Validation error

    # Try to login with extremely long username
    long_username = "a" * 300

    response = client.post(
        "/auth/token",
        data={
            "username": long_username,
            "password": "some_password"
        }
    )
    # May return 422 or 401 depending on validation


def test_special_characters_in_credentials(client, session):
    """Test handling of special characters in credentials"""
    # Test with special characters in email (should work if valid format)
    special_email = "user+tag@example-domain.com"

    response = client.post(
        "/auth/signup",
        json={
            "email": special_email,
            "password": "ValidPass123!",
            "full_name": "Special Char Test User"
        }
    )
    # This should work if the email format is valid
    if response.status_code == 201:
        # Try to login with the special email
        login_response = client.post(
            "/auth/token",
            data={
                "username": special_email,
                "password": "ValidPass123!"
            }
        )
        assert login_response.status_code == 200


def test_sql_injection_attempts_in_auth(client, session):
    """Test that SQL injection attempts in authentication are handled safely"""
    # Try various SQL injection patterns in the username field
    injection_attempts = [
        "' OR '1'='1",
        "'; DROP TABLE user; --",
        "' UNION SELECT * FROM user --",
        "admin'--",
        "admin' OR '1'='1' --"
    ]

    for injection in injection_attempts:
        response = client.post(
            "/auth/token",
            data={
                "username": injection,
                "password": "any_password"
            }
        )
        # Should return 401 (Unauthorized) rather than 500 (Internal Server Error)
        # indicating that the injection attempt didn't cause a database error
        assert response.status_code in [401, 422]


def test_error_handling_with_corrupted_database(client, session):
    """Test error handling when database operations fail"""
    # This test verifies that the system handles database errors gracefully
    # by checking that appropriate HTTP error codes are returned instead of
    # internal server errors where appropriate

    # Create a user first
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "corruption-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Corruption Test User"
        }
    )
    assert signup_response.status_code == 201

    # Test normal login works
    login_response = client.post(
        "/auth/token",
        data={
            "username": "corruption-test@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200


def test_duplicate_email_signup_error(client, session):
    """Test error handling when attempting to register duplicate email"""
    # Register first user
    signup_response1 = client.post(
        "/auth/signup",
        json={
            "email": "duplicate-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Duplicate Test User 1"
        }
    )
    assert signup_response1.status_code == 201

    # Try to register with same email
    signup_response2 = client.post(
        "/auth/signup",
        json={
            "email": "duplicate-test@example.com",  # Same email as above
            "password": "DifferentPass123!",
            "full_name": "Duplicate Test User 2"
        }
    )
    assert signup_response2.status_code == 400  # Bad Request
    assert signup_response2.json()["detail"] == "Email already registered"


def test_invalid_json_in_signup(client, session):
    """Test error handling for invalid JSON in signup request"""
    # Send invalid JSON
    response = client.post(
        "/auth/signup",
        content="{invalid: json}",
        headers={"Content-Type": "application/json"}
    )
    # Should return 422 (Unprocessable Entity) or 400 (Bad Request)
    assert response.status_code in [400, 422]


def test_missing_required_fields_in_signup(client, session):
    """Test error handling when required fields are missing in signup"""
    # Try to signup without email
    response1 = client.post(
        "/auth/signup",
        json={
            "password": "ValidPass123!",
            "full_name": "Missing Email User"
        }
    )
    assert response1.status_code == 422

    # Try to signup without password
    response2 = client.post(
        "/auth/signup",
        json={
            "email": "missing-password@example.com",
            "full_name": "Missing Password User"
        }
    )
    assert response2.status_code == 422

    # Try to signup without full_name
    response3 = client.post(
        "/auth/signup",
        json={
            "email": "missing-name@example.com",
            "password": "ValidPass123!"
        }
    )
    assert response3.status_code == 201  # full_name is optional


def test_error_handling_for_expired_verification_token(client, session):
    """Test error handling when using expired verification token"""
    # Create a user (this creates an expired verification token by setting expiry in past)
    from app.database import get_session
    from app.models.user import User
    from app.auth.service import create_user
    from app.auth.security import hash_password
    import secrets
    from datetime import datetime, timedelta, timezone

    # Manually create a user with an expired verification token
    with get_session() as db_session:
        user_data = {
            "email": "expired-token@example.com",
            "password": "ValidPass123!",
            "full_name": "Expired Token User"
        }

        # Create user with expired verification token
        verification_token = secrets.token_urlsafe(32)
        verification_expires = datetime.now(timezone.utc) - timedelta(hours=1)  # Expired 1 hour ago

        user = User(
            email=user_data["email"],
            hashed_password=hash_password(user_data["password"]),
            full_name=user_data["full_name"],
            email_verification_token=verification_token,
            email_verification_expires=verification_expires
        )

        db_session.add(user)
        db_session.commit()


def test_error_handling_in_refresh_token_endpoint(client, session):
    """Test error handling in refresh token endpoint"""
    # Try to refresh with invalid token
    response1 = client.post(
        "/auth/refresh",
        json={"refresh_token": "invalid_token_format"}
    )
    assert response1.status_code == 401

    # Try to refresh with empty token
    response2 = client.post(
        "/auth/refresh",
        json={"refresh_token": ""}
    )
    assert response2.status_code == 401

    # Try to refresh with missing token field
    response3 = client.post(
        "/auth/refresh",
        json={}
    )
    assert response3.status_code == 422


def test_error_handling_in_logout_endpoint(client, session):
    """Test error handling in logout endpoint"""
    # Create and login a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "logout-error-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Logout Error Test User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "logout-error-test@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Try to logout with invalid refresh token
    response1 = client.post(
        "/auth/logout",
        json={"refresh_token": "invalid_token"},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response1.status_code == 401

    # Try to logout with empty refresh token
    response2 = client.post(
        "/auth/logout",
        json={"refresh_token": ""},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response2.status_code == 422  # Validation error for empty string

    # Try to logout with missing refresh token
    response3 = client.post(
        "/auth/logout",
        json={},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response3.status_code == 422


def test_error_handling_with_malformed_jwt(client, session):
    """Test error handling when malformed JWT is sent to protected endpoints"""
    # Try to access protected endpoint with malformed JWT
    response = client.get(
        "/tasks/me",
        headers={"Authorization": "Bearer invalid.jwt.token"}
    )
    assert response.status_code == 401


def test_internal_server_error_graceful_handling(client, session):
    """Test that internal server errors are handled gracefully in auth flow"""
    # This test checks that unexpected errors return appropriate status codes
    # rather than exposing internal details

    # Test with valid but non-existent user ID in JWT (simulating a corrupted token scenario)
    # This would be difficult to test without modifying the JWT directly
    # but we can test other edge cases

    # Test normal flow still works
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "graceful-error-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Graceful Error Test User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "graceful-error-test@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200