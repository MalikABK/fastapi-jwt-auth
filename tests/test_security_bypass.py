"""
Security bypass tests for the FastAPI JWT Authentication Service
Tests various security bypass attempts including account lockout bypass and token blacklisting circumvention
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from main import create_app
from app.database import get_session, engine
from app.models.user import User
from app.models.token_blacklist import TokenBlacklist
from app.auth.service import blacklist_access_token
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


def test_account_lockout_bypass_multiple_users_same_ip(client, session):
    """Test that account lockout cannot be bypassed by creating multiple accounts from same IP"""
    # This test simulates trying to bypass lockout by using multiple accounts
    # Since we don't have IP tracking in the current implementation, we'll test
    # the individual account lockout mechanisms

    # Create first user
    signup_response1 = client.post(
        "/auth/signup",
        json={
            "email": "lockout-bypass1@example.com",
            "password": "ValidPass123!",
            "full_name": "Lockout Bypass User 1"
        }
    )
    assert signup_response1.status_code == 201

    # Create second user
    signup_response2 = client.post(
        "/auth/signup",
        json={
            "email": "lockout-bypass2@example.com",
            "password": "ValidPass123!",
            "full_name": "Lockout Bypass User 2"
        }
    )
    assert signup_response2.status_code == 201

    # Attempt to login to first user with wrong password multiple times
    for i in range(settings.max_login_attempts):
        login_response = client.post(
            "/auth/token",
            data={
                "username": "lockout-bypass1@example.com",
                "password": "wrongpassword"
            }
        )
        assert login_response.status_code == 401

    # First user should now be locked
    locked_response = client.post(
        "/auth/token",
        data={
            "username": "lockout-bypass1@example.com",
            "password": "ValidPass123!"  # Correct password but account should be locked
        }
    )
    assert locked_response.status_code == 401
    assert locked_response.json()["detail"] == "Account is temporarily locked due to multiple failed login attempts"

    # Second user should still work normally
    second_user_response = client.post(
        "/auth/token",
        data={
            "username": "lockout-bypass2@example.com",
            "password": "ValidPass123!"
        }
    )
    assert second_user_response.status_code == 200


def test_account_lockout_bypass_concurrent_attempts(client, session):
    """Test that concurrent login attempts don't bypass lockout mechanism"""
    import threading

    # Create user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "concurrent-lockout@example.com",
            "password": "ValidPass123!",
            "full_name": "Concurrent Lockout User"
        }
    )
    assert signup_response.status_code == 201

    results = []

    def attempt_login():
        response = client.post(
            "/auth/token",
            data={
                "username": "concurrent-lockout@example.com",
                "password": "wrongpassword"
            }
        )
        results.append(response.status_code)

    # Start multiple threads to attempt login simultaneously
    threads = []
    for i in range(settings.max_login_attempts + 2):  # More than the lockout threshold
        thread = threading.Thread(target=attempt_login)
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Verify that account gets locked despite concurrent attempts
    locked_check_response = client.post(
        "/auth/token",
        data={
            "username": "concurrent-lockout@example.com",
            "password": "ValidPass123!"  # Correct password but account should be locked
        }
    )
    assert locked_check_response.status_code == 401
    assert locked_check_response.json()["detail"] == "Account is temporarily locked due to multiple failed login attempts"


def test_account_lockout_time_bypass(client, session):
    """Test that waiting for lockout period to expire properly unlocks the account"""
    # Create user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "time-bypass@example.com",
            "password": "ValidPass123!",
            "full_name": "Time Bypass User"
        }
    )
    assert signup_response.status_code == 201

    # Lock the account by exceeding failed attempts
    for i in range(settings.max_login_attempts):
        login_response = client.post(
            "/auth/token",
            data={
                "username": "time-bypass@example.com",
                "password": "wrongpassword"
            }
        )
        assert login_response.status_code == 401

    # Account should be locked
    locked_response = client.post(
        "/auth/token",
        data={
            "username": "time-bypass@example.com",
            "password": "ValidPass123!"
        }
    )
    assert locked_response.status_code == 401

    # Manually update the user's locked_until time to simulate time passing
    # In a real test, we'd use mocking to control time
    from app.database import get_session
    with get_session() as db_session:
        user = db_session.exec(select(User).where(User.email == "time-bypass@example.com")).first()
        user.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)  # Time in past
        db_session.add(user)
        db_session.commit()

    # Now login should work again
    unlocked_response = client.post(
        "/auth/token",
        data={
            "username": "time-bypass@example.com",
            "password": "ValidPass123!"
        }
    )
    assert unlocked_response.status_code == 200


def test_token_blacklist_circumvention_attempts(client, session):
    """Test that attempts to circumvent token blacklisting fail"""
    # Create and login user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "blacklist-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Blacklist Test User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "blacklist-test@example.com",
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

    # Verify token is now blacklisted
    blacklisted_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert blacklisted_response.status_code == 401
    assert blacklisted_response.json()["detail"] == "Token has been revoked"

    # Verify the token is in the blacklist table
    blacklisted_token_db = session.exec(
        select(TokenBlacklist).where(TokenBlacklist.token == access_token)
    ).first()
    assert blacklisted_token_db is not None
    assert blacklisted_token_db.token_type == "access"
    assert blacklisted_token_db.reason == "User logged out"


def test_token_blacklist_manual_addition(client, session):
    """Test that manually blacklisting a token works correctly"""
    # Create and login user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "manual-blacklist@example.com",
            "password": "ValidPass123!",
            "full_name": "Manual Blacklist User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "manual-blacklist@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]

    # Get user ID to manually blacklist token
    from app.database import get_session
    with get_session() as db_session:
        user = db_session.exec(select(User).where(User.email == "manual-blacklist@example.com")).first()

        # Manually blacklist the token
        blacklist_access_token(
            session=db_session,
            token=access_token,
            user_id=user.id,
            reason="Manual test blacklist"
        )

    # Token should now be rejected
    blacklisted_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert blacklisted_response.status_code == 401
    assert blacklisted_response.json()["detail"] == "Token has been revoked"


def test_refresh_token_reuse_prevention(client, session):
    """Test that refresh tokens cannot be reused after being used once"""
    # Create and login user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "refresh-reuse@example.com",
            "password": "ValidPass123!",
            "full_name": "Refresh Reuse Test User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "refresh-reuse@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    initial_refresh_token = tokens["refresh_token"]

    # Use refresh token once - should work
    refresh_response1 = client.post(
        "/auth/refresh",
        json={"refresh_token": initial_refresh_token}
    )
    assert refresh_response1.status_code == 200

    new_tokens = refresh_response1.json()
    new_access_token = new_tokens["access_token"]

    # Verify new access token works
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {new_access_token}"}
    )
    assert protected_response.status_code == 200

    # Try to reuse the same refresh token - should fail
    refresh_response2 = client.post(
        "/auth/refresh",
        json={"refresh_token": initial_refresh_token}
    )
    assert refresh_response2.status_code == 401
    assert refresh_response2.json()["detail"] == "Invalid refresh token"


def test_token_blacklist_race_condition(client, session):
    """Test that race conditions don't allow token reuse during blacklisting"""
    # Create and login user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "race-condition@example.com",
            "password": "ValidPass123!",
            "full_name": "Race Condition Test User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "race-condition@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Verify token works initially
    protected_response1 = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response1.status_code == 200

    # Perform logout (which blacklists the token) and immediately try to use token again
    logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert logout_response.status_code == 200

    # Try to use the same token again (simulating a race condition attempt)
    protected_response2 = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response2.status_code == 401  # Should be rejected as blacklisted


def test_multiple_simultaneous_blacklist_attempts(client, session):
    """Test that multiple simultaneous attempts to blacklist the same token don't cause issues"""
    # Create and login user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "simultaneous-blacklist@example.com",
            "password": "ValidPass123!",
            "full_name": "Simultaneous Blacklist Test User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "simultaneous-blacklist@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Simulate multiple logout attempts simultaneously (this would happen in real-world race conditions)
    import threading

    results = []

    def logout_attempt():
        response = client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {access_token}"}
        )
        results.append((response.status_code, response.json() if response.status_code != 200 else None))

    # Start multiple threads to logout simultaneously
    threads = []
    for i in range(3):  # 3 simultaneous logout attempts
        thread = threading.Thread(target=logout_attempt)
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # At least one should succeed, others might fail gracefully
    successful_logout = any(result[0] == 200 for result in results)
    assert successful_logout  # At least one should succeed

    # The token should definitely be blacklisted after these attempts
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response.status_code == 401  # Should be rejected as blacklisted


def test_account_status_change_during_authentication(client, session):
    """Test that account deactivation during an active session is handled properly"""
    # Create and login user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "deactivate-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Deactivate Test User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "deactivate-test@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]

    # Verify token works initially
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response.status_code == 200

    # Manually deactivate the user in the database
    from app.database import get_session
    with get_session() as db_session:
        user = db_session.exec(select(User).where(User.email == "deactivate-test@example.com")).first()
        user.is_active = False
        db_session.add(user)
        db_session.commit()

    # Now the same token should fail because user is deactivated
    deactivated_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert deactivated_response.status_code == 401
    assert deactivated_response.json()["detail"] == "User not found or inactive"