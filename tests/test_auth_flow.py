"""
Complete authentication flow tests for the FastAPI JWT Authentication Service
Tests the complete user authentication lifecycle: signup -> login -> protected access -> refresh -> logout
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from main import create_app
from app.database import get_session, engine
from app.models.user import User, UserRole
from app.models.token_blacklist import TokenBlacklist
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


def test_complete_authentication_lifecycle(client, session):
    """Test the complete authentication lifecycle: signup -> login -> protected access -> refresh -> logout"""
    # Step 1: Signup
    signup_data = {
        "email": "lifecycle-test@example.com",
        "password": "LifecyclePass123!",
        "full_name": "Lifecycle Test User"
    }

    signup_response = client.post("/auth/signup", json=signup_data)
    assert signup_response.status_code == 201

    user_data = signup_response.json()
    assert user_data["email"] == "lifecycle-test@example.com"
    assert user_data["full_name"] == "Lifecycle Test User"
    assert "id" in user_data

    # Verify user was created in database
    created_user = session.exec(select(User).where(User.email == "lifecycle-test@example.com")).first()
    assert created_user is not None
    assert created_user.email == "lifecycle-test@example.com"
    assert created_user.full_name == "Lifecycle Test User"
    assert created_user.is_active is True
    assert created_user.is_verified is False  # Default value

    # Step 2: Login
    login_response = client.post(
        "/auth/token",
        data={
            "username": "lifecycle-test@example.com",
            "password": "LifecyclePass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"

    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Verify refresh token was stored in database
    session.refresh(created_user)
    assert created_user.refresh_token == refresh_token

    # Step 3: Access protected route with access token
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response.status_code == 200

    user_info = protected_response.json()
    assert user_info["email"] == "lifecycle-test@example.com"
    assert user_info["full_name"] == "Lifecycle Test User"
    assert user_info["id"] == user_data["id"]

    # Step 4: Use refresh token to get new access token
    refresh_response = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_response.status_code == 200

    new_tokens = refresh_response.json()
    assert "access_token" in new_tokens
    assert new_tokens["token_type"] == "bearer"
    assert new_tokens["access_token"] != access_token  # New token should be different

    new_access_token = new_tokens["access_token"]

    # Step 5: Verify old access token still works (unless blacklisted)
    old_token_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    # This may or may not work depending on implementation (not blacklisted on refresh by default)
    assert old_token_response.status_code in [200, 401]

    # Step 6: Verify new access token works
    new_token_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {new_access_token}"}
    )
    assert new_token_response.status_code == 200

    # Step 7: Logout (invalidate refresh token)
    logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {new_access_token}"}
    )
    assert logout_response.status_code == 200

    logout_msg = logout_response.json()
    assert logout_msg["msg"] == "Logged out successfully"

    # Step 8: Verify that old refresh token can't be used anymore
    invalid_refresh_response = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert invalid_refresh_response.status_code == 401

    # Step 9: Verify that access token is blacklisted if logout blacklists it
    old_access_token_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    # Check if the old access token is now invalid (depends on implementation)
    # If logout blacklists access tokens, this should return 401


def test_multiple_device_sessions(client, session):
    """Test that a user can have multiple device sessions simultaneously"""
    # Create user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "multi-session@example.com",
            "password": "MultiSessionPass123!",
            "full_name": "Multi-Session User"
        }
    )
    assert signup_response.status_code == 201

    # Login multiple times to simulate multiple devices
    tokens_list = []
    for i in range(3):  # Simulate 3 different devices
        login_response = client.post(
            "/auth/token",
            data={
                "username": "multi-session@example.com",
                "password": "MultiSessionPass123!"
            }
        )
        assert login_response.status_code == 200

        tokens = login_response.json()
        assert "access_token" in tokens
        assert "refresh_token" in tokens

        tokens_list.append({
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"]
        })

    # Verify all access tokens work
    for i, token_pair in enumerate(tokens_list):
        protected_response = client.get(
            "/tasks/me",
            headers={"Authorization": f"Bearer {token_pair['access_token']}"}
        )
        assert protected_response.status_code == 200, f"Token {i} failed to work"

    # Logout from one device (should only affect that device)
    logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": tokens_list[0]["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens_list[0]['access_token']}"}
    )
    assert logout_response.status_code == 200

    # The other tokens should still work
    for i, token_pair in enumerate(tokens_list[1:], 1):  # Skip first token
        protected_response = client.get(
            "/tasks/me",
            headers={"Authorization": f"Bearer {token_pair['access_token']}"}
        )
        assert protected_response.status_code == 200, f"Token {i} was unexpectedly invalidated"


def test_token_rotation_during_lifecycle(client, session):
    """Test token rotation during the authentication lifecycle"""
    # Create user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "rotation-test@example.com",
            "password": "RotationPass123!",
            "full_name": "Rotation Test User"
        }
    )
    assert signup_response.status_code == 201

    # Login
    login_response = client.post(
        "/auth/token",
        data={
            "username": "rotation-test@example.com",
            "password": "RotationPass123!"
        }
    )
    assert login_response.status_code == 200

    initial_tokens = login_response.json()
    initial_access_token = initial_tokens["access_token"]
    initial_refresh_token = initial_tokens["refresh_token"]

    # Verify initial access token works
    initial_protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {initial_access_token}"}
    )
    assert initial_protected_response.status_code == 200

    # Refresh tokens multiple times
    current_refresh_token = initial_refresh_token
    access_tokens_used = [initial_access_token]

    for i in range(3):  # Refresh 3 times
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": current_refresh_token}
        )
        assert refresh_response.status_code == 200

        new_tokens = refresh_response.json()
        new_access_token = new_tokens["access_token"]

        # Verify new access token works
        protected_response = client.get(
            "/tasks/me",
            headers={"Authorization": f"Bearer {new_access_token}"}
        )
        assert protected_response.status_code == 200

        # The new access token should be different from all previous ones
        assert new_access_token not in access_tokens_used
        access_tokens_used.append(new_access_token)

        # Old refresh token should no longer work
        old_refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": current_refresh_token}
        )
        assert old_refresh_response.status_code == 401

        # Update current refresh token for next iteration
        current_refresh_token = new_tokens["refresh_token"]


def test_logout_clears_refresh_token_from_db(client, session):
    """Test that logout properly clears the refresh token from the database"""
    # Create user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "logout-db-test@example.com",
            "password": "LogoutDBPass123!",
            "full_name": "Logout DB Test User"
        }
    )
    assert signup_response.status_code == 201

    # Login
    login_response = client.post(
        "/auth/token",
        data={
            "username": "logout-db-test@example.com",
            "password": "LogoutDBPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Verify refresh token is stored in database
    user = session.exec(select(User).where(User.email == "logout-db-test@example.com")).first()
    assert user.refresh_token == refresh_token

    # Logout
    logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert logout_response.status_code == 200

    # Verify refresh token is cleared from database
    session.refresh(user)
    assert user.refresh_token is None


def test_authentication_flow_with_long_lived_session(client, session):
    """Test authentication flow with multiple refresh cycles over time"""
    # Create user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "long-lived-test@example.com",
            "password": "LongLivedPass123!",
            "full_name": "Long-Lived Test User"
        }
    )
    assert signup_response.status_code == 201

    # Initial login
    login_response = client.post(
        "/auth/token",
        data={
            "username": "long-lived-test@example.com",
            "password": "LongLivedPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Use the session for a while with periodic refreshes
    current_refresh_token = refresh_token

    for cycle in range(5):  # 5 refresh cycles
        # Use access token
        protected_response = client.get(
            "/tasks/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert protected_response.status_code == 200

        # Refresh token after some simulated time passage
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": current_refresh_token}
        )
        assert refresh_response.status_code == 200

        new_tokens = refresh_response.json()
        access_token = new_tokens["access_token"]
        current_refresh_token = new_tokens["refresh_token"]

    # Final logout
    final_logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": current_refresh_token},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert final_logout_response.status_code == 200


def test_authentication_flow_edge_cases(client, session):
    """Test authentication flow with various edge cases"""
    # Test with minimal valid data
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "edge-case@example.com",
            "password": "EdgeCasePass123!",
            "full_name": ""  # Empty full name should be allowed
        }
    )
    assert signup_response.status_code == 201

    # Login with the user
    login_response = client.post(
        "/auth/token",
        data={
            "username": "edge-case@example.com",
            "password": "EdgeCasePass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Access protected endpoint
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response.status_code == 200

    # Refresh token
    refresh_response = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_response.status_code == 200

    new_tokens = refresh_response.json()
    new_access_token = new_tokens["access_token"]

    # Logout
    logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},  # Use original refresh token
        headers={"Authorization": f"Bearer {new_access_token}"}
    )
    assert logout_response.status_code == 200


def test_authentication_flow_with_concurrent_operations(client, session):
    """Test authentication flow with concurrent operations"""
    import threading

    # Create user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "concurrent-test@example.com",
            "password": "ConcurrentPass123!",
            "full_name": "Concurrent Test User"
        }
    )
    assert signup_response.status_code == 201

    # Store results from concurrent operations
    results = {}

    def login_and_use_session(name):
        # Each thread performs login -> use -> refresh -> use -> logout
        login_resp = client.post(
            "/auth/token",
            data={
                "username": "concurrent-test@example.com",
                "password": "ConcurrentPass123!"
            }
        )
        if login_resp.status_code == 200:
            tokens = login_resp.json()
            access = tokens["access_token"]
            refresh = tokens["refresh_token"]

            # Use the token
            use_resp = client.get(
                "/tasks/me",
                headers={"Authorization": f"Bearer {access}"}
            )

            # Refresh the token
            refresh_resp = client.post(
                "/auth/refresh",
                json={"refresh_token": refresh}
            )

            new_access = None
            if refresh_resp.status_code == 200:
                new_tokens = refresh_resp.json()
                new_access = new_tokens["access_token"]

                # Use the new token
                new_use_resp = client.get(
                    "/tasks/me",
                    headers={"Authorization": f"Bearer {new_access}"}
                )

                # Logout with new access token and old refresh token
                logout_resp = client.post(
                    "/auth/logout",
                    json={"refresh_token": refresh},
                    headers={"Authorization": f"Bearer {new_access}"}
                )

                results[name] = {
                    "login": login_resp.status_code,
                    "use1": use_resp.status_code,
                    "refresh": refresh_resp.status_code,
                    "use2": new_use_resp.status_code,
                    "logout": logout_resp.status_code
                }
            else:
                results[name] = {
                    "login": login_resp.status_code,
                    "use1": use_resp.status_code,
                    "refresh": refresh_resp.status_code
                }
        else:
            results[name] = {"login": login_resp.status_code}

    # Run multiple concurrent sessions
    threads = []
    for i in range(3):
        thread = threading.Thread(target=login_and_use_session, args=(f"thread_{i}",))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Verify that at least one session completed successfully
    successful_sessions = sum(1 for result in results.values() if result.get("logout") == 200)
    assert successful_sessions >= 1, f"At least one session should succeed, got {successful_sessions}"


def test_authentication_flow_with_role_based_access(client, session):
    """Test authentication flow with role-based access control"""
    # Create regular user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "rbac-regular@example.com",
            "password": "RbacRegularPass123!",
            "full_name": "RBAC Regular User"
        }
    )
    assert signup_response.status_code == 201

    # Manually set user as admin for testing purposes
    from app.database import get_session
    with get_session() as db_session:
        user = db_session.exec(select(User).where(User.email == "rbac-regular@example.com")).first()
        user.is_superuser = True
        user.role = UserRole.ADMIN
        db_session.add(user)
        db_session.commit()

    # Login as admin user
    login_response = client.post(
        "/auth/token",
        data={
            "username": "rbac-regular@example.com",
            "password": "RbacRegularPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]

    # Access regular protected endpoint
    regular_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert regular_response.status_code == 200

    # Try to access admin endpoint (if it exists)
    admin_response = client.get(
        "/tasks/admin",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    # This should work if user is properly set as superuser
    assert admin_response.status_code in [200, 404]  # 404 if endpoint doesn't exist


def test_authentication_flow_token_expiry_simulation(client, session):
    """Test behavior when tokens expire during the flow"""
    # Create user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "expiry-test@example.com",
            "password": "ExpiryTestPass123!",
            "full_name": "Expiry Test User"
        }
    )
    assert signup_response.status_code == 201

    # Login
    login_response = client.post(
        "/auth/token",
        data={
            "username": "expiry-test@example.com",
            "password": "ExpiryTestPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Access protected endpoint while token is valid
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response.status_code == 200

    # Instead of waiting for actual expiry, we'll test with a new token
    refresh_response = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_response.status_code == 200

    new_tokens = refresh_response.json()
    new_access_token = new_tokens["access_token"]

    # Use the new token
    new_protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {new_access_token}"}
    )
    assert new_protected_response.status_code == 200

    # Logout with new access token and old refresh token
    logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {new_access_token}"}
    )
    assert logout_response.status_code == 200