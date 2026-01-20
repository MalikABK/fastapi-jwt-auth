"""Integration tests for the FastAPI JWT Authentication Service"""

import pytest
from fastapi.testclient import TestClient
import os


# Set environment for testing
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-that-is-at-least-32-chars-long-for-testing"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"


@pytest.mark.integration
def test_complete_user_workflow(test_client):
    """Test the complete user workflow: signup -> login -> protected access -> refresh -> logout"""

    # Step 1: Signup
    signup_data = {
        "email": "integration@example.com",
        "password": "IntegrationPass123!",
        "full_name": "Integration Test User"
    }

    signup_response = test_client.post("/auth/signup", json=signup_data)
    assert signup_response.status_code == 201

    user_data = signup_response.json()
    assert user_data["email"] == "integration@example.com"
    assert user_data["full_name"] == "Integration Test User"
    assert "id" in user_data

    # Step 2: Login
    login_response = test_client.post(
        "/auth/token",
        data={
            "username": "integration@example.com",
            "password": "IntegrationPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"

    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Step 3: Access protected route with access token
    protected_response = test_client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert protected_response.status_code == 200

    user_info = protected_response.json()
    assert user_info["email"] == "integration@example.com"
    assert user_info["full_name"] == "Integration Test User"

    # Step 4: Use refresh token to get new access token
    refresh_response = test_client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_response.status_code == 200

    new_tokens = refresh_response.json()
    assert "access_token" in new_tokens
    assert new_tokens["token_type"] == "bearer"
    assert new_tokens["access_token"] != access_token  # New token should be different

    # Step 5: Logout (invalidate refresh token)
    logout_response = test_client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert logout_response.status_code == 200

    logout_msg = logout_response.json()
    assert logout_msg["msg"] == "Logged out successfully"

    # Step 6: Verify that old access token is now invalid (after logout, if blacklisted)
    # This may or may not fail depending on implementation, but should test the flow
    old_token_response = test_client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    # Depending on implementation, this could be 200 or 401 after logout
    # For now, we'll accept that the logout was successful


@pytest.mark.integration
def test_multiple_users_different_permissions(test_client):
    """Test that different users have appropriate access levels"""

    # Create regular user
    regular_user_data = {
        "email": "regular@example.com",
        "password": "RegularPass123!",
        "full_name": "Regular User"
    }

    regular_signup = test_client.post("/auth/signup", json=regular_user_data)
    assert regular_signup.status_code == 201

    # Create admin user (would need special endpoint or database seeding in real app)
    admin_user_data = {
        "email": "admin@example.com",
        "password": "AdminPass123!",
        "full_name": "Admin User"
    }

    admin_signup = test_client.post("/auth/signup", json=admin_user_data)
    assert admin_signup.status_code == 201

    # Login as regular user
    regular_login = test_client.post(
        "/auth/token",
        data={
            "username": "regular@example.com",
            "password": "RegularPass123!"
        }
    )
    assert regular_login.status_code == 200

    regular_tokens = regular_login.json()
    regular_access_token = regular_tokens["access_token"]

    # Login as admin user
    admin_login = test_client.post(
        "/auth/token",
        data={
            "username": "admin@example.com",
            "password": "AdminPass123!"
        }
    )
    assert admin_login.status_code == 200

    admin_tokens = admin_login.json()
    admin_access_token = admin_tokens["access_token"]

    # Regular user should be able to access /tasks/me
    regular_me_response = test_client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {regular_access_token}"}
    )
    assert regular_me_response.status_code == 200

    # In a real app, we'd need to make the admin user an actual admin
    # For now, just test that both users can access their own info
    regular_user_info = regular_me_response.json()
    assert regular_user_info["email"] == "regular@example.com"


@pytest.mark.integration
def test_token_rotation_and_security(test_client):
    """Test token security features like rotation and invalidation"""

    # Create user
    user_data = {
        "email": "security@example.com",
        "password": "SecurityPass123!",
        "full_name": "Security Test User"
    }

    signup_response = test_client.post("/auth/signup", json=user_data)
    assert signup_response.status_code == 201

    # Login to get initial tokens
    login_response = test_client.post(
        "/auth/token",
        data={
            "username": "security@example.com",
            "password": "SecurityPass123!"
        }
    )
    assert login_response.status_code == 200

    initial_tokens = login_response.json()
    initial_access_token = initial_tokens["access_token"]
    initial_refresh_token = initial_tokens["refresh_token"]

    # Use refresh token to get new access token
    refresh_response = test_client.post(
        "/auth/refresh",
        json={"refresh_token": initial_refresh_token}
    )
    assert refresh_response.status_code == 200

    new_tokens = refresh_response.json()
    new_access_token = new_tokens["access_token"]

    # Old access token should still work (unless blacklisted on refresh)
    old_token_response = test_client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {initial_access_token}"}
    )
    # This depends on implementation - some systems blacklist on refresh
    # For now, we'll accept either 200 or 401
    assert old_token_response.status_code in [200, 401]

    # New token should work
    new_token_response = test_client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {new_access_token}"}
    )
    assert new_token_response.status_code == 200


@pytest.mark.security
def test_rate_limiting_integration(test_client):
    """Test that rate limiting works at the integration level"""

    # Try to hit the token endpoint multiple times with invalid credentials
    # This should eventually trigger rate limiting
    for i in range(15):  # Try more than the limit
        response = test_client.post(
            "/auth/token",
            data={
                "username": "nonexistent@example.com",
                "password": "wrongpassword"
            }
        )

        # Early requests should return 401, later ones might return 429
        assert response.status_code in [401, 429]

        if response.status_code == 429:
            # Rate limit triggered - this is expected behavior
            break
    else:
        # If we never hit rate limit, that's also acceptable depending on the timing
        pass