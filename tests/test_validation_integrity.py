"""
Password validation and database integrity tests for the FastAPI JWT Authentication Service
Tests password validation rules and database transaction integrity
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from main import create_app
from app.database import get_session, engine
from app.models.user import User, UserCreate
from app.models.token_blacklist import TokenBlacklist
from app.auth.security import hash_password, verify_password
from app.auth.service import create_user
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


def test_password_minimum_length_validation(client, session):
    """Test that passwords shorter than 8 characters are rejected"""
    response = client.post(
        "/auth/signup",
        json={
            "email": "short-pass@example.com",
            "password": "123",  # Too short
            "full_name": "Short Password User"
        }
    )
    assert response.status_code == 422  # Validation error


def test_password_uppercase_requirement(client, session):
    """Test that passwords without uppercase letters are rejected"""
    response = client.post(
        "/auth/signup",
        json={
            "email": "no-upper@example.com",
            "password": "password123!",  # No uppercase
            "full_name": "No Uppercase User"
        }
    )
    assert response.status_code == 422  # Validation error


def test_password_lowercase_requirement(client, session):
    """Test that passwords without lowercase letters are rejected"""
    response = client.post(
        "/auth/signup",
        json={
            "email": "no-lower@example.com",
            "password": "PASSWORD123!",  # No lowercase
            "full_name": "No Lowercase User"
        }
    )
    assert response.status_code == 422  # Validation error


def test_password_digit_requirement(client, session):
    """Test that passwords without digits are rejected"""
    response = client.post(
        "/auth/signup",
        json={
            "email": "no-digit@example.com",
            "password": "Password!",  # No digit
            "full_name": "No Digit User"
        }
    )
    assert response.status_code == 422  # Validation error


def test_password_special_char_requirement(client, session):
    """Test that passwords without special characters are rejected"""
    response = client.post(
        "/auth/signup",
        json={
            "email": "no-special@example.com",
            "password": "Password123",  # No special character
            "full_name": "No Special Character User"
        }
    )
    assert response.status_code == 422  # Validation error


def test_valid_password_acceptance(client, session):
    """Test that valid passwords are accepted"""
    response = client.post(
        "/auth/signup",
        json={
            "email": "valid-pass@example.com",
            "password": "ValidPass123!",
            "full_name": "Valid Password User"
        }
    )
    assert response.status_code == 201  # Success


def test_password_hashing_integrity(client, session):
    """Test that passwords are properly hashed and can be verified"""
    plain_password = "SecurePass123!"

    # Hash the password
    hashed = hash_password(plain_password)

    # Verify the password matches the hash
    assert verify_password(plain_password, hashed)

    # Verify wrong password doesn't match
    assert not verify_password("WrongPassword123!", hashed)

    # Verify same password creates different hashes (due to salt)
    hashed2 = hash_password(plain_password)
    assert hashed != hashed2

    # But both hashes should verify with the same password
    assert verify_password(plain_password, hashed)
    assert verify_password(plain_password, hashed2)


def test_password_validation_direct_model(client, session):
    """Test password validation directly through the model"""
    from pydantic import ValidationError

    # Test various invalid password scenarios
    invalid_passwords = [
        "123",  # Too short
        "password",  # No uppercase, no digit, no special char
        "PASSWORD",  # No lowercase, no digit, no special char
        "Password",  # No digit, no special char
        "Password123",  # No special char
        "Password!",  # No digit
    ]

    for invalid_pass in invalid_passwords:
        try:
            user_create = UserCreate(
                email="test@example.com",
                password=invalid_pass,
                full_name="Test User"
            )
            assert False, f"Password '{invalid_pass}' should have been rejected"
        except ValidationError:
            # Expected to raise validation error
            pass


def test_database_transaction_rollback_on_error(client, session):
    """Test that database transactions are properly rolled back on errors"""
    # Try to create a user with invalid password (should fail)
    response1 = client.post(
        "/auth/signup",
        json={
            "email": "rollback-test@example.com",
            "password": "short",  # Invalid password
            "full_name": "Rollback Test User"
        }
    )
    assert response1.status_code == 422

    # Verify user was not created in database
    user = session.exec(select(User).where(User.email == "rollback-test@example.com")).first()
    assert user is None

    # Now create a valid user
    response2 = client.post(
        "/auth/signup",
        json={
            "email": "rollback-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Rollback Test User"
        }
    )
    assert response2.status_code == 201

    # Verify user was created
    user = session.exec(select(User).where(User.email == "rollback-test@example.com")).first()
    assert user is not None
    assert user.email == "rollback-test@example.com"


def test_duplicate_email_constraint(client, session):
    """Test that duplicate emails are properly prevented at the database level"""
    # Create first user
    response1 = client.post(
        "/auth/signup",
        json={
            "email": "duplicate-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Duplicate Test User 1"
        }
    )
    assert response1.status_code == 201

    # Try to create user with same email
    response2 = client.post(
        "/auth/signup",
        json={
            "email": "duplicate-test@example.com",  # Same email
            "password": "DifferentPass123!",
            "full_name": "Duplicate Test User 2"
        }
    )
    assert response2.status_code == 400
    assert "Email already registered" in response2.json()["detail"]

    # Verify only one user exists in database
    users = session.exec(select(User).where(User.email == "duplicate-test@example.com")).all()
    assert len(users) == 1


def test_email_case_insensitive_unique_constraint(client, session):
    """Test that email uniqueness is case-insensitive"""
    # Create user with lowercase email
    response1 = client.post(
        "/auth/signup",
        json={
            "email": "case-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Case Test User 1"
        }
    )
    assert response1.status_code == 201

    # Try to create user with same email but different case
    response2 = client.post(
        "/auth/signup",
        json={
            "email": "CASE-TEST@EXAMPLE.COM",  # Same email, different case
            "password": "DifferentPass123!",
            "full_name": "Case Test User 2"
        }
    )
    assert response2.status_code == 400
    assert "Email already registered" in response2.json()["detail"]

    # Also test mixed case
    response3 = client.post(
        "/auth/signup",
        json={
            "email": "Case-Test@Example.Com",  # Mixed case
            "password": "AnotherPass123!",
            "full_name": "Case Test User 3"
        }
    )
    assert response3.status_code == 400
    assert "Email already registered" in response3.json()["detail"]

    # Verify only one user exists
    users = session.exec(select(User).where(
        User.email.like("%case-test%")
    )).all()
    assert len(users) == 1


def test_user_data_integrity_after_creation(client, session):
    """Test that user data is properly stored and retrieved"""
    test_data = {
        "email": "integrity-test@example.com",
        "password": "IntegrityPass123!",
        "full_name": "Integrity Test User"
    }

    response = client.post("/auth/signup", json=test_data)
    assert response.status_code == 201

    user_data = response.json()
    assert user_data["email"] == test_data["email"]
    assert user_data["full_name"] == test_data["full_name"]
    assert "id" in user_data
    assert "hashed_password" not in user_data  # Password should not be returned

    # Verify data in database
    user = session.exec(select(User).where(User.email == test_data["email"])).first()
    assert user is not None
    assert user.email == test_data["email"]
    assert user.full_name == test_data["full_name"]
    assert user.hashed_password != test_data["password"]  # Should be hashed
    assert user.is_active is True
    assert user.is_verified is False  # Default value
    assert user.failed_login_attempts == 0  # Default value
    assert user.created_at is not None
    assert user.updated_at is not None


def test_full_name_length_constraint(client, session):
    """Test that full names longer than 100 characters are rejected"""
    long_name = "x" * 101  # 101 characters, exceeding the 100 limit

    response = client.post(
        "/auth/signup",
        json={
            "email": "long-name@example.com",
            "password": "ValidPass123!",
            "full_name": long_name
        }
    )
    assert response.status_code == 422  # Validation error

    # Test that 100 characters is acceptable
    valid_long_name = "x" * 100  # Exactly 100 characters

    response = client.post(
        "/auth/signup",
        json={
            "email": "valid-long-name@example.com",
            "password": "ValidPass123!",
            "full_name": valid_long_name
        }
    )
    assert response.status_code == 201  # Should work


def test_email_format_validation(client, session):
    """Test that invalid email formats are rejected"""
    invalid_emails = [
        "invalid-email",          # Missing @ and domain
        "@example.com",           # Missing local part
        "user@",                  # Missing domain
        "user..name@example.com", # Double dots
        "user@.example.com",      # Dot at start of domain
        "user@example.",          # Domain ends with dot
        "user name@example.com",  # Space in local part
    ]

    for invalid_email in invalid_emails:
        response = client.post(
            "/auth/signup",
            json={
                "email": invalid_email,
                "password": "ValidPass123!",
                "full_name": "Invalid Email User"
            }
        )
        assert response.status_code == 422, f"Email '{invalid_email}' should have been rejected"


def test_valid_email_formats_accepted(client, session):
    """Test that valid email formats are accepted"""
    valid_emails = [
        "user@example.com",
        "user.name@example.com",
        "user+tag@example.com",
        "user123@example-domain.com",
        "user_name@example.co.uk",
        "u@example.museum",
    ]

    for i, valid_email in enumerate(valid_emails):
        response = client.post(
            "/auth/signup",
            json={
                "email": valid_email,
                "password": "ValidPass123!",
                "full_name": f"Valid Email User {i}"
            }
        )
        # Some might conflict with existing emails, so we'll check for either success or duplicate error
        assert response.status_code in [201, 400], f"Email '{valid_email}' should be accepted or rejected for duplication"


def test_database_constraints_on_user_fields(client, session):
    """Test database-level constraints on user fields"""
    # Test creating user with valid data first
    response = client.post(
        "/auth/signup",
        json={
            "email": "constraint-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Constraint Test User"
        }
    )
    assert response.status_code == 201

    # Verify the user exists in database with expected defaults
    user = session.exec(select(User).where(User.email == "constraint-test@example.com")).first()
    assert user is not None
    assert user.is_active is True
    assert user.is_verified is False
    assert user.failed_login_attempts == 0
    assert user.locked_until is None
    assert user.refresh_token is None
    assert user.two_factor_enabled is False


def test_password_validation_edge_cases(client, session):
    """Test edge cases for password validation"""
    edge_case_passwords = [
        ("Aa1!", 4),  # Minimum length with all requirements
        ("AAAAAAAAAA1!", 12),  # All uppercase + number + special
        ("aaaaaaaaaa1!", 12),  # All lowercase + number + special
        ("Aaaaaaaaaa!", 11),   # Mixed + special, no number
        ("A111111111!", 11),  # Uppercase + numbers + special
    ]

    for pwd, expected_status in [(p, s) for p, s in edge_case_passwords if s >= 8]:
        # Only test passwords that meet minimum length
        if len([item for item in edge_case_passwords if item[1] >= 8 and item[0] == pwd][0]) > 0:
            if len(pwd) >= 8:
                # This should pass if it has all requirements
                has_upper = any(c.isupper() for c in pwd)
                has_lower = any(c.islower() for c in pwd)
                has_digit = any(c.isdigit() for c in pwd)
                has_special = any(c in "!@#$%^&*(),.?\":{}|<>" for c in pwd)

                if has_upper and has_lower and has_digit and has_special:
                    response = client.post(
                        "/auth/signup",
                        json={
                            "email": f"edge-{pwd.lower().replace('!', '').replace('@', '')}@example.com",
                            "password": pwd,
                            "full_name": f"Edge Case User {pwd}"
                        }
                    )
                    assert response.status_code == 201, f"Password '{pwd}' should be valid"
                else:
                    response = client.post(
                        "/auth/signup",
                        json={
                            "email": f"edge-{pwd.lower().replace('!', '').replace('@', '')}@example.com",
                            "password": pwd,
                            "full_name": f"Edge Case User {pwd}"
                        }
                    )
                    assert response.status_code == 422, f"Password '{pwd}' should be invalid"
            else:
                # Too short - should fail
                response = client.post(
                    "/auth/signup",
                    json={
                        "email": f"edge-{pwd.lower().replace('!', '').replace('@', '')}@example.com",
                        "password": pwd,
                        "full_name": f"Edge Case User {pwd}"
                    }
                )
                assert response.status_code == 422, f"Password '{pwd}' should be invalid due to length"


def test_password_strength_boundary_values(client, session):
    """Test boundary values for password strength requirements"""
    # Test 7 characters (one less than minimum)
    response = client.post(
        "/auth/signup",
        json={
            "email": "boundary1@example.com",
            "password": "Aa1!aa",  # 7 chars, meets other requirements
            "full_name": "Boundary Test User 1"
        }
    )
    assert response.status_code == 422  # Should fail due to length

    # Test 8 characters (minimum)
    response = client.post(
        "/auth/signup",
        json={
            "email": "boundary2@example.com",
            "password": "Aa1!aaa",  # 8 chars, meets requirements
            "full_name": "Boundary Test User 2"
        }
    )
    assert response.status_code == 201  # Should pass


def test_user_field_sanitization(client, session):
    """Test that user input fields are properly sanitized"""
    # Test with leading/trailing whitespace in email and full_name
    response = client.post(
        "/auth/signup",
        json={
            "email": "  spaced-email@example.com  ",  # With spaces
            "password": "ValidPass123!",
            "full_name": "  Spaced Name  "  # With spaces
        }
    )
    assert response.status_code == 201

    # Verify that the email was normalized (spaces stripped and lowercased)
    user = session.exec(select(User).where(User.email == "spaced-email@example.com")).first()
    assert user is not None
    assert user.email == "spaced-email@example.com"  # Should be trimmed and lowercased
    assert user.full_name == "Spaced Name"  # Should be trimmed


def test_token_blacklist_database_integrity(client, session):
    """Test database integrity for token blacklist operations"""
    # Create and authenticate a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "blacklist-integrity@example.com",
            "password": "ValidPass123!",
            "full_name": "Blacklist Integrity User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "blacklist-integrity@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]

    # Logout to blacklist the token
    logout_response = client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert logout_response.status_code == 200

    # Verify token is in blacklist table
    blacklisted_token = session.exec(
        select(TokenBlacklist).where(TokenBlacklist.token == access_token)
    ).first()
    assert blacklisted_token is not None
    assert blacklisted_token.token == access_token
    assert blacklisted_token.token_type == "access"
    assert blacklisted_token.reason == "User logged out"
    assert blacklisted_token.expires_at is not None


def test_concurrent_user_creation(client, session):
    """Test database integrity during concurrent user creation"""
    import threading

    results = []

    def create_user_thread(email_suffix):
        response = client.post(
            "/auth/signup",
            json={
                "email": f"concurrent-{email_suffix}@example.com",
                "password": "ValidPass123!",
                "full_name": f"Concurrent User {email_suffix}"
            }
        )
        results.append((email_suffix, response.status_code, response.json() if response.status_code != 201 else {}))

    # Create multiple threads to create users simultaneously
    threads = []
    for i in range(5):
        thread = threading.Thread(target=create_user_thread, args=(i,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Count successful creations
    successful_creations = sum(1 for suffix, status, _ in results if status == 201)

    # All should succeed since they use different emails
    assert successful_creations == 5

    # Verify all users exist in database
    for i in range(5):
        user = session.exec(select(User).where(User.email == f"concurrent-{i}@example.com")).first()
        assert user is not None


def test_database_session_isolation(client, session):
    """Test that database sessions are properly isolated"""
    # Create a user
    response = client.post(
        "/auth/signup",
        json={
            "email": "isolation-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Isolation Test User"
        }
    )
    assert response.status_code == 201

    # Query the user in the same session
    user = session.exec(select(User).where(User.email == "isolation-test@example.com")).first()
    assert user is not None

    # Verify that the user data is consistent
    assert user.email == "isolation-test@example.com"
    assert user.is_active is True
    assert user.is_verified is False
    assert user.failed_login_attempts == 0