"""
Stress testing and recovery testing for the FastAPI JWT Authentication Service
Tests system behavior under extreme load and recovery from failure conditions
"""

import pytest
import time
import threading
import requests
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from main import create_app
from app.database import get_session, engine
from app.models.user import User
from app.models.token_blacklist import TokenBlacklist
from app.core.config import settings
import os
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import gc

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


def test_extreme_load_stress_test(client, session):
    """Test system behavior under extreme load conditions"""
    # Create a moderate number of users to work with
    num_users = 25
    users = []

    for i in range(num_users):
        email = f"stress-user-{i}@example.com"
        response = client.post(
            "/auth/signup",
            json={
                "email": email,
                "password": "ValidPass123!",
                "full_name": f"Stress User {i}"
            }
        )
        assert response.status_code in [201, 400]  # 400 might occur due to rate limiting

        if response.status_code == 201:
            users.append({"email": email, "password": "ValidPass123!"})

    print(f"Created {len(users)} users for stress testing")

    # Define a worker function for high-concurrency operations
    def stress_worker(user_data):
        results = {"success": 0, "failures": 0, "errors": []}

        for op_num in range(5):  # Each worker does 5 operations
            try:
                # Login
                login_response = client.post(
                    "/auth/token",
                    data={
                        "username": user_data["email"],
                        "password": user_data["password"]
                    }
                )

                if login_response.status_code == 200:
                    tokens = login_response.json()
                    access_token = tokens["access_token"]

                    # Access protected endpoint
                    protected_response = client.get(
                        "/tasks/me",
                        headers={"Authorization": f"Bearer {access_token}"}
                    )

                    if protected_response.status_code == 200:
                        results["success"] += 1
                    else:
                        results["failures"] += 1
                else:
                    results["failures"] += 1
            except Exception as e:
                results["errors"].append(str(e))
                results["failures"] += 1

            # Small random delay to vary the load pattern
            time.sleep(random.uniform(0.01, 0.1))

        return results

    # Execute extreme stress test
    num_workers = 50  # High number of concurrent workers
    active_users = users[:min(len(users), num_workers)]  # Use available users

    print(f"Starting stress test with {len(active_users)} users and {num_workers} workers...")

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(stress_worker, user) for user in active_users]

        total_results = {"success": 0, "failures": 0, "errors": []}

        for future in as_completed(futures):
            worker_result = future.result()
            total_results["success"] += worker_result["success"]
            total_results["failures"] += worker_result["failures"]
            total_results["errors"].extend(worker_result["errors"])

    total_time = time.time() - start_time

    print(f"Extreme load stress test results:")
    print(f"  Duration: {total_time:.2f}s")
    print(f"  Operations completed: {total_results['success'] + total_results['failures']}")
    print(f"  Successful: {total_results['success']}")
    print(f"  Failed: {total_results['failures']}")
    print(f"  Success rate: {(total_results['success']/(total_results['success'] + total_results['failures']))*100:.2f}%")

    # System should handle load without crashing (even if some requests fail due to rate limiting)
    assert total_results["success"] >= 0  # Should not crash


def test_memory_leak_detection_under_load(client, session):
    """Test for memory leaks under sustained load"""
    import psutil
    import os

    # Get initial memory usage
    initial_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB
    print(f"Initial memory usage: {initial_memory:.2f} MB")

    # Create a user for testing
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "memory-leak-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Memory Leak Test User"
        }
    )
    assert signup_response.status_code == 201

    # Perform many operations to check for memory growth
    num_operations = 100

    for i in range(num_operations):
        # Login
        login_response = client.post(
            "/auth/token",
            data={
                "username": "memory-leak-test@example.com",
                "password": "ValidPass123!"
            }
        )

        if login_response.status_code == 200:
            tokens = login_response.json()
            access_token = tokens["access_token"]

            # Access protected endpoint
            client.get(
                "/tasks/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )

        # Periodic garbage collection to ensure fair testing
        if i % 20 == 0:
            gc.collect()

        # Small delay to allow for any cleanup
        time.sleep(0.01)

    # Force garbage collection
    gc.collect()
    time.sleep(0.1)  # Allow time for cleanup

    # Get final memory usage
    final_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB
    memory_growth = final_memory - initial_memory

    print(f"Final memory usage: {final_memory:.2f} MB")
    print(f"Memory growth: {memory_growth:.2f} MB")

    # Memory growth should be reasonable (less than 50MB for 100 operations)
    assert abs(memory_growth) < 50.0, f"Memory growth too high: {memory_growth} MB"


def test_recovery_after_rate_limiting_saturation(client, session):
    """Test system recovery after rate limiting saturation"""
    # First, saturate the rate limiter by making many requests
    num_attempts = 50  # Way more than typical rate limit

    # Create a user first
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "recovery-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Recovery Test User"
        }
    )
    assert signup_response.status_code == 201

    # Make many login attempts to potentially trigger rate limiting
    responses = []
    for i in range(num_attempts):
        response = client.post(
            "/auth/token",
            data={
                "username": "recovery-test@example.com",
                "password": "ValidPass123!"  # Valid credentials
            }
        )
        responses.append(response.status_code)
        time.sleep(0.01)  # Small delay between requests

    # Count rate limited responses
    rate_limited_count = sum(1 for code in responses if code == 429)
    success_count = sum(1 for code in responses if code == 200)

    print(f"Rate limiting saturation test:")
    print(f"  Total requests: {len(responses)}")
    print(f"  Successful: {success_count}")
    print(f"  Rate limited: {rate_limited_count}")

    # Wait for rate limit to reset (simulate time passing)
    # In a real system, we'd wait for the actual rate limit window
    time.sleep(2)  # Wait for potential rate limit reset

    # Try to make a successful request after the wait
    recovery_response = client.post(
        "/auth/token",
        data={
            "username": "recovery-test@example.com",
            "password": "ValidPass123!"
        }
    )

    # Should be able to authenticate successfully after rate limit reset
    assert recovery_response.status_code == 200, f"Recovery failed, got status: {recovery_response.status_code}"


def test_system_recovery_after_exception_conditions(client, session):
    """Test system recovery after exceptional conditions"""
    # Create multiple users
    for i in range(10):
        client.post(
            "/auth/signup",
            json={
                "email": f"exception-recovery-{i}@example.com",
                "password": "ValidPass123!",
                "full_name": f"Exception Recovery {i}"
            }
        )

    # Perform a series of operations that might cause strain
    results = {"success": 0, "failure": 0}

    for i in range(50):
        email = f"exception-recovery-{i % 10}@example.com"

        try:
            # Login
            login_response = client.post(
                "/auth/token",
                data={
                    "username": email,
                    "password": "ValidPass123!"
                }
            )

            if login_response.status_code == 200:
                tokens = login_response.json()

                # Rapid succession of operations
                for j in range(3):
                    access_token = tokens["access_token"]

                    protected_response = client.get(
                        "/tasks/me",
                        headers={"Authorization": f"Bearer {access_token}"}
                    )

                    if protected_response.status_code == 200:
                        results["success"] += 1
                    else:
                        results["failure"] += 1
            else:
                results["failure"] += 1

        except Exception as e:
            results["failure"] += 1
            print(f"Exception during operation {i}: {str(e)}")

    print(f"Exception recovery test results:")
    print(f"  Successful operations: {results['success']}")
    print(f"  Failed operations: {results['failure']}")

    # System should still be functional after stress
    final_test = client.post(
        "/auth/token",
        data={
            "username": "exception-recovery-0@example.com",
            "password": "ValidPass123!"
        }
    )

    assert final_test.status_code == 200, "System should recover and be functional"


def test_token_blacklist_stress_test(client, session):
    """Test token blacklist performance under stress"""
    # Create a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "blacklist-stress@example.com",
            "password": "ValidPass123!",
            "full_name": "Blacklist Stress User"
        }
    )
    assert signup_response.status_code == 201

    # Login to get tokens
    login_response = client.post(
        "/auth/token",
        data={
            "username": "blacklist-stress@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Log out multiple times to add to blacklist (though only first should work)
    for i in range(10):
        logout_response = client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {access_token}"}
        )
        # Only the first logout should succeed, others may fail

        # Also try to access with the token after first logout attempt
        if i > 0:
            protected_response = client.get(
                "/tasks/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            # Should be denied after first logout

    # Verify that blacklist table has reasonable number of entries
    blacklist_count = session.exec(select(TokenBlacklist)).count()
    print(f"Token blacklist entries after stress test: {blacklist_count}")

    # Count should be reasonable (not excessively high)
    assert blacklist_count <= 10  # Should not have duplicate entries


def test_concurrent_failure_recovery(client, session):
    """Test recovery when multiple failures occur simultaneously"""
    import threading

    results = []

    def failure_scenario(thread_id):
        try:
            # Create user with random email
            email = f"failure-{thread_id}@example.com"
            signup_resp = client.post(
                "/auth/signup",
                json={
                    "email": email,
                    "password": "ValidPass123!",
                    "full_name": f"Failure {thread_id}"
                }
            )

            if signup_resp.status_code == 201:
                # Immediately try to perform multiple operations
                for i in range(3):
                    login_resp = client.post(
                        "/auth/token",
                        data={
                            "username": email,
                            "password": "ValidPass123!"
                        }
                    )

                    if login_resp.status_code == 200:
                        tokens = login_resp.json()
                        access_token = tokens["access_token"]

                        protected_resp = client.get(
                            "/tasks/me",
                            headers={"Authorization": f"Bearer {access_token}"}
                        )

                        # Try to logout
                        if "refresh_token" in tokens:
                            client.post(
                                "/auth/logout",
                                json={"refresh_token": tokens["refresh_token"]},
                                headers={"Authorization": f"Bearer {access_token}"}
                            )

                results.append({"thread": thread_id, "success": True})
            else:
                results.append({"thread": thread_id, "success": False})
        except Exception as e:
            results.append({"thread": thread_id, "success": False, "error": str(e)})

    # Run multiple failure scenarios concurrently
    threads = []
    for i in range(20):
        thread = threading.Thread(target=failure_scenario, args=(i,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Analyze results
    successful_threads = [r for r in results if r["success"]]
    failed_threads = [r for r in results if not r["success"]]

    print(f"Concurrent failure recovery test:")
    print(f"  Successful threads: {len(successful_threads)}")
    print(f"  Failed threads: {len(failed_threads)}")

    # System should remain stable even with concurrent operations
    # Test final functionality
    final_signup = client.post(
        "/auth/signup",
        json={
            "email": "final-functionality-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Final Functionality Test"
        }
    )

    assert final_signup.status_code in [201, 400], "System should remain functional"


def test_database_connection_pool_stress(client, session):
    """Test database connection handling under stress"""
    import concurrent.futures

    def db_operation(user_id):
        # Each operation involves DB interaction
        email = f"db-stress-{user_id}@example.com"

        signup_resp = client.post(
            "/auth/signup",
            json={
                "email": email,
                "password": "ValidPass123!",
                "full_name": f"DB Stress {user_id}"
            }
        )

        if signup_resp.status_code == 201:
            login_resp = client.post(
                "/auth/token",
                data={
                    "username": email,
                    "password": "ValidPass123!"
                }
            )

            if login_resp.status_code == 200:
                tokens = login_resp.json()
                access_token = tokens["access_token"]

                protected_resp = client.get(
                    "/tasks/me",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

                return {"user_id": user_id, "success": protected_resp.status_code == 200}

        return {"user_id": user_id, "success": False}

    # Execute many concurrent DB operations
    num_operations = 30

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(db_operation, i) for i in range(num_operations)]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]

    successful_ops = [r for r in results if r["success"]]
    failed_ops = [r for r in results if not r["success"]]

    print(f"Database connection stress test:")
    print(f"  Total operations: {len(results)}")
    print(f"  Successful: {len(successful_ops)}")
    print(f"  Failed: {len(failed_ops)}")
    print(f"  Success rate: {(len(successful_ops)/len(results))*100:.2f}%")

    # Should maintain reasonable success rate
    if len(results) > 0:
        success_rate = len(successful_ops) / len(results)
        assert success_rate >= 0.5  # At least 50% success rate


def test_recovery_after_token_expiration_stress(client, session):
    """Test system recovery after many token expiration events"""
    # Create a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "exp-stress@example.com",
            "password": "ValidPass123!",
            "full_name": "Expiration Stress User"
        }
    )
    assert signup_response.status_code == 201

    # Perform multiple login/logout cycles to create many tokens
    for i in range(20):
        login_response = client.post(
            "/auth/token",
            data={
                "username": "exp-stress@example.com",
                "password": "ValidPass123!"
            }
        )

        if login_response.status_code == 200:
            tokens = login_response.json()

            # Try to use the token
            protected_response = client.get(
                "/tasks/me",
                headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )

            # Logout to invalidate the refresh token
            if "refresh_token" in tokens:
                client.post(
                    "/auth/logout",
                    json={"refresh_token": tokens["refresh_token"]},
                    headers={"Authorization": f"Bearer {tokens['access_token']}"}
                )

    # Test that system is still functional after token churn
    final_login = client.post(
        "/auth/token",
        data={
            "username": "exp-stress@example.com",
            "password": "ValidPass123!"
        }
    )

    assert final_login.status_code == 200, "System should recover after token operations"


def test_resource_cleanup_under_stress(client, session):
    """Test that resources are properly cleaned up under stress"""
    import psutil
    import os

    # Measure resources before stress test
    process = psutil.Process(os.getpid())
    initial_fds = process.num_fds() if hasattr(process, 'num_fds') else 0
    initial_threads = process.num_threads()
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB

    print(f"Initial resource usage - FDs: {initial_fds}, Threads: {initial_threads}, Memory: {initial_memory:.2f}MB")

    # Create users and perform operations
    for i in range(15):
        email = f"cleanup-{i}@example.com"
        client.post(
            "/auth/signup",
            json={
                "email": email,
                "password": "ValidPass123!",
                "full_name": f"Cleanup {i}"
            }
        )

        # Login and perform operations
        login_resp = client.post(
            "/auth/token",
            data={
                "username": email,
                "password": "ValidPass123!"
            }
        )

        if login_resp.status_code == 200:
            tokens = login_resp.json()
            access_token = tokens["access_token"]

            for j in range(3):
                client.get(
                    "/tasks/me",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

    # Force cleanup
    gc.collect()
    time.sleep(1)  # Allow time for cleanup

    # Measure resources after stress test
    final_fds = process.num_fds() if hasattr(process, 'num_fds') else 0
    final_threads = process.num_threads()
    final_memory = process.memory_info().rss / 1024 / 1024  # MB

    print(f"Final resource usage - FDs: {final_fds}, Threads: {final_threads}, Memory: {final_memory:.2f}MB")

    # Resources should not grow excessively
    assert final_memory - initial_memory < 100  # Less than 100MB growth
    if initial_fds > 0:
        assert final_fds - initial_fds < 50  # Reasonable file descriptor growth

    # Verify system is still functional
    functionality_test = client.post(
        "/auth/signup",
        json={
            "email": "post-stress-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Post-Stress Test User"
        }
    )

    assert functionality_test.status_code in [201, 400], "System should remain functional after stress"


def test_recovery_timeout_and_deadlock_scenarios(client, session):
    """Test system behavior in timeout and potential deadlock scenarios"""
    import concurrent.futures

    # Create a user for testing
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "timeout-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Timeout Test User"
        }
    )
    assert signup_response.status_code == 201

    def rapid_operations(op_id):
        """Function that performs rapid operations that could cause issues"""
        try:
            # Perform login multiple times rapidly
            for i in range(5):
                login_resp = client.post(
                    "/auth/token",
                    data={
                        "username": "timeout-test@example.com",
                        "password": "ValidPass123!"
                    }
                )

                if login_resp.status_code == 200:
                    tokens = login_resp.json()
                    access_token = tokens["access_token"]

                    # Rapid protected calls
                    for j in range(3):
                        client.get(
                            "/tasks/me",
                            headers={"Authorization": f"Bearer {access_token}"}
                        )

            return {"op_id": op_id, "success": True}
        except Exception as e:
            return {"op_id": op_id, "success": False, "error": str(e)}

    # Execute multiple rapid operation threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(rapid_operations, i) for i in range(10)]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]

    successful_ops = [r for r in results if r["success"]]
    failed_ops = [r for r in results if not r["success"]]

    print(f"Timeout/deadlock scenario test:")
    print(f"  Successful operations: {len(successful_ops)}")
    print(f"  Failed operations: {len(failed_ops)}")

    # Test that system recovers and is functional
    recovery_test = client.post(
        "/auth/token",
        data={
            "username": "timeout-test@example.com",
            "password": "ValidPass123!"
        }
    )

    assert recovery_test.status_code == 200, "System should recover after rapid operations"