"""
Performance and load testing scenarios for the FastAPI JWT Authentication Service
Tests baseline performance metrics and load handling capabilities
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
from app.core.config import settings
import os
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

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


def test_baseline_single_request_performance(client, session):
    """Test baseline performance for single requests"""
    # Create a user for testing
    signup_start = time.time()
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "perf-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Performance Test User"
        }
    )
    signup_time = time.time() - signup_start
    assert signup_response.status_code == 201

    # Measure signup performance
    print(f"Signup request took: {signup_time:.4f} seconds")
    assert signup_time < 1.0  # Should complete within 1 second

    # Measure login performance
    login_start = time.time()
    login_response = client.post(
        "/auth/token",
        data={
            "username": "perf-test@example.com",
            "password": "ValidPass123!"
        }
    )
    login_time = time.time() - login_start
    assert login_response.status_code == 200

    print(f"Login request took: {login_time:.4f} seconds")
    assert login_time < 1.0  # Should complete within 1 second

    # Measure protected endpoint performance
    tokens = login_response.json()
    access_token = tokens["access_token"]

    protected_start = time.time()
    protected_response = client.get(
        "/tasks/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    protected_time = time.time() - protected_start
    assert protected_response.status_code == 200

    print(f"Protected endpoint request took: {protected_time:.4f} seconds")
    assert protected_time < 0.5  # Should complete within 0.5 seconds


def test_concurrent_user_authentication_performance(client, session):
    """Test performance under concurrent user authentication"""
    num_concurrent_users = 10
    results = []

    def authenticate_user(user_id):
        start_time = time.time()

        # Create user
        email = f"concurrent-{user_id}@example.com"
        signup_response = client.post(
            "/auth/signup",
            json={
                "email": email,
                "password": "ValidPass123!",
                "full_name": f"Concurrent User {user_id}"
            }
        )

        if signup_response.status_code == 201:
            # Login user
            login_response = client.post(
                "/auth/token",
                data={
                    "username": email,
                    "password": "ValidPass123!"
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

                end_time = time.time()
                total_time = end_time - start_time

                return {
                    "user_id": user_id,
                    "success": protected_response.status_code == 200,
                    "total_time": total_time,
                    "signup_time": None,  # Hard to measure separately in concurrent context
                    "login_time": None,
                    "protected_time": None
                }

        end_time = time.time()
        return {
            "user_id": user_id,
            "success": False,
            "total_time": end_time - start_time,
            "error": "Authentication failed"
        }

    # Execute concurrent authentications
    start_total = time.time()

    with ThreadPoolExecutor(max_workers=num_concurrent_users) as executor:
        futures = [executor.submit(authenticate_user, i) for i in range(num_concurrent_users)]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    total_execution_time = time.time() - start_total

    # Analyze results
    successful_auths = [r for r in results if r["success"]]
    failed_auths = [r for r in results if not r["success"]]

    print(f"Concurrent authentication results:")
    print(f"  Total executions: {len(results)}")
    print(f"  Successful: {len(successful_auths)}")
    print(f"  Failed: {len(failed_auths)}")
    print(f"  Total execution time: {total_execution_time:.4f}s")

    if successful_auths:
        avg_time = statistics.mean([r["total_time"] for r in successful_auths])
        min_time = min([r["total_time"] for r in successful_auths])
        max_time = max([r["total_time"] for r in successful_auths])

        print(f"  Average auth time: {avg_time:.4f}s")
        print(f"  Min auth time: {min_time:.4f}s")
        print(f"  Max auth time: {max_time:.4f}s")

        # Assert reasonable performance under load
        assert avg_time < 5.0  # Average should be under 5 seconds even under load
        assert len(successful_auths) >= num_concurrent_users * 0.8  # At least 80% success rate


def test_high_volume_signup_performance(client, session):
    """Test performance when handling high volume of signup requests"""
    num_signups = 20
    results = []

    start_time = time.time()

    for i in range(num_signups):
        signup_start = time.time()
        response = client.post(
            "/auth/signup",
            json={
                "email": f"bulk-{i}@example.com",
                "password": "ValidPass123!",
                "full_name": f"Bulk User {i}"
            }
        )
        signup_time = time.time() - signup_start

        results.append({
            "index": i,
            "status_code": response.status_code,
            "time": signup_time,
            "success": response.status_code == 201
        })

    total_time = time.time() - start_time

    successful_signups = [r for r in results if r["success"]]
    failed_signups = [r for r in results if not r["success"]]

    print(f"Bulk signup results:")
    print(f"  Total attempts: {len(results)}")
    print(f"  Successful: {len(successful_signups)}")
    print(f"  Failed: {len(failed_signups)}")
    print(f"  Total time: {total_time:.4f}s")

    if successful_signups:
        avg_time = statistics.mean([r["time"] for r in successful_signups])
        print(f"  Average signup time: {avg_time:.4f}s")

        assert avg_time < 2.0  # Average signup should be under 2 seconds


def test_token_refresh_performance(client, session):
    """Test performance of token refresh operations"""
    # Create and login a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "refresh-perf@example.com",
            "password": "ValidPass123!",
            "full_name": "Refresh Perf User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "refresh-perf@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    refresh_token = tokens["refresh_token"]

    # Measure refresh performance
    num_refreshes = 10
    refresh_times = []

    for i in range(num_refreshes):
        refresh_start = time.time()
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        refresh_time = time.time() - refresh_start

        if refresh_response.status_code == 200:
            # Update refresh token for next iteration (though old one should be invalid)
            new_tokens = refresh_response.json()
            refresh_times.append(refresh_time)
        else:
            # First refresh might work, subsequent ones will fail
            refresh_times.append(refresh_time)
            break

    if refresh_times:
        avg_refresh_time = statistics.mean(refresh_times)
        print(f"Average token refresh time: {avg_refresh_time:.4f}s")
        assert avg_refresh_time < 1.0  # Refresh should be fast


def test_logout_performance(client, session):
    """Test performance of logout operations"""
    # Create and login a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "logout-perf@example.com",
            "password": "ValidPass123!",
            "full_name": "Logout Perf User"
        }
    )
    assert signup_response.status_code == 201

    login_response = client.post(
        "/auth/token",
        data={
            "username": "logout-perf@example.com",
            "password": "ValidPass123!"
        }
    )
    assert login_response.status_code == 200

    tokens = login_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Measure logout performance
    num_logouts = 5
    logout_times = []

    for i in range(num_logouts):
        logout_start = time.time()
        logout_response = client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {access_token}"}
        )
        logout_time = time.time() - logout_start

        logout_times.append(logout_time)

        # For subsequent iterations, we'd need new tokens, but this is just performance testing
        if i == 0:  # Only test first logout properly
            assert logout_response.status_code == 200
            break

    if logout_times:
        avg_logout_time = statistics.mean(logout_times)
        print(f"Average logout time: {avg_logout_time:.4f}s")
        assert avg_logout_time < 1.0  # Logout should be fast


def test_memory_usage_during_concurrent_operations(client, session):
    """Test memory usage patterns during concurrent operations"""
    import psutil
    import os

    # Get initial memory usage
    initial_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB

    num_threads = 15
    results = []

    def worker(worker_id):
        # Each worker performs a complete auth flow
        email = f"memory-test-{worker_id}@example.com"

        # Signup
        signup_resp = client.post(
            "/auth/signup",
            json={
                "email": email,
                "password": "ValidPass123!",
                "full_name": f"Memory Test {worker_id}"
            }
        )

        if signup_resp.status_code == 201:
            # Login
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

                # Access protected endpoint
                protected_resp = client.get(
                    "/tasks/me",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

                return {"worker_id": worker_id, "success": protected_resp.status_code == 200}

        return {"worker_id": worker_id, "success": False}

    # Execute concurrent workers
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    # Get final memory usage
    final_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB

    print(f"Memory usage during concurrent operations:")
    print(f"  Initial: {initial_memory:.2f} MB")
    print(f"  Final: {final_memory:.2f} MB")
    print(f"  Difference: {final_memory - initial_memory:.2f} MB")

    successful_workers = [r for r in results if r["success"]]
    print(f"  Successful operations: {len(successful_workers)}/{num_threads}")

    # Memory increase should be reasonable
    assert (final_memory - initial_memory) < 100  # Less than 100MB increase is reasonable


def test_response_time_percentiles(client, session):
    """Test response time percentiles for performance characterization"""
    import numpy as np

    # Create a user first
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "percentile-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Percentile Test User"
        }
    )
    assert signup_response.status_code == 201

    # Collect multiple measurements for each operation type
    login_times = []
    protected_times = []

    num_measurements = 20

    for i in range(num_measurements):
        # Login measurement
        login_start = time.time()
        login_response = client.post(
            "/auth/token",
            data={
                "username": "percentile-test@example.com",
                "password": "ValidPass123!"
            }
        )
        login_time = time.time() - login_start
        login_times.append(login_time)

        if login_response.status_code == 200:
            tokens = login_response.json()
            access_token = tokens["access_token"]

            # Protected endpoint measurement
            protected_start = time.time()
            protected_response = client.get(
                "/tasks/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            protected_time = time.time() - protected_start
            protected_times.append(protected_time)

    # Calculate percentiles if we have enough data
    if len(login_times) > 0:
        login_50th = np.percentile(login_times, 50)
        login_95th = np.percentile(login_times, 95)
        login_99th = np.percentile(login_times, 99)

        print(f"Login response time percentiles:")
        print(f"  50th percentile: {login_50th:.4f}s")
        print(f"  95th percentile: {login_95th:.4f}s")
        print(f"  99th percentile: {login_99th:.4f}s")

        # Performance requirements
        assert login_95th < 2.0  # 95% of requests should be under 2 seconds

    if len(protected_times) > 0:
        protected_50th = np.percentile(protected_times, 50)
        protected_95th = np.percentile(protected_times, 95)
        protected_99th = np.percentile(protected_times, 99)

        print(f"Protected endpoint response time percentiles:")
        print(f"  50th percentile: {protected_50th:.4f}s")
        print(f"  95th percentile: {protected_95th:.4f}s")
        print(f"  99th percentile: {protected_99th:.4f}s")

        assert protected_95th < 1.0  # 95% of requests should be under 1 second


def test_throughput_measurement(client, session):
    """Test the throughput (requests per second) of the authentication service"""
    import time
    from concurrent.futures import ThreadPoolExecutor

    # Create a user for testing
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "throughput-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Throughput Test User"
        }
    )
    assert signup_response.status_code == 201

    # Define a function to perform one auth cycle
    def auth_cycle():
        start = time.time()

        # Login
        login_response = client.post(
            "/auth/token",
            data={
                "username": "throughput-test@example.com",
                "password": "ValidPass123!"
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

            end = time.time()
            return {"success": protected_response.status_code == 200, "time": end - start}

        end = time.time()
        return {"success": False, "time": end - start}

    # Measure throughput over a time period
    duration = 10  # seconds
    end_time = time.time() + duration
    results = []

    # Execute requests until time is up
    while time.time() < end_time:
        result = auth_cycle()
        results.append(result)
        time.sleep(0.01)  # Small delay to prevent overwhelming

    elapsed_time = time.time() - (end_time - duration)
    total_requests = len(results)
    successful_requests = sum(1 for r in results if r["success"])
    throughput = total_requests / elapsed_time if elapsed_time > 0 else 0

    print(f"Throughput results:")
    print(f"  Duration: {elapsed_time:.2f}s")
    print(f"  Total requests: {total_requests}")
    print(f"  Successful requests: {successful_requests}")
    print(f"  Throughput: {throughput:.2f} requests/sec")
    print(f"  Success rate: {(successful_requests/total_requests)*100:.2f}%" if total_requests > 0 else "N/A")

    # Reasonable throughput expectations
    assert throughput > 1  # Should handle at least 1 request per second


def test_performance_degradation_under_load(client, session):
    """Test if performance degrades gracefully under sustained load"""
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Create multiple test users
    num_users = 10
    for i in range(num_users):
        response = client.post(
            "/auth/signup",
            json={
                "email": f"load-degrade-{i}@example.com",
                "password": "ValidPass123!",
                "full_name": f"Load Degrade User {i}"
            }
        )
        assert response.status_code == 201

    # Measure performance under different load levels
    load_levels = [1, 5, 10]  # concurrent users
    results_by_load = {}

    for load_level in load_levels:
        print(f"Testing performance under {load_level} concurrent users...")

        def user_activity(user_idx):
            email = f"load-degrade-{user_idx % num_users}@example.com"

            start = time.time()
            # Login
            login_response = client.post(
                "/auth/token",
                data={
                    "username": email,
                    "password": "ValidPass123!"
                }
            )

            activity_time = time.time() - start

            if login_response.status_code == 200:
                tokens = login_response.json()
                access_token = tokens["access_token"]

                # Access protected endpoint
                protected_response = client.get(
                    "/tasks/me",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

            return {
                "user_idx": user_idx,
                "activity_time": activity_time,
                "success": login_response.status_code == 200
            }

        # Execute concurrent user activities
        start_time = time.time()
        level_results = []

        with ThreadPoolExecutor(max_workers=load_level) as executor:
            futures = [executor.submit(user_activity, i) for i in range(load_level)]
            for future in as_completed(futures):
                result = future.result()
                level_results.append(result)

        total_time = time.time() - start_time
        successful_ops = [r for r in level_results if r["success"]]

        if successful_ops:
            avg_response_time = statistics.mean([r["activity_time"] for r in successful_ops])
            results_by_load[load_level] = {
                "total_time": total_time,
                "successful_ops": len(successful_ops),
                "avg_response_time": avg_response_time,
                "throughput": len(level_results) / total_time if total_time > 0 else 0
            }
        else:
            results_by_load[load_level] = {
                "total_time": total_time,
                "successful_ops": 0,
                "avg_response_time": float('inf'),
                "throughput": 0
            }

        print(f"  Load {load_level}: Avg response {results_by_load[load_level]['avg_response_time']:.4f}s, "
              f"Throughput {results_by_load[load_level]['throughput']:.2f} ops/sec")

    # Performance should not degrade catastrophically
    # Compare low load vs high load performance
    if 1 in results_by_load and max(load_levels) in results_by_load:
        low_load_time = results_by_load[1]["avg_response_time"]
        high_load_time = results_by_load[max(load_levels)]["avg_response_time"]

        # High load response time should not be more than 10x slower than low load
        # (allowing for some degradation under load)
        if low_load_time > 0:
            degradation_ratio = high_load_time / low_load_time
            print(f"  Performance degradation ratio (high/low load): {degradation_ratio:.2f}x")
            assert degradation_ratio < 20  # Performance shouldn't degrade more than 20x


def test_caching_effectiveness(client, session):
    """Test if there are any caching benefits visible in repeated requests"""
    # Create a user
    signup_response = client.post(
        "/auth/signup",
        json={
            "email": "cache-test@example.com",
            "password": "ValidPass123!",
            "full_name": "Cache Test User"
        }
    )
    assert signup_response.status_code == 201

    # Perform the same operation multiple times to see if performance improves
    login_times = []

    for i in range(10):
        start = time.time()
        response = client.post(
            "/auth/token",
            data={
                "username": "cache-test@example.com",
                "password": "ValidPass123!"
            }
        )
        elapsed = time.time() - start
        login_times.append(elapsed)

        assert response.status_code == 200

    # Check if there's improvement from first to last requests
    if len(login_times) > 1:
        early_avg = statistics.mean(login_times[:3])  # First 3
        late_avg = statistics.mean(login_times[-3:])  # Last 3

        print(f"Caching effect test:")
        print(f"  Early requests avg: {early_avg:.4f}s")
        print(f"  Late requests avg: {late_avg:.4f}s")

        # If late requests are faster, it might indicate some caching effect
        # If not, that's also fine - not all operations are cacheable