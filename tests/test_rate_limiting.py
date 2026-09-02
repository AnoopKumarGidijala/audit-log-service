"""Tests for the real rate-limiting behavior (see
docs/defensive-limits-design.md and app/core/rate_limit.py).

Deliberately does NOT use the shared `client` fixture from conftest.py -
that fixture overrides both rate-limit dependencies to no-ops precisely
so the rest of the suite isn't affected by them. This file uses its own
`real_client` fixture (a plain TestClient with no overrides) and resets
the process-wide limiter singletons before every test, so each test here
starts from a clean budget.
"""

import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.rate_limit import InMemoryRateLimiter, login_rate_limiter, sensitive_endpoint_rate_limiter
from app.main import app

_SEED_PASSWORD = "test-password"  # matches conftest.py's _SEED_PASSWORD


# --- InMemoryRateLimiter unit test (its own instance, not a singleton) ---------


def test_in_memory_rate_limiter_slides_the_window():
    """A short, deliberately isolated window (not one of the app's real
    singletons) to prove the limiter actually forgets old attempts once
    they age out, rather than accumulating forever."""
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=0.05)

    assert limiter.check("key") is True
    assert limiter.check("key") is False  # immediately over budget

    time.sleep(0.1)

    assert limiter.check("key") is True  # the earlier hit has aged out


@pytest.fixture
def real_client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    login_rate_limiter.reset()
    sensitive_endpoint_rate_limiter.reset()
    yield


def _login(real_client, username: str) -> dict:
    response = real_client.post("/auth/token", data={"username": username, "password": _SEED_PASSWORD})
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# --- login rate limiting --------------------------------------------------------


def test_login_attempts_within_the_limit_all_succeed(real_client):
    for _ in range(settings.login_rate_limit_max_attempts):
        response = real_client.post(
            "/auth/token", data={"username": "admin", "password": _SEED_PASSWORD}
        )
        assert response.status_code == 200


def test_login_attempts_exceeding_the_limit_are_rejected_with_429(real_client):
    for _ in range(settings.login_rate_limit_max_attempts):
        response = real_client.post(
            "/auth/token", data={"username": "admin", "password": _SEED_PASSWORD}
        )
        assert response.status_code == 200

    one_too_many = real_client.post(
        "/auth/token", data={"username": "admin", "password": _SEED_PASSWORD}
    )

    assert one_too_many.status_code == 429


def test_login_rate_limit_counts_failed_attempts_too(real_client):
    """Every attempt counts against the limit, not just successful ones -
    otherwise the limit wouldn't actually bound brute-force guessing."""
    for _ in range(settings.login_rate_limit_max_attempts):
        response = real_client.post(
            "/auth/token", data={"username": "admin", "password": "wrong-password"}
        )
        assert response.status_code == 401

    one_too_many = real_client.post(
        "/auth/token", data={"username": "admin", "password": "wrong-password"}
    )

    assert one_too_many.status_code == 429


# --- sensitive-endpoint rate limiting --------------------------------------------


def test_sensitive_endpoint_requests_within_the_limit_all_succeed(real_client):
    headers = _login(real_client, "admin")

    for _ in range(settings.sensitive_rate_limit_max_requests):
        response = real_client.get("/audit/verify", headers=headers)
        assert response.status_code == 200


def test_sensitive_endpoint_requests_exceeding_the_limit_are_rejected_with_429(real_client):
    headers = _login(real_client, "admin")

    for _ in range(settings.sensitive_rate_limit_max_requests):
        response = real_client.get("/audit/verify", headers=headers)
        assert response.status_code == 200

    one_too_many = real_client.get("/audit/verify", headers=headers)

    assert one_too_many.status_code == 429


def test_sensitive_endpoint_rate_limit_is_shared_across_its_endpoints_for_one_caller(real_client):
    """The limiter is keyed by caller, not by which of the three sensitive
    endpoints was called - hammering a mix of them exhausts the same
    budget just as hammering one of them alone would."""
    headers = _login(real_client, "admin")

    for _ in range(settings.sensitive_rate_limit_max_requests):
        response = real_client.get("/audit/verify", headers=headers)
        assert response.status_code == 200

    exports_response = real_client.get("/audit/export", params={"actorId": "someone"}, headers=headers)

    assert exports_response.status_code == 429


def test_sensitive_endpoint_rate_limit_is_scoped_per_caller(real_client):
    """A different authenticated caller has their own, independent budget
    - one caller exhausting theirs doesn't affect another."""
    admin_headers = _login(real_client, "admin")
    auditor_headers = _login(real_client, "auditor")

    for _ in range(settings.sensitive_rate_limit_max_requests):
        response = real_client.get("/audit/verify", headers=admin_headers)
        assert response.status_code == 200
    admin_next = real_client.get("/audit/verify", headers=admin_headers)
    assert admin_next.status_code == 429

    # auditor's own budget is untouched by admin's usage.
    auditor_response = real_client.get("/audit/verify", headers=auditor_headers)
    assert auditor_response.status_code == 200
