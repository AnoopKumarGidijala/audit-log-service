"""Authentication hardening tests (see docs/auth-hardening-design.md).

Covers the password-hashing switch and the JWT hardening (fixed algorithm,
issuer/audience validation, expiry) added on top of the prototype JWT auth
already covered by tests/test_auth.py. Tokens for the negative cases here
are hand-forged with PyJWT directly (not via /auth/token) so each test
isolates exactly one thing going wrong.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.core.passwords import hash_password, verify_password
from app.core.roles import Role
from app.core.security import JWT_ALGORITHM

_ADMIN = next(u for u in settings.auth_users if u.role == Role.ADMIN)
_SEED_PASSWORD = "test-password"

# A protected endpoint used purely to exercise the authentication layer -
# any role-gated route would do, since every failure mode tested here is
# rejected before a role is ever checked.
_PROTECTED_PATH = "/audit/events"


# --- password hashing (unit level) ------------------------------------------


def test_hash_password_does_not_store_plaintext():
    hashed = hash_password("correct horse battery staple")

    assert hashed != "correct horse battery staple"
    assert hashed.startswith("$argon2id$")


def test_verify_password_accepts_correct_password():
    hashed = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", hashed) is True


def test_verify_password_rejects_incorrect_password():
    hashed = hash_password("correct horse battery staple")

    assert verify_password("wrong password", hashed) is False


# --- correct / incorrect password, via the real login endpoint -------------


def test_login_with_correct_password_succeeds(client):
    response = client.post("/auth/token", data={"username": _ADMIN.username, "password": _SEED_PASSWORD})

    assert response.status_code == 200
    assert response.json()["access_token"]


def test_login_with_incorrect_password_is_rejected(client):
    response = client.post("/auth/token", data={"username": _ADMIN.username, "password": "not-the-password"})

    assert response.status_code == 401
    # Same generic message as an unknown username (test_auth.py's
    # test_login_unknown_username) - nothing here reveals which of the
    # two actually happened, or any hashing/verification detail.
    detail = response.json()["detail"].lower()
    assert detail == "incorrect username or password"
    assert "hash" not in detail
    assert "argon2" not in detail


# --- missing token -----------------------------------------------------------


def test_missing_token_is_rejected(client):
    response = client.get(_PROTECTED_PATH)

    assert response.status_code == 401


# --- malformed token ----------------------------------------------------------


def test_malformed_token_is_rejected(client):
    response = client.get(_PROTECTED_PATH, headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401


# --- expired token -------------------------------------------------------------


def test_expired_token_is_rejected(client):
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    token = jwt.encode(
        {
            "sub": _ADMIN.username,
            "role": _ADMIN.role.value,
            "tenantId": _ADMIN.tenant_id,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": past - timedelta(minutes=30),
            "exp": past,
        },
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )

    response = client.get(_PROTECTED_PATH, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


# --- invalid signature ---------------------------------------------------------


def test_invalid_signature_is_rejected(client):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": _ADMIN.username,
            "role": _ADMIN.role.value,
            "tenantId": _ADMIN.tenant_id,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        "a-completely-different-signing-key-not-the-real-one",
        algorithm=JWT_ALGORITHM,
    )

    response = client.get(_PROTECTED_PATH, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


# --- wrong issuer / wrong audience ----------------------------------------------


def test_wrong_issuer_is_rejected(client):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": _ADMIN.username,
            "role": _ADMIN.role.value,
            "tenantId": _ADMIN.tenant_id,
            "iss": "some-other-service",
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )

    response = client.get(_PROTECTED_PATH, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_wrong_audience_is_rejected(client):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": _ADMIN.username,
            "role": _ADMIN.role.value,
            "tenantId": _ADMIN.tenant_id,
            "iss": settings.jwt_issuer,
            "aud": "some-other-clients",
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )

    response = client.get(_PROTECTED_PATH, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


# --- unexpected algorithm -------------------------------------------------------


def test_unexpected_algorithm_is_rejected(client):
    """A token that is otherwise well-formed and signed with the real
    secret key, but using a different algorithm than the service issues
    (and accepts) - must be rejected outright, not accepted just because
    the key material matches."""
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": _ADMIN.username,
            "role": _ADMIN.role.value,
            "tenantId": _ADMIN.tenant_id,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        settings.secret_key,
        algorithm="HS384",
    )

    response = client.get(_PROTECTED_PATH, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


# --- well-signed token, but with a payload that no longer makes sense ----------


def test_token_with_unknown_role_is_rejected(client):
    """Properly signed, right issuer/audience, not expired - but claiming a
    role that isn't one of the four the service knows about (e.g. because
    AUTH_USERS was edited to remove a role the token was issued for).
    Authorization has no chance to reject this on its own terms, since
    require_roles() never even runs - it's authentication's job to refuse
    a token it can't map to a real identity."""
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": _ADMIN.username,
            "role": "superuser",
            "tenantId": _ADMIN.tenant_id,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )

    response = client.get(_PROTECTED_PATH, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_token_missing_role_claim_is_rejected(client):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": _ADMIN.username,
            "tenantId": _ADMIN.tenant_id,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )

    response = client.get(_PROTECTED_PATH, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


# --- startup: weak/default signing secrets are rejected ------------------------


@pytest.mark.parametrize(
    "bad_secret",
    [
        "short",  # below the minimum length
        "change-me-to-a-random-secret",  # the exact .env.example placeholder
        "secret",
        "password",
    ],
)
def test_settings_rejects_weak_secret_key(bad_secret):
    with pytest.raises(ValidationError):
        Settings(secret_key=bad_secret)


def test_settings_accepts_a_sufficiently_long_random_secret_key():
    # Doesn't raise - other required fields are still sourced from the
    # real .env, same as every other Settings() call in this suite.
    Settings(secret_key="a" * 32 + "-genuinely-long-enough-value")
