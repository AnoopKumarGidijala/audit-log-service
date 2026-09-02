import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.config import settings
from app.core.roles import Role
from app.db.base import Base
from app.db.session import engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def _create_tables():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture(autouse=True)
def _clean_audit_events():
    yield
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE audit_events RESTART IDENTITY"))


@pytest.fixture
def client():
    return TestClient(app)


# AUTH_USERS in .env stores only Argon2 password hashes (see
# app/core/passwords.py) - the plaintext is not recoverable from
# settings.auth_users, so tests that need to log in as a seeded user have
# to know the raw password out of band. Every seed user in .env shares this
# one password; if .env changes, this must change with it.
_SEED_PASSWORD = "local_dev_password"


def _headers_for_username(client, username: str) -> dict:
    user = next(u for u in settings.auth_users if u.username == username)
    response = client.post("/auth/token", data={"username": user.username, "password": _SEED_PASSWORD})
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _headers_for_role(client, role: Role) -> dict:
    user = next(u for u in settings.auth_users if u.role == role)
    return _headers_for_username(client, user.username)


@pytest.fixture
def auth_headers(client):
    """Admin credentials. Admin can perform every operation (see
    docs/authorization-design.md), so this fixture is kept as the default
    for every pre-existing test that isn't specifically about
    authorization - none of them need to change role just because roles
    now exist.
    """
    return _headers_for_role(client, Role.ADMIN)


@pytest.fixture
def writer_headers(client):
    """A writer in tenant-a."""
    return _headers_for_username(client, "writer")


@pytest.fixture
def reader_headers(client):
    """A reader in tenant-a."""
    return _headers_for_username(client, "reader")


@pytest.fixture
def writer_headers_b(client):
    """A writer in a second tenant, tenant-b - for cross-tenant tests."""
    return _headers_for_username(client, "writer-b")


@pytest.fixture
def reader_headers_b(client):
    """A reader in a second tenant, tenant-b - for cross-tenant tests."""
    return _headers_for_username(client, "reader-b")


@pytest.fixture
def auditor_headers(client):
    """An auditor - no tenant, reads span every tenant."""
    return _headers_for_role(client, Role.AUDITOR)


@pytest.fixture
def admin_headers(client):
    return _headers_for_role(client, Role.ADMIN)


@pytest.fixture
def writer_headers_no_tenant(client):
    """A writer with no tenant configured - a misconfiguration case used to
    test that writes are rejected rather than silently stamped with an
    empty/blank tenant."""
    return _headers_for_username(client, "writer-no-tenant")


@pytest.fixture
def reader_headers_no_tenant(client):
    """A reader with no tenant configured - the mirror case for reads."""
    return _headers_for_username(client, "reader-no-tenant")
