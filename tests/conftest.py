import os

# Tests must never run against a developer's normal local database - they
# create tables and destructively truncate them after every test (see
# _clean_audit_events below). Setting this here, unconditionally, before
# anything imports app.core.config (which reads it to pick a dotenv file),
# means "just run pytest" always loads the dedicated test configuration
# (.env.test) - no environment variable to remember, no way to forget it.
# See the "Testing" section of README.md.
os.environ["ENV_FILE"] = ".env.test"

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.core.config import settings
from app.core.rate_limit import enforce_login_rate_limit, enforce_sensitive_endpoint_rate_limit
from app.core.roles import Role
from app.db.session import engine
from app.main import app

_ALEMBIC_INI_PATH = Path(__file__).resolve().parent.parent / "alembic.ini"


def _assert_using_a_test_database() -> None:
    """A second, independent safety net beyond the ENV_FILE override above:
    even if something else in the environment overrode ENV_FILE back to a
    real .env, refuse outright to run against a database whose name
    doesn't look like a dedicated test database. This suite is
    destructive (see _clean_audit_events), so getting this wrong would be
    real data loss, not just a wrong test result.
    """
    database_name = make_url(settings.database_url).database or ""
    if not database_name.endswith("_test"):
        raise RuntimeError(
            f"Refusing to run tests: DATABASE_URL points at {database_name!r}, which "
            "doesn't look like a dedicated test database (its name doesn't end in "
            "'_test'). The test suite creates and truncates tables destructively and "
            "must only run against the database provisioned by "
            "docker-compose.test.yml (see the 'Testing' section of README.md), not a "
            "developer's normal local database."
        )


_assert_using_a_test_database()


@pytest.fixture(scope="session", autouse=True)
def _create_tables():
    """Applies real Alembic migrations against the test database, the
    same mechanism (and the same migrations/versions/ files) used against
    a real deployment - not a shortcut like Base.metadata.create_all()
    (removed - see app/main.py). This means the test suite also serves as
    an ongoing check that the migrations actually apply cleanly and stay
    in sync with app/db/models.py; a genuine drift between them (someone
    changing a model without adding a migration) would surface here as a
    failure before any test even runs, not silently.

    Idempotent: alembic tracks applied revisions in its own
    alembic_version table, so re-running this against an already-migrated
    database (e.g. a test DB container reused across multiple local
    `pytest` invocations without a `docker compose down -v` in between) is
    a no-op, not an error.
    """
    alembic_cfg = Config(str(_ALEMBIC_INI_PATH))
    command.upgrade(alembic_cfg, "head")
    yield


@pytest.fixture(autouse=True)
def _clean_audit_events():
    yield
    with engine.begin() as conn:
        # audit_event_idempotency_keys has a FK to audit_events, so both
        # must be truncated together (or CASCADE) - truncating
        # audit_events alone fails with a FK-referenced-table error.
        conn.execute(text("TRUNCATE TABLE audit_events, audit_event_idempotency_keys RESTART IDENTITY"))


@pytest.fixture
def client():
    """A TestClient with the rate-limit dependencies overridden to no-ops.

    The rate limiters (app/core/rate_limit.py) are process-wide singletons
    that persist for the whole pytest session, not reset between tests -
    and Starlette's TestClient sends every request from the same fake
    client host, and most of this suite logs in and calls the
    sensitive-endpoint routes as the same handful of usernames (e.g.
    "admin") across dozens of tests. Without this override, unrelated
    tests would start failing with 429s once the real limits were
    exhausted, well before any test actually about rate limiting ran.
    tests/test_rate_limiting.py is the one place that needs (and uses) the
    real, non-overridden behavior - see its own `real_client` fixture.
    """
    app.dependency_overrides[enforce_login_rate_limit] = lambda: None
    app.dependency_overrides[enforce_sensitive_endpoint_rate_limit] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.pop(enforce_login_rate_limit, None)
    app.dependency_overrides.pop(enforce_sensitive_endpoint_rate_limit, None)


# AUTH_USERS in .env.test stores only Argon2 password hashes (see
# app/core/passwords.py) - the plaintext is not recoverable from
# settings.auth_users, so tests that need to log in as a seeded user have
# to know the raw password out of band. Every seed user in .env.test
# shares this one password; if .env.test changes, this must change with it.
_SEED_PASSWORD = "test-password"


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
