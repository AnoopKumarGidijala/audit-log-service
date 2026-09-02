"""Tests for the two health endpoints (see app/api/routes/health.py):
liveness must never depend on the database, readiness must actually
detect a database that can't be reached, without leaking any raw
driver/DB error detail to the client.
"""

from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_db
from app.main import app


def test_liveness_reports_ok(client):
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_liveness_requires_no_authentication(client):
    """No Authorization header at all - a load balancer/uptime check has
    no credentials."""
    response = client.get("/health/live")

    assert response.status_code == 200


def test_readiness_reports_ok_when_the_database_is_reachable(client):
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "reachable"}


def test_readiness_reports_503_when_the_database_is_unreachable(client):
    class _FailingSession:
        def execute(self, *args, **kwargs):
            raise SQLAlchemyError("simulated: connection to server failed")

        def close(self):
            pass

    def _failing_get_db():
        yield _FailingSession()

    app.dependency_overrides[get_db] = _failing_get_db
    try:
        response = client.get("/health/ready")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    body = response.json()
    assert body == {"status": "unavailable", "database": "unreachable"}
    # No raw driver/DB error text reaches the client.
    assert "simulated" not in response.text
    assert "SQLAlchemyError" not in response.text
