"""Tests for the global unexpected-exception handler (see
docs/security-logging-design.md §4) - a genuinely unhandled error must
never leak its type, message, or traceback to the client, while the full
detail must still be visible server-side. Also confirms the new
catch-all handler doesn't interfere with existing, intentional error
responses (404/422/etc.), which are handled separately and never reach it.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from app.core.error_handling import SAFE_ERROR_DETAIL
from app.core.rate_limit import enforce_login_rate_limit, enforce_sensitive_endpoint_rate_limit
from app.main import app
from app.services import chain_verification_service


@pytest.fixture
def error_client():
    """A TestClient with raise_server_exceptions=False.

    The shared `client` fixture (conftest.py) leaves this at its default
    of True, so a genuine bug elsewhere in the suite surfaces immediately
    as a failing test with a real traceback, not a silently "passing" 500
    response. This file specifically needs the opposite: Starlette's
    ServerErrorMiddleware re-raises the original exception after handing
    it to a registered handler (so tools like an error tracker can still
    see it) - with the default TestClient settings that re-raise would
    surface in the test itself, before ever letting us inspect the actual
    HTTP response our handler produced. Rate-limit dependencies are
    overridden the same way the shared `client` fixture does, since this
    is a separate TestClient instance that wouldn't otherwise get that
    protection.
    """
    app.dependency_overrides[enforce_login_rate_limit] = lambda: None
    app.dependency_overrides[enforce_sensitive_endpoint_rate_limit] = lambda: None
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(enforce_login_rate_limit, None)
    app.dependency_overrides.pop(enforce_sensitive_endpoint_rate_limit, None)


def test_unexpected_exception_returns_a_safe_generic_response(error_client, admin_headers, monkeypatch):
    def _boom(db):
        raise RuntimeError("boom: connection string had password=hunter2 embedded")

    monkeypatch.setattr(chain_verification_service, "verify_chain", _boom)

    response = error_client.get("/audit/verify", headers=admin_headers)

    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == SAFE_ERROR_DETAIL
    assert "correlationId" in body
    # Nothing about the real exception reaches the client.
    assert "boom" not in response.text
    assert "RuntimeError" not in response.text
    assert "hunter2" not in response.text
    assert "Traceback" not in response.text


def test_unexpected_exception_still_logs_full_diagnostic_detail_server_side(
    error_client, admin_headers, monkeypatch, caplog
):
    def _boom(db):
        raise RuntimeError("boom: something specific went wrong")

    monkeypatch.setattr(chain_verification_service, "verify_chain", _boom)

    caplog.set_level(logging.ERROR, logger="audit_log_service")
    response = error_client.get("/audit/verify", headers=admin_headers)

    assert response.status_code == 500
    matches = [r for r in caplog.records if getattr(r, "event", None) == "unhandled_exception"]
    assert len(matches) == 1
    assert matches[0].exception_type == "RuntimeError"
    assert "something specific went wrong" in matches[0].exception_message
    assert matches[0].path == "/audit/verify"
    assert matches[0].levelno == logging.ERROR


def test_response_correlation_id_matches_the_logged_one(error_client, admin_headers, monkeypatch, caplog):
    def _boom(db):
        raise RuntimeError("boom")

    monkeypatch.setattr(chain_verification_service, "verify_chain", _boom)

    caplog.set_level(logging.ERROR, logger="audit_log_service")
    response = error_client.get(
        "/audit/verify", headers={**admin_headers, "X-Request-ID": "known-trace-id"}
    )

    assert response.json()["correlationId"] == "known-trace-id"
    assert response.headers["X-Request-ID"] == "known-trace-id"
    matches = [r for r in caplog.records if getattr(r, "event", None) == "unhandled_exception"]
    assert matches[0].correlation_id == "known-trace-id"


# --- existing intentional error responses are unaffected ---------------------------


def test_404_from_a_missing_event_is_unaffected(client, admin_headers):
    response = client.post(
        "/audit/events/999999/redact", json={"fields": ["x"]}, headers=admin_headers
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_422_validation_error_is_unaffected(client, admin_headers):
    response = client.post(
        "/audit/events",
        json={"eventType": "", "actorId": "u", "resourceType": "SESSION", "resourceId": "r", "payload": {}},
        headers=admin_headers,
    )

    assert response.status_code == 422


def test_401_missing_auth_is_unaffected(client):
    response = client.get("/audit/verify")

    assert response.status_code == 401
