"""Tests that each security-sensitive operation actually emits its
structured log event (see docs/security-logging-design.md), and that the
correlation id is generated/propagated correctly. Uses pytest's `caplog`
fixture to inspect the raw LogRecord objects `app.core.security_logging`
produces - a structural check ("was this event logged, with these
fields") distinct from tests/test_log_sanitization.py's check of the
serialized, sanitized JSON output.

caplog's default capture level is WARNING; every test here that needs an
INFO-level event calls caplog.set_level(logging.INFO, logger="audit_log_service")
first.
"""

import logging

from app.core.correlation import CORRELATION_ID_HEADER


def _events(caplog, name: str):
    return [r for r in caplog.records if getattr(r, "event", None) == name]


# --- authentication --------------------------------------------------------------


def test_successful_login_is_logged(client, caplog):
    caplog.set_level(logging.INFO, logger="audit_log_service")

    response = client.post("/auth/token", data={"username": "writer", "password": "test-password"})

    assert response.status_code == 200
    matches = _events(caplog, "auth.login.success")
    assert len(matches) == 1
    assert matches[0].username == "writer"
    assert matches[0].role == "writer"
    assert matches[0].levelno == logging.INFO


def test_failed_login_is_logged(client, caplog):
    caplog.set_level(logging.WARNING, logger="audit_log_service")

    response = client.post("/auth/token", data={"username": "writer", "password": "wrong-password"})

    assert response.status_code == 401
    matches = _events(caplog, "auth.login.failure")
    assert len(matches) == 1
    assert matches[0].username == "writer"
    assert matches[0].levelno == logging.WARNING


# --- authorization -----------------------------------------------------------------


def test_authorization_denial_is_logged(client, reader_headers, caplog):
    caplog.set_level(logging.WARNING, logger="audit_log_service")

    response = client.get("/audit/verify", headers=reader_headers)

    assert response.status_code == 403
    matches = _events(caplog, "authz.denied")
    assert len(matches) == 1
    assert matches[0].role == "reader"
    assert matches[0].required_roles == ["auditor", "admin"]
    assert matches[0].path == "/audit/verify"


# --- retention / redaction / export / compliance ------------------------------------


def test_retention_execution_is_logged(client, admin_headers, caplog):
    caplog.set_level(logging.INFO, logger="audit_log_service")

    response = client.post("/audit/retention/apply", headers=admin_headers)

    assert response.status_code == 200
    matches = _events(caplog, "retention.applied")
    assert len(matches) == 1
    assert matches[0].requested_by == "admin"
    assert matches[0].archived_count == response.json()["archivedCount"]


def test_redaction_execution_is_logged(client, admin_headers, caplog):
    create_response = client.post(
        "/audit/events",
        json={
            "eventType": "USER_LOGIN",
            "actorId": "user-1",
            "resourceType": "SESSION",
            "resourceId": "sess-1",
            "payload": {"accountNumber": "1234567890"},
        },
        headers=admin_headers,
    )
    event_id = create_response.json()["id"]

    caplog.set_level(logging.INFO, logger="audit_log_service")
    response = client.post(
        f"/audit/events/{event_id}/redact", json={"fields": ["accountNumber"]}, headers=admin_headers
    )

    assert response.status_code == 200
    matches = _events(caplog, "redaction.applied")
    assert len(matches) == 1
    assert matches[0].redacted_by == "admin"
    assert matches[0].event_id == event_id
    assert matches[0].newly_redacted_fields == ["accountNumber"]
    # Only the field name, never the original value.
    assert "1234567890" not in repr(matches[0].__dict__)


def test_export_is_logged(client, admin_headers, caplog):
    client.post(
        "/audit/events",
        json={
            "eventType": "USER_LOGIN",
            "actorId": "export-log-user",
            "resourceType": "SESSION",
            "resourceId": "sess-1",
            "payload": {},
        },
        headers=admin_headers,
    )

    caplog.set_level(logging.INFO, logger="audit_log_service")
    response = client.get("/audit/export", params={"actorId": "export-log-user"}, headers=admin_headers)

    assert response.status_code == 200
    matches = _events(caplog, "export.performed")
    assert len(matches) == 1
    assert matches[0].requested_by == "admin"
    assert matches[0].actor_id == "export-log-user"
    assert matches[0].record_count == 1


def test_compliance_report_access_is_logged(client, admin_headers, caplog):
    caplog.set_level(logging.INFO, logger="audit_log_service")

    response = client.get("/audit/compliance/account-access", headers=admin_headers)

    assert response.status_code == 200
    matches = _events(caplog, "compliance.report_accessed")
    assert len(matches) == 1
    assert matches[0].requested_by == "admin"


# --- chain verification -------------------------------------------------------------


def test_chain_verification_failure_is_logged(client, admin_headers, caplog):
    from app.db.models import AuditEvent
    from app.db.session import SessionLocal

    create_response = client.post(
        "/audit/events",
        json={
            "eventType": "USER_LOGIN",
            "actorId": "user-1",
            "resourceType": "SESSION",
            "resourceId": "sess-1",
            "payload": {},
        },
        headers=admin_headers,
    )
    event_id = create_response.json()["id"]

    db = SessionLocal()
    try:
        record = db.get(AuditEvent, event_id)
        record.actor_id = "attacker"
        db.commit()
    finally:
        db.close()

    caplog.set_level(logging.ERROR, logger="audit_log_service")
    response = client.get("/audit/verify", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["intact"] is False
    matches = _events(caplog, "chain.verification_failed")
    assert len(matches) == 1
    assert matches[0].record_id == event_id
    assert matches[0].violation_type == "EVENT_HASH_MISMATCH"
    assert matches[0].levelno == logging.ERROR


def test_intact_chain_verification_is_not_logged(client, admin_headers, caplog):
    """Only failures are logged - a routine, intact check isn't a
    security event (see docs/security-logging-design.md §1)."""
    caplog.set_level(logging.INFO, logger="audit_log_service")

    response = client.get("/audit/verify", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["intact"] is True
    assert _events(caplog, "chain.verification_failed") == []


# --- correlation id --------------------------------------------------------------


def test_response_includes_a_correlation_id_header(client):
    response = client.get("/")

    assert CORRELATION_ID_HEADER in response.headers
    assert len(response.headers[CORRELATION_ID_HEADER]) > 0


def test_correlation_id_is_echoed_back_when_the_caller_supplies_one(client):
    response = client.get("/", headers={CORRELATION_ID_HEADER: "caller-supplied-id-123"})

    assert response.headers[CORRELATION_ID_HEADER] == "caller-supplied-id-123"


def test_correlation_id_differs_across_independent_requests(client):
    first = client.get("/")
    second = client.get("/")

    assert first.headers[CORRELATION_ID_HEADER] != second.headers[CORRELATION_ID_HEADER]


def test_logged_events_carry_the_requests_correlation_id(client, caplog):
    caplog.set_level(logging.WARNING, logger="audit_log_service")

    response = client.post(
        "/auth/token",
        data={"username": "writer", "password": "wrong-password"},
        headers={CORRELATION_ID_HEADER: "trace-me-123"},
    )

    assert response.status_code == 401
    matches = _events(caplog, "auth.login.failure")
    assert len(matches) == 1
    assert matches[0].correlation_id == "trace-me-123"
