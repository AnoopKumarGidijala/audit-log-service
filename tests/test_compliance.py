from datetime import datetime, timedelta, timezone

from app.db.models import AuditEvent
from app.db.session import SessionLocal
from app.services import retention_service


def _create_event(client, auth_headers, **overrides):
    body = {
        "eventType": "ACCOUNT_VIEWED",
        "actorId": "user-1",
        "resourceType": "ACCOUNT",
        "resourceId": "acct-1",
        "payload": {"accountNumber": "1234567890"},
    }
    body.update(overrides)
    response = client.post("/audit/events", json=body, headers=auth_headers)
    assert response.status_code == 201
    return response.json()


def _report(client, auth_headers, **params):
    return client.get("/audit/compliance/account-access", params=params, headers=auth_headers)


def _set_timestamp(event_id, ts):
    db = SessionLocal()
    try:
        event = db.get(AuditEvent, event_id)
        event.timestamp = ts
        db.commit()
    finally:
        db.close()


def test_compliance_report_requires_auth(client):
    response = client.get("/audit/compliance/account-access")

    assert response.status_code == 401


def test_compliance_report_includes_account_access_events(client, auth_headers):
    event = _create_event(client, auth_headers, actorId="user-1", resourceId="acct-1")

    response = _report(client, auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["resourceType"] == "ACCOUNT"
    assert body["recordCount"] == 1
    assert [record["id"] for record in body["records"]] == [event["id"]]


def test_compliance_report_excludes_unrelated_resource_types(client, auth_headers):
    account_event = _create_event(client, auth_headers, resourceType="ACCOUNT", resourceId="acct-1")
    _create_event(client, auth_headers, resourceType="SESSION", resourceId="sess-1")

    response = _report(client, auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert [record["id"] for record in body["records"]] == [account_event["id"]]


def test_compliance_report_filters_by_resource_id(client, auth_headers):
    a = _create_event(client, auth_headers, resourceId="acct-1")
    _create_event(client, auth_headers, resourceId="acct-2")

    response = _report(client, auth_headers, resourceId="acct-1")

    assert response.status_code == 200
    body = response.json()
    assert [record["id"] for record in body["records"]] == [a["id"]]
    assert body["filter"]["resourceId"] == "acct-1"


def test_compliance_report_filters_by_actor_id(client, auth_headers):
    a = _create_event(client, auth_headers, actorId="user-1")
    _create_event(client, auth_headers, actorId="user-2")

    response = _report(client, auth_headers, actorId="user-1")

    assert response.status_code == 200
    body = response.json()
    assert [record["id"] for record in body["records"]] == [a["id"]]
    assert body["filter"]["actorId"] == "user-1"


def test_compliance_report_filters_by_time_range(client, auth_headers):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    a = _create_event(client, auth_headers)
    b = _create_event(client, auth_headers)
    c = _create_event(client, auth_headers)
    _set_timestamp(a["id"], base)
    _set_timestamp(b["id"], base + timedelta(days=1))
    _set_timestamp(c["id"], base + timedelta(days=2))

    response = _report(
        client,
        auth_headers,
        **{"from": (base + timedelta(hours=12)).isoformat(), "to": (base + timedelta(days=1, hours=12)).isoformat()},
    )

    assert response.status_code == 200
    body = response.json()
    assert [record["id"] for record in body["records"]] == [b["id"]]


def test_compliance_report_naive_from_is_rejected(client, auth_headers):
    response = _report(client, auth_headers, **{"from": "2026-01-01T00:00:00"})

    assert response.status_code == 422


def test_compliance_report_from_after_to_is_rejected(client, auth_headers):
    response = _report(
        client,
        auth_headers,
        **{"from": "2026-01-02T00:00:00Z", "to": "2026-01-01T00:00:00Z"},
    )

    assert response.status_code == 422


def test_compliance_report_blank_filter_value_is_rejected(client, auth_headers):
    response = _report(client, auth_headers, actorId="")

    assert response.status_code == 422


def test_compliance_report_empty_when_no_matches(client, auth_headers):
    response = _report(client, auth_headers, actorId="no-such-user")

    assert response.status_code == 200
    body = response.json()
    assert body["recordCount"] == 0
    assert body["records"] == []


def test_compliance_report_includes_archived_records(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_event = _create_event(client, auth_headers, actorId="user-1")
    new_event = _create_event(client, auth_headers, actorId="user-1")
    _set_timestamp(old_event["id"], now - timedelta(days=100))

    db = SessionLocal()
    try:
        result = retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()
    assert result.archived_count == 1

    response = _report(client, auth_headers, actorId="user-1")

    assert response.status_code == 200
    body = response.json()
    ids = [record["id"] for record in body["records"]]
    assert old_event["id"] in ids
    assert new_event["id"] in ids
    archived_record = next(r for r in body["records"] if r["id"] == old_event["id"])
    assert archived_record["archivedAt"] is not None


def test_compliance_report_redacted_field_stays_redacted(client, auth_headers):
    event = _create_event(client, auth_headers, actorId="user-1")
    redact_response = client.post(
        f"/audit/events/{event['id']}/redact",
        json={"fields": ["accountNumber"]},
        headers=auth_headers,
    )
    assert redact_response.status_code == 200

    response = _report(client, auth_headers, actorId="user-1")

    assert response.status_code == 200
    body = response.json()
    record = next(r for r in body["records"] if r["id"] == event["id"])
    assert record["payload"]["accountNumber"] == "[REDACTED]"
    assert "1234567890" not in str(body)
    assert record["redactedFields"] == ["accountNumber"]
