from app.db.models import AuditEvent
from app.db.session import SessionLocal
from app.services.hashing import GENESIS_HASH, compute_event_hash


def _valid_event(**overrides):
    event = {
        "eventType": "USER_LOGIN",
        "actorId": "user-1",
        "resourceType": "SESSION",
        "resourceId": "sess-1",
        "payload": {"ip": "127.0.0.1"},
    }
    event.update(overrides)
    return event


def test_create_audit_event_success(client, auth_headers):
    response = client.post("/audit/events", json=_valid_event(), headers=auth_headers)

    assert response.status_code == 201
    body = response.json()
    assert body["eventType"] == "USER_LOGIN"
    assert body["actorId"] == "user-1"
    assert body["resourceType"] == "SESSION"
    assert body["resourceId"] == "sess-1"
    assert body["payload"] == {"ip": "127.0.0.1"}
    assert body["previousHash"] == GENESIS_HASH
    assert len(body["eventHash"]) == 64
    assert "id" in body and "timestamp" in body


def test_missing_required_field_returns_422(client, auth_headers):
    event = _valid_event()
    del event["eventType"]

    response = client.post("/audit/events", json=event, headers=auth_headers)

    assert response.status_code == 422


def test_missing_payload_returns_422(client, auth_headers):
    event = _valid_event()
    del event["payload"]

    response = client.post("/audit/events", json=event, headers=auth_headers)

    assert response.status_code == 422


def test_hash_chain_stored_values(client, auth_headers):
    client.post("/audit/events", json=_valid_event(), headers=auth_headers)
    client.post("/audit/events", json=_valid_event(actorId="user-2"), headers=auth_headers)

    db = SessionLocal()
    try:
        events = db.query(AuditEvent).order_by(AuditEvent.id).all()
    finally:
        db.close()

    assert len(events) == 2
    first, second = events

    # Chain linkage: first uses the genesis value, second points at first.
    assert first.previous_hash == GENESIS_HASH
    assert second.previous_hash == first.event_hash

    # Recompute each stored event's hash independently from its stored
    # fields to confirm the stored event_hash is reproducible - this is
    # exactly what the future verify endpoint will need to do.
    for event in (first, second):
        expected_hash = compute_event_hash(
            event_type=event.event_type,
            actor_id=event.actor_id,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            payload=event.payload,
            timestamp=event.timestamp,
            previous_hash=event.previous_hash,
        )
        assert expected_hash == event.event_hash
