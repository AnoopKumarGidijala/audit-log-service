from app.db.models import AuditEvent
from app.db.session import SessionLocal
from app.services.hashing import compute_event_hash


def _create_event(client, auth_headers, **overrides):
    body = {
        "eventType": "USER_LOGIN",
        "actorId": "user-1",
        "resourceType": "SESSION",
        "resourceId": "sess-1",
        "payload": {"ip": "127.0.0.1"},
    }
    body.update(overrides)
    response = client.post("/audit/events", json=body, headers=auth_headers)
    assert response.status_code == 201
    return response.json()


def _tamper_content(event_id, **field_overrides):
    """Modify a stored event directly in Postgres, bypassing the API - this
    is what "outside the normal application write flow" means for these
    tests: there is no update endpoint, so tampering has to go straight at
    the database, exactly like the tamper-detection demo in the
    requirements."""
    db = SessionLocal()
    try:
        record = db.get(AuditEvent, event_id)
        for field, value in field_overrides.items():
            setattr(record, field, value)
        db.commit()
    finally:
        db.close()


def test_verify_requires_auth(client):
    response = client.get("/audit/verify")

    assert response.status_code == 401


def test_verify_empty_chain_is_intact(client, auth_headers):
    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is True
    assert body["recordsChecked"] == 0
    assert body["violation"] is None


def test_verify_valid_chain_is_intact(client, auth_headers):
    for i in range(4):
        _create_event(client, auth_headers, actorId=f"user-{i}")

    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is True
    assert body["recordsChecked"] == 4
    assert body["violation"] is None


def test_verify_detects_content_tampering(client, auth_headers):
    events = [_create_event(client, auth_headers, actorId=f"user-{i}") for i in range(3)]
    tampered_id = events[1]["id"]

    # Change the record's content directly in Postgres without touching its
    # stored hashes - a recompute from the (now different) content will no
    # longer match the stored event_hash.
    _tamper_content(tampered_id, actor_id="attacker")

    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is False
    assert body["recordsChecked"] == 2
    assert body["violation"]["recordId"] == tampered_id
    assert body["violation"]["violationType"] == "EVENT_HASH_MISMATCH"


def test_verify_detects_broken_link(client, auth_headers):
    events = [_create_event(client, auth_headers, actorId=f"user-{i}") for i in range(3)]
    target_id = events[1]["id"]

    db = SessionLocal()
    try:
        record = db.get(AuditEvent, target_id)
        forged_previous_hash = "1" * 64  # does not match record 0's real event_hash
        # Recompute event_hash (reusing the same hashing helper the service
        # uses) so it's internally consistent with the forged previous_hash.
        # This isolates the previous_hash check: record 1 passes the
        # event_hash check on its own but still doesn't correctly point at
        # record 0.
        record.previous_hash = forged_previous_hash
        record.event_hash = compute_event_hash(
            tenant_id=record.tenant_id,
            event_type=record.event_type,
            actor_id=record.actor_id,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            payload=record.payload,
            timestamp=record.timestamp,
            previous_hash=forged_previous_hash,
        )
        db.commit()
    finally:
        db.close()

    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is False
    assert body["recordsChecked"] == 2
    assert body["violation"]["recordId"] == target_id
    assert body["violation"]["violationType"] == "PREVIOUS_HASH_MISMATCH"


def test_verify_stops_at_first_inconsistency(client, auth_headers):
    events = [_create_event(client, auth_headers, actorId=f"user-{i}") for i in range(4)]

    # Tamper with both record 1 and record 2; verification should stop at
    # record 1 and never even examine record 2.
    _tamper_content(events[1]["id"], actor_id="attacker-1")
    _tamper_content(events[2]["id"], actor_id="attacker-2")

    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is False
    assert body["recordsChecked"] == 2
    assert body["violation"]["recordId"] == events[1]["id"]
