from datetime import datetime, timezone

from app.db.models import AuditEvent
from app.db.session import SessionLocal
from app.services.hashing import hash_field_value


def _create_event(client, auth_headers, **overrides):
    body = {
        "eventType": "USER_LOGIN",
        "actorId": "user-1",
        "resourceType": "SESSION",
        "resourceId": "sess-1",
        "payload": {"accountNumber": "1234567890", "ip": "127.0.0.1"},
    }
    body.update(overrides)
    response = client.post("/audit/events", json=body, headers=auth_headers)
    assert response.status_code == 201
    return response.json()


def _get_stored(event_id):
    db = SessionLocal()
    try:
        return db.get(AuditEvent, event_id)
    finally:
        db.close()


def _redact(client, auth_headers, event_id, fields, **overrides):
    body = {"fields": fields}
    body.update(overrides)
    return client.post(f"/audit/events/{event_id}/redact", json=body, headers=auth_headers)


def test_redact_requires_auth(client):
    response = client.post("/audit/events/1/redact", json={"fields": ["accountNumber"]})

    assert response.status_code == 401


def test_redact_nonexistent_event_returns_404(client, auth_headers):
    response = _redact(client, auth_headers, 999999, ["accountNumber"])

    assert response.status_code == 404


def test_redact_no_matching_fields_returns_422(client, auth_headers):
    event = _create_event(client, auth_headers)

    response = _redact(client, auth_headers, event["id"], ["fieldThatDoesNotExist"])

    assert response.status_code == 422


def test_redact_replaces_field_and_keeps_other_fields(client, auth_headers):
    event = _create_event(client, auth_headers)

    response = _redact(client, auth_headers, event["id"], ["accountNumber"])

    assert response.status_code == 200
    body = response.json()
    assert body["eventId"] == event["id"]
    assert body["newlyRedactedFields"] == ["accountNumber"]
    assert body["redactedFields"] == ["accountNumber"]
    assert "redactedAt" in body
    assert "redactionEventId" in body

    stored = _get_stored(event["id"])
    assert stored.payload["accountNumber"] == "[REDACTED]"
    assert stored.payload["ip"] == "127.0.0.1"  # untouched


def test_redact_does_not_change_event_hash_or_previous_hash(client, auth_headers):
    event = _create_event(client, auth_headers)
    original_hash = event["eventHash"]
    original_previous_hash = event["previousHash"]

    _redact(client, auth_headers, event["id"], ["accountNumber"])

    stored = _get_stored(event["id"])
    assert stored.event_hash == original_hash
    assert stored.previous_hash == original_previous_hash


def test_redact_stores_original_field_hash(client, auth_headers):
    event = _create_event(client, auth_headers)

    _redact(client, auth_headers, event["id"], ["accountNumber"])

    stored = _get_stored(event["id"])
    assert stored.redacted_field_hashes["accountNumber"] == hash_field_value("1234567890")


def test_redact_appends_companion_audit_event(client, auth_headers):
    event = _create_event(client, auth_headers)

    response = _redact(client, auth_headers, event["id"], ["accountNumber"], reason="customer request")
    redaction_event_id = response.json()["redactionEventId"]

    list_response = client.get(
        "/audit/events",
        params={"resourceType": "AUDIT_EVENT", "resourceId": str(event["id"])},
        headers=auth_headers,
    )
    assert list_response.status_code == 200
    matches = list_response.json()
    assert len(matches) == 1
    companion = matches[0]
    assert companion["id"] == redaction_event_id
    assert companion["eventType"] == "AUDIT_EVENT_REDACTED"
    assert companion["payload"]["targetEventId"] == event["id"]
    assert companion["payload"]["redactedFields"] == ["accountNumber"]
    assert companion["payload"]["reason"] == "customer request"
    # the commitment travelling in the companion event's payload is what
    # verification later checks the record's current content against
    assert companion["payload"]["redactedContentHash"] == response.json()["redactedContentHash"]


def test_redact_mixed_present_and_absent_fields_only_redacts_present_ones(client, auth_headers):
    event = _create_event(client, auth_headers)

    response = _redact(client, auth_headers, event["id"], ["accountNumber", "doesNotExist"])

    assert response.status_code == 200
    assert response.json()["newlyRedactedFields"] == ["accountNumber"]


def test_redact_same_field_twice_does_not_corrupt_original_hash(client, auth_headers):
    """Re-requesting redaction of an already-redacted field must be a
    no-op for that field, not rehash the tombstone marker in place of the
    true original value."""
    event = _create_event(client, auth_headers)
    _redact(client, auth_headers, event["id"], ["accountNumber"])
    original_field_hash = _get_stored(event["id"]).redacted_field_hashes["accountNumber"]

    second_response = _redact(client, auth_headers, event["id"], ["accountNumber"])

    assert second_response.status_code == 422  # nothing new to redact
    stored = _get_stored(event["id"])
    assert stored.redacted_field_hashes["accountNumber"] == original_field_hash
    assert stored.payload["accountNumber"] == "[REDACTED]"


def test_redact_twice_with_different_fields_accumulates(client, auth_headers):
    event = _create_event(client, auth_headers)
    _redact(client, auth_headers, event["id"], ["accountNumber"])

    response = _redact(client, auth_headers, event["id"], ["ip"])

    assert response.status_code == 200
    body = response.json()
    assert body["newlyRedactedFields"] == ["ip"]
    assert body["redactedFields"] == ["accountNumber", "ip"]


# --- verification after redaction -------------------------------------------


def test_verify_remains_intact_after_redaction(client, auth_headers):
    events = [_create_event(client, auth_headers, actorId=f"user-{i}") for i in range(3)]
    _redact(client, auth_headers, events[1]["id"], ["accountNumber"])

    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is True
    # 3 original events + 1 companion redaction event
    assert body["recordsChecked"] == 4
    assert body["violation"] is None


def test_verify_still_detects_tampering_on_a_non_redacted_record(client, auth_headers):
    events = [_create_event(client, auth_headers, actorId=f"user-{i}") for i in range(3)]
    _redact(client, auth_headers, events[1]["id"], ["accountNumber"])

    db = SessionLocal()
    try:
        record = db.get(AuditEvent, events[2]["id"])
        record.actor_id = "attacker"
        db.commit()
    finally:
        db.close()

    response = client.get("/audit/verify", headers=auth_headers)

    body = response.json()
    assert body["intact"] is False
    assert body["violation"]["recordId"] == events[2]["id"]
    assert body["violation"]["violationType"] == "EVENT_HASH_MISMATCH"


def test_verify_detects_tampering_on_a_non_redacted_field_of_a_redacted_record(client, auth_headers):
    """The core property this design exists for: redacting one field must
    not blind verification to tampering with the record's OTHER fields."""
    event = _create_event(client, auth_headers)
    _redact(client, auth_headers, event["id"], ["accountNumber"])

    db = SessionLocal()
    try:
        record = db.get(AuditEvent, event["id"])
        record.actor_id = "attacker"  # untouched by the redaction itself
        db.commit()
    finally:
        db.close()

    response = client.get("/audit/verify", headers=auth_headers)

    body = response.json()
    assert body["intact"] is False
    assert body["violation"]["recordId"] == event["id"]
    assert body["violation"]["violationType"] == "REDACTED_CONTENT_MISMATCH"


def test_verify_detects_tampering_on_the_redacted_field_itself(client, auth_headers):
    """Changing the redacted field to something other than the approved
    marker (e.g. planting a fake "unredacted" value) must also be caught -
    only the exact, logged redaction is authorized."""
    event = _create_event(client, auth_headers)
    _redact(client, auth_headers, event["id"], ["accountNumber"])

    db = SessionLocal()
    try:
        record = db.get(AuditEvent, event["id"])
        record.payload = {**record.payload, "accountNumber": "0000000000"}
        db.commit()
    finally:
        db.close()

    response = client.get("/audit/verify", headers=auth_headers)

    body = response.json()
    assert body["intact"] is False
    assert body["violation"]["recordId"] == event["id"]
    assert body["violation"]["violationType"] == "REDACTED_CONTENT_MISMATCH"


def test_verify_detects_forged_redaction_flag_without_companion_event(client, auth_headers):
    """Setting redacted_at directly (bypassing the real redaction path, so
    no companion event/commitment exists) must be detected, not silently
    treated as a legitimately redacted record."""
    event = _create_event(client, auth_headers)

    db = SessionLocal()
    try:
        record = db.get(AuditEvent, event["id"])
        record.redacted_at = datetime.now(timezone.utc)
        record.redacted_fields = ["accountNumber"]
        db.commit()
    finally:
        db.close()

    response = client.get("/audit/verify", headers=auth_headers)

    body = response.json()
    assert body["intact"] is False
    assert body["violation"]["recordId"] == event["id"]
    assert body["violation"]["violationType"] == "REDACTION_COMMITMENT_MISSING"


def test_verify_detects_tampering_with_companion_event_commitment(client, auth_headers):
    """The commitment itself is only trustworthy because the companion
    event carrying it is an ordinary, fully hash-chain-protected event -
    tampering with it directly (without correctly recomputing its own
    event_hash to match) must still make the chain report intact=False.

    Note on attribution: verification walks in ascending id order and the
    target record (lower id) is always checked before its companion
    (appended later, higher id). A tampered companion's commitment is
    excluded rather than trusted (see
    chain_verification_service._latest_redaction_commitments), so this
    surfaces as REDACTION_COMMITMENT_MISSING at the *target* record, not
    as an EVENT_HASH_MISMATCH at the companion itself - the corruption is
    still caught, just reported at the first record the forward walk
    reaches, consistent with "stop at the first inconsistency" everywhere
    else in this service.
    """
    event = _create_event(client, auth_headers)
    response = _redact(client, auth_headers, event["id"], ["accountNumber"])
    companion_id = response.json()["redactionEventId"]

    db = SessionLocal()
    try:
        companion = db.get(AuditEvent, companion_id)
        companion.payload = {**companion.payload, "redactedContentHash": "0" * 64}
        db.commit()
    finally:
        db.close()

    verify_response = client.get("/audit/verify", headers=auth_headers)

    body = verify_response.json()
    assert body["intact"] is False
    assert body["violation"]["recordId"] == event["id"]
    assert body["violation"]["violationType"] == "REDACTION_COMMITMENT_MISSING"


def test_verify_intact_after_multiple_redactions_uses_latest_commitment(client, auth_headers):
    event = _create_event(client, auth_headers)
    _redact(client, auth_headers, event["id"], ["accountNumber"])
    _redact(client, auth_headers, event["id"], ["ip"])

    response = client.get("/audit/verify", headers=auth_headers)

    body = response.json()
    assert body["intact"] is True
    # 1 original event + 2 companion redaction events
    assert body["recordsChecked"] == 3
    assert body["violation"] is None
