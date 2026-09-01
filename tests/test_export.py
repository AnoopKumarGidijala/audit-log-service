from datetime import datetime, timedelta, timezone

from app.db.models import AuditEvent
from app.db.session import SessionLocal
from app.services import retention_service
from app.services.hashing import compute_event_hash, compute_manifest_hash


def _create_event(client, auth_headers, **overrides):
    body = {
        "eventType": "USER_LOGIN",
        "actorId": "user-1",
        "resourceType": "SESSION",
        "resourceId": "sess-1",
        "payload": {"accountNumber": "1234567890", "note": "hello"},
    }
    body.update(overrides)
    response = client.post("/audit/events", json=body, headers=auth_headers)
    assert response.status_code == 201
    return response.json()


def _export(client, auth_headers, **params):
    return client.get("/audit/export", params=params, headers=auth_headers)


def _verify_bundle_self_consistency(bundle: dict) -> bool:
    """The exact recipe documented in docs/export-design.md §4, performed
    using only the bundle's own JSON and the service's public hashing
    functions - no DB access."""
    for record in bundle["records"]:
        recomputed = compute_event_hash(
            event_type=record["eventType"],
            actor_id=record["actorId"],
            resource_type=record["resourceType"],
            resource_id=record["resourceId"],
            payload=record["payload"],
            timestamp=datetime.fromisoformat(record["timestamp"]),
            previous_hash=record["previousHash"],
        )
        if recomputed != record["eventHash"]:
            return False

    entries = [{"id": record["id"], "eventHash": record["eventHash"]} for record in bundle["records"]]
    return compute_manifest_hash(entries) == bundle["manifestHash"]


def test_export_requires_auth(client):
    response = client.get("/audit/export", params={"actorId": "user-1"})

    assert response.status_code == 401


def test_export_requires_a_filter(client, auth_headers):
    response = _export(client, auth_headers)

    assert response.status_code == 422


def test_export_rejects_blank_filter_value(client, auth_headers):
    response = _export(client, auth_headers, actorId="")

    assert response.status_code == 422


def test_export_by_actor_id(client, auth_headers):
    a = _create_event(client, auth_headers, actorId="user-1", resourceId="sess-1")
    b = _create_event(client, auth_headers, actorId="user-1", resourceId="sess-2")
    _create_event(client, auth_headers, actorId="user-2", resourceId="sess-3")

    response = _export(client, auth_headers, actorId="user-1")

    assert response.status_code == 200
    body = response.json()
    assert body["filter"] == {"actorId": "user-1", "resourceId": None}
    assert body["recordCount"] == 2
    assert [record["id"] for record in body["records"]] == [a["id"], b["id"]]


def test_export_by_resource_id(client, auth_headers):
    a = _create_event(client, auth_headers, actorId="user-1", resourceId="acct-1")
    _create_event(client, auth_headers, actorId="user-2", resourceId="acct-2")
    b = _create_event(client, auth_headers, actorId="user-3", resourceId="acct-1")

    response = _export(client, auth_headers, resourceId="acct-1")

    assert response.status_code == 200
    body = response.json()
    assert body["recordCount"] == 2
    assert [record["id"] for record in body["records"]] == [a["id"], b["id"]]


def test_export_combined_actor_and_resource_filters(client, auth_headers):
    a = _create_event(client, auth_headers, actorId="user-1", resourceId="acct-1")
    _create_event(client, auth_headers, actorId="user-1", resourceId="acct-2")
    _create_event(client, auth_headers, actorId="user-2", resourceId="acct-1")

    response = _export(client, auth_headers, actorId="user-1", resourceId="acct-1")

    assert response.status_code == 200
    body = response.json()
    assert [record["id"] for record in body["records"]] == [a["id"]]


def test_export_empty_bundle_when_no_matches(client, auth_headers):
    response = _export(client, auth_headers, actorId="no-such-user")

    assert response.status_code == 200
    body = response.json()
    assert body["recordCount"] == 0
    assert body["records"] == []
    # a well-defined manifest hash for an empty bundle, not an error
    assert body["manifestHash"] == compute_manifest_hash([])


# --- bundle self-verification -----------------------------------------------


def test_export_bundle_is_self_consistent(client, auth_headers):
    for i in range(3):
        _create_event(client, auth_headers, actorId="user-1", resourceId=f"sess-{i}")

    response = _export(client, auth_headers, actorId="user-1")

    assert response.status_code == 200
    assert _verify_bundle_self_consistency(response.json()) is True


def test_export_detects_tampering_with_a_records_content(client, auth_headers):
    _create_event(client, auth_headers, actorId="user-1")

    bundle = _export(client, auth_headers, actorId="user-1").json()
    assert _verify_bundle_self_consistency(bundle) is True

    # simulate the recipient's copy being tampered with after export
    bundle["records"][0]["payload"]["accountNumber"] = "0000000000"

    assert _verify_bundle_self_consistency(bundle) is False


def test_export_detects_tampering_via_manifest_hash(client, auth_headers):
    _create_event(client, auth_headers, actorId="user-1")
    _create_event(client, auth_headers, actorId="user-1")

    bundle = _export(client, auth_headers, actorId="user-1").json()
    assert _verify_bundle_self_consistency(bundle) is True

    # A record is dropped from the recipient's copy, but each remaining
    # record is still internally self-consistent on its own - only the
    # manifest (which records/order the bundle claims to contain) catches
    # this, not the per-record content-hash check.
    del bundle["records"][1]
    bundle["recordCount"] = len(bundle["records"])

    assert _verify_bundle_self_consistency(bundle) is False


# --- retention: archived records are included -------------------------------


def test_export_includes_archived_records(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_event = _create_event(client, auth_headers, actorId="user-1")
    new_event = _create_event(client, auth_headers, actorId="user-1")

    db = SessionLocal()
    try:
        record = db.get(AuditEvent, old_event["id"])
        record.timestamp = now - timedelta(days=100)
        db.commit()
    finally:
        db.close()

    db = SessionLocal()
    try:
        result = retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()
    assert result.archived_count == 1

    response = _export(client, auth_headers, actorId="user-1")

    assert response.status_code == 200
    body = response.json()
    ids = [record["id"] for record in body["records"]]
    assert old_event["id"] in ids
    assert new_event["id"] in ids
    archived_record = next(r for r in body["records"] if r["id"] == old_event["id"])
    assert archived_record["archivedAt"] is not None


# --- redaction: sensitive values are never re-exposed -----------------------


def test_export_redacted_record_shows_marker_not_original_value(client, auth_headers):
    event = _create_event(client, auth_headers, actorId="user-1")
    redact_response = client.post(
        f"/audit/events/{event['id']}/redact",
        json={"fields": ["accountNumber"]},
        headers=auth_headers,
    )
    assert redact_response.status_code == 200

    response = _export(client, auth_headers, actorId="user-1")

    assert response.status_code == 200
    body = response.json()
    assert body["recordCount"] == 1
    exported_record = body["records"][0]
    assert exported_record["payload"]["accountNumber"] == "[REDACTED]"
    assert "1234567890" not in str(body)  # original value nowhere in the bundle
    assert exported_record["redactedFields"] == ["accountNumber"]
    assert exported_record["redactedAt"] is not None


def test_export_by_resource_id_includes_redaction_companion_event(client, auth_headers):
    """The companion AUDIT_EVENT_REDACTED event is a normal audit event
    (see docs/redaction-design.md), so an export scoped to the *redacted
    record's* resource (resourceType/resourceId = AUDIT_EVENT/<id>) picks
    it up too, exactly like any other event referencing that resource."""
    event = _create_event(client, auth_headers, actorId="user-1")
    redact_response = client.post(
        f"/audit/events/{event['id']}/redact",
        json={"fields": ["accountNumber"]},
        headers=auth_headers,
    )
    assert redact_response.status_code == 200

    response = _export(client, auth_headers, resourceId=str(event["id"]))

    assert response.status_code == 200
    body = response.json()
    assert body["recordCount"] == 1
    assert body["records"][0]["eventType"] == "AUDIT_EVENT_REDACTED"
