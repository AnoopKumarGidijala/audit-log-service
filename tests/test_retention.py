from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.db.models import AuditEvent
from app.db.session import SessionLocal
from app.services import retention_service
from app.services.hashing import GENESIS_HASH, compute_event_hash


def _create_event(client, auth_headers, **overrides):
    body = {
        "eventType": "USER_LOGIN",
        "actorId": "user-1",
        "resourceType": "SESSION",
        "resourceId": "sess-1",
        "payload": {},
    }
    body.update(overrides)
    response = client.post("/audit/events", json=body, headers=auth_headers)
    assert response.status_code == 201
    return response.json()


def _set_timestamp(event_id, ts):
    """Directly overwrite a stored event's timestamp for retention-window
    tests that only check timestamp-based archiving/filtering, not chain
    validity. NOT safe to use before calling /audit/verify: timestamp is
    part of the hashed content, so this desyncs event_hash from the
    record's content exactly like tampering would (see _insert_events for
    the alternative used by verify-adjacent tests below)."""
    db = SessionLocal()
    try:
        event = db.get(AuditEvent, event_id)
        event.timestamp = ts
        db.commit()
    finally:
        db.close()


def _insert_events(timestamps, *, actor_prefix="user"):
    """Insert one event per timestamp directly (bypassing the API/service),
    correctly hash-chained with compute_event_hash() - the same function
    the app uses at write time - continuing from whatever the current last
    record is. Used instead of _set_timestamp() whenever a test needs
    "old" records that are still genuinely chain-valid (i.e. before a call
    to /audit/verify), since the real write path always timestamps "now"
    and there's no way to backdate a record after creation without
    invalidating its own event_hash.
    """
    db = SessionLocal()
    try:
        last = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        previous_hash = last.event_hash if last else GENESIS_HASH
        created = []
        for i, ts in enumerate(timestamps):
            fields = {
                "tenant_id": "tenant-a",
                "event_type": "USER_LOGIN",
                "actor_id": f"{actor_prefix}-{i}",
                "resource_type": "SESSION",
                "resource_id": "sess-1",
                "payload": {},
            }
            event_hash = compute_event_hash(timestamp=ts, previous_hash=previous_hash, **fields)
            event = AuditEvent(timestamp=ts, previous_hash=previous_hash, event_hash=event_hash, **fields)
            db.add(event)
            db.flush()
            created.append({"id": event.id, "eventHash": event.event_hash, "previousHash": event.previous_hash})
            previous_hash = event.event_hash
        db.commit()
        return created
    finally:
        db.close()


def _get_stored(event_id):
    db = SessionLocal()
    try:
        return db.get(AuditEvent, event_id)
    finally:
        db.close()


# --- records inside/outside the retention window ---------------------------


def test_apply_retention_archives_only_records_older_than_window(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_event = _create_event(client, auth_headers, actorId="old-user")
    new_event = _create_event(client, auth_headers, actorId="new-user")
    _set_timestamp(old_event["id"], now - timedelta(days=100))
    _set_timestamp(new_event["id"], now - timedelta(days=10))

    db = SessionLocal()
    try:
        result = retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()

    assert result.archived_count == 1
    assert _get_stored(old_event["id"]).archived_at is not None
    assert _get_stored(new_event["id"]).archived_at is None


def test_apply_retention_boundary_is_exclusive(client, auth_headers):
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    window_days = 90
    cutoff = now - timedelta(days=window_days)

    at_boundary = _create_event(client, auth_headers, actorId="boundary-user")
    just_older = _create_event(client, auth_headers, actorId="older-user")
    _set_timestamp(at_boundary["id"], cutoff)
    _set_timestamp(just_older["id"], cutoff - timedelta(seconds=1))

    db = SessionLocal()
    try:
        result = retention_service.apply_retention(db, retention_window_days=window_days, now=now)
    finally:
        db.close()

    assert result.cutoff == cutoff
    assert result.archived_count == 1
    # exactly at the cutoff is not "older than" the window - stays active
    assert _get_stored(at_boundary["id"]).archived_at is None
    assert _get_stored(just_older["id"]).archived_at is not None


def test_apply_retention_is_idempotent(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_event = _create_event(client, auth_headers, actorId="old-user")
    _set_timestamp(old_event["id"], now - timedelta(days=100))

    db = SessionLocal()
    try:
        first = retention_service.apply_retention(db, retention_window_days=90, now=now)
        second = retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()

    assert first.archived_count == 1
    assert second.archived_count == 0


# --- authenticated retention-apply endpoint ---------------------------------


def test_apply_retention_requires_auth(client):
    response = client.post("/audit/retention/apply")

    assert response.status_code == 401


def test_apply_retention_endpoint_returns_summary(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_event = _create_event(client, auth_headers, actorId="old-user")
    _set_timestamp(old_event["id"], now - timedelta(days=settings.retention_window_days + 10))

    response = client.post("/audit/retention/apply", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["archivedCount"] == 1
    assert "cutoff" in body
    assert _get_stored(old_event["id"]).archived_at is not None


# --- query behavior after retention -----------------------------------------


def test_list_events_excludes_archived_by_default(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_event = _create_event(client, auth_headers, actorId="old-user")
    new_event = _create_event(client, auth_headers, actorId="new-user")
    _set_timestamp(old_event["id"], now - timedelta(days=100))
    _set_timestamp(new_event["id"], now - timedelta(days=1))

    db = SessionLocal()
    try:
        retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()

    response = client.get("/audit/events", headers=auth_headers)

    assert response.status_code == 200
    ids = [event["id"] for event in response.json()]
    assert old_event["id"] not in ids
    assert new_event["id"] in ids


def test_list_events_archived_filter_still_applies_with_actor_filter(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_event = _create_event(client, auth_headers, actorId="shared-user")
    new_event = _create_event(client, auth_headers, actorId="shared-user")
    _set_timestamp(old_event["id"], now - timedelta(days=100))
    _set_timestamp(new_event["id"], now - timedelta(days=1))

    db = SessionLocal()
    try:
        retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()

    response = client.get("/audit/events", params={"actorId": "shared-user"}, headers=auth_headers)

    assert response.status_code == 200
    ids = [event["id"] for event in response.json()]
    assert ids == [new_event["id"]]


# --- verification after retention -------------------------------------------


def test_verify_remains_intact_after_retention(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_events = _insert_events([now - timedelta(days=100), now - timedelta(days=100)], actor_prefix="old")
    new_events = [_create_event(client, auth_headers, actorId=f"user-{i}") for i in range(2)]

    db = SessionLocal()
    try:
        result = retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()
    assert result.archived_count == 2
    assert _get_stored(new_events[0]["id"]).archived_at is None

    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is True
    # verification still walks archived records too - nothing is skipped
    assert body["recordsChecked"] == 4
    assert body["violation"] is None


def test_new_event_after_full_archive_chains_onto_archived_last_event(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_events = _insert_events([now - timedelta(days=100)] * 3, actor_prefix="old")

    db = SessionLocal()
    try:
        result = retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()
    assert result.archived_count == 3

    # Every existing record is now archived. A new write must still chain
    # onto the true last record, not reset to the genesis value.
    new_event = _create_event(client, auth_headers, actorId="fresh-user")

    assert new_event["previousHash"] == old_events[-1]["eventHash"]

    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is True
    assert body["recordsChecked"] == 4
    assert body["violation"] is None


def test_verify_detects_tampering_on_an_archived_record(client, auth_headers):
    now = datetime.now(timezone.utc)
    old_events = _insert_events([now - timedelta(days=100)], actor_prefix="old")
    _create_event(client, auth_headers, actorId="user-mid")
    _create_event(client, auth_headers, actorId="user-last")

    db = SessionLocal()
    try:
        retention_service.apply_retention(db, retention_window_days=90, now=now)
    finally:
        db.close()

    # Tamper directly in Postgres with the now-archived record.
    db = SessionLocal()
    try:
        record = db.get(AuditEvent, old_events[0]["id"])
        record.actor_id = "attacker"
        db.commit()
    finally:
        db.close()

    response = client.get("/audit/verify", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is False
    assert body["violation"]["recordId"] == old_events[0]["id"]
    assert body["violation"]["violationType"] == "EVENT_HASH_MISMATCH"
