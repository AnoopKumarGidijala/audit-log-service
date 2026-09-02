"""Idempotency tests for POST /audit/events (see docs/idempotency-design.md).

Covers: normal creation (with and without a key), identical retry,
conflicting reuse of a key, concurrent duplicate requests, and that a key
is scoped per authenticated caller (not global).
"""

from concurrent.futures import ThreadPoolExecutor

from app.db.models import AuditEvent
from app.db.session import SessionLocal


def _body(**overrides):
    body = {
        "eventType": "USER_LOGIN",
        "actorId": "user-1",
        "resourceType": "SESSION",
        "resourceId": "sess-1",
        "payload": {"ip": "127.0.0.1"},
    }
    body.update(overrides)
    return body


def _post(client, headers, idempotency_key=None, **overrides):
    request_headers = dict(headers)
    if idempotency_key is not None:
        request_headers["Idempotency-Key"] = idempotency_key
    return client.post("/audit/events", json=_body(**overrides), headers=request_headers)


def _count_events_with_resource_id(resource_id: str) -> int:
    db = SessionLocal()
    try:
        return db.query(AuditEvent).filter(AuditEvent.resource_id == resource_id).count()
    finally:
        db.close()


# --- normal creation (with and without a key) --------------------------------


def test_create_without_idempotency_key_behaves_as_before(client, writer_headers):
    """No header at all - every request creates its own event, exactly as
    before this feature existed. Idempotency is opt-in."""
    first = _post(client, writer_headers, resourceId="no-key-res")
    second = _post(client, writer_headers, resourceId="no-key-res")

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] != second.json()["id"]
    assert _count_events_with_resource_id("no-key-res") == 2


def test_create_with_a_fresh_idempotency_key_succeeds_normally(client, writer_headers):
    response = _post(client, writer_headers, idempotency_key="fresh-key-1", resourceId="fresh-key-res")

    assert response.status_code == 201
    body = response.json()
    assert body["resourceId"] == "fresh-key-res"
    assert len(body["eventHash"]) == 64


# --- identical retry -----------------------------------------------------------


def test_identical_retry_returns_original_event_without_appending(client, writer_headers):
    first = _post(client, writer_headers, idempotency_key="retry-key-1", resourceId="retry-res")
    assert first.status_code == 201

    second = _post(client, writer_headers, idempotency_key="retry-key-1", resourceId="retry-res")

    assert second.status_code == 201
    assert second.json() == first.json()
    assert _count_events_with_resource_id("retry-res") == 1


def test_third_identical_retry_still_returns_the_same_original_event(client, writer_headers):
    first = _post(client, writer_headers, idempotency_key="retry-key-2", resourceId="retry-res-2")

    for _ in range(2):
        again = _post(client, writer_headers, idempotency_key="retry-key-2", resourceId="retry-res-2")
        assert again.status_code == 201
        assert again.json()["id"] == first.json()["id"]

    assert _count_events_with_resource_id("retry-res-2") == 1


# --- conflicting reuse of a key -------------------------------------------------


def test_conflicting_reuse_of_key_with_different_content_is_rejected(client, writer_headers):
    first = _post(client, writer_headers, idempotency_key="conflict-key-1", resourceId="conflict-res")
    assert first.status_code == 201

    conflicting = _post(
        client, writer_headers, idempotency_key="conflict-key-1", resourceId="conflict-res", actorId="user-2"
    )

    assert conflicting.status_code == 409
    # Nothing new was appended - only the original event exists.
    assert _count_events_with_resource_id("conflict-res") == 1


def test_conflicting_reuse_detects_a_payload_only_difference(client, writer_headers):
    first = _post(client, writer_headers, idempotency_key="conflict-key-2", resourceId="conflict-res-2")
    assert first.status_code == 201

    conflicting = _post(
        client,
        writer_headers,
        idempotency_key="conflict-key-2",
        resourceId="conflict-res-2",
        payload={"ip": "10.0.0.1"},
    )

    assert conflicting.status_code == 409
    assert _count_events_with_resource_id("conflict-res-2") == 1


# --- concurrent duplicate requests ----------------------------------------------


def test_concurrent_identical_retries_create_only_one_event(client, writer_headers):
    """Fires several identical requests (same caller, same idempotency
    key, same content) truly concurrently and confirms the hash chain
    ends up with exactly one event for them, not a fork or a duplicate -
    the property the existing append advisory lock is relied on for (see
    docs/idempotency-design.md §5)."""
    worker_count = 5

    def _fire(_):
        return _post(client, writer_headers, idempotency_key="concurrent-key-1", resourceId="concurrent-res")

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        responses = list(executor.map(_fire, range(worker_count)))

    assert all(r.status_code == 201 for r in responses)
    event_ids = {r.json()["id"] for r in responses}
    assert len(event_ids) == 1, f"expected every response to reference the same event, got {event_ids}"
    assert _count_events_with_resource_id("concurrent-res") == 1


def test_concurrent_conflicting_requests_exactly_one_succeeds(client, writer_headers):
    """Same idempotency key, fired concurrently, but with two different
    payloads mixed in - exactly one distinct piece of content should "win"
    the key (whichever request's insert lands first via the advisory
    lock), and every other request - including ones with the same content
    as the winner, if any raced in after it - must not append a second
    event."""
    worker_count = 6

    def _fire(i):
        actor = "user-a" if i % 2 == 0 else "user-b"
        return _post(
            client, writer_headers, idempotency_key="concurrent-key-2", resourceId="concurrent-res-2", actorId=actor
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        responses = list(executor.map(_fire, range(worker_count)))

    statuses = [r.status_code for r in responses]
    assert set(statuses) <= {201, 409}
    assert statuses.count(201) >= 1
    # Every 201 response must reference the same single winning event.
    winning_ids = {r.json()["id"] for r in responses if r.status_code == 201}
    assert len(winning_ids) == 1
    assert _count_events_with_resource_id("concurrent-res-2") == 1


# --- scoped per authenticated caller --------------------------------------------


def test_idempotency_key_is_scoped_per_caller_not_global(client, writer_headers, writer_headers_b):
    """The identical key string, used by two different authenticated
    callers, must not conflict or replay across them - each caller gets
    their own independent event."""
    a = _post(client, writer_headers, idempotency_key="shared-key", resourceId="tenant-a-res", actorId="user-a")
    b = _post(
        client, writer_headers_b, idempotency_key="shared-key", resourceId="tenant-b-res", actorId="user-b"
    )

    assert a.status_code == 201
    assert b.status_code == 201
    assert a.json()["id"] != b.json()["id"]
    assert a.json()["tenantId"] == "tenant-a"
    assert b.json()["tenantId"] == "tenant-b"


# --- chain integrity ------------------------------------------------------------


def test_hash_chain_remains_intact_after_replays_and_conflicts(client, writer_headers, admin_headers):
    _post(client, writer_headers, idempotency_key="chain-key-1", resourceId="chain-res-1")
    _post(client, writer_headers, idempotency_key="chain-key-1", resourceId="chain-res-1")  # replay
    _post(
        client, writer_headers, idempotency_key="chain-key-1", resourceId="chain-res-1", actorId="attacker"
    )  # conflict, rejected
    _post(client, writer_headers, resourceId="chain-res-2")  # unrelated, no key

    response = client.get("/audit/verify", headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intact"] is True
    # Exactly 2 real events: the original chain-res-1 event, and the
    # unrelated chain-res-2 one. The replay appended nothing; the conflict
    # was rejected before anything was appended.
    assert body["recordsChecked"] == 2
