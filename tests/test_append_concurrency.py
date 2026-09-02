"""Integration tests proving the real PostgreSQL advisory-lock append
mechanism, not just documenting it (see docs/architecture.md's
"Concurrency Concern" section and docs/idempotency-design.md §5).

Deliberately does not mock anything about PostgreSQL or its locking -
every test here fires real, concurrent requests (via a thread pool) or
forces a real constraint violation against the actual test database
(the same one every other test in this suite uses), and then inspects
the actual persisted rows directly, not just what an API response claims.
"""

from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.db.models import AuditEvent
from app.db.session import SessionLocal
from app.schemas.audit_event import AuditEventCreate
from app.services import audit_event_service
from app.services.hashing import GENESIS_HASH


def _body(**overrides):
    body = {
        "eventType": "USER_LOGIN",
        "actorId": "user-1",
        "resourceType": "SESSION",
        "resourceId": "sess-1",
        "payload": {},
    }
    body.update(overrides)
    return body


def _post(client, headers, idempotency_key=None, **overrides):
    request_headers = dict(headers)
    if idempotency_key is not None:
        request_headers["Idempotency-Key"] = idempotency_key
    return client.post("/audit/events", json=_body(**overrides), headers=request_headers)


def _all_events_ordered():
    db = SessionLocal()
    try:
        return db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    finally:
        db.close()


def _count_all_events() -> int:
    db = SessionLocal()
    try:
        return db.query(AuditEvent).count()
    finally:
        db.close()


def _count_duplicate_previous_hashes() -> int:
    """Reads directly via raw SQL, independent of any application code
    path, whether two committed records ever point at the same parent -
    the literal definition of a fork in the chain."""
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                "SELECT previous_hash, COUNT(*) AS c FROM audit_events "
                "GROUP BY previous_hash HAVING COUNT(*) > 1"
            )
        ).fetchall()
        return len(rows)
    finally:
        db.close()


# --- multiple concurrent creates: all succeed, form one linear chain, no fork --


def test_concurrent_creates_all_succeed_and_form_a_single_linear_unforked_chain(client, writer_headers, admin_headers):
    """Fires several genuinely concurrent POST /audit/events requests (real
    threads hitting the real ASGI app, backed by the real Postgres test
    database - no mocking of the advisory lock or the DB) with distinct
    content and no idempotency key, then proves three things about the
    result:

    1. every concurrent request actually succeeded (the lock serializes,
       it doesn't drop or fail concurrent requests)
    2. the resulting records form exactly one linear chain in insertion
       order - each previous_hash points at exactly the prior record's
       event_hash, starting from the genesis value
    3. no two records share a previous_hash - i.e. no fork - checked both
       via the API's own chain verification and independently via a raw
       SQL query, so this isn't just trusting the same code path twice
    """
    worker_count = 8

    def _fire(i: int):
        return _post(client, writer_headers, resourceId=f"linear-chain-res-{i}", actorId=f"user-{i}")

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        responses = list(executor.map(_fire, range(worker_count)))

    # 1. every concurrent request succeeded.
    assert [r.status_code for r in responses] == [201] * worker_count
    ids = [r.json()["id"] for r in responses]
    assert len(set(ids)) == worker_count  # every request produced its own distinct record

    # 2. exactly one linear chain, in insertion (id) order.
    events = _all_events_ordered()
    assert len(events) == worker_count
    assert events[0].previous_hash == GENESIS_HASH
    for earlier, later in zip(events, events[1:]):
        assert later.previous_hash == earlier.event_hash

    # 3a. no fork, per the system's own verification logic.
    verify_response = client.get("/audit/verify", headers=admin_headers)
    assert verify_response.status_code == 200
    verify_body = verify_response.json()
    assert verify_body["intact"] is True
    assert verify_body["recordsChecked"] == worker_count
    assert verify_body["violation"] is None

    # 3b. no fork, independently confirmed via raw SQL - no two committed
    # records reference the same parent.
    assert _count_duplicate_previous_hashes() == 0


# --- a transaction failure during append leaves no partial record --------------


def test_failed_append_leaves_no_partial_record_and_next_append_uses_correct_tail(
    client, writer_headers, admin_headers
):
    """Forces a genuine PostgreSQL transaction failure partway through the
    append path - a real NOT NULL constraint violation on tenant_id,
    triggered by calling the service directly with a value the API layer
    would never allow through (see app/api/routes/audit_events.py's own
    "tenant_id is None" guard) but that reaches the real INSERT
    unvalidated at the ORM level. This is not a mock: PostgreSQL itself
    rejects the write and the transaction rolls back for real, which is
    exactly the failure mode this test needs to exercise - some failure
    occurring after the advisory lock is acquired but before commit.

    Then confirms two things: nothing partial was left behind, and the
    advisory lock was correctly released by the rollback (proven simply by
    the next append succeeding at all, with the correct chain tail - if
    the lock had leaked, this next call would hang rather than complete).
    """
    first = _post(client, writer_headers, resourceId="fail-tail-res")
    assert first.status_code == 201
    assert _count_all_events() == 1

    db = SessionLocal()
    try:
        with pytest.raises(IntegrityError):
            audit_event_service.create_audit_event(
                db,
                AuditEventCreate(
                    event_type="SHOULD_NOT_PERSIST",
                    actor_id="doomed",
                    resource_type="SESSION",
                    resource_id="fail-tail-res",
                    payload={},
                ),
                tenant_id=None,  # violates AuditEvent.tenant_id's NOT NULL constraint
            )
    finally:
        db.rollback()
        db.close()

    # The failed attempt left no row behind - still just the one real event.
    assert _count_all_events() == 1
    assert all(e.event_type != "SHOULD_NOT_PERSIST" for e in _all_events_ordered())

    # The next append is unaffected: it chains onto the true last event,
    # not onto anything from the failed attempt (which never got an id or
    # an event_hash at all), and it doesn't hang - proving the advisory
    # lock was released by the rollback.
    second = _post(client, writer_headers, resourceId="fail-tail-res-2")
    assert second.status_code == 201
    assert second.json()["previousHash"] == first.json()["eventHash"]

    verify_response = client.get("/audit/verify", headers=admin_headers)
    verify_body = verify_response.json()
    assert verify_body["intact"] is True
    assert verify_body["recordsChecked"] == 2
    assert verify_body["violation"] is None


# --- concurrent requests using the same idempotency key ------------------------


def test_concurrent_requests_with_same_idempotency_key_produce_exactly_one_record(client, writer_headers):
    """The same real advisory lock this whole module is about also
    protects the idempotency check (see
    app/services/audit_event_service.py and docs/idempotency-design.md
    §5) - proven here the same way as the plain-concurrency test above:
    real concurrent HTTP requests against the real database, then
    inspecting what was actually persisted. Complements (does not
    replace) tests/test_idempotency.py's own coverage of this scenario -
    included here too because it's a direct consequence of the same
    locking behavior this file exists to verify.
    """
    worker_count = 5

    def _fire(_):
        return _post(client, writer_headers, idempotency_key="lock-proof-key", resourceId="idem-lock-res")

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        responses = list(executor.map(_fire, range(worker_count)))

    assert [r.status_code for r in responses] == [201] * worker_count
    ids = {r.json()["id"] for r in responses}
    assert len(ids) == 1

    db = SessionLocal()
    try:
        matching = db.query(AuditEvent).filter(AuditEvent.resource_id == "idem-lock-res").all()
    finally:
        db.close()
    assert len(matching) == 1
