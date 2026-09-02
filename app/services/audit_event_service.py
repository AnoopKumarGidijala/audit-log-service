from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.repositories import audit_event_repository as repo
from app.schemas.audit_event import AuditEventCreate
from app.services.hashing import GENESIS_HASH, compute_event_hash, compute_request_fingerprint


class IdempotencyKeyConflictError(Exception):
    """Raised when an idempotency key was already used by the same caller
    for a request with different content (see docs/idempotency-design.md).
    """

    def __init__(self, idempotency_key: str):
        self.idempotency_key = idempotency_key
        super().__init__(
            f"Idempotency key {idempotency_key!r} was already used with different request content"
        )


def _replay_or_conflict(
    db: Session, *, requested_by: str, idempotency_key: str, fingerprint: str
) -> AuditEvent | None:
    """Looks up whatever the given (caller, idempotency_key) pair has
    already produced, if anything.

    Returns the original event when the key is a legitimate replay
    (identical content); raises IdempotencyKeyConflictError when the key
    was already used for different content; returns None when the key
    hasn't been used yet, meaning the caller should proceed to create a
    new event.
    """
    existing = repo.get_idempotency_record(db, username=requested_by, idempotency_key=idempotency_key)
    if existing is None:
        return None
    if existing.request_fingerprint != fingerprint:
        raise IdempotencyKeyConflictError(idempotency_key)
    return repo.get_event(db, existing.event_id)


def create_audit_event(
    db: Session,
    event_in: AuditEventCreate,
    *,
    tenant_id: str,
    idempotency_key: str | None = None,
    requested_by: str | None = None,
) -> AuditEvent:
    """tenant_id is a required, explicit parameter rather than a field on
    AuditEventCreate: it is never client-supplied (see
    app/api/routes/audit_events.py, which derives it from the
    authenticated user, and app/services/redaction_service.py, which
    derives it from the record being redacted) - keeping it out of the
    request schema makes it impossible to forge via the API.

    idempotency_key/requested_by are both optional and only meaningful
    together (see docs/idempotency-design.md) - callers that don't need
    idempotency (e.g. redaction_service's companion-event append) simply
    omit them, and this behaves exactly as it did before idempotency
    support existed. When given, a request already answered for this
    (requested_by, idempotency_key) pair is replayed rather than
    reappended; the same pair reused with different request content
    raises IdempotencyKeyConflictError.

    The idempotency check, the event insert, and the idempotency
    bookkeeping insert all happen inside the single transaction
    lock_for_append() holds the advisory lock for, and share one commit
    (see repo.insert_event/repo.record_idempotency_key) - so a concurrent
    retry that arrives before this transaction commits simply blocks on
    the same lock every other concurrent append already blocks on, and by
    the time it proceeds, this request's outcome (including its
    idempotency row) is already visible to it. No new locking primitive
    was needed for this guarantee; it rides entirely on the existing
    append lock.
    """
    repo.lock_for_append(db)

    fingerprint = None
    if idempotency_key is not None:
        fingerprint = compute_request_fingerprint(
            tenant_id=tenant_id,
            event_type=event_in.event_type,
            actor_id=event_in.actor_id,
            resource_type=event_in.resource_type,
            resource_id=event_in.resource_id,
            payload=event_in.payload,
        )
        replay = _replay_or_conflict(
            db, requested_by=requested_by, idempotency_key=idempotency_key, fingerprint=fingerprint
        )
        if replay is not None:
            return replay

    last_event = repo.get_last_event(db)
    previous_hash = last_event.event_hash if last_event else GENESIS_HASH

    timestamp = datetime.now(timezone.utc)

    event_hash = compute_event_hash(
        tenant_id=tenant_id,
        event_type=event_in.event_type,
        actor_id=event_in.actor_id,
        resource_type=event_in.resource_type,
        resource_id=event_in.resource_id,
        payload=event_in.payload,
        timestamp=timestamp,
        previous_hash=previous_hash,
    )

    event = AuditEvent(
        tenant_id=tenant_id,
        event_type=event_in.event_type,
        actor_id=event_in.actor_id,
        resource_type=event_in.resource_type,
        resource_id=event_in.resource_id,
        payload=event_in.payload,
        timestamp=timestamp,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    repo.insert_event(db, event)

    if idempotency_key is not None:
        repo.record_idempotency_key(
            db,
            username=requested_by,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            event_id=event.id,
            now=timestamp,
        )

    db.commit()
    db.refresh(event)
    return event


def list_audit_events(
    db: Session,
    *,
    tenant_id: str | None = None,
    actor_id: str | None = None,
    event_type: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int,
    offset: int,
) -> list[AuditEvent]:
    return repo.list_events(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
