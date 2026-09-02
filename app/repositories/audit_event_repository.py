from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import AuditEvent, IdempotencyKey

# Arbitrary fixed key identifying "appending an audit event" for Postgres
# advisory locks. Only meaningful as a lock namespace, not stored data.
_APPEND_LOCK_KEY = 8241773


def lock_for_append(db: Session) -> None:
    """Serialize concurrent audit-event appends.

    Two concurrent writes could otherwise both read the same "last event",
    compute a previous_hash pointing to it, and both attempt to append -
    forking the chain. Taking a transaction-scoped Postgres advisory lock
    before reading the last event forces concurrent append attempts to run
    one at a time. The lock is released automatically when the current
    transaction commits or rolls back.
    """
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _APPEND_LOCK_KEY})


def get_last_event(db: Session) -> AuditEvent | None:
    """The most recently appended record, including archived ones.

    The chain is one continuous sequence regardless of retention, so a new
    record must still chain onto the true last record even if it has since
    been archived - retention is query-visibility metadata, not a
    structural break in the chain.
    """
    return db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()


def insert_event(db: Session, event: AuditEvent) -> AuditEvent:
    """Stage a new event for insertion without committing. audit_event_service
    always follows this with a single db.commit() after also handling any
    idempotency-key bookkeeping (see app/services/audit_event_service.py) -
    the event row and its idempotency row, when there is one, must commit
    together, atomically, in the same transaction the advisory lock holds.
    A flush (not a commit) is enough to assign the event its id, which the
    idempotency row needs as a foreign key.
    """
    db.add(event)
    db.flush()
    return event


def get_event(db: Session, event_id: int) -> AuditEvent | None:
    return db.query(AuditEvent).filter(AuditEvent.id == event_id).first()


def get_idempotency_record(db: Session, *, username: str, idempotency_key: str) -> IdempotencyKey | None:
    return (
        db.query(IdempotencyKey)
        .filter(IdempotencyKey.username == username, IdempotencyKey.idempotency_key == idempotency_key)
        .first()
    )


def record_idempotency_key(
    db: Session,
    *,
    username: str,
    idempotency_key: str,
    request_fingerprint: str,
    event_id: int,
    now: datetime,
) -> IdempotencyKey:
    """Stage the idempotency bookkeeping row without committing - see
    insert_event() above; the caller (audit_event_service) commits both
    together."""
    record = IdempotencyKey(
        username=username,
        idempotency_key=idempotency_key,
        request_fingerprint=request_fingerprint,
        event_id=event_id,
        created_at=now,
    )
    db.add(record)
    db.flush()
    return record


def list_events(
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
    # Ordered by id (assignment order is serialized by lock_for_append, so
    # it matches chain/insertion order) for a deterministic, predictable
    # sequence across repeated requests, including across pages.
    #
    # Archived (retained) records are excluded from normal query results:
    # that's the point of retention, to reduce what's visible in everyday
    # queries. Full history (including archived records) is still available
    # via list_all_events(), which chain verification uses.
    #
    # tenant_id, when given, restricts results to that tenant - the caller
    # (app/api/routes/audit_events.py) passes it for a reader (whose reads
    # are always tenant-scoped) and omits it for auditor/admin (whose reads
    # deliberately span every tenant - see docs/authorization-design.md).
    query = db.query(AuditEvent).filter(AuditEvent.archived_at.is_(None))
    if tenant_id is not None:
        query = query.filter(AuditEvent.tenant_id == tenant_id)
    if actor_id is not None:
        query = query.filter(AuditEvent.actor_id == actor_id)
    if event_type is not None:
        query = query.filter(AuditEvent.event_type == event_type)
    if resource_type is not None:
        query = query.filter(AuditEvent.resource_type == resource_type)
    if resource_id is not None:
        query = query.filter(AuditEvent.resource_id == resource_id)
    if start_time is not None:
        query = query.filter(AuditEvent.timestamp >= start_time)
    if end_time is not None:
        query = query.filter(AuditEvent.timestamp <= end_time)
    return query.order_by(AuditEvent.id.asc()).offset(offset).limit(limit).all()


def list_all_events(db: Session) -> list[AuditEvent]:
    """Every event in chain order, including archived ones, unfiltered and
    unpaginated.

    For full chain verification, which must walk the whole history from the
    beginning - unlike list_events(), which serves the paginated query API
    and excludes archived records. Archived records must stay included
    here: a later record's previous_hash can point at an archived record's
    event_hash, so skipping archived records would make verification see a
    gap in the chain that isn't actually there - exactly the false break
    retention must not cause.
    """
    return db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()


def list_events_including_archived(
    db: Session,
    *,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[AuditEvent]:
    """Every event matching the given filter(s), regardless of archive
    status. Retention must not silently drop relevant history from a
    result that needs the full historical record - unlike list_events()
    (the paginated query API), this never filters on archived_at. Used by
    export and compliance reporting, both of which need this same
    "filtered, but archive-inclusive" shape. Ordered by id ascending, the
    same determinism as list_events()/list_all_events().
    """
    query = db.query(AuditEvent)
    if actor_id is not None:
        query = query.filter(AuditEvent.actor_id == actor_id)
    if resource_type is not None:
        query = query.filter(AuditEvent.resource_type == resource_type)
    if resource_id is not None:
        query = query.filter(AuditEvent.resource_id == resource_id)
    if start_time is not None:
        query = query.filter(AuditEvent.timestamp >= start_time)
    if end_time is not None:
        query = query.filter(AuditEvent.timestamp <= end_time)
    return query.order_by(AuditEvent.id.asc()).all()


def archive_events_older_than(db: Session, cutoff: datetime) -> int:
    """Archive (soft-delete) every active record with timestamp < cutoff.

    Only ever sets archived_at - never touches any hash-relevant field, so
    it cannot affect an event_hash or a previous_hash link. A single bulk
    UPDATE at the database level (not a Python loop over loaded rows), so
    the cost doesn't depend on how many records already exist.
    """
    archived_count = (
        db.query(AuditEvent)
        .filter(AuditEvent.archived_at.is_(None))
        .filter(AuditEvent.timestamp < cutoff)
        .update({AuditEvent.archived_at: datetime.now(timezone.utc)}, synchronize_session=False)
    )
    db.commit()
    return archived_count


def redact_event_fields(
    db: Session,
    event: AuditEvent,
    *,
    payload: dict,
    redacted_fields: list[str],
    redacted_field_hashes: dict[str, str],
    now: datetime,
) -> AuditEvent:
    """Persist an already-computed redaction onto an existing record.

    Purely mechanical: the caller (redaction_service) decides what the new
    payload/metadata should be; this only writes it. Never touches
    event_hash, previous_hash, or timestamp - those are exactly what makes
    a redacted record's chain link (and every other record's) still valid
    (see docs/redaction-design.md). Not a general-purpose update - only
    these four columns can ever be set here, and only via
    redaction_service.
    """
    event.payload = payload
    event.redacted_fields = redacted_fields
    event.redacted_field_hashes = redacted_field_hashes
    event.redacted_at = now
    db.commit()
    db.refresh(event)
    return event
