from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import AuditEvent

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
    return db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()


def create_event(db: Session, event: AuditEvent) -> AuditEvent:
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def list_events(
    db: Session,
    *,
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
    query = db.query(AuditEvent)
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
