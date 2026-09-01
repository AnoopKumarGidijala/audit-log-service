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
