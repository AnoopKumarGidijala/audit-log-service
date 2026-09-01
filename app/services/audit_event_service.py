from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.repositories import audit_event_repository as repo
from app.schemas.audit_event import AuditEventCreate
from app.services.hashing import GENESIS_HASH, compute_event_hash


def create_audit_event(db: Session, event_in: AuditEventCreate) -> AuditEvent:
    repo.lock_for_append(db)

    last_event = repo.get_last_event(db)
    previous_hash = last_event.event_hash if last_event else GENESIS_HASH

    timestamp = datetime.now(timezone.utc)

    event_hash = compute_event_hash(
        event_type=event_in.event_type,
        actor_id=event_in.actor_id,
        resource_type=event_in.resource_type,
        resource_id=event_in.resource_id,
        payload=event_in.payload,
        timestamp=timestamp,
        previous_hash=previous_hash,
    )

    event = AuditEvent(
        event_type=event_in.event_type,
        actor_id=event_in.actor_id,
        resource_type=event_in.resource_type,
        resource_id=event_in.resource_id,
        payload=event_in.payload,
        timestamp=timestamp,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    return repo.create_event(db, event)
