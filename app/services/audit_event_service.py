from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.repositories import audit_event_repository as repo
from app.schemas.audit_event import AuditEventCreate
from app.services.hashing import GENESIS_HASH, compute_event_hash


def create_audit_event(db: Session, event_in: AuditEventCreate, *, tenant_id: str) -> AuditEvent:
    """tenant_id is a required, explicit parameter rather than a field on
    AuditEventCreate: it is never client-supplied (see
    app/api/routes/audit_events.py, which derives it from the
    authenticated user, and app/services/redaction_service.py, which
    derives it from the record being redacted) - keeping it out of the
    request schema makes it impossible to forge via the API.
    """
    repo.lock_for_append(db)

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
    return repo.create_event(db, event)


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
