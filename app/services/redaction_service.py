from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.repositories import audit_event_repository as repo
from app.schemas.audit_event import AuditEventCreate
from app.services import audit_event_service
from app.services.hashing import compute_event_hash, hash_field_value

REDACTED_MARKER = "[REDACTED]"
REDACTION_EVENT_TYPE = "AUDIT_EVENT_REDACTED"
REDACTION_RESOURCE_TYPE = "AUDIT_EVENT"


class EventNotFoundError(Exception):
    def __init__(self, event_id: int):
        self.event_id = event_id
        super().__init__(f"Audit event {event_id} not found")


class NoRedactableFieldsError(Exception):
    """None of the requested fields exist in the payload and aren't
    already redacted - there's nothing new for this call to do."""

    def __init__(self, fields: list[str]):
        self.fields = fields
        super().__init__(f"None of {fields!r} are present, redactable payload fields")


@dataclass
class RedactionResult:
    event: AuditEvent
    newly_redacted_fields: list[str]
    redacted_content_hash: str
    redaction_event: AuditEvent


def redact_event_fields(
    db: Session,
    *,
    event_id: int,
    fields: list[str],
    actor_id: str,
    reason: str | None = None,
    now: datetime | None = None,
) -> RedactionResult:
    """Redact the given top-level payload fields on an existing record.

    Never touches event_hash, previous_hash, or timestamp - only the named
    payload keys and a small block of redaction metadata (see
    app/db/models.py). The record's event_hash stays exactly as it was
    computed at write time - chain_verification_service never recomputes
    or compares against it once a record is redacted.

    Instead, this also computes redacted_content_hash: a commitment over
    the record's full CURRENT content (all fields, redacted and not),
    using the same compute_event_hash() logic as event_hash itself, just
    fed the post-redaction payload. That commitment travels in the
    companion AUDIT_EVENT_REDACTED event's payload - an ordinary event,
    appended through the normal, unmodified write path
    (app.services.audit_event_service), so it is itself fully covered by
    the normal hash chain. Verification uses it to keep checking every
    field of a redacted record that WASN'T authorized to change - so
    tampering with a non-redacted field, or replacing the redaction marker
    with something else, is still detected after redaction. Only the
    specific field(s) actually redacted are exempt going forward (see
    docs/redaction-design.md for the full design rationale, alternatives,
    and trade-offs).
    """
    reference_time = now if now is not None else datetime.now(timezone.utc)

    event = repo.get_event(db, event_id)
    if event is None:
        raise EventNotFoundError(event_id)

    already_redacted = set(event.redacted_fields or [])
    fields_to_redact = [f for f in fields if f in event.payload and f not in already_redacted]
    if not fields_to_redact:
        raise NoRedactableFieldsError(fields)

    # Hash each field's current (pre-redaction) value before it's
    # overwritten - the only place the original value is available.
    new_field_hashes = {field: hash_field_value(event.payload[field]) for field in fields_to_redact}

    new_payload = dict(event.payload)
    for field in fields_to_redact:
        new_payload[field] = REDACTED_MARKER

    # The "approved post-redaction representation": what the record's full
    # current content is authorized to hash to, from now until it's
    # redacted again. See the docstring above and docs/redaction-design.md.
    redacted_content_hash = compute_event_hash(
        tenant_id=event.tenant_id,
        event_type=event.event_type,
        actor_id=event.actor_id,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        payload=new_payload,
        timestamp=event.timestamp,
        previous_hash=event.previous_hash,
    )

    updated_event = repo.redact_event_fields(
        db,
        event,
        payload=new_payload,
        redacted_fields=sorted(already_redacted | set(fields_to_redact)),
        redacted_field_hashes={**(event.redacted_field_hashes or {}), **new_field_hashes},
        now=reference_time,
    )

    redaction_payload = {
        "targetEventId": event_id,
        "redactedFields": fields_to_redact,
        "redactedContentHash": redacted_content_hash,
    }
    if reason:
        redaction_payload["reason"] = reason

    redaction_event = audit_event_service.create_audit_event(
        db,
        AuditEventCreate(
            event_type=REDACTION_EVENT_TYPE,
            actor_id=actor_id,
            resource_type=REDACTION_RESOURCE_TYPE,
            resource_id=str(event_id),
            payload=redaction_payload,
        ),
        # The companion event belongs to the same tenant as the record it
        # documents - not the redacting admin's own tenant (admin may have
        # none) - so that tenant's own readers/auditors see it alongside
        # the record it describes.
        tenant_id=event.tenant_id,
    )

    return RedactionResult(
        event=updated_event,
        newly_redacted_fields=fields_to_redact,
        redacted_content_hash=redacted_content_hash,
        redaction_event=redaction_event,
    )
