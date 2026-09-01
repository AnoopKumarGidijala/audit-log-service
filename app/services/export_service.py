from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.repositories import audit_event_repository as repo
from app.services.hashing import compute_manifest_hash


@dataclass
class ExportBundle:
    exported_at: datetime
    actor_id: str | None
    resource_id: str | None
    records: list[AuditEvent]
    manifest_hash: str


def export_events(
    db: Session,
    *,
    actor_id: str | None = None,
    resource_id: str | None = None,
    now: datetime | None = None,
) -> ExportBundle:
    """Build a self-contained, verifiable export bundle for the given
    filter. See docs/export-design.md for the full design and the exact
    verification recipe a recipient follows.

    Records keep their original previous_hash/event_hash untouched (they
    are read straight from storage via list_events_including_archived(),
    which - unlike list_events() - never excludes archived records, so
    retention can't silently drop relevant history from an export). Redacted records
    are exported exactly as currently stored: since redaction tombstones
    the sensitive payload field(s) in place (see
    app/services/redaction_service.py), there is no separate step needed
    here to keep a redacted value from being re-exposed - it is simply no
    longer present in the row being exported.

    Because a filtered subset is not necessarily chain-adjacent (see
    docs/export-design.md §1), each record's own previous_hash cannot be
    used to verify the *subset* the way chain verification does for the
    *whole* chain. Instead, manifest_hash - computed the same way the
    write path computes any hash, reusing compute_manifest_hash() - is a
    single commitment over exactly which records (id + event_hash), in
    what order, this bundle contains.
    """
    reference_time = now if now is not None else datetime.now(timezone.utc)

    records = repo.list_events_including_archived(db, actor_id=actor_id, resource_id=resource_id)

    manifest_entries = [{"id": record.id, "eventHash": record.event_hash} for record in records]
    manifest_hash = compute_manifest_hash(manifest_entries)

    return ExportBundle(
        exported_at=reference_time,
        actor_id=actor_id,
        resource_id=resource_id,
        records=records,
        manifest_hash=manifest_hash,
    )
