from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.repositories import audit_event_repository as repo

# Fixed per docs/requirements.md Scenario C, "Decided (Prototype Scope)":
# client account data access is represented by audit events recorded
# against this resource type. Not a caller-supplied filter - this endpoint
# reports on account access specifically, nothing else.
ACCOUNT_RESOURCE_TYPE = "ACCOUNT"


def get_account_access_report(
    db: Session,
    *,
    actor_id: str | None = None,
    resource_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[AuditEvent]:
    """Account-access events for compliance reporting.

    Reuses list_events_including_archived() (also used by export) rather
    than list_events() (the paginated query API): archived records must
    remain visible here - retention changes what's shown in routine
    queries, not what's available for compliance/historical review of
    account access. Redacted records need no special handling: the query
    reads the same stored rows every other read path reads, and a
    redacted field's original value is simply not present in them to
    expose (see docs/redaction-design.md).
    """
    return repo.list_events_including_archived(
        db,
        actor_id=actor_id,
        resource_type=ACCOUNT_RESOURCE_TYPE,
        resource_id=resource_id,
        start_time=start_time,
        end_time=end_time,
    )
