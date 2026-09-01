from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.repositories import audit_event_repository as repo


@dataclass
class RetentionResult:
    cutoff: datetime
    archived_count: int


def apply_retention(
    db: Session,
    *,
    retention_window_days: int,
    now: datetime | None = None,
) -> RetentionResult:
    """Archive every record older than the retention window.

    `now` is an injectable reference point (defaults to the real current
    time) so callers - namely tests - can pin an exact cutoff instead of
    depending on wall-clock timing.
    """
    reference_time = now if now is not None else datetime.now(timezone.utc)
    cutoff = reference_time - timedelta(days=retention_window_days)
    archived_count = repo.archive_events_older_than(db, cutoff)
    return RetentionResult(cutoff=cutoff, archived_count=archived_count)
