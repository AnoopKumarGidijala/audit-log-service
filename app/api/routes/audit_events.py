from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import get_current_subject
from app.db.session import get_db
from app.schemas.audit_event import AuditEventCreate, AuditEventOut
from app.services import audit_event_service

router = APIRouter(tags=["audit"])

# Pagination bounds: a default page small enough to be a sane response
# size, and a hard cap so a client can't request the entire history (which
# is exactly what pagination exists to avoid) in one call.
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


@router.post("/audit/events", response_model=AuditEventOut, status_code=status.HTTP_201_CREATED)
def create_audit_event(
    event_in: AuditEventCreate,
    db: Session = Depends(get_db),
    _subject: str = Depends(get_current_subject),
) -> AuditEventOut:
    return audit_event_service.create_audit_event(db, event_in)


@router.get("/audit/events", response_model=list[AuditEventOut])
def list_audit_events(
    actor_id: Annotated[str | None, Query(alias="actorId")] = None,
    event_type: Annotated[str | None, Query(alias="eventType")] = None,
    resource_type: Annotated[str | None, Query(alias="resourceType")] = None,
    resource_id: Annotated[str | None, Query(alias="resourceId")] = None,
    start_time: Annotated[datetime | None, Query(alias="from")] = None,
    end_time: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: Session = Depends(get_db),
    _subject: str = Depends(get_current_subject),
) -> list[AuditEventOut]:
    start_time = _require_utc(start_time, field_name="from")
    end_time = _require_utc(end_time, field_name="to")
    if start_time is not None and end_time is not None and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="'from' must not be later than 'to'",
        )

    return audit_event_service.list_audit_events(
        db,
        actor_id=actor_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )


def _require_utc(value: datetime | None, *, field_name: str) -> datetime | None:
    """Reject timezone-naive datetimes rather than guessing their offset.

    Events are stored with server-generated UTC timestamps, so a
    timezone-naive `from`/`to` value is ambiguous - we don't know what
    timezone the caller meant. Values are normalized to UTC so the
    comparison against stored (UTC) timestamps is unambiguous regardless of
    which offset the caller used.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"'{field_name}' must include timezone information (e.g. a 'Z' or '+00:00' offset)",
        )
    return value.astimezone(timezone.utc)
