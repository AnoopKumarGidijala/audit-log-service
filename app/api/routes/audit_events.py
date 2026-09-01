from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.time_range import require_utc, validate_range
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
    start_time = require_utc(start_time, field_name="from")
    end_time = require_utc(end_time, field_name="to")
    validate_range(start_time, end_time)

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
