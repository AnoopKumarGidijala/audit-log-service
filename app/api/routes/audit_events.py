from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.time_range import require_utc, validate_range
from app.core.authorization import require_roles
from app.core.roles import Role
from app.core.security import CurrentUser
from app.db.session import get_db
from app.schemas.audit_event import AuditEventCreate, AuditEventOut
from app.services import audit_event_service
from app.services.audit_event_service import IdempotencyKeyConflictError

router = APIRouter(tags=["audit"])

# Pagination bounds: a default page small enough to be a sane response
# size, and a hard cap so a client can't request the entire history (which
# is exactly what pagination exists to avoid) in one call.
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


@router.post("/audit/events", response_model=AuditEventOut, status_code=status.HTTP_201_CREATED)
def create_audit_event(
    event_in: AuditEventCreate,
    idempotency_key: Annotated[
        str | None, Header(alias="Idempotency-Key", min_length=1, max_length=255)
    ] = None,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles(Role.WRITER, Role.ADMIN)),
) -> AuditEventOut:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Authenticated user has no tenant configured; cannot create audit events.",
        )
    try:
        return audit_event_service.create_audit_event(
            db,
            event_in,
            tenant_id=current_user.tenant_id,
            idempotency_key=idempotency_key,
            requested_by=current_user.username,
        )
    except IdempotencyKeyConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


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
    current_user: CurrentUser = Depends(require_roles(Role.READER, Role.AUDITOR, Role.ADMIN)),
) -> list[AuditEventOut]:
    start_time = require_utc(start_time, field_name="from")
    end_time = require_utc(end_time, field_name="to")
    validate_range(start_time, end_time)

    # A reader's results are always restricted to their own tenant,
    # regardless of what other filters they pass - so a reader can never
    # see another tenant's data, even by guessing an actorId/resourceId
    # that belongs to it. Auditor/admin are deliberately not restricted:
    # cross-tenant visibility is their explicit purpose (see
    # docs/authorization-design.md), not an accidental side effect of
    # missing a filter.
    tenant_id = None
    if current_user.role == Role.READER:
        if current_user.tenant_id is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Reader has no tenant configured; cannot query audit events.",
            )
        tenant_id = current_user.tenant_id

    return audit_event_service.list_audit_events(
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
