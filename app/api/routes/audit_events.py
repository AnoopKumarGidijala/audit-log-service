from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.security import get_current_subject
from app.db.session import get_db
from app.schemas.audit_event import AuditEventCreate, AuditEventOut
from app.services import audit_event_service

router = APIRouter(tags=["audit"])


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
    db: Session = Depends(get_db),
    _subject: str = Depends(get_current_subject),
) -> list[AuditEventOut]:
    return audit_event_service.list_audit_events(db, actor_id=actor_id, event_type=event_type)
