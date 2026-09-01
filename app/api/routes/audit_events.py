from fastapi import APIRouter, Depends, status
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
