from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import get_current_subject
from app.db.session import get_db
from app.schemas.redaction import RedactionRequest, RedactionResultOut
from app.services import redaction_service
from app.services.redaction_service import EventNotFoundError, NoRedactableFieldsError

router = APIRouter(tags=["audit"])


@router.post("/audit/events/{event_id}/redact", response_model=RedactionResultOut)
def redact_audit_event(
    event_id: int,
    request: RedactionRequest,
    db: Session = Depends(get_db),
    subject: str = Depends(get_current_subject),
) -> RedactionResultOut:
    try:
        result = redaction_service.redact_event_fields(
            db,
            event_id=event_id,
            fields=request.fields,
            actor_id=subject,
            reason=request.reason,
        )
    except EventNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except NoRedactableFieldsError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    return RedactionResultOut(
        event_id=result.event.id,
        newly_redacted_fields=result.newly_redacted_fields,
        redacted_fields=result.event.redacted_fields,
        redacted_at=result.event.redacted_at,
        redacted_content_hash=result.redacted_content_hash,
        redaction_event_id=result.redaction_event.id,
    )
