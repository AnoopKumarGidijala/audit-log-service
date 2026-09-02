from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.authorization import require_roles
from app.core.roles import Role
from app.core.security import CurrentUser
from app.core.security_logging import log_security_event
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
    current_user: CurrentUser = Depends(require_roles(Role.ADMIN)),
) -> RedactionResultOut:
    try:
        result = redaction_service.redact_event_fields(
            db,
            event_id=event_id,
            fields=request.fields,
            actor_id=current_user.username,
            reason=request.reason,
        )
    except EventNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except NoRedactableFieldsError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    # Field *names* only - the whole point of redaction is that the
    # original values never need to be retained anywhere, logs included
    # (see docs/security-logging-design.md and docs/redaction-design.md).
    log_security_event(
        "redaction.applied",
        redacted_by=current_user.username,
        event_id=event_id,
        newly_redacted_fields=result.newly_redacted_fields,
        redaction_event_id=result.redaction_event.id,
    )

    return RedactionResultOut(
        event_id=result.event.id,
        newly_redacted_fields=result.newly_redacted_fields,
        redacted_fields=result.event.redacted_fields,
        redacted_at=result.event.redacted_at,
        redacted_content_hash=result.redacted_content_hash,
        redaction_event_id=result.redaction_event.id,
    )
