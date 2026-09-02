from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.authorization import require_roles
from app.core.config import settings
from app.core.roles import Role
from app.core.security import CurrentUser
from app.core.security_logging import log_security_event
from app.db.session import get_db
from app.schemas.retention import RetentionResultOut
from app.services import retention_service

router = APIRouter(tags=["audit"])


@router.post("/audit/retention/apply", response_model=RetentionResultOut)
def apply_retention(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles(Role.ADMIN)),
) -> RetentionResultOut:
    result = retention_service.apply_retention(db, retention_window_days=settings.retention_window_days)
    log_security_event(
        "retention.applied",
        requested_by=current_user.username,
        archived_count=result.archived_count,
        cutoff=result.cutoff.isoformat(),
        retention_window_days=settings.retention_window_days,
    )
    return result
