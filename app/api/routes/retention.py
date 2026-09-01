from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_current_subject
from app.db.session import get_db
from app.schemas.retention import RetentionResultOut
from app.services import retention_service

router = APIRouter(tags=["audit"])


@router.post("/audit/retention/apply", response_model=RetentionResultOut)
def apply_retention(
    db: Session = Depends(get_db),
    _subject: str = Depends(get_current_subject),
) -> RetentionResultOut:
    return retention_service.apply_retention(db, retention_window_days=settings.retention_window_days)
