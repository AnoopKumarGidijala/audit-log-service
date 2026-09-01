from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.security import get_current_subject
from app.db.session import get_db
from app.schemas.chain_verification import ChainVerificationResultOut
from app.services import chain_verification_service

router = APIRouter(tags=["audit"])


@router.get("/audit/verify", response_model=ChainVerificationResultOut)
def verify_audit_chain(
    db: Session = Depends(get_db),
    _subject: str = Depends(get_current_subject),
) -> ChainVerificationResultOut:
    return chain_verification_service.verify_chain(db)
