from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.authorization import require_roles
from app.core.roles import Role
from app.core.security import CurrentUser
from app.db.session import get_db
from app.schemas.chain_verification import ChainVerificationResultOut
from app.services import chain_verification_service

router = APIRouter(tags=["audit"])


@router.get("/audit/verify", response_model=ChainVerificationResultOut)
def verify_audit_chain(
    db: Session = Depends(get_db),
    _current_user: CurrentUser = Depends(require_roles(Role.AUDITOR, Role.ADMIN)),
) -> ChainVerificationResultOut:
    return chain_verification_service.verify_chain(db)
