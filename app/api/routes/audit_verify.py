import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.authorization import require_roles
from app.core.rate_limit import enforce_sensitive_endpoint_rate_limit
from app.core.roles import Role
from app.core.security import CurrentUser
from app.core.security_logging import log_security_event
from app.db.session import get_db
from app.schemas.chain_verification import ChainVerificationResultOut
from app.services import chain_verification_service

router = APIRouter(tags=["audit"])


@router.get("/audit/verify", response_model=ChainVerificationResultOut)
def verify_audit_chain(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles(Role.AUDITOR, Role.ADMIN)),
    _rate_limit: None = Depends(enforce_sensitive_endpoint_rate_limit),
) -> ChainVerificationResultOut:
    result = chain_verification_service.verify_chain(db)

    # Logged only on failure, at ERROR - a broken chain means tamper
    # evidence, the most severe security signal this service can produce
    # (see docs/security-logging-design.md). A routine, intact
    # verification is not logged - it isn't itself a security event, and
    # logging one on every call would just be noise on an endpoint
    # already rate-limited (see docs/defensive-limits-design.md).
    if not result.intact:
        log_security_event(
            "chain.verification_failed",
            level=logging.ERROR,
            requested_by=current_user.username,
            record_id=result.violation.record_id,
            violation_type=result.violation.violation_type.value,
            records_checked=result.records_checked,
        )

    return result
