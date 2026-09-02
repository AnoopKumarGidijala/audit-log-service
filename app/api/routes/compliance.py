from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.time_range import require_utc, validate_range
from app.core.authorization import require_roles
from app.core.roles import Role
from app.core.security import CurrentUser
from app.db.session import get_db
from app.schemas.audit_event import AuditEventOut
from app.schemas.compliance import ComplianceReportFilterOut, ComplianceReportOut
from app.services import compliance_service
from app.services.compliance_service import ACCOUNT_RESOURCE_TYPE

router = APIRouter(tags=["audit"])


@router.get("/audit/compliance/account-access", response_model=ComplianceReportOut)
def get_account_access_report(
    actor_id: Annotated[str | None, Query(alias="actorId", min_length=1)] = None,
    resource_id: Annotated[str | None, Query(alias="resourceId", min_length=1)] = None,
    start_time: Annotated[datetime | None, Query(alias="from")] = None,
    end_time: Annotated[datetime | None, Query(alias="to")] = None,
    db: Session = Depends(get_db),
    _current_user: CurrentUser = Depends(require_roles(Role.AUDITOR, Role.ADMIN)),
) -> ComplianceReportOut:
    start_time = require_utc(start_time, field_name="from")
    end_time = require_utc(end_time, field_name="to")
    validate_range(start_time, end_time)

    records = compliance_service.get_account_access_report(
        db,
        actor_id=actor_id,
        resource_id=resource_id,
        start_time=start_time,
        end_time=end_time,
    )

    return ComplianceReportOut(
        resource_type=ACCOUNT_RESOURCE_TYPE,
        filter=ComplianceReportFilterOut(
            actor_id=actor_id,
            resource_id=resource_id,
            start_time=start_time,
            end_time=end_time,
        ),
        record_count=len(records),
        records=[AuditEventOut.model_validate(record) for record in records],
    )
