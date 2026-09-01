from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import get_current_subject
from app.db.session import get_db
from app.schemas.audit_event import AuditEventOut
from app.schemas.export import ExportBundleOut, ExportFilterOut
from app.services import export_service

router = APIRouter(tags=["audit"])


@router.get("/audit/export", response_model=ExportBundleOut)
def export_audit_events(
    actor_id: Annotated[str | None, Query(alias="actorId", min_length=1)] = None,
    resource_id: Annotated[str | None, Query(alias="resourceId", min_length=1)] = None,
    db: Session = Depends(get_db),
    _subject: str = Depends(get_current_subject),
) -> ExportBundleOut:
    if not actor_id and not resource_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Provide at least one of 'actorId' or 'resourceId' to export.",
        )

    bundle = export_service.export_events(db, actor_id=actor_id, resource_id=resource_id)

    return ExportBundleOut(
        exported_at=bundle.exported_at,
        filter=ExportFilterOut(actor_id=bundle.actor_id, resource_id=bundle.resource_id),
        record_count=len(bundle.records),
        records=[AuditEventOut.model_validate(record) for record in bundle.records],
        manifest_hash=bundle.manifest_hash,
    )
