from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.audit_event import AuditEventOut


class ExportFilterOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    actor_id: str | None = Field(default=None, alias="actorId")
    resource_id: str | None = Field(default=None, alias="resourceId")


class ExportBundleOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    exported_at: datetime = Field(alias="exportedAt")
    filter: ExportFilterOut
    record_count: int = Field(alias="recordCount")
    records: list[AuditEventOut]
    manifest_hash: str = Field(alias="manifestHash")
