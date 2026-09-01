from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.audit_event import AuditEventOut


class ComplianceReportFilterOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    actor_id: str | None = Field(default=None, alias="actorId")
    resource_id: str | None = Field(default=None, alias="resourceId")
    start_time: datetime | None = Field(default=None, alias="from")
    end_time: datetime | None = Field(default=None, alias="to")


class ComplianceReportOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    resource_type: str = Field(alias="resourceType")
    filter: ComplianceReportFilterOut
    record_count: int = Field(alias="recordCount")
    records: list[AuditEventOut]
