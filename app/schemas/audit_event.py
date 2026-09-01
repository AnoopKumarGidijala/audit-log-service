from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditEventCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    event_type: str = Field(alias="eventType", min_length=1)
    actor_id: str = Field(alias="actorId", min_length=1)
    resource_type: str = Field(alias="resourceType", min_length=1)
    resource_id: str = Field(alias="resourceId", min_length=1)
    payload: dict[str, Any]


class AuditEventOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

    id: int
    event_type: str = Field(alias="eventType")
    actor_id: str = Field(alias="actorId")
    resource_type: str = Field(alias="resourceType")
    resource_id: str = Field(alias="resourceId")
    payload: dict[str, Any]
    timestamp: datetime
    previous_hash: str = Field(alias="previousHash")
    event_hash: str = Field(alias="eventHash")
    archived_at: datetime | None = Field(default=None, alias="archivedAt")
