from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import settings
from app.core.payload_limits import (
    compute_payload_byte_size,
    compute_payload_depth,
    payload_has_overlong_string,
)


class AuditEventCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # max_length values match the corresponding AuditEvent DB column sizes
    # (app/db/models.py) - rejecting an overlong value here gives a clean
    # 422 instead of letting it reach a raw Postgres "value too long for
    # type character varying(N)" error at insert time.
    event_type: str = Field(alias="eventType", min_length=1, max_length=100)
    actor_id: str = Field(alias="actorId", min_length=1, max_length=255)
    resource_type: str = Field(alias="resourceType", min_length=1, max_length=100)
    resource_id: str = Field(alias="resourceId", min_length=1, max_length=255)
    payload: dict[str, Any]

    @field_validator("payload")
    @classmethod
    def _enforce_payload_limits(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Defensive limits on the free-form `payload` field (see
        docs/defensive-limits-design.md) - unlike the identity fields
        above, `payload` has no DB-column-length precedent to borrow from,
        since it's a JSON column with no inherent size cap, so these
        thresholds are configured explicitly (Settings, not hardcoded
        here) rather than scattered as constants in a route handler.
        """
        byte_size = compute_payload_byte_size(value)
        if byte_size > settings.max_payload_bytes:
            raise ValueError(
                f"payload is {byte_size} bytes, which exceeds the maximum of "
                f"{settings.max_payload_bytes} bytes."
            )

        depth = compute_payload_depth(value)
        if depth > settings.max_payload_depth:
            raise ValueError(
                f"payload is nested {depth} levels deep, which exceeds the maximum of "
                f"{settings.max_payload_depth} levels."
            )

        if payload_has_overlong_string(value, max_length=settings.max_payload_string_length):
            raise ValueError(
                "payload contains a string value longer than the maximum of "
                f"{settings.max_payload_string_length} characters."
            )

        return value


class AuditEventOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

    id: int
    tenant_id: str = Field(alias="tenantId")
    event_type: str = Field(alias="eventType")
    actor_id: str = Field(alias="actorId")
    resource_type: str = Field(alias="resourceType")
    resource_id: str = Field(alias="resourceId")
    payload: dict[str, Any]
    timestamp: datetime
    previous_hash: str = Field(alias="previousHash")
    event_hash: str = Field(alias="eventHash")
    archived_at: datetime | None = Field(default=None, alias="archivedAt")
    redacted_at: datetime | None = Field(default=None, alias="redactedAt")
    redacted_fields: list[str] | None = Field(default=None, alias="redactedFields")
