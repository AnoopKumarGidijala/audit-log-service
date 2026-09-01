from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RedactionRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    fields: list[str] = Field(min_length=1)
    reason: str | None = None


class RedactionResultOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    event_id: int = Field(alias="eventId")
    newly_redacted_fields: list[str] = Field(alias="newlyRedactedFields")
    redacted_fields: list[str] = Field(alias="redactedFields")
    redacted_at: datetime = Field(alias="redactedAt")
    redacted_content_hash: str = Field(alias="redactedContentHash")
    redaction_event_id: int = Field(alias="redactionEventId")
