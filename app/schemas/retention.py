from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RetentionResultOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

    cutoff: datetime
    archived_count: int = Field(alias="archivedCount")
