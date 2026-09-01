from pydantic import BaseModel, ConfigDict, Field

from app.services.chain_verification_service import ChainViolationType


class ChainViolationOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

    record_id: int = Field(alias="recordId")
    violation_type: ChainViolationType = Field(alias="violationType")
    detail: str


class ChainVerificationResultOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

    intact: bool
    records_checked: int = Field(alias="recordsChecked")
    violation: ChainViolationOut | None = None
