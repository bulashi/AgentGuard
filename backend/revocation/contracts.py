from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from backend.authorization.contracts import IDENTIFIER_PATTERN


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RevokeCredentialRequest(StrictContract):
    reason: str = Field(min_length=1, max_length=256)
    revoked_by: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)


class RevocationResponse(StrictContract):
    credential_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    revoked_at: int = Field(ge=0)
    revocation_reason: str = Field(min_length=1, max_length=256)
    revoked_by: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    status: str = "REVOKED"
