from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator

from backend.authorization.contracts import IDENTIFIER_PATTERN, MAX_SAFE_INTEGER, StrictContract

REVOCATION_BOUNDARY = "DISPATCH_BOUNDARY_NO_ROLLBACK"
EvidenceId = Annotated[str, Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)]


class UiRevokeCredentialRequest(StrictContract):
    confirmed: Literal[True]
    reason: str = Field(min_length=1, max_length=256)

    @field_validator("confirmed", mode="before")
    @classmethod
    def explicit_confirmation(cls, value: object) -> object:
        if value is not True:
            raise ValueError("explicit Boolean confirmation is required")
        return value

    @field_validator("reason")
    @classmethod
    def nonblank_reason(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a nonblank revocation reason is required")
        return value


class CancellationEvidenceLink(StrictContract):
    cancellation_id: EvidenceId
    reason_code: Literal["ANCESTOR_REVOKED", "KEY_REVOKED"]
    original_execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    denied_execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    denied_receipt_id: EvidenceId | None
    audit_event_ids: list[EvidenceId]


class RevocationExecutionObservation(StrictContract):
    scope: Literal["TASK_SNAPSHOT"] = "TASK_SNAPSHOT"
    released_count: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    dispatched_or_unknown_count: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    admitted_count: int = Field(ge=0, le=MAX_SAFE_INTEGER)


class UiRevocationResponse(StrictContract):
    schema_version: Literal["1.0"] = "1.0"
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    credential_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    status: Literal["REVOKED"] = "REVOKED"
    revoked_by: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    revoked_at: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    revocation_reason: str = Field(min_length=1, max_length=256)
    descendant_count: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    already_revoked: bool
    boundary: Literal["DISPATCH_BOUNDARY_NO_ROLLBACK"] = REVOCATION_BOUNDARY
    audit_status: Literal["PENDING", "RECORDED"]
    audit_event_ids: list[EvidenceId]
    cancellations: list[CancellationEvidenceLink]
    execution_observation: RevocationExecutionObservation
