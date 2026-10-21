from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.authorization.contracts import BusinessIdentifier, IDENTIFIER_PATTERN, MAX_SAFE_INTEGER


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RequestEnvelopeModel(StrictContract):
    schema_version: Literal["1.0"]
    credential_chain: list[dict[str, Any]] = Field(min_length=1, max_length=17)
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    tool_service: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9-]*$")
    tool_name: str = Field(
        min_length=3,
        max_length=96,
        pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$",
    )
    tool_version: str = Field(pattern=r"^v[1-9][0-9]*$")
    canonical_parameters: dict[str, Any]
    request_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    issued_at: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    holder_key_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    business_action_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )
    holder_proof: dict[str, Any]


class ResultRetrievalRequestModel(StrictContract):
    schema_version: Literal["1.0"]
    credential_chain: list[dict[str, Any]] = Field(min_length=1, max_length=17)
    holder_proof: dict[str, Any]
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    execution_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )
    receipt_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )
    request_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    issued_at: int = Field(ge=0, le=MAX_SAFE_INTEGER)

    @model_validator(mode="after")
    def exactly_one_target(self) -> ResultRetrievalRequestModel:
        if (self.execution_id is None) == (self.receipt_id is None):
            raise ValueError("exactly one of execution_id or receipt_id must be non-null")
        return self


class RetrievalResponseModel(StrictContract):
    execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    state: str = Field(min_length=1, max_length=64)
    result: dict[str, Any] | None


class ValidatedToolCommandModel(StrictContract):
    schema_version: Literal["1.0"]
    execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    tenant_id: BusinessIdentifier
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    tool_service: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9-]*$")
    tool_name: str = Field(
        min_length=3,
        max_length=96,
        pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$",
    )
    tool_version: str = Field(pattern=r"^v[1-9][0-9]*$")
    validated_parameters: dict[str, Any]
    business_action_id: str | None = None
    business_idempotency_key: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    parameter_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class GatewayDecisionModel(StrictContract):
    execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    state: Literal[
        "RECEIVED",
        "DENIED",
        "ADMITTED",
        "DISPATCHED",
        "UNKNOWN",
        "RECONCILING",
        "COMMITTED",
        "RELEASED",
        "RECOVERY_FAILED_FINAL",
    ]
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    request_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    credential_chain_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    admission_outcome: Literal[
        "NEW_EXECUTION",
        "IDEMPOTENT_RETURN",
        "EXISTING_EXECUTION",
        "DENIED",
    ] | None = None
    validated_command: ValidatedToolCommandModel | None = None
    receipt: dict[str, Any] | None = None
