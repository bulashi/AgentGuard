from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.authorization.contracts import BusinessIdentifier, IDENTIFIER_PATTERN


class EnvelopePayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: str = Field(pattern=r"^1\.0$")
    execution_id: str
    execution_attempt_id: str
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    tenant_id: str
    task_id: str
    tool_service: str
    tool_name: str
    tool_version: str = Field(pattern=r"^v[1-9][0-9]*$")
    canonical_validated_parameters: dict[str, Any]
    business_action_id: str | None
    business_idempotency_key: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    parameter_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)
    gateway_key_id: str


class EnvelopeSignature(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    algorithm: str = Field(pattern="^SM2$")
    key_id: str
    key_purpose: str = Field(pattern="^GATEWAY_EXECUTION_SIGNING$")
    encoding: str = Field(pattern="^SM2_RS_HEX_128_LOWERCASE$")
    value: str = Field(pattern=r"^[0-9a-f]{128}$")
    signed_at: int = Field(ge=0)


class GatewayExecutionEnvelopeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    payload: EnvelopePayload
    signature: EnvelopeSignature


class ToolExecutionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    execution_attempt_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    outcome: str
    result: dict[str, Any] | None = None
    business_effect_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )
    business_result_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reason_code: str = "ALLOWED"


class ReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0"]
    execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    tenant_id: BusinessIdentifier
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    business_action_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    business_idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    parameter_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReconcileResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0"] = "1.0"
    execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    status: Literal[
        "ALREADY_EXECUTED",
        "NOT_EXECUTED",
        "IDEMPOTENCY_CONFLICT",
        "UNKNOWN",
    ]
    parameter_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result: dict[str, Any] | None = None
    business_effect_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )
    reason_code: str = "ALLOWED"

    @model_validator(mode="after")
    def validate_evidence_for_status(self) -> ReconcileResponse:
        if self.status == "ALREADY_EXECUTED" and (
            self.parameter_hash is None or self.result is None or self.business_effect_id is None
        ):
            raise ValueError("executed reconciliation requires result and effect evidence")
        if self.status in {"NOT_EXECUTED", "UNKNOWN"} and any(
            value is not None
            for value in (self.parameter_hash, self.result, self.business_effect_id)
        ):
            raise ValueError("unconfirmed reconciliation cannot carry executed effect evidence")
        return self
