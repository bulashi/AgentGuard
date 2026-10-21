from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.authorization.contracts import IDENTIFIER_PATTERN, MAX_SAFE_INTEGER, BusinessIdentifier

BaselineMode = Literal["shared_static_credential", "conventional_rbac"]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ConfigureRunRequest(StrictContract):
    run_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)


class SetupWorkloadRequest(StrictContract):
    run_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    workload_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    tenant_id: BusinessIdentifier
    ticket_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    customer_id: BusinessIdentifier
    refund_total_fen: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    max_tool_calls: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    expires_in_seconds: int = Field(default=1_800, ge=1, le=86_400)


class BaselineToolRequest(StrictContract):
    run_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    workload_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    request_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    operation_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    tenant_id: BusinessIdentifier
    tool_service: Literal[
        "ticket-service",
        "knowledge-service",
        "refund-service",
        "notification-service",
    ]
    tool_name: Literal[
        "ticket.read",
        "knowledge.read_associated",
        "refund.create",
        "notification.send_template",
    ]
    tool_version: Literal["v1"] = "v1"
    canonical_parameters: dict[str, Any]
    trusted_action_slot: Literal[
        "primary-refund",
        "approved-second-refund",
        "refund-success-notification",
    ] | None = None

    @model_validator(mode="after")
    def require_action_slot(self) -> BaselineToolRequest:
        side_effect = self.tool_name in {"refund.create", "notification.send_template"}
        if side_effect != (self.trusted_action_slot is not None):
            raise ValueError("side-effect operations require exactly one trusted action slot")
        if self.tool_name == "refund.create" and self.trusted_action_slot not in {
            "primary-refund",
            "approved-second-refund",
        }:
            raise ValueError("refund operation requires a refund action slot")
        if (
            self.tool_name == "notification.send_template"
            and self.trusted_action_slot != "refund-success-notification"
        ):
            raise ValueError("notification operation requires the notification action slot")
        return self


class RevokePrincipalRequest(StrictContract):
    run_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    reason: str = Field(min_length=1, max_length=256)


class BaselineDecision(StrictContract):
    mode: BaselineMode
    request_id: str
    operation_id: str
    decision: Literal["ALLOW", "DENY"]
    state: Literal["DENIED", "DISPATCHED", "COMMITTED", "RELEASED"]
    reason_code: str
    execution_id: str | None = None
    business_effect_id: str | None = None
    result: dict[str, Any] | None = None
    idempotent_return: bool = False
    timings: dict[str, float]
