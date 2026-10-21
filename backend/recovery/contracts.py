from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from backend.authorization.contracts import IDENTIFIER_PATTERN, MAX_SAFE_INTEGER
from backend.gateway.contracts import StrictContract

EXECUTION_STATES = Literal[
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


class RecoveryRunRequest(StrictContract):
    execution_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )
    current_time: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)


class RecoveryDecisionModel(StrictContract):
    execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    state: EXECUTION_STATES
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    request_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    credential_chain_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    admission_outcome: Literal[
        "NEW_EXECUTION", "IDEMPOTENT_RETURN", "EXISTING_EXECUTION", "DENIED"
    ] | None = "EXISTING_EXECUTION"
    recovery_attempt_count: int = Field(ge=0)
    max_recovery_attempts: int = Field(ge=1)
    recovery_deadline: int = Field(ge=0)
    manual_review_required: bool
    result: dict[str, Any] | None = None
    business_effect_id: str | None = None
    receipt: dict[str, Any] | None = None


class RecoveryRunResponse(StrictContract):
    status: Literal["IDLE", "PROCESSED"]
    processed_count: int = Field(ge=0)
    decisions: list[RecoveryDecisionModel]
