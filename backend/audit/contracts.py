from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from backend.authorization.contracts import IDENTIFIER_PATTERN, MAX_SAFE_INTEGER
from backend.gateway.contracts import StrictContract


class RejectedAuditEventModel(StrictContract):
    schema_version: Literal["1.0"]
    event_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    raw_request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    parser_stage: Literal["UTF8", "JSON", "DUPLICATE_KEY", "SCHEMA"]
    reason_code: Literal[
        "INVALID_UTF8",
        "MALFORMED_JSON",
        "DUPLICATE_FIELD",
        "REQUEST_SCHEMA_INVALID",
        "UNKNOWN_FIELD",
    ]
    source_context: dict[str, str]
    received_at: int = Field(ge=0, le=MAX_SAFE_INTEGER)


class AuditAppendRequest(StrictContract):
    max_events: int = Field(default=100, ge=1, le=10_000)


class AuditAppendResponse(StrictContract):
    appended_count: int = Field(ge=0)
    latest_event_sequence: int = Field(ge=0)
    latest_event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuditVerifyRequest(StrictContract):
    from_sequence: int = Field(default=1, ge=1, le=MAX_SAFE_INTEGER)
    include_independent_checkpoint: bool = True


class AuditVerifyResponse(StrictContract):
    valid: bool
    checked_events: int = Field(ge=0)
    latest_event_sequence: int = Field(ge=0)
    rollback_detected: bool
    first_invalid_sequence: int | None = Field(default=None, ge=1)


class CheckpointRunResponse(StrictContract):
    status: Literal["IDLE", "CREATED", "EXISTING"]
    checkpoint: dict[str, Any] | None = None
