from __future__ import annotations

from typing import Any

from pydantic import Field

from backend.authorization.contracts import IDENTIFIER_PATTERN, MAX_SAFE_INTEGER
from backend.gateway.contracts import StrictContract


class ReceiptIssueRequest(StrictContract):
    execution_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    current_time: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)


class ReceiptIssueResponse(StrictContract):
    receipt: dict[str, Any]


class ReceiptHealthResponse(StrictContract):
    status: str
    service: str
