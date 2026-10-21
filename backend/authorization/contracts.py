from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
BUSINESS_IDENTIFIER_PATTERN = (
    r"^[A-Za-z0-9\u3007\u3400-\u4dbf\u4e00-\u9fff]"
    r"[A-Za-z0-9\u3007\u3400-\u4dbf\u4e00-\u9fff._:()\u00b7\uff08\uff09-]*$"
)


def _exact_business_identifier(value: str) -> str:
    if re.fullmatch(BUSINESS_IDENTIFIER_PATTERN, value) is None:
        raise ValueError("business identifier contains a forbidden character")
    return value


BusinessIdentifier = Annotated[
    str, Field(min_length=1, max_length=128, pattern=BUSINESS_IDENTIFIER_PATTERN),
    AfterValidator(_exact_business_identifier),
]
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateTaskRequest(StrictContract):
    tenant_id: BusinessIdentifier
    ticket_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    customer_id: BusinessIdentifier
    refund_total_fen: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    max_tool_calls: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    expires_in_seconds: int = Field(ge=1, le=86_400)


class AuthorizeTaskRequest(StrictContract):
    confirmed: Literal[True]
    confirmer_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    holder_agent_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    holder_key_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    delegation_depth: int = Field(ge=0, le=16)


class TaskResponse(StrictContract):
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    status: Literal["PENDING_AUTHORIZATION", "AUTHORIZED", "CLOSED"]
