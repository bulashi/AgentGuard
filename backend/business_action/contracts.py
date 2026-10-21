from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.authorization.contracts import BusinessIdentifier

IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class BusinessPaymentFact(StrictContract):
    transaction_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    amount_fen: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    status: Literal["SUCCESS", "FAILED", "PROCESSING"]
    refunded_amount_fen: int = Field(default=0, ge=0, le=MAX_SAFE_INTEGER)

    @model_validator(mode="after")
    def validate_refunded_amount(self) -> BusinessPaymentFact:
        if self.refunded_amount_fen > self.amount_fen:
            raise ValueError("previous refunds cannot exceed the payment amount")
        if self.status != "SUCCESS" and self.refunded_amount_fen != 0:
            raise ValueError("an unsuccessful payment cannot have a previous refund")
        return self


class BusinessOrderFact(StrictContract):
    order_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    amount_fen: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    currency: Literal["CNY"] = "CNY"


def _validate_fact_inputs(payments: list[BusinessPaymentFact], claim_text: str) -> None:
    if not claim_text.strip():
        raise ValueError("claim text must not be blank")
    if len({payment.transaction_id for payment in payments}) != len(payments):
        raise ValueError("payment transaction identifiers must be distinct")
    if sum(payment.amount_fen for payment in payments) > MAX_SAFE_INTEGER:
        raise ValueError("the combined payment amount exceeds the safe integer limit")


class RawBusinessFacts(StrictContract):
    schema_version: Literal["1.0"] = "1.0"
    order: BusinessOrderFact
    payments: list[BusinessPaymentFact] = Field(min_length=1, max_length=8)
    claim_text: str = Field(min_length=1, max_length=4000)

    @model_validator(mode="after")
    def validate_facts(self) -> RawBusinessFacts:
        _validate_fact_inputs(self.payments, self.claim_text)
        return self


class CreateBusinessCaseRequest(StrictContract):
    tenant_id: BusinessIdentifier
    customer_id: BusinessIdentifier
    ticket_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    order_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    order_amount_fen: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    claim_text: str = Field(min_length=1, max_length=4000)
    payments: list[BusinessPaymentFact] = Field(min_length=1, max_length=8)
    cloud_shareable: bool = False

    @model_validator(mode="after")
    def validate_facts(self) -> CreateBusinessCaseRequest:
        _validate_fact_inputs(self.payments, self.claim_text)
        return self

    def raw_facts(self) -> dict:
        return RawBusinessFacts(
            order=BusinessOrderFact(order_id=self.order_id, amount_fen=self.order_amount_fen),
            payments=self.payments,
            claim_text=self.claim_text,
        ).model_dump()


class CreateBusinessCaseResponse(StrictContract):
    ticket_id: str
    tenant_id: BusinessIdentifier
    customer_id: BusinessIdentifier
    title: str
    description: str
    status: Literal["OPEN"]
    cloud_shareable: bool
    business_facts: RawBusinessFacts
    facts_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: int = Field(ge=0, le=MAX_SAFE_INTEGER)


class EvaluateRefundFactsRequest(StrictContract):
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)


class BusinessFactEvaluationResponse(StrictContract):
    schema_version: Literal["1.0"]
    task_id: str
    ticket_id: str
    facts_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["VERIFIED", "REJECTED", "PENDING"]
    reason_code: str
    reason: str
    refundable_amount_fen: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    original_transaction_id: str | None
    evidence_ids: list[str]
    policy_version: Literal["duplicate-full-charge-v1"]
    evaluated_at: int = Field(ge=0, le=MAX_SAFE_INTEGER)


class ResolveRefundActionRequest(StrictContract):
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)


class ResolveNotificationActionRequest(StrictContract):
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    template_id: Literal["REFUND_SUCCESS"]
    related_business_effect_id: str = Field(
        min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )


class BusinessActionResponse(StrictContract):
    schema_version: Literal["1.0"]
    business_action_id: str = Field(
        min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )
    action_scope_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    tenant_id: BusinessIdentifier
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    tool_service: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    tool_name: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    trusted_action_slot: str = Field(
        min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN
    )
    created_at: int = Field(ge=0, le=9_007_199_254_740_991)
    status: Literal["ACTIVE", "COMMITTED", "RELEASED", "CONFLICT"]
