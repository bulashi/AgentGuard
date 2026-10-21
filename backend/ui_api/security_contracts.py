from __future__ import annotations

from typing import Literal

from pydantic import Field

from backend.agent_runtime.contracts import StrictContract
from backend.agent_runtime.security_proof import ProofKind


class ProofBudget(StrictContract):
    credential_id: str
    quota_type: Literal["refund_total_fen", "max_tool_calls"]
    limit: int = Field(ge=0)
    reserved: int = Field(ge=0)
    committed: int = Field(ge=0)
    remaining: int = Field(ge=0)
    version: int = Field(ge=0)


class ProofScope(StrictContract):
    type: Literal["task"]
    task_id: str


class ProofObservation(StrictContract):
    observed_at_ms: int = Field(ge=0)
    scope: ProofScope
    budgets: list[ProofBudget]
    refund_rows: int = Field(ge=0)
    notification_rows: int = Field(ge=0)
    refund_amount_fen: int = Field(ge=0)


class SignatureProjection(StrictContract):
    algorithm: Literal["SM2"]
    key_id: str
    key_purpose: str
    signed_at: int = Field(ge=0)
    fingerprint_sm3: str = Field(pattern=r"^[0-9a-f]{64}$")


class RefundParameters(StrictContract):
    ticket_id: str
    customer_id: str
    amount_fen: int = Field(gt=0)


class ProofRequestProjection(StrictContract):
    task_id: str
    tool_service: Literal["refund-service"]
    tool_name: Literal["refund.create"]
    tool_version: Literal["v1"]
    canonical_parameters: RefundParameters
    request_id: str
    issued_at: int = Field(ge=0)
    holder_key_id: str
    business_action_id: str
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    credential_chain_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    parameter_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    credential_ids: list[str] = Field(min_length=3, max_length=3)
    holder_signature: SignatureProjection


class ProofReceiptProjection(StrictContract):
    receipt_id: str
    receipt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_id: str
    signature: SignatureProjection


class ProofGatewayProjection(StrictContract):
    decision: Literal["ALLOW", "DENY"] | None
    state: str | None
    reason_code: str | None
    execution_id: str | None
    receipt: ProofReceiptProjection | None = None


class ProofAttempt(StrictContract):
    kind: Literal["wrong_customer", "over_amount", "legal_control"]
    request: ProofRequestProjection
    http_status: int = Field(ge=100, le=599)
    gateway: ProofGatewayProjection
    holder_proof_valid: bool
    chain_valid: bool
    receipt_valid: bool
    record_binding_valid: bool
    before: ProofObservation
    after: ProofObservation
    budget_unchanged: bool
    refund_delta: int
    notification_delta: int


class ProofChecks(StrictContract):
    denied_without_effect: bool
    legal_control_committed: bool


class SecurityProofResponse(StrictContract):
    schema_version: Literal["1.0"]
    proof_id: str = Field(pattern=r"^PROOF-[0-9a-f]{32}$")
    profile: Literal["AGENTGUARD_DETERMINISTIC_SECURITY_PROOF_V1"]
    observation_kind: Literal["operational_test_observation_not_signed_authorization"]
    candidate_origin: Literal["deterministic_security_probe"]
    llm_required: Literal[False]
    created_at_ms: int = Field(ge=0)
    kind: ProofKind
    task_id: str
    tenant_id: str
    ticket_id: str
    customer_id: str
    refund_limit_fen: int = Field(gt=0)
    status: Literal["PASS", "FAIL"]
    checks: ProofChecks
    attack: ProofAttempt
    control: ProofAttempt | None


class SecurityProofHistory(StrictContract):
    items: list[SecurityProofResponse] = Field(max_length=20)
