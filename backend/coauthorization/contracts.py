from __future__ import annotations

from typing import Annotated, Literal

from pydantic import ConfigDict, Field, model_validator

from backend.authorization.contracts import (
    BusinessIdentifier,
    IDENTIFIER_PATTERN,
    MAX_SAFE_INTEGER,
    StrictContract,
)

COAUTHORIZATION_DOMAIN = "AGENTGUARD|TASK_COAUTHORIZATION_APPROVAL|V1"
APPROVAL_PURPOSE = "TASK_COAUTHORIZATION_APPROVAL_V1"
APPROVAL_AUDIENCE = "agentguard-root-authorization"
MAX_BUNDLE_BYTES = 32_768

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)]
SafeInteger = Annotated[int, Field(ge=0, le=MAX_SAFE_INTEGER)]
Sm3Hex = Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]
ApprovalRole = Literal["ENTERPRISE_APPROVER", "FINANCE_APPROVER"]


class ExtensionContract(StrictContract):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class EmptyConstraints(ExtensionContract):
    pass


class TicketResources(ExtensionContract):
    ticket_ids: list[Identifier] = Field(min_length=1, max_length=1)


class CustomerResources(ExtensionContract):
    customer_ids: list[BusinessIdentifier] = Field(min_length=1, max_length=1)


class RefundResources(TicketResources):
    customer_ids: list[BusinessIdentifier] = Field(min_length=1, max_length=1)


class RefundConstraints(ExtensionContract):
    single_max_fen: SafeInteger


class NotificationConstraints(ExtensionContract):
    template_ids: list[Identifier] = Field(min_length=1, max_length=1)


class TicketCapability(ExtensionContract):
    service: Literal["ticket-service"]
    tool: Literal["ticket.read"]
    version: Literal["v1"]
    resources: TicketResources
    constraints: EmptyConstraints


class KnowledgeCapability(ExtensionContract):
    service: Literal["knowledge-service"]
    tool: Literal["knowledge.read_associated"]
    version: Literal["v1"]
    resources: TicketResources
    constraints: EmptyConstraints


class RefundCapability(ExtensionContract):
    service: Literal["refund-service"]
    tool: Literal["refund.create"]
    version: Literal["v1"]
    resources: RefundResources
    constraints: RefundConstraints


class NotificationCapability(ExtensionContract):
    service: Literal["notification-service"]
    tool: Literal["notification.send_template"]
    version: Literal["v1"]
    resources: CustomerResources
    constraints: NotificationConstraints


RootCapability = Annotated[
    TicketCapability | KnowledgeCapability | RefundCapability | NotificationCapability,
    Field(discriminator="tool"),
]


class Quotas(ExtensionContract):
    refund_total_fen: SafeInteger
    max_tool_calls: SafeInteger


class Holder(ExtensionContract):
    agent_id: Identifier
    key_id: Identifier


class RequiredSigner(ExtensionContract):
    subject_id: Identifier
    key_id: Identifier


class RequiredSigners(ExtensionContract):
    enterprise_approver: RequiredSigner
    finance_approver: RequiredSigner

    def for_role(self, role: ApprovalRole) -> RequiredSigner:
        if role == "ENTERPRISE_APPROVER":
            return self.enterprise_approver
        return self.finance_approver


class TrustedTask(ExtensionContract):
    tenant_id: BusinessIdentifier
    task_id: Identifier
    ticket_id: Identifier
    customer_id: BusinessIdentifier
    holder: Holder
    capabilities: list[RootCapability] = Field(min_length=4, max_length=4)
    quotas: Quotas
    not_before: SafeInteger
    expires_at: SafeInteger
    delegation_depth: int = Field(ge=0, le=16)
    status: Literal["PENDING_AUTHORIZATION", "AUTHORIZED", "CLOSED"]

    @model_validator(mode="after")
    def validate_task_scope(self) -> TrustedTask:
        if self.expires_at <= self.not_before:
            raise ValueError("task validity window must be nonempty")
        if len({item.tool for item in self.capabilities}) != 4:
            raise ValueError("all four distinct v1 root tools are required")
        for capability in self.capabilities:
            resources = capability.resources
            if isinstance(resources, TicketResources):
                if resources.ticket_ids != [self.ticket_id]:
                    raise ValueError("capability ticket scope differs from the trusted task")
            if isinstance(resources, (CustomerResources, RefundResources)):
                if resources.customer_ids != [self.customer_id]:
                    raise ValueError("capability customer scope differs from the trusted task")
            if isinstance(capability, RefundCapability):
                if capability.constraints.single_max_fen > self.quotas.refund_total_fen:
                    raise ValueError("single refund limit exceeds the task quota")
        return self


class TrustedApprovalPolicy(ExtensionContract):
    tenant_id: BusinessIdentifier
    revision: Identifier
    required_signers: RequiredSigners
    not_before: SafeInteger
    expires_at: SafeInteger

    @model_validator(mode="after")
    def validate_window(self) -> TrustedApprovalPolicy:
        if self.expires_at <= self.not_before:
            raise ValueError("policy validity window must be nonempty")
        return self


class ApprovalPayload(ExtensionContract):
    schema_version: Literal["1.0"]
    payload_type: Literal["COAUTHORIZATION_TASK_APPROVAL"]
    approval_purpose: Literal["TASK_COAUTHORIZATION_APPROVAL_V1"]
    verifier_audience: Literal["agentguard-root-authorization"]
    tenant_id: BusinessIdentifier
    task_id: Identifier
    ticket_id: Identifier
    customer_id: BusinessIdentifier
    capabilities_hash: Sm3Hex
    quotas: Quotas
    holder: Holder
    not_before: SafeInteger
    expires_at: SafeInteger
    delegation_depth: int = Field(ge=0, le=16)
    policy_revision: Identifier
    required_signers: RequiredSigners
    challenge_id: Identifier
    approval_not_before: SafeInteger
    approval_expires_at: SafeInteger

    @model_validator(mode="after")
    def validate_windows(self) -> ApprovalPayload:
        if self.expires_at <= self.not_before:
            raise ValueError("task validity window must be nonempty")
        if not (
            self.not_before <= self.approval_not_before
            < self.approval_expires_at <= self.expires_at
        ):
            raise ValueError("approval validity must fit within the task validity")
        return self


class ApprovalStatement(ExtensionContract):
    schema_version: Literal["1.0"]
    statement_type: Literal["COAUTHORIZATION_APPROVAL_STATEMENT"]
    approval_purpose: Literal["TASK_COAUTHORIZATION_APPROVAL_V1"]
    approval_payload_hash: Sm3Hex
    role: ApprovalRole
    subject_id: Identifier
    key_id: Identifier
    approved_at: SafeInteger


class ApprovalSignature(ExtensionContract):
    algorithm: Literal["SM2"]
    key_id: Identifier
    key_purpose: Literal["AUTHORIZATION_ROOT_SIGNING"]
    encoding: Literal["SM2_RS_HEX_128_LOWERCASE"]
    value: Annotated[str, Field(min_length=128, max_length=128, pattern=r"^[0-9a-f]{128}$")]
    signed_at: SafeInteger


class ApprovalEvidence(ExtensionContract):
    statement: ApprovalStatement
    signature: ApprovalSignature


class CoauthorizationBundle(ExtensionContract):
    payload: ApprovalPayload
    approvals: list[ApprovalEvidence] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def validate_roles(self) -> CoauthorizationBundle:
        if {item.statement.role for item in self.approvals} != {
            "ENTERPRISE_APPROVER", "FINANCE_APPROVER"
        }:
            raise ValueError("exactly one enterprise and one finance approval are required")
        return self


class TrustedChallenge(ExtensionContract):
    challenge_id: Identifier
    tenant_id: BusinessIdentifier
    task_id: Identifier
    policy_revision: Identifier
    approval_payload_hash: Sm3Hex
    issued_at: SafeInteger
    expires_at: SafeInteger
    status: Literal["PENDING", "CONSUMED", "REVOKED"]

    @model_validator(mode="after")
    def validate_window(self) -> TrustedChallenge:
        if self.expires_at <= self.issued_at:
            raise ValueError("challenge validity window must be nonempty")
        return self


class RegisteredApprovalKey(ExtensionContract):
    tenant_id: BusinessIdentifier
    subject_id: Identifier
    principal_id: Identifier
    key_id: Identifier
    role: ApprovalRole
    approval_purpose: Literal["TASK_COAUTHORIZATION_APPROVAL_V1"]
    signing_purpose: Literal["AUTHORIZATION_ROOT_SIGNING"]
    algorithm: Literal["SM2"]
    public_key_hex: Annotated[
        str, Field(min_length=128, max_length=128, pattern=r"^[0-9a-f]{128}$")
    ]
    status: Literal["ACTIVE", "RETIRED", "REVOKED", "COMPROMISED"]
    activated_at: SafeInteger
    expires_at: SafeInteger
    retired_at: SafeInteger | None
    revoked_at: SafeInteger | None
    compromised_at: SafeInteger | None

    @model_validator(mode="after")
    def validate_window(self) -> RegisteredApprovalKey:
        if self.expires_at <= self.activated_at:
            raise ValueError("registry key validity window must be nonempty")
        return self


class CreateChallengeRequest(ExtensionContract):
    holder_agent_id: Identifier
    holder_key_id: Identifier
    delegation_depth: int = Field(ge=0, le=16)


class ChallengeResponse(ExtensionContract):
    schema_version: Literal["1.0"] = "1.0"
    challenge_status: Literal["PENDING"] = "PENDING"
    payload: ApprovalPayload
    approval_payload_hash: Sm3Hex
    task_capabilities: list[RootCapability] = Field(min_length=4, max_length=4)
    signature_domain: Literal["AGENTGUARD|TASK_COAUTHORIZATION_APPROVAL|V1"] = COAUTHORIZATION_DOMAIN


class CoauthorizationResponse(ExtensionContract):
    schema_version: Literal["1.0"] = "1.0"
    challenge_id: Identifier
    approval_payload_hash: Sm3Hex
    bundle_hash: Sm3Hex
    root_credential_id: Identifier
    root_credential_hash: Sm3Hex
    reused: bool
    credential: dict


class CoauthorizationHistoryEntry(ExtensionContract):
    challenge_id: Identifier
    challenge_status: Literal["PENDING", "CONSUMED", "REVOKED"]
    window_state: Literal["NOT_YET_VALID", "OPEN", "EXPIRED"]
    issued_at: SafeInteger
    expires_at: SafeInteger
    consumed_at: SafeInteger | None
    revoked_at: SafeInteger | None
    payload: ApprovalPayload
    approval_payload_hash: Sm3Hex
    task_capabilities: list[RootCapability] = Field(min_length=4, max_length=4)
    bundle_hash: Sm3Hex | None
    signed_bundle: CoauthorizationBundle | None
    root_credential_id: Identifier | None
    root_credential_hash: Sm3Hex | None

    @model_validator(mode="after")
    def validate_stored_evidence(self) -> CoauthorizationHistoryEntry:
        payload = self.payload
        if (self.challenge_id, self.issued_at, self.expires_at) != (
            payload.challenge_id, payload.approval_not_before, payload.approval_expires_at
        ):
            raise ValueError("stored challenge window differs from payload")
        if len({capability.tool for capability in self.task_capabilities}) != 4:
            raise ValueError("four distinct stored capability types are required")
        if self.challenge_status == "CONSUMED":
            if any(value is None for value in (
                self.consumed_at, self.bundle_hash, self.signed_bundle,
                self.root_credential_id, self.root_credential_hash,
            )) or self.revoked_at is not None:
                raise ValueError("consumed challenge evidence is incomplete")
            if not self.issued_at <= self.consumed_at < self.expires_at:
                raise ValueError("consumption must be inside the approval window")
            if self.signed_bundle.payload != payload:
                raise ValueError("stored bundle payload differs from challenge")
            for evidence in self.signed_bundle.approvals:
                statement = evidence.statement
                required = payload.required_signers.for_role(statement.role)
                if (statement.subject_id, statement.key_id, statement.approval_payload_hash) != (
                    required.subject_id, required.key_id, self.approval_payload_hash
                ) or evidence.signature.key_id != statement.key_id or (
                    evidence.signature.signed_at != statement.approved_at
                ) or not self.issued_at <= statement.approved_at <= self.consumed_at:
                    raise ValueError("stored signer metadata differs from approved task")
        elif any(value is not None for value in (
            self.consumed_at, self.bundle_hash, self.signed_bundle,
            self.root_credential_id, self.root_credential_hash,
        )):
            raise ValueError("unconsumed challenge cannot have authorization evidence")
        if (self.challenge_status == "REVOKED") != (self.revoked_at is not None):
            raise ValueError("challenge revocation metadata differs from status")
        if self.revoked_at is not None and self.revoked_at < self.issued_at:
            raise ValueError("revocation cannot precede challenge issuance")
        return self


class CoauthorizationTaskReview(ExtensionContract):
    schema_version: Literal["1.0"] = "1.0"
    observation_kind: Literal["STORED_EVIDENCE_NOT_REVALIDATED"] = "STORED_EVIDENCE_NOT_REVALIDATED"
    task_id: Identifier
    task_status: Literal["PENDING_AUTHORIZATION", "AUTHORIZED", "CLOSED"]
    observed_at: SafeInteger
    offset: int = Field(ge=0, le=1_000_000)
    limit: Literal[20] = 20
    has_more: bool
    items: list[CoauthorizationHistoryEntry] = Field(max_length=20)
    signature_domain: Literal["AGENTGUARD|TASK_COAUTHORIZATION_APPROVAL|V1"] = COAUTHORIZATION_DOMAIN

    @model_validator(mode="after")
    def validate_observation(self) -> CoauthorizationTaskReview:
        if len({item.challenge_id for item in self.items}) != len(self.items):
            raise ValueError("duplicate history entries")
        for item in self.items:
            if item.payload.task_id != self.task_id:
                raise ValueError("history entry belongs to another task")
            expected = (
                "NOT_YET_VALID" if self.observed_at < item.issued_at else
                "EXPIRED" if self.observed_at >= item.expires_at else "OPEN"
            )
            if item.window_state != expected:
                raise ValueError("history window observation is inconsistent")
        return self


class PublicApprovalSetup(ExtensionContract):
    policy: TrustedApprovalPolicy
    keys: list[RegisteredApprovalKey] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def validate_registration(self) -> PublicApprovalSetup:
        if {key.role for key in self.keys} != {"ENTERPRISE_APPROVER", "FINANCE_APPROVER"}:
            raise ValueError("one public approval key per role is required")
        for key in self.keys:
            required = self.policy.required_signers.for_role(key.role)
            if (key.tenant_id, key.subject_id, key.key_id) != (
                self.policy.tenant_id, required.subject_id, required.key_id
            ):
                raise ValueError("public key binding differs from the policy")
            if key.status != "ACTIVE" or any(value is not None for value in (
                key.retired_at, key.revoked_at, key.compromised_at
            )):
                raise ValueError("newly registered approval keys must be active")
            if not key.activated_at <= self.policy.not_before < self.policy.expires_at <= key.expires_at:
                raise ValueError("policy validity must fit within both key validity windows")
        if len({key.principal_id for key in self.keys}) != 2 or len({key.subject_id for key in self.keys}) != 2:
            raise ValueError("two independent registered principals are required")
        if len({key.key_id for key in self.keys}) != 2 or len({key.public_key_hex for key in self.keys}) != 2:
            raise ValueError("two distinct public keys are required")
        return self
