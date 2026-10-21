from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from jsonschema import ValidationError as SchemaValidationError
from pydantic import ValidationError as ContractValidationError

from backend.coauthorization.contracts import (
    APPROVAL_AUDIENCE,
    APPROVAL_PURPOSE,
    COAUTHORIZATION_DOMAIN,
    MAX_BUNDLE_BYTES,
    ApprovalPayload,
    ApprovalRole,
    ApprovalStatement,
    CoauthorizationBundle,
    RegisteredApprovalKey,
    TrustedApprovalPolicy,
    TrustedChallenge,
    TrustedTask,
)
from backend.common.enums import KeyPurpose
from backend.common.schema import PROJECT_ROOT, SchemaStore
from backend.crypto.canonical_json import CanonicalizationError, canonicalize
from backend.crypto.sm import sm3_hex, verify_payload
from backend.crypto.strict_json import MAX_SAFE_INTEGER, StrictJsonError, parse_strict_json

EXTENSION_SCHEMA_ROOT: Path = PROJECT_ROOT / "protocol" / "extensions" / "coauthorization-v1"


class CoauthorizationReason(StrEnum):
    DISABLED = "COAUTH_DISABLED"
    REQUIRED = "COAUTH_REQUIRED"
    POLICY_NOT_CONFIGURED = "COAUTH_POLICY_NOT_CONFIGURED"
    POLICY_NOT_ACTIVE = "COAUTH_POLICY_NOT_ACTIVE"
    CHALLENGE_CONFLICT = "COAUTH_CHALLENGE_CONFLICT"
    IDEMPOTENCY_CONFLICT = "COAUTH_IDEMPOTENCY_CONFLICT"
    ROOT_REVOKED_OR_INVALID = "COAUTH_ROOT_REVOKED_OR_INVALID"
    INVALID_BUNDLE = "COAUTH_INVALID_BUNDLE"
    INVALID_TRUSTED_CONTEXT = "COAUTH_INVALID_TRUSTED_CONTEXT"
    TASK_NOT_AUTHORIZABLE = "COAUTH_TASK_NOT_AUTHORIZABLE"
    TASK_EXPIRED_OR_NOT_YET_VALID = "COAUTH_TASK_EXPIRED_OR_NOT_YET_VALID"
    POLICY_EXPIRED_OR_NOT_YET_VALID = "COAUTH_POLICY_EXPIRED_OR_NOT_YET_VALID"
    CHALLENGE_NOT_PENDING = "COAUTH_CHALLENGE_NOT_PENDING"
    CHALLENGE_EXPIRED_OR_NOT_YET_VALID = "COAUTH_CHALLENGE_EXPIRED_OR_NOT_YET_VALID"
    TASK_OR_POLICY_MISMATCH = "COAUTH_TASK_OR_POLICY_MISMATCH"
    CHALLENGE_MISMATCH = "COAUTH_CHALLENGE_MISMATCH"
    SIGNER_MISMATCH = "COAUTH_SIGNER_MISMATCH"
    SAME_PRINCIPAL = "COAUTH_SAME_PRINCIPAL"
    SAME_KEY = "COAUTH_SAME_KEY"
    REGISTRY_UNAVAILABLE = "COAUTH_REGISTRY_UNAVAILABLE"
    STORED_EVIDENCE_INVALID = "COAUTH_STORED_EVIDENCE_INVALID"
    UNTRUSTED_KEY = "COAUTH_UNTRUSTED_KEY"
    KEY_NOT_ACTIVE = "COAUTH_KEY_NOT_ACTIVE"
    KEY_EXPIRED_OR_NOT_YET_VALID = "COAUTH_KEY_EXPIRED_OR_NOT_YET_VALID"
    APPROVAL_TIME_INVALID = "COAUTH_APPROVAL_TIME_INVALID"
    INVALID_SIGNATURE = "COAUTH_INVALID_SIGNATURE"


class CoauthorizationError(ValueError):
    def __init__(self, reason_code: CoauthorizationReason, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class ApprovalKeyRegistry(Protocol):
    def __call__(
        self,
        *,
        tenant_id: str,
        role: ApprovalRole,
        subject_id: str,
        key_id: str,
        approval_purpose: str,
        now: int,
    ) -> RegisteredApprovalKey | None: ...


@dataclass(frozen=True)
class VerifiedCoauthorizationEvidence:
    approval_payload_hash: str
    challenge_id: str
    verified_subject_ids: tuple[str, str]
    verified_key_ids: tuple[str, str]
    verified_principal_ids: tuple[str, str]
    verified_at: int
    required_next_step: str = "TRANSACTIONAL_CHALLENGE_CONSUMPTION"


def capabilities_hash(task: TrustedTask) -> str:
    # The wrapper preserves the frozen profile's set semantics for capabilities.
    return sm3_hex(canonicalize({
        "capabilities": [item.model_dump(mode="json") for item in task.capabilities]
    }))


def approval_payload_hash(payload: ApprovalPayload) -> str:
    return sm3_hex(canonicalize(payload.model_dump(mode="json")))


def build_approval_payload(
    *,
    task: TrustedTask,
    policy: TrustedApprovalPolicy,
    challenge_id: str,
    approval_not_before: int,
    approval_expires_at: int,
) -> ApprovalPayload:
    """Prepare data only, from trusted snapshots; does not approve or issue credentials."""
    task = TrustedTask.model_validate(task.model_dump(mode="json"))
    policy = TrustedApprovalPolicy.model_validate(policy.model_dump(mode="json"))
    if task.tenant_id != policy.tenant_id:
        raise ValueError("policy tenant differs from the trusted task")
    if not (
        policy.not_before <= approval_not_before < approval_expires_at <= policy.expires_at
    ):
        raise ValueError("approval window must fit within the trusted policy window")
    return ApprovalPayload.model_validate({
        "schema_version": "1.0",
        "payload_type": "COAUTHORIZATION_TASK_APPROVAL",
        "approval_purpose": APPROVAL_PURPOSE,
        "verifier_audience": APPROVAL_AUDIENCE,
        "tenant_id": task.tenant_id,
        "task_id": task.task_id,
        "ticket_id": task.ticket_id,
        "customer_id": task.customer_id,
        "capabilities_hash": capabilities_hash(task),
        "quotas": task.quotas.model_dump(mode="json"),
        "holder": task.holder.model_dump(mode="json"),
        "not_before": task.not_before,
        "expires_at": task.expires_at,
        "delegation_depth": task.delegation_depth,
        "policy_revision": policy.revision,
        "required_signers": policy.required_signers.model_dump(mode="json"),
        "challenge_id": challenge_id,
        "approval_not_before": approval_not_before,
        "approval_expires_at": approval_expires_at,
    })


def build_approval_statement(
    *,
    payload: ApprovalPayload,
    role: ApprovalRole,
    approved_at: int,
) -> ApprovalStatement:
    payload = ApprovalPayload.model_validate(payload.model_dump(mode="json"))
    if role not in {"ENTERPRISE_APPROVER", "FINANCE_APPROVER"}:
        raise ValueError("unknown approval role")
    if not payload.approval_not_before <= approved_at < payload.approval_expires_at:
        raise ValueError("approval time must be inside the signed approval window")
    signer = payload.required_signers.for_role(role)
    return ApprovalStatement.model_validate({
        "schema_version": "1.0",
        "statement_type": "COAUTHORIZATION_APPROVAL_STATEMENT",
        "approval_purpose": APPROVAL_PURPOSE,
        "approval_payload_hash": approval_payload_hash(payload),
        "role": role,
        "subject_id": signer.subject_id,
        "key_id": signer.key_id,
        "approved_at": approved_at,
    })


def _trusted_context(
    task: TrustedTask,
    policy: TrustedApprovalPolicy,
    challenge: TrustedChallenge,
    now: int,
) -> tuple[TrustedTask, TrustedApprovalPolicy, TrustedChallenge]:
    try:
        if type(now) is not int or not 0 <= now <= MAX_SAFE_INTEGER:
            raise ValueError("now must be a trusted nonnegative safe integer timestamp")
        return (
            TrustedTask.model_validate(task.model_dump(mode="json")),
            TrustedApprovalPolicy.model_validate(policy.model_dump(mode="json")),
            TrustedChallenge.model_validate(challenge.model_dump(mode="json")),
        )
    except (ContractValidationError, ValueError, AttributeError, TypeError) as exc:
        raise CoauthorizationError(
            CoauthorizationReason.INVALID_TRUSTED_CONTEXT, "invalid trusted context"
        ) from exc


def verify_coauthorization(
    raw_bundle: bytes,
    *,
    trusted_task: TrustedTask,
    trusted_policy: TrustedApprovalPolicy,
    trusted_challenge: TrustedChallenge,
    now: int,
    registry: ApprovalKeyRegistry,
    allow_existing_authorization: bool = False,
) -> VerifiedCoauthorizationEvidence:
    """Verify evidence only. This function never consumes a challenge or issues a root."""
    task, policy, challenge = _trusted_context(
        trusted_task, trusted_policy, trusted_challenge, now
    )
    if type(allow_existing_authorization) is not bool:
        raise CoauthorizationError(
            CoauthorizationReason.INVALID_TRUSTED_CONTEXT, "invalid verification mode"
        )
    try:
        if not isinstance(raw_bundle, bytes) or len(raw_bundle) > MAX_BUNDLE_BYTES:
            raise ValueError("bundle must be at most 32768 UTF-8 bytes")
        document = parse_strict_json(raw_bundle)
        SchemaStore(EXTENSION_SCHEMA_ROOT).validate("coauthorization-bundle.schema.json", document)
        bundle = CoauthorizationBundle.model_validate(document)
    except (
        StrictJsonError, SchemaValidationError, ContractValidationError,
        ValueError, TypeError, RecursionError,
    ) as exc:
        raise CoauthorizationError(
            CoauthorizationReason.INVALID_BUNDLE, "bundle violates the coauthorization v1 contract"
        ) from exc

    expected_task_status = "AUTHORIZED" if allow_existing_authorization else "PENDING_AUTHORIZATION"
    expected_challenge_status = "CONSUMED" if allow_existing_authorization else "PENDING"
    if task.status != expected_task_status:
        raise CoauthorizationError(
            CoauthorizationReason.TASK_NOT_AUTHORIZABLE, "task does not match the verification mode"
        )
    if not task.not_before <= now < task.expires_at:
        raise CoauthorizationError(
            CoauthorizationReason.TASK_EXPIRED_OR_NOT_YET_VALID, "task is outside its validity"
        )
    if not policy.not_before <= now < policy.expires_at:
        raise CoauthorizationError(
            CoauthorizationReason.POLICY_EXPIRED_OR_NOT_YET_VALID, "policy is outside its validity"
        )
    if challenge.status != expected_challenge_status:
        raise CoauthorizationError(
            CoauthorizationReason.CHALLENGE_NOT_PENDING, "challenge does not match the verification mode"
        )
    if not challenge.issued_at <= now < challenge.expires_at:
        raise CoauthorizationError(
            CoauthorizationReason.CHALLENGE_EXPIRED_OR_NOT_YET_VALID,
            "challenge is outside its validity",
        )
    if (challenge.tenant_id, challenge.task_id, challenge.policy_revision) != (
        task.tenant_id, task.task_id, policy.revision
    ):
        raise CoauthorizationError(
            CoauthorizationReason.CHALLENGE_MISMATCH, "challenge is not for this task and policy"
        )
    try:
        expected_payload = build_approval_payload(
            task=task, policy=policy, challenge_id=challenge.challenge_id,
            approval_not_before=challenge.issued_at, approval_expires_at=challenge.expires_at,
        )
    except (ContractValidationError, ValueError, CanonicalizationError) as exc:
        raise CoauthorizationError(
            CoauthorizationReason.INVALID_TRUSTED_CONTEXT,
            "trusted task, policy and challenge cannot produce a consistent approval payload",
        ) from exc
    digest = approval_payload_hash(expected_payload)
    if challenge.approval_payload_hash != digest:
        raise CoauthorizationError(
            CoauthorizationReason.CHALLENGE_MISMATCH,
            "trusted challenge does not bind the current task and policy snapshot",
        )
    if bundle.payload != expected_payload:
        raise CoauthorizationError(
            CoauthorizationReason.TASK_OR_POLICY_MISMATCH,
            "approval payload differs from the current trusted task, policy or challenge",
        )

    signers = policy.required_signers
    if signers.enterprise_approver.subject_id == signers.finance_approver.subject_id:
        raise CoauthorizationError(CoauthorizationReason.SAME_PRINCIPAL, "one subject has both roles")
    if signers.enterprise_approver.key_id == signers.finance_approver.key_id:
        raise CoauthorizationError(CoauthorizationReason.SAME_KEY, "one key id has both roles")

    records: list[RegisteredApprovalKey] = []
    subjects: list[str] = []
    keys: list[str] = []
    for role in ("ENTERPRISE_APPROVER", "FINANCE_APPROVER"):
        evidence = next(item for item in bundle.approvals if item.statement.role == role)
        statement = evidence.statement
        signature = evidence.signature
        required = signers.for_role(role)
        if (statement.subject_id, statement.key_id) != (required.subject_id, required.key_id):
            raise CoauthorizationError(
                CoauthorizationReason.SIGNER_MISMATCH, "approval signer is not the required signer"
            )
        if statement.approval_payload_hash != digest:
            raise CoauthorizationError(
                CoauthorizationReason.TASK_OR_POLICY_MISMATCH, "signers did not approve the same task"
            )
        if not challenge.issued_at <= statement.approved_at <= now:
            raise CoauthorizationError(
                CoauthorizationReason.APPROVAL_TIME_INVALID, "approval predates issuance or is future"
            )
        if signature.key_id != statement.key_id or signature.signed_at != statement.approved_at:
            raise CoauthorizationError(
                CoauthorizationReason.INVALID_SIGNATURE, "signature metadata differs from signed data"
            )
        try:
            record = registry(
                tenant_id=task.tenant_id, role=role, subject_id=required.subject_id,
                key_id=required.key_id, approval_purpose=APPROVAL_PURPOSE, now=now,
            )
        except Exception as exc:
            raise CoauthorizationError(
                CoauthorizationReason.REGISTRY_UNAVAILABLE, "trusted key registry lookup failed"
            ) from exc
        if not isinstance(record, RegisteredApprovalKey):
            raise CoauthorizationError(
                CoauthorizationReason.UNTRUSTED_KEY, "trusted registry did not return an approval key"
            )
        try:
            record = RegisteredApprovalKey.model_validate(record.model_dump(mode="json"))
        except (ContractValidationError, ValueError, TypeError) as exc:
            raise CoauthorizationError(
                CoauthorizationReason.UNTRUSTED_KEY, "trusted registry returned invalid key metadata"
            ) from exc
        if (record.tenant_id, record.role, record.subject_id, record.key_id) != (
            task.tenant_id, role, required.subject_id, required.key_id
        ):
            raise CoauthorizationError(
                CoauthorizationReason.UNTRUSTED_KEY, "registry identity or role binding mismatch"
            )
        if record.status != "ACTIVE" or any(value is not None for value in (
            record.retired_at, record.revoked_at, record.compromised_at
        )):
            raise CoauthorizationError(
                CoauthorizationReason.KEY_NOT_ACTIVE, "approval key is retired, revoked or compromised"
            )
        if not record.activated_at <= statement.approved_at <= now < record.expires_at:
            raise CoauthorizationError(
                CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID, "approval key is outside validity"
            )
        if not verify_payload(
            statement.model_dump(mode="json"), signature.model_dump(mode="json"),
            domain_separator=COAUTHORIZATION_DOMAIN, expected_key_id=required.key_id,
            expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            public_key_hex=record.public_key_hex,
        ):
            raise CoauthorizationError(
                CoauthorizationReason.INVALID_SIGNATURE, "SM2 approval verification failed"
            )
        records.append(record)
        subjects.append(required.subject_id)
        keys.append(required.key_id)

    if records[0].principal_id == records[1].principal_id:
        raise CoauthorizationError(
            CoauthorizationReason.SAME_PRINCIPAL, "two subject aliases resolve to one principal"
        )
    if records[0].public_key_hex == records[1].public_key_hex:
        raise CoauthorizationError(
            CoauthorizationReason.SAME_KEY, "two key ids resolve to the same SM2 public key"
        )
    return VerifiedCoauthorizationEvidence(
        approval_payload_hash=digest, challenge_id=challenge.challenge_id,
        verified_subject_ids=(subjects[0], subjects[1]),
        verified_key_ids=(keys[0], keys[1]),
        verified_principal_ids=(records[0].principal_id, records[1].principal_id),
        verified_at=now,
        required_next_step=(
            "RETURN_EXISTING_AUTHORIZATION" if allow_existing_authorization
            else "TRANSACTIONAL_CHALLENGE_CONSUMPTION"
        ),
    )
