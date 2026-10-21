from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

from jsonschema import ValidationError as SchemaValidationError

from backend.coauthorization.contracts import (
    APPROVAL_PURPOSE,
    COAUTHORIZATION_DOMAIN,
    MAX_BUNDLE_BYTES,
    ApprovalEvidence,
    ApprovalRole,
    ChallengeResponse,
    CoauthorizationBundle,
    PublicApprovalSetup,
    RegisteredApprovalKey,
    TrustedChallenge,
    TrustedTask,
)
from backend.coauthorization.public_keys import valid_public_point
from backend.coauthorization.verifier import (
    EXTENSION_SCHEMA_ROOT,
    CoauthorizationError,
    approval_payload_hash,
    build_approval_payload,
    build_approval_statement,
    capabilities_hash,
    verify_coauthorization,
)
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import (
    SM2_CURVE_ORDER,
    derive_public_key,
    sign_payload,
    verify_payload,
)
from backend.crypto.strict_json import MAX_SAFE_INTEGER, StrictJsonError, parse_strict_json


class OfflineApprovalError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class OfflineApprovalReview:
    challenge: ChallengeResponse
    setup: PublicApprovalSetup
    task: TrustedTask
    checked_at: int
    raw_challenge: bytes = field(repr=False)
    raw_public_setup: bytes = field(repr=False)
    trusted_setup_sha256: str
    expected_task_id: str
    expected_approval_payload_hash: str


def _safe_time(now: int) -> None:
    if type(now) is not int or not 0 <= now <= MAX_SAFE_INTEGER:
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_TIME_INVALID", "invalid local observation time"
        )


def _document(raw: bytes, schema_name: str) -> dict:
    try:
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BUNDLE_BYTES:
            raise ValueError("invalid document size")
        document = parse_strict_json(raw)
        if not isinstance(document, dict):
            raise ValueError("document must be an object")
        SchemaStore(EXTENSION_SCHEMA_ROOT).validate(schema_name, document)
        return document
    except (ValueError, TypeError, RecursionError, StrictJsonError, SchemaValidationError) as exc:
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_INPUT_INVALID", "document violates the bounded strict JSON contract"
        ) from exc


def review_approval_task(
    raw_challenge: bytes,
    raw_public_setup: bytes,
    *,
    trusted_setup_sha256: str,
    expected_task_id: str,
    expected_approval_payload_hash: str,
    now: int,
) -> OfflineApprovalReview:
    """Check pinned public snapshots, not live Authority state or challenge origin."""
    _safe_time(now)
    if (
        not isinstance(raw_public_setup, bytes) or not 0 < len(raw_public_setup) <= MAX_BUNDLE_BYTES
        or not isinstance(trusted_setup_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", trusted_setup_sha256) is None
        or not hmac.compare_digest(hashlib.sha256(raw_public_setup).hexdigest(), trusted_setup_sha256)
    ):
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_TRUST_PIN_MISMATCH",
            "public policy does not match the independently trusted pin",
        )
    try:
        setup = PublicApprovalSetup.model_validate(
            _document(raw_public_setup, "public-approval-setup.schema.json")
        )
        challenge = ChallengeResponse.model_validate(
            _document(raw_challenge, "challenge-response.schema.json")
        )
    except (ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, OfflineApprovalError):
            raise
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_INPUT_INVALID", "invalid public policy or challenge"
        ) from exc
    payload, policy = challenge.payload, setup.policy
    if (
        not isinstance(expected_task_id, str) or expected_task_id != payload.task_id
        or not isinstance(expected_approval_payload_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_approval_payload_hash) is None
        or not hmac.compare_digest(approval_payload_hash(payload), expected_approval_payload_hash)
        or challenge.approval_payload_hash != expected_approval_payload_hash
    ):
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_TASK_BINDING_MISMATCH",
            "task or approval digest differs from the operator's expected task",
        )
    if (payload.tenant_id, payload.policy_revision, payload.required_signers) != (
        policy.tenant_id, policy.revision, policy.required_signers
    ):
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_POLICY_MISMATCH", "challenge differs from pinned approval policy"
        )
    try:
        task = TrustedTask.model_validate({
            "tenant_id": payload.tenant_id, "task_id": payload.task_id,
            "ticket_id": payload.ticket_id, "customer_id": payload.customer_id,
            "holder": payload.holder.model_dump(mode="json"),
            "capabilities": [item.model_dump(mode="json") for item in challenge.task_capabilities],
            "quotas": payload.quotas.model_dump(mode="json"),
            "not_before": payload.not_before, "expires_at": payload.expires_at,
            "delegation_depth": payload.delegation_depth, "status": "PENDING_AUTHORIZATION",
        })
        expected_payload = build_approval_payload(
            task=task, policy=policy, challenge_id=payload.challenge_id,
            approval_not_before=payload.approval_not_before,
            approval_expires_at=payload.approval_expires_at,
        )
        if expected_payload != payload or capabilities_hash(task) != payload.capabilities_hash:
            raise ValueError("full capability scope differs from approval")
    except (ValueError, TypeError, RecursionError) as exc:
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_SCOPE_MISMATCH", "task scope or approval window differs"
        ) from exc
    if not 1 <= payload.approval_expires_at - payload.approval_not_before <= 3600:
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_TIME_INVALID", "challenge TTL is outside the v1 1-3600 second bound"
        )
    if not (
        task.not_before <= now < task.expires_at
        and policy.not_before <= now < policy.expires_at
        and payload.approval_not_before <= now < payload.approval_expires_at
    ):
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_TIME_INVALID", "task, policy or challenge is outside validity"
        )
    for key in setup.keys:
        if not valid_public_point(key.public_key_hex):
            raise OfflineApprovalError(
                "COAUTH_OFFLINE_KEY_INVALID", "registered approval key is not an SM2 curve point"
            )
        if not key.activated_at <= now < key.expires_at:
            raise OfflineApprovalError(
                "COAUTH_OFFLINE_TIME_INVALID", "registered approval key is outside validity"
            )
    return OfflineApprovalReview(
        challenge=challenge, setup=setup, task=task, checked_at=now,
        raw_challenge=raw_challenge, raw_public_setup=raw_public_setup,
        trusted_setup_sha256=trusted_setup_sha256, expected_task_id=expected_task_id,
        expected_approval_payload_hash=expected_approval_payload_hash,
    )


def _fresh_review(review: OfflineApprovalReview, now: int) -> OfflineApprovalReview:
    if not isinstance(review, OfflineApprovalReview):
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_INPUT_INVALID", "a checked offline review is required"
        )
    _safe_time(now)
    if now < review.checked_at:
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_TIME_INVALID", "local time moved backwards after review"
        )
    # Reparse the original bytes, not mutable nested models from a previous review.
    return review_approval_task(
        review.raw_challenge, review.raw_public_setup,
        trusted_setup_sha256=review.trusted_setup_sha256,
        expected_task_id=review.expected_task_id,
        expected_approval_payload_hash=review.expected_approval_payload_hash, now=now,
    )


def sign_approval(
    review: OfflineApprovalReview,
    *,
    role: ApprovalRole,
    expected_subject_id: str,
    expected_key_id: str,
    expected_principal_id: str,
    private_key_hex: str,
    now: int,
) -> ApprovalEvidence:
    """Sign one role with the caller's dedicated key; never issue a ROOT or consume state."""
    review = _fresh_review(review, now)
    record = next((key for key in review.setup.keys if key.role == role), None)
    if record is None or (record.subject_id, record.key_id, record.principal_id) != (
        expected_subject_id, expected_key_id, expected_principal_id
    ):
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_SIGNER_MISMATCH", "operator does not match the pinned approval role"
        )
    if (
        not isinstance(private_key_hex, str)
        or re.fullmatch(r"[0-9a-f]{64}", private_key_hex) is None
        or not 1 <= int(private_key_hex, 16) < SM2_CURVE_ORDER - 1
    ):
        raise OfflineApprovalError("COAUTH_OFFLINE_KEY_INVALID", "invalid SM2 signing scalar")
    if derive_public_key(private_key_hex) != record.public_key_hex:
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_PRIVATE_KEY_MISMATCH",
            "private key differs from the pinned role's public key",
        )
    statement = build_approval_statement(
        payload=review.challenge.payload, role=role, approved_at=now
    )
    try:
        signature = sign_payload(
            statement.model_dump(mode="json"), domain_separator=COAUTHORIZATION_DOMAIN,
            key_id=record.key_id, key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            private_key_hex=private_key_hex, public_key_hex=record.public_key_hex, signed_at=now,
        )
        evidence = ApprovalEvidence.model_validate({
            "statement": statement.model_dump(mode="json"), "signature": signature,
        })
        SchemaStore(EXTENSION_SCHEMA_ROOT).validate(
            "single-approval.schema.json", evidence.model_dump(mode="json")
        )
        if (
            evidence.signature.key_id != statement.key_id
            or evidence.signature.signed_at != statement.approved_at
            or not verify_payload(
                statement.model_dump(mode="json"), evidence.signature.model_dump(mode="json"),
                domain_separator=COAUTHORIZATION_DOMAIN, expected_key_id=record.key_id,
                expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
                public_key_hex=record.public_key_hex,
            )
        ):
            raise ValueError("new signature did not verify")
    except Exception as exc:
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_SIGNATURE_INVALID", "local SM2 signing or self-verification failed"
        ) from exc
    return evidence


def assemble_bundle(
    review: OfflineApprovalReview,
    raw_enterprise_approval: bytes,
    raw_finance_approval: bytes,
    *,
    now: int,
) -> bytes:
    """Verify two signatures against pinned snapshots; no live revocation or admission claim."""
    review = _fresh_review(review, now)
    try:
        enterprise = ApprovalEvidence.model_validate(
            _document(raw_enterprise_approval, "single-approval.schema.json")
        )
        finance = ApprovalEvidence.model_validate(
            _document(raw_finance_approval, "single-approval.schema.json")
        )
        if (enterprise.statement.role, finance.statement.role) != ("ENTERPRISE_APPROVER", "FINANCE_APPROVER"):
            raise ValueError("approval files do not match the requested roles")
        bundle = CoauthorizationBundle(payload=review.challenge.payload, approvals=[enterprise, finance])
        raw_bundle = canonicalize(bundle.model_dump(mode="json"))
        if len(raw_bundle) > MAX_BUNDLE_BYTES:
            raise ValueError("assembled bundle is too large")
    except (ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, OfflineApprovalError):
            raise
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_APPROVAL_INVALID",
            "single-role evidence cannot form the required bundle",
        ) from exc
    payload = review.challenge.payload
    challenge = TrustedChallenge(
        challenge_id=payload.challenge_id, tenant_id=payload.tenant_id, task_id=payload.task_id,
        policy_revision=payload.policy_revision,
        approval_payload_hash=review.challenge.approval_payload_hash,
        issued_at=payload.approval_not_before, expires_at=payload.approval_expires_at, status="PENDING",
    )

    def snapshot_registry(
        *, tenant_id: str, role: ApprovalRole, subject_id: str, key_id: str,
        approval_purpose: str, now: int,
    ) -> RegisteredApprovalKey | None:
        if approval_purpose != APPROVAL_PURPOSE or now != review.checked_at:
            return None
        return next((key for key in review.setup.keys if (
            key.tenant_id, key.role, key.subject_id, key.key_id
        ) == (tenant_id, role, subject_id, key_id)), None)

    try:
        verify_coauthorization(
            raw_bundle, trusted_task=review.task, trusted_policy=review.setup.policy,
            trusted_challenge=challenge, now=now, registry=snapshot_registry,
        )
    except CoauthorizationError as exc:
        raise OfflineApprovalError(
            exc.reason_code.value, "signatures do not satisfy the pinned offline approval context"
        ) from exc
    return raw_bundle
