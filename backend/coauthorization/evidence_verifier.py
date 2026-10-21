from __future__ import annotations

import hashlib
import hmac
import re
from functools import lru_cache

from jsonschema import ValidationError
from referencing import Resource

from backend.audit.service import AuditService
from backend.authorization.contracts import IDENTIFIER_PATTERN
from backend.coauthorization.audit import (
    MAX_EVIDENCE_BYTES,
    load_authorization_audit_schemas,
    validate_authorization_audit_evidence,
)
from backend.coauthorization.contracts import (
    APPROVAL_PURPOSE,
    PublicApprovalSetup,
    TrustedChallenge,
    TrustedTask,
)
from backend.coauthorization.public_keys import valid_public_point
from backend.coauthorization.verifier import CoauthorizationError, verify_coauthorization
from backend.common.enums import KeyPurpose
from backend.common.schema import PROJECT_ROOT, SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_CHECKPOINT, CAPABILITY_CREDENTIAL
from backend.crypto.sm import sm3_hex, verify_payload
from backend.crypto.strict_json import MAX_SAFE_INTEGER, parse_strict_json

MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_TRUST_BYTES = 65_536
MAX_CHECKPOINT_BYTES = 16_384
MAX_EVENTS = 10_000
SCHEMA_ROOT = PROJECT_ROOT / "protocol" / "extensions" / "coauthorization-evidence-v1"


class EvidenceVerificationError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__("coauthorization evidence verification refused")
        self.reason_code = reason_code


@lru_cache(maxsize=1)
def evidence_schemas() -> SchemaStore:
    schemas = SchemaStore(SCHEMA_ROOT)
    for source in (load_authorization_audit_schemas(), SchemaStore()):
        schemas.registry = schemas.registry.with_resources(
            (document["$id"], Resource.from_contents(document))
            for document in source.documents.values()
        )
    return schemas


def _document(raw: bytes, *, limit: int, schema: str) -> dict:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= limit:
            raise ValueError("invalid size")
        document = parse_strict_json(raw)
        if type(document) is not dict:
            raise ValueError("expected an object")
        evidence_schemas().validate(schema, document)
        return document
    except (ValueError, TypeError, RecursionError, ValidationError):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_INPUT_INVALID") from None


def _check_pin(raw: bytes, expected: str, *, limit: int) -> None:
    if (
        type(raw) is not bytes or not 0 < len(raw) <= limit
        or type(expected) is not str or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected)
    ):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_TRUST_PIN_MISMATCH")


def _check_expected(value: str, *, digest: bool = False) -> None:
    pattern = r"[0-9a-f]{64}" if digest else IDENTIFIER_PATTERN
    if type(value) is not str or not 1 <= len(value) <= 128 or re.fullmatch(pattern, value) is None:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_EXPECTATION_INVALID")


def validate_verification_expectations(task_id: str, root_id: str, approval_hash: str, observed_at: int) -> None:
    _check_expected(task_id)
    _check_expected(root_id)
    _check_expected(approval_hash, digest=True)
    if type(observed_at) is not int or not 0 <= observed_at <= MAX_SAFE_INTEGER:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_EXPECTATION_INVALID")


def load_pinned_trust_context(raw: bytes, trusted_sha256: str) -> dict:
    _check_pin(raw, trusted_sha256, limit=MAX_TRUST_BYTES)
    trust = _document(raw, limit=MAX_TRUST_BYTES, schema="trust-context.schema.json")
    try:
        setup = PublicApprovalSetup.model_validate(trust["approval_setup"])
    except (ValueError, TypeError, RecursionError):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_TRUST_CONTEXT_INVALID") from None
    runtime_keys = [trust["root_signer"], trust["checkpoint_signer"]]
    public_keys = [key.public_key_hex for key in setup.keys] + [key["public_key_hex"] for key in runtime_keys]
    key_ids = [key.key_id for key in setup.keys] + [key["key_id"] for key in runtime_keys]
    if (
        len(set(public_keys)) != 4 or len(set(key_ids)) != 4
        or any(not valid_public_point(key) for key in public_keys)
    ):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_TRUST_CONTEXT_INVALID")
    return trust


def _verify_runtime_signature(signed: dict, key: dict, *, purpose: KeyPurpose, domain: str) -> None:
    signature = signed["signature"]
    if signature["signed_at"] < key["activated_at"] or not verify_payload(
        signed["payload"], signature, domain_separator=domain,
        expected_key_id=key["key_id"], expected_key_purpose=purpose,
        public_key_hex=key["public_key_hex"],
    ):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_SIGNATURE_INVALID")


def verify_evidence_package(
    raw_package: bytes,
    *,
    raw_trust_context: bytes,
    trusted_context_sha256: str,
    raw_checkpoint: bytes,
    trusted_checkpoint_sha256: str,
    expected_task_id: str,
    expected_root_credential_id: str,
    expected_approval_payload_hash: str,
    observed_at: int,
) -> dict:
    """Verify a pinned prefix, without DB/network access, signing or live-state claims."""
    validate_verification_expectations(
        expected_task_id, expected_root_credential_id, expected_approval_payload_hash, observed_at
    )
    trust = load_pinned_trust_context(raw_trust_context, trusted_context_sha256)
    checkpoint = load_pinned_checkpoint(raw_checkpoint, trusted_checkpoint_sha256)
    package = _document(raw_package, limit=MAX_PACKAGE_BYTES, schema="package.schema.json")
    evidence = package["authorization_evidence"]
    try:
        if len(canonicalize(evidence, normalize_sets=False)) > MAX_EVIDENCE_BYTES:
            raise ValueError("oversized evidence")
        validate_authorization_audit_evidence(evidence)
        setup = PublicApprovalSetup.model_validate(trust["approval_setup"])
    except (ValueError, TypeError, RecursionError):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_BINDING_INVALID") from None
    if (
        evidence["task_id"] != expected_task_id
        or evidence["root_credential_id"] != expected_root_credential_id
        or evidence["approval_payload_hash"] != expected_approval_payload_hash
    ):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_EXPECTATION_MISMATCH")

    root_key, checkpoint_key = trust["root_signer"], trust["checkpoint_signer"]
    credential = evidence["credential"]
    root, payload = credential["payload"], evidence["signed_bundle"]["payload"]
    if not 1 <= payload["approval_expires_at"] - payload["approval_not_before"] <= 3600:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_BINDING_INVALID")
    if root["issuer"] != {"subject_id": root_key["subject_id"], "key_id": root_key["key_id"]}:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_SIGNER_MISMATCH")
    _verify_runtime_signature(
        credential, root_key, purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        domain=CAPABILITY_CREDENTIAL,
    )
    # Statuses reconstruct the signed evidence context, not a database observation.
    task = TrustedTask.model_validate({
        **{name: root[name] for name in (
            "tenant_id", "task_id", "holder", "capabilities", "quotas",
            "not_before", "expires_at", "delegation_depth",
        )},
        "ticket_id": payload["ticket_id"], "customer_id": payload["customer_id"],
        "status": "AUTHORIZED",
    })
    challenge = TrustedChallenge.model_validate({
        "challenge_id": payload["challenge_id"], "tenant_id": payload["tenant_id"],
        "task_id": payload["task_id"], "policy_revision": payload["policy_revision"],
        "approval_payload_hash": evidence["approval_payload_hash"],
        "issued_at": payload["approval_not_before"], "expires_at": payload["approval_expires_at"],
        "status": "CONSUMED",
    })

    def pinned_registry(**lookup):
        if lookup["approval_purpose"] != APPROVAL_PURPOSE or lookup["now"] != evidence["authorized_at"]:
            return None
        return next((key for key in setup.keys if (
            key.tenant_id, key.role, key.subject_id, key.key_id
        ) == (lookup["tenant_id"], lookup["role"], lookup["subject_id"], lookup["key_id"])), None)

    try:
        approvals = verify_coauthorization(
            canonicalize(evidence["signed_bundle"]), trusted_task=task,
            trusted_policy=setup.policy, trusted_challenge=challenge,
            now=evidence["authorized_at"], registry=pinned_registry,
            allow_existing_authorization=True,
        )
    except CoauthorizationError:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_APPROVAL_INVALID") from None

    anchor = checkpoint["payload"]
    if (
        checkpoint["signature"]["signed_at"] != anchor["timestamp"]
        or anchor["timestamp"] > observed_at
    ):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_CHECKPOINT_INVALID")
    _verify_runtime_signature(
        checkpoint, checkpoint_key, purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
        domain=AUDIT_CHECKPOINT,
    )
    events = package["audit_events"]
    if len(events) != anchor["latest_event_sequence"] or len(events) > MAX_EVENTS:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_PREFIX_INVALID")
    previous_hash = "0" * 64
    event_ids: set[str] = set()
    matched: list[int] = []
    target_hash = sm3_hex(canonicalize(evidence))
    for expected_sequence, event in enumerate(events, start=1):
        without_hash = {name: value for name, value in event.items() if name != "event_hash"}
        if (
            event["event_sequence"] != expected_sequence
            or event["event_id"] in event_ids
            or event["previous_event_hash"] != previous_hash
            or AuditService._event_hash(without_hash) != event["event_hash"]
            or event["timestamp"] > anchor["timestamp"]
        ):
            raise EvidenceVerificationError("COAUTH_EVIDENCE_PREFIX_INVALID")
        event_ids.add(event["event_id"])
        previous_hash = event["event_hash"]
        if event["evidence_reference"] == expected_root_credential_id:
            if (
                event["schema_version"] != "2.0" or event["event_type"] != "COAUTH_ROOT_AUTHORIZED"
                or event["execution_id"] is not None or event["payload_hash"] != target_hash
                or event["timestamp"] < evidence["authorized_at"]
            ):
                raise EvidenceVerificationError("COAUTH_EVIDENCE_AUDIT_BINDING_INVALID")
            matched.append(expected_sequence)
    if previous_hash != anchor["latest_event_hash"] or len(matched) != 1:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_AUDIT_BINDING_INVALID")
    result = {
        "schema_version": "1.0",
        "verification_scope": "COAUTHORIZATION_SIGNATURES_AND_PINNED_AUDIT_PREFIX",
        "verified": True,
        "task_id": expected_task_id,
        "root_credential_id": expected_root_credential_id,
        "approval_payload_hash": expected_approval_payload_hash,
        "root_credential_hash": evidence["root_credential_hash"],
        "authorized_at_claim": evidence["authorized_at"],
        "observed_at": observed_at,
        "verified_subject_ids": list(approvals.verified_subject_ids),
        "verified_principal_ids": list(approvals.verified_principal_ids),
        "checked_events": len(events),
        "authorization_event_sequence": matched[0],
        "checkpoint_sequence": anchor["checkpoint_sequence"],
        "checkpoint_latest_event_sequence": anchor["latest_event_sequence"],
        "trusted_context_sha256": trusted_context_sha256,
        "trusted_checkpoint_sha256": trusted_checkpoint_sha256,
        "package_sha256": hashlib.sha256(raw_package).hexdigest(),
        "authorizes_execution": False,
        "proves_current_revocation": False,
        "proves_challenge_consumption": False,
        "proves_business_side_effects": False,
        "proves_real_principal_independence": False,
        "proves_all_independent_anchors": False,
        "proves_other_event_payloads": False,
        "proves_latest_chain_head": False,
        "proves_trusted_wall_clock": False,
    }
    try:
        evidence_schemas().validate("verified-result.schema.json", result)
    except (ValidationError, ValueError, TypeError):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_RESULT_INVALID") from None
    return result


def load_pinned_checkpoint(raw: bytes, trusted_sha256: str) -> dict:
    """Read the frozen checkpoint shape only after checking its external byte pin."""
    _check_pin(raw, trusted_sha256, limit=MAX_CHECKPOINT_BYTES)
    try:
        document = parse_strict_json(raw)
        if type(document) is not dict:
            raise ValueError("expected an object")
        SchemaStore().validate("audit-checkpoint.schema.json", document)
        return document
    except (ValueError, TypeError, RecursionError, ValidationError):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_CHECKPOINT_INVALID") from None
