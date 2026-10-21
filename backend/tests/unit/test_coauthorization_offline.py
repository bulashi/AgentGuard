"""Offline coauthorization test source; no execution or results are implied.

All identities, timestamps and altered hashes below are synthetic test inputs.
The key fixture calls the existing real SM2 generator only when tests are run;
it never reads, creates or persists deployment keys. Happy paths use real SM2.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from jsonschema import ValidationError as SchemaValidationError
from pydantic import ValidationError as ContractValidationError

from backend.coauthorization import offline
from backend.coauthorization.contracts import (
    APPROVAL_PURPOSE,
    COAUTHORIZATION_DOMAIN,
    MAX_BUNDLE_BYTES,
    ApprovalEvidence,
    ApprovalPayload,
    ApprovalRole,
    ChallengeResponse,
    CoauthorizationBundle,
    PublicApprovalSetup,
    TrustedApprovalPolicy,
    TrustedChallenge,
    TrustedTask,
)
from backend.coauthorization.public_keys import valid_public_point
from backend.coauthorization.verifier import (
    EXTENSION_SCHEMA_ROOT,
    CoauthorizationReason,
    approval_payload_hash,
    build_approval_payload,
    capabilities_hash,
    verify_coauthorization,
)
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import CAPABILITY_CREDENTIAL
from backend.crypto.sm import (
    SM2_CURVE_ORDER,
    SM2_SIGNATURE_ENCODING,
    SM2_USER_ID_UTF8,
    Sm2KeyPair,
    domain_message,
    generate_keypair,
    sign_payload,
    sm3_hex,
    verify_payload,
)
from backend.crypto.strict_json import MAX_SAFE_INTEGER, parse_strict_json

NOW = 1_800_000_120  # Synthetic observation time, never an observed result.
ROLES: tuple[ApprovalRole, ApprovalRole] = ("ENTERPRISE_APPROVER", "FINANCE_APPROVER")
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _wire(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class OfflineCase:
    task: TrustedTask
    setup: PublicApprovalSetup
    challenge: ChallengeResponse
    keypairs: dict[ApprovalRole, Sm2KeyPair]
    now: int

    @property
    def raw_challenge(self) -> bytes:
        return _wire(self.challenge.model_dump(mode="json"))

    @property
    def raw_setup(self) -> bytes:
        return _wire(self.setup.model_dump(mode="json"))


@pytest.fixture(scope="module")
def offline_keypairs() -> dict[ApprovalRole, Sm2KeyPair]:
    # Generation happens only in a future test run, with no key file I/O.
    return {role: generate_keypair() for role in ROLES}


def _make_case(
    keypairs: dict[ApprovalRole, Sm2KeyPair],
    *,
    now: int = NOW,
    task_id: str = "synthetic-task-offline-01",
) -> OfflineCase:
    task = TrustedTask.model_validate({
        "tenant_id": "synthetic-tenant-A",
        "task_id": task_id,
        "ticket_id": "synthetic-ticket-01",
        "customer_id": "synthetic-customer-01",
        "holder": {
            "agent_id": "synthetic-agent-coordinator",
            "key_id": "synthetic-holder-key-01",
        },
        "capabilities": [
            {
                "service": "ticket-service", "tool": "ticket.read", "version": "v1",
                "resources": {"ticket_ids": ["synthetic-ticket-01"]}, "constraints": {},
            },
            {
                "service": "knowledge-service", "tool": "knowledge.read_associated",
                "version": "v1", "resources": {"ticket_ids": ["synthetic-ticket-01"]},
                "constraints": {},
            },
            {
                "service": "refund-service", "tool": "refund.create", "version": "v1",
                "resources": {
                    "ticket_ids": ["synthetic-ticket-01"],
                    "customer_ids": ["synthetic-customer-01"],
                },
                "constraints": {"single_max_fen": 7000},
            },
            {
                "service": "notification-service", "tool": "notification.send_template",
                "version": "v1", "resources": {"customer_ids": ["synthetic-customer-01"]},
                "constraints": {"template_ids": ["SYNTHETIC_REFUND_SUCCESS"]},
            },
        ],
        "quotas": {"refund_total_fen": 7000, "max_tool_calls": 4},
        "not_before": max(0, now - 100), "expires_at": min(MAX_SAFE_INTEGER, now + 1800),
        "delegation_depth": 2, "status": "PENDING_AUTHORIZATION",
    })
    policy = TrustedApprovalPolicy.model_validate({
        "tenant_id": task.tenant_id, "revision": "synthetic-approval-policy-v1",
        "required_signers": {
            "enterprise_approver": {
                "subject_id": "synthetic-enterprise-approver",
                "key_id": "synthetic-enterprise-key",
            },
            "finance_approver": {
                "subject_id": "synthetic-finance-approver", "key_id": "synthetic-finance-key",
            },
        },
        "not_before": max(0, now - 200), "expires_at": min(MAX_SAFE_INTEGER, now + 2000),
    })
    keys = []
    for role in ROLES:
        required = policy.required_signers.for_role(role)
        keys.append({
            "tenant_id": task.tenant_id, "role": role,
            "subject_id": required.subject_id, "key_id": required.key_id,
            "principal_id": f"synthetic-principal-{role.lower()}",
            "approval_purpose": APPROVAL_PURPOSE,
            "signing_purpose": "AUTHORIZATION_ROOT_SIGNING", "algorithm": "SM2",
            "public_key_hex": keypairs[role].public_key_hex, "status": "ACTIVE",
            "activated_at": max(0, now - 1000),
            "expires_at": min(MAX_SAFE_INTEGER, now + 5000),
            "retired_at": None, "revoked_at": None, "compromised_at": None,
        })
    setup = PublicApprovalSetup.model_validate({"policy": policy.model_dump(), "keys": keys})
    payload = build_approval_payload(
        task=task, policy=policy, challenge_id="synthetic-challenge-offline-01",
        approval_not_before=max(0, now - 60),
        approval_expires_at=min(MAX_SAFE_INTEGER, now + 120),
    )
    challenge = ChallengeResponse(
        payload=payload, approval_payload_hash=approval_payload_hash(payload),
        task_capabilities=list(task.capabilities),
    )
    return OfflineCase(task, setup, challenge, keypairs, now)


@pytest.fixture
def offline_case(offline_keypairs) -> OfflineCase:
    return _make_case(offline_keypairs)


def _review(case: OfflineCase, **overrides) -> offline.OfflineApprovalReview:
    arguments = {
        "raw_challenge": case.raw_challenge, "raw_public_setup": case.raw_setup,
        "trusted_setup_sha256": hashlib.sha256(case.raw_setup).hexdigest(),
        "expected_task_id": case.task.task_id,
        "expected_approval_payload_hash": case.challenge.approval_payload_hash,
        "now": case.now,
    }
    arguments.update(overrides)
    return offline.review_approval_task(**arguments)


def _review_documents(case: OfflineCase, *, challenge=None, setup=None, **overrides):
    raw_setup = case.raw_setup if setup is None else _wire(setup)
    arguments = {
        "raw_challenge": case.raw_challenge if challenge is None else _wire(challenge),
        "raw_public_setup": raw_setup,
        "trusted_setup_sha256": hashlib.sha256(raw_setup).hexdigest(),
    }
    arguments.update(overrides)
    return _review(case, **arguments)


def _sign_arguments(case: OfflineCase, role: ApprovalRole = ROLES[0]) -> dict:
    record = next(key for key in case.setup.keys if key.role == role)
    return {
        "role": role, "expected_subject_id": record.subject_id, "expected_key_id": record.key_id,
        "expected_principal_id": record.principal_id,
        "private_key_hex": case.keypairs[role].private_key_hex, "now": case.now,
    }


def _sign(case: OfflineCase, review=None, *, role: ApprovalRole = ROLES[0], **overrides):
    arguments = _sign_arguments(case, role)
    arguments.update(overrides)
    return offline.sign_approval(_review(case) if review is None else review, **arguments)


@pytest.fixture
def signed_offline_case(offline_case):
    review = _review(offline_case)
    enterprise = _sign(offline_case, review, role=ROLES[0])
    finance = _sign(offline_case, review, role=ROLES[1])
    return (
        offline_case, review,
        _wire(enterprise.model_dump(mode="json")), _wire(finance.model_dump(mode="json")),
    )


def _assert_real_signature(case: OfflineCase, evidence: ApprovalEvidence, *, domain=None) -> None:
    record = next(key for key in case.setup.keys if key.role == evidence.statement.role)
    assert verify_payload(
        evidence.statement.model_dump(mode="json"), evidence.signature.model_dump(mode="json"),
        domain_separator=COAUTHORIZATION_DOMAIN if domain is None else domain,
        expected_key_id=record.key_id, expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=record.public_key_hex,
    )


def _verify_bundle(case: OfflineCase, raw: bytes, *, now: int):
    payload = case.challenge.payload
    challenge = TrustedChallenge(
        challenge_id=payload.challenge_id, tenant_id=payload.tenant_id, task_id=payload.task_id,
        policy_revision=payload.policy_revision,
        approval_payload_hash=case.challenge.approval_payload_hash,
        issued_at=payload.approval_not_before, expires_at=payload.approval_expires_at,
        status="PENDING",
    )
    lookups = []

    def registry(**lookup):
        lookups.append(lookup)
        assert lookup["now"] == now
        assert lookup["approval_purpose"] == APPROVAL_PURPOSE
        return next((key for key in case.setup.keys if (
            key.tenant_id, key.role, key.subject_id, key.key_id
        ) == (
            lookup["tenant_id"], lookup["role"], lookup["subject_id"], lookup["key_id"]
        )), None)

    verified = verify_coauthorization(
        raw, trusted_task=case.task, trusted_policy=case.setup.policy,
        trusted_challenge=challenge, now=now, registry=registry,
    )
    assert [lookup["role"] for lookup in lookups] == list(ROLES)
    assert challenge.status == "PENDING"
    return verified


def _assert_review_rejected(case: OfflineCase, reason: str, **overrides) -> None:
    output = None
    with pytest.raises(offline.OfflineApprovalError) as error:
        output = _review(case, **overrides)
    assert error.value.reason_code == reason
    assert output is None


def _assert_assembly_rejected(review, enterprise, finance, reason: str, *, now=NOW) -> None:
    output = None
    with pytest.raises(offline.OfflineApprovalError) as error:
        output = offline.assemble_bundle(review, enterprise, finance, now=now)
    assert error.value.reason_code == reason
    assert output is None


def _replace_integer_token(raw: bytes, field: str, token: bytes) -> bytes:
    pattern = rb'("' + field.encode("ascii") + rb'":)-?\d+'
    changed, count = re.subn(pattern, lambda match: match[1] + token, raw, count=1)
    assert count == 1
    return changed


def _bad_document(raw: bytes, kind: str, *, time_field: str) -> bytes:
    if kind == "invalid-utf8":
        return b"\xff" + raw
    if kind == "utf8-bom":
        return b"\xef\xbb\xbf" + raw
    if kind == "duplicate-root":
        key = next(iter(json.loads(raw)))
        return b"{" + json.dumps(key).encode("ascii") + b":null," + raw[1:]
    if kind == "duplicate-nested":
        field = b'"' + time_field.encode("ascii") + b'":'
        assert field in raw
        return raw.replace(field, field + b"0," + field, 1)
    if kind in {"extra-root", "extra-nested"}:
        document = json.loads(raw)
        target = document if kind == "extra-root" else document.get(
            "payload", document.get("policy", document.get("statement"))
        )
        target["unexpected"] = True
        return _wire(document)
    tokens = {
        "scientific": b"1.8e9", "decimal": b"1800000000.0", "boolean": b"true",
        "false": b"false", "unsafe": str(MAX_SAFE_INTEGER + 1).encode("ascii"),
        "unsafe-negative": str(-MAX_SAFE_INTEGER - 1).encode("ascii"),
        "negative": b"-1", "null-number": b"null", "nan": b"NaN", "infinity": b"Infinity",
    }
    if kind in tokens:
        return _replace_integer_token(raw, time_field, tokens[kind])
    literals = {"empty": b"", "whitespace": b" ", "array": b"[]", "null": b"null"}
    if kind in literals:
        return literals[kind]
    if kind == "oversize":
        assert len(raw) < MAX_BUNDLE_BYTES
        return raw + b" " * (MAX_BUNDLE_BYTES + 1 - len(raw))
    raise AssertionError(f"unknown synthetic mutation: {kind}")


def test_review_keeps_pinned_bytes_and_binds_full_original_task(offline_case) -> None:
    case = offline_case
    review = _review(case)
    assert review.raw_challenge == case.raw_challenge
    assert review.raw_public_setup == case.raw_setup
    assert review.trusted_setup_sha256 == hashlib.sha256(case.raw_setup).hexdigest()
    assert review.expected_task_id == case.task.task_id
    assert review.expected_approval_payload_hash == sm3_hex(
        canonicalize(case.challenge.payload.model_dump(mode="json"))
    )
    assert review.task.model_dump(mode="json") == case.task.model_dump(mode="json")
    assert capabilities_hash(review.task) == case.challenge.payload.capabilities_hash
    assert review.checked_at == case.now


@pytest.mark.parametrize("role", ROLES)
def test_sign_approval_returns_real_sm2_evidence_for_its_dedicated_role(offline_case, role) -> None:
    evidence = _sign(offline_case, role=role)
    record = next(key for key in offline_case.setup.keys if key.role == role)
    assert isinstance(evidence, ApprovalEvidence)
    assert evidence.statement.role == role
    assert (evidence.statement.subject_id, evidence.statement.key_id) == (
        record.subject_id, record.key_id,
    )
    assert evidence.statement.approval_payload_hash == offline_case.challenge.approval_payload_hash
    assert evidence.statement.approved_at == evidence.signature.signed_at == NOW
    _assert_real_signature(offline_case, evidence)


def test_assemble_two_real_signatures_uses_role_order_and_current_now(offline_case) -> None:
    case = offline_case
    review = _review(case)
    enterprise = _sign(case, review, role=ROLES[0], now=NOW + 1)
    finance = _sign(case, review, role=ROLES[1], now=NOW + 2)
    raw = offline.assemble_bundle(
        review, _wire(enterprise.model_dump(mode="json")), _wire(finance.model_dump(mode="json")),
        now=NOW + 3,
    )
    bundle = CoauthorizationBundle.model_validate(parse_strict_json(raw))
    assert raw == canonicalize(bundle.model_dump(mode="json"))
    assert len(raw) <= MAX_BUNDLE_BYTES
    assert [item.statement.role for item in bundle.approvals] == list(ROLES)
    assert bundle.payload == case.challenge.payload
    verified = _verify_bundle(case, raw, now=NOW + 3)
    assert verified.verified_at == NOW + 3
    assert verified.approval_payload_hash == case.challenge.approval_payload_hash
    assert verified.required_next_step == "TRANSACTIONAL_CHALLENGE_CONSUMPTION"


def test_single_approval_schema_reuses_existing_evidence_and_frozen_crypto_profile(
    signed_offline_case,
) -> None:
    case, _, enterprise, finance = signed_offline_case
    schemas = SchemaStore(EXTENSION_SCHEMA_ROOT)
    reference = "common.schema.json#/$defs/approvalEvidence"
    assert schemas.documents["single-approval.schema.json"]["$ref"] == reference
    assert schemas.documents["coauthorization-bundle.schema.json"]["properties"]["approvals"][
        "items"
    ] == {"$ref": reference}
    profile = json.loads((PROJECT_ROOT / "protocol" / "crypto-profile.json").read_text(
        encoding="utf-8"
    ))
    assert COAUTHORIZATION_DOMAIN == "AGENTGUARD|TASK_COAUTHORIZATION_APPROVAL|V1"
    assert APPROVAL_PURPOSE == "TASK_COAUTHORIZATION_APPROVAL_V1"
    assert profile["signature_algorithm"] == "SM2-with-SM3"
    assert profile["sm2_user_id_utf8"] == SM2_USER_ID_UTF8 == "1234567812345678"
    assert profile["signature_encoding"] == SM2_SIGNATURE_ENCODING
    assert profile["hash_algorithm"] == "SM3"
    assert profile["public_key_encoding"] == "SM2_XY_HEX_128_LOWERCASE_NO_04_PREFIX"
    assert profile["private_key_encoding"] == "HEX_64_LOWERCASE"
    assert profile["signed_message"] == (
        "UTF8(domain_separator) || 0x00 || RFC8785_AGENTGUARD_PROFILE(payload)"
    )
    for raw in (enterprise, finance):
        document = parse_strict_json(raw)
        schemas.validate("single-approval.schema.json", document)
        evidence = ApprovalEvidence.model_validate(document)
        assert evidence.model_dump(mode="json") == document
        assert set(document) == {"statement", "signature"}
        assert evidence.signature.algorithm == "SM2"
        assert evidence.signature.key_purpose == KeyPurpose.AUTHORIZATION_ROOT_SIGNING.value
        assert evidence.signature.encoding == SM2_SIGNATURE_ENCODING
        assert domain_message(COAUTHORIZATION_DOMAIN, document["statement"]) == (
            COAUTHORIZATION_DOMAIN.encode("utf-8") + b"\x00" + canonicalize(document["statement"])
        )
        _assert_real_signature(case, evidence)


@pytest.mark.parametrize("document_kind", ["challenge", "setup"])
@pytest.mark.parametrize("mutation", [
    "invalid-utf8", "utf8-bom", "duplicate-root", "duplicate-nested",
    "extra-root", "extra-nested", "scientific", "decimal", "boolean", "false",
    "unsafe", "unsafe-negative", "negative", "null-number", "nan", "infinity",
    "empty", "whitespace", "array", "null", "oversize",
])
def test_review_rejects_bounded_strict_json_violations(
    offline_case, document_kind, mutation,
) -> None:
    case = offline_case
    raw = case.raw_challenge if document_kind == "challenge" else case.raw_setup
    malformed = _bad_document(raw, mutation, time_field="not_before")
    if document_kind == "challenge":
        arguments = {"raw_challenge": malformed}
        reason = "COAUTH_OFFLINE_INPUT_INVALID"
    else:
        # Repin deliberately malformed bytes to reach parsing rather than a wrong-pin failure.
        arguments = {
            "raw_public_setup": malformed,
            "trusted_setup_sha256": hashlib.sha256(malformed).hexdigest(),
        }
        reason = (
            "COAUTH_OFFLINE_TRUST_PIN_MISMATCH" if mutation in {"empty", "oversize"}
            else "COAUTH_OFFLINE_INPUT_INVALID"
        )
    _assert_review_rejected(case, reason, **arguments)


@pytest.mark.parametrize("document_kind", ["challenge", "setup"])
@pytest.mark.parametrize("representation", ["text", "bytearray", "memoryview", "none"])
def test_review_requires_bytes_instead_of_coercing_other_input_types(
    offline_case, document_kind, representation,
) -> None:
    raw = offline_case.raw_challenge if document_kind == "challenge" else offline_case.raw_setup
    values = {
        "text": raw.decode("utf-8"), "bytearray": bytearray(raw),
        "memoryview": memoryview(raw), "none": None,
    }
    argument = "raw_challenge" if document_kind == "challenge" else "raw_public_setup"
    reason = (
        "COAUTH_OFFLINE_INPUT_INVALID" if document_kind == "challenge"
        else "COAUTH_OFFLINE_TRUST_PIN_MISMATCH"
    )
    _assert_review_rejected(offline_case, reason, **{argument: values[representation]})


def test_review_accepts_exact_size_boundary_with_an_exact_pin(offline_case) -> None:
    case = offline_case
    challenge = case.raw_challenge + b" " * (MAX_BUNDLE_BYTES - len(case.raw_challenge))
    setup = case.raw_setup + b" " * (MAX_BUNDLE_BYTES - len(case.raw_setup))
    assert len(challenge) == len(setup) == MAX_BUNDLE_BYTES
    review = _review(
        case, raw_challenge=challenge, raw_public_setup=setup,
        trusted_setup_sha256=hashlib.sha256(setup).hexdigest(),
    )
    assert review.task == case.task
    assert review.raw_challenge == challenge
    assert review.raw_public_setup == setup


@pytest.mark.parametrize("pin", [
    "0" * 64, "A" * 64, "g" * 64, "a" * 63, "a" * 65, "", None, True, b"a" * 64,
])
def test_public_setup_sha256_pin_is_required_and_fail_closed(offline_case, pin) -> None:
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_TRUST_PIN_MISMATCH", trusted_setup_sha256=pin,
    )


def test_semantically_identical_setup_bytes_still_require_their_exact_sha256_pin(
    offline_case,
) -> None:
    altered = offline_case.raw_setup + b"\n"
    assert json.loads(altered) == json.loads(offline_case.raw_setup)
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_TRUST_PIN_MISMATCH", raw_public_setup=altered,
    )
    assert _review(
        offline_case, raw_public_setup=altered,
        trusted_setup_sha256=hashlib.sha256(altered).hexdigest(),
    ).task == offline_case.task


@pytest.mark.parametrize(("field", "value"), [
    ("expected_task_id", "synthetic-other-task"), ("expected_task_id", ""),
    ("expected_task_id", None), ("expected_task_id", True), ("expected_task_id", 1),
    ("expected_approval_payload_hash", "0" * 64), ("expected_approval_payload_hash", "A" * 64),
    ("expected_approval_payload_hash", "g" * 64), ("expected_approval_payload_hash", "a" * 63),
    ("expected_approval_payload_hash", "a" * 65), ("expected_approval_payload_hash", ""),
    ("expected_approval_payload_hash", None), ("expected_approval_payload_hash", True),
    ("expected_approval_payload_hash", b"a" * 64),
])
def test_operator_expected_task_and_hash_are_out_of_band_requirements(
    offline_case, field, value,
) -> None:
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_TASK_BINDING_MISMATCH", **{field: value},
    )


def test_challenge_advertised_hash_must_match_its_payload_and_operator_hash(offline_case) -> None:
    document = offline_case.challenge.model_dump(mode="json")
    document["approval_payload_hash"] = "0" * 64  # Deliberately false synthetic digest.
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_TASK_BINDING_MISMATCH", raw_challenge=_wire(document),
    )


def _set_path(document: dict, path: tuple, value) -> None:
    target = document
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = deepcopy(value)


def _rehash_challenge(document: dict) -> str:
    digest = approval_payload_hash(ApprovalPayload.model_validate(document["payload"]))
    document["approval_payload_hash"] = digest
    return digest


@pytest.mark.parametrize(("path", "value"), [
    (("task_id",), "synthetic-other-task"),
    (("ticket_id",), "synthetic-other-ticket"),
    (("customer_id",), "synthetic-other-customer"),
    (("quotas", "refund_total_fen"), 7001), (("quotas", "max_tool_calls"), 5),
    (("holder", "agent_id"), "synthetic-other-agent"),
    (("holder", "key_id"), "synthetic-other-holder-key"),
    (("delegation_depth",), 3), (("expires_at",), NOW + 1799),
])
def test_expected_payload_hash_binds_task_identity_scope_limits_holder_and_window(
    offline_case, path, value,
) -> None:
    document = offline_case.challenge.model_dump(mode="json")
    _set_path(document["payload"], path, value)
    _rehash_challenge(document)
    assert document["approval_payload_hash"] != offline_case.challenge.approval_payload_hash
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_TASK_BINDING_MISMATCH", raw_challenge=_wire(document),
    )


@pytest.mark.parametrize(("path", "value"), [
    ((0, "resources", "ticket_ids"), ["synthetic-other-ticket"]),
    ((2, "resources", "customer_ids"), ["synthetic-other-customer"]),
    ((3, "resources", "customer_ids"), ["synthetic-other-customer"]),
    ((2, "constraints", "single_max_fen"), 6999),
    ((2, "constraints", "single_max_fen"), 7001),
    ((3, "constraints", "template_ids"), ["SYNTHETIC_OTHER_TEMPLATE"]),
])
def test_matching_payload_hash_cannot_replace_full_capability_binding(
    offline_case, path, value,
) -> None:
    document = offline_case.challenge.model_dump(mode="json")
    _set_path(document["task_capabilities"], path, value)
    assert _rehash_challenge(document) == offline_case.challenge.approval_payload_hash
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_SCOPE_MISMATCH", raw_challenge=_wire(document),
    )


@pytest.mark.parametrize(("path", "value"), [
    (("ticket_id",), "synthetic-other-ticket"),
    (("customer_id",), "synthetic-other-customer"),
    (("quotas", "refund_total_fen"), 6999), (("capabilities_hash",), "0" * 64),
])
def test_even_an_expected_rehashed_payload_must_match_the_full_unsigned_task(
    offline_case, path, value,
) -> None:
    document = offline_case.challenge.model_dump(mode="json")
    _set_path(document["payload"], path, value)
    digest = _rehash_challenge(document)
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_SCOPE_MISMATCH", raw_challenge=_wire(document),
        expected_approval_payload_hash=digest,
    )


@pytest.mark.parametrize("mutation", [
    "missing-tool", "duplicate-tool", "unknown-tool", "wrong-service", "wrong-version",
    "empty-ticket", "extra-template", "extra-constraint",
])
def test_full_capability_contract_rejects_omitted_expanded_or_wrong_tools(
    offline_case, mutation,
) -> None:
    document = offline_case.challenge.model_dump(mode="json")
    capabilities = document["task_capabilities"]
    if mutation == "missing-tool":
        capabilities.pop()
    elif mutation == "duplicate-tool":
        capabilities[1] = deepcopy(capabilities[0])
    elif mutation == "unknown-tool":
        capabilities[0]["tool"] = "ticket.write"
    elif mutation == "wrong-service":
        capabilities[0]["service"] = "refund-service"
    elif mutation == "wrong-version":
        capabilities[0]["version"] = "v2"
    elif mutation == "empty-ticket":
        capabilities[0]["resources"]["ticket_ids"] = []
    elif mutation == "extra-template":
        capabilities[3]["constraints"]["template_ids"].append("SYNTHETIC_OTHER_TEMPLATE")
    else:
        capabilities[0]["constraints"]["unbounded"] = True
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_INPUT_INVALID", raw_challenge=_wire(document),
    )


def test_capability_order_uses_existing_frozen_set_semantics(offline_case) -> None:
    document = offline_case.challenge.model_dump(mode="json")
    document["task_capabilities"].reverse()
    review = _review_documents(offline_case, challenge=document)
    assert capabilities_hash(review.task) == capabilities_hash(offline_case.task)
    assert review.expected_approval_payload_hash == offline_case.challenge.approval_payload_hash


@pytest.mark.parametrize("mutation", ["revision", "tenant", "role-subject", "role-key"])
def test_challenge_must_match_the_pinned_policy_revision_tenant_and_role_keys(
    offline_case, mutation,
) -> None:
    document = offline_case.setup.model_dump(mode="json")
    if mutation == "revision":
        document["policy"]["revision"] = "synthetic-policy-v2"
    elif mutation == "tenant":
        document["policy"]["tenant_id"] = "synthetic-tenant-B"
        for record in document["keys"]:
            record["tenant_id"] = "synthetic-tenant-B"
    else:
        field = "subject_id" if mutation == "role-subject" else "key_id"
        value = "synthetic-finance-replacement"
        document["policy"]["required_signers"]["finance_approver"][field] = value
        document["keys"][1][field] = value
    PublicApprovalSetup.model_validate(document)
    raw = _wire(document)
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_POLICY_MISMATCH", raw_public_setup=raw,
        trusted_setup_sha256=hashlib.sha256(raw).hexdigest(),
    )


@pytest.mark.parametrize("mutation", [
    "tenant", "subject", "key-id", "swapped-roles", "duplicate-role", "principal-alias",
    "subject-alias", "key-id-alias", "same-public-key", "retired", "revoked", "compromised",
    "revocation-marker", "private-material", "policy-outside-key-window",
])
def test_pinned_setup_rejects_invalid_bindings_aliases_and_key_state(
    offline_case, mutation,
) -> None:
    document = offline_case.setup.model_dump(mode="json")
    first, second = document["keys"]
    if mutation in {"tenant", "subject", "key-id"}:
        field = {"tenant": "tenant_id", "subject": "subject_id", "key-id": "key_id"}[mutation]
        second[field] = "synthetic-unbound-identity"
    elif mutation == "swapped-roles":
        first["role"], second["role"] = second["role"], first["role"]
    elif mutation == "duplicate-role":
        second["role"] = first["role"]
    elif mutation == "principal-alias":
        second["principal_id"] = first["principal_id"]
    elif mutation in {"subject-alias", "key-id-alias"}:
        field = "subject_id" if mutation == "subject-alias" else "key_id"
        second[field] = first[field]
        document["policy"]["required_signers"]["finance_approver"][field] = first[field]
    elif mutation == "same-public-key":
        second["public_key_hex"] = first["public_key_hex"]
    elif mutation in {"retired", "revoked", "compromised"}:
        second["status"] = mutation.upper()
        second[f"{mutation}_at"] = NOW - 1
    elif mutation == "revocation-marker":
        second["revoked_at"] = NOW - 1
    elif mutation == "private-material":
        second["private_key_hex"] = "synthetic-not-a-private-key"
    else:
        second["expires_at"] = document["policy"]["expires_at"] - 1
    raw = _wire(document)
    _assert_review_rejected(
        offline_case, "COAUTH_OFFLINE_INPUT_INVALID", raw_public_setup=raw,
        trusted_setup_sha256=hashlib.sha256(raw).hexdigest(),
    )


@pytest.mark.parametrize("now", [
    NOW - 1001, NOW - 201, NOW - 101, NOW - 61,
    NOW + 120, NOW + 1800, NOW + 2000, NOW + 5000,
])
def test_review_rejects_future_or_expired_task_policy_challenge_and_key_windows(
    offline_case, now,
) -> None:
    _assert_review_rejected(offline_case, "COAUTH_OFFLINE_TIME_INVALID", now=now)


@pytest.mark.parametrize("now", [NOW - 60, NOW + 119])
def test_review_accepts_the_half_open_challenge_window_boundaries(offline_case, now) -> None:
    assert _review(offline_case, now=now).checked_at == now


@pytest.mark.parametrize("now", [True, False, -1, MAX_SAFE_INTEGER + 1, 1.0, "1800000120", None])
def test_review_current_time_requires_a_non_boolean_nonnegative_safe_integer(
    offline_case, now,
) -> None:
    _assert_review_rejected(offline_case, "COAUTH_OFFLINE_TIME_INVALID", now=now)


@pytest.mark.parametrize("now", [0, MAX_SAFE_INTEGER - 1])
def test_safe_integer_time_edges_work_when_all_validity_windows_cover_now(
    offline_keypairs, now,
) -> None:
    case = _make_case(offline_keypairs, now=now)
    review = _review(case)
    assert review.checked_at == now
    evidence = _sign(case, review)
    assert evidence.statement.approved_at == evidence.signature.signed_at == now
    _assert_real_signature(case, evidence)


def _case_with_ttl(case: OfflineCase, ttl: int) -> OfflineCase:
    task_document = case.task.model_dump(mode="json")
    task_document["expires_at"] = NOW + 5000
    task = TrustedTask.model_validate(task_document)
    setup_document = case.setup.model_dump(mode="json")
    setup_document["policy"]["expires_at"] = NOW + 6000
    for record in setup_document["keys"]:
        record["expires_at"] = NOW + 7000
    setup = PublicApprovalSetup.model_validate(setup_document)
    payload = build_approval_payload(
        task=task, policy=setup.policy, challenge_id=case.challenge.payload.challenge_id,
        approval_not_before=NOW, approval_expires_at=NOW + ttl,
    )
    challenge = ChallengeResponse(
        payload=payload, approval_payload_hash=approval_payload_hash(payload),
        task_capabilities=list(task.capabilities),
    )
    return OfflineCase(task, setup, challenge, case.keypairs, NOW)


def _assert_window_and_digest_preconditions(case: OfflineCase) -> None:
    payload, policy = case.challenge.payload, case.setup.policy
    assert case.task.not_before <= payload.approval_not_before < payload.approval_expires_at
    assert payload.approval_expires_at <= case.task.expires_at
    assert policy.not_before <= payload.approval_not_before < payload.approval_expires_at
    assert payload.approval_expires_at <= policy.expires_at
    assert case.task.not_before <= NOW < case.task.expires_at
    assert policy.not_before <= NOW < policy.expires_at
    assert payload.approval_not_before <= NOW < payload.approval_expires_at
    for record in case.setup.keys:
        assert record.activated_at <= policy.not_before < policy.expires_at <= record.expires_at
        assert record.activated_at <= NOW < record.expires_at
        assert valid_public_point(record.public_key_hex)
    assert case.challenge.approval_payload_hash == approval_payload_hash(payload)
    assert payload.capabilities_hash == capabilities_hash(case.task)
    schemas = SchemaStore(EXTENSION_SCHEMA_ROOT)
    schemas.validate("challenge-response.schema.json", case.challenge.model_dump(mode="json"))
    schemas.validate("public-approval-setup.schema.json", case.setup.model_dump(mode="json"))


def test_challenge_ttl_above_3600_rejects_even_with_matching_hash_pin_and_valid_scope(
    offline_case,
) -> None:
    case = _case_with_ttl(offline_case, 3601)
    _assert_window_and_digest_preconditions(case)
    payload = case.challenge.payload
    assert payload.approval_expires_at - payload.approval_not_before == 3601
    _assert_review_rejected(case, "COAUTH_OFFLINE_TIME_INVALID")


@pytest.mark.parametrize("ttl", [1, 3600])
def test_challenge_ttl_legal_boundaries_with_full_task_policy_and_key_coverage(
    offline_case, ttl,
) -> None:
    case = _case_with_ttl(offline_case, ttl)
    _assert_window_and_digest_preconditions(case)
    review = _review(case)
    enterprise = _sign(case, review, role=ROLES[0])
    finance = _sign(case, review, role=ROLES[1])
    raw = offline.assemble_bundle(
        review, _wire(enterprise.model_dump(mode="json")), _wire(finance.model_dump(mode="json")),
        now=NOW,
    )
    verified = _verify_bundle(case, raw, now=NOW)
    assert verified.approval_payload_hash == case.challenge.approval_payload_hash
    _assert_review_rejected(case, "COAUTH_OFFLINE_TIME_INVALID", now=NOW + ttl)


def _invalid_public_point(case: OfflineCase, mutation: str):
    public = case.keypairs[ROLES[0]].public_key_hex
    values = {
        "none": None, "boolean": True, "short": "a" * 127, "long": "a" * 129,
        "uppercase": "A" * 128, "nonhex": "g" * 128, "off-curve-zero": "0" * 128,
        "x-outside-field": "f" * 64 + public[64:],
        "y-outside-field": public[:64] + "f" * 64,
    }
    return values[mutation]


@pytest.mark.parametrize("role", ROLES)
def test_public_point_validation_accepts_real_registered_sm2_points(offline_case, role) -> None:
    assert valid_public_point(offline_case.keypairs[role].public_key_hex)
    assert _review(offline_case).setup == offline_case.setup


@pytest.mark.parametrize("mutation", [
    "none", "boolean", "short", "long", "uppercase", "nonhex", "off-curve-zero",
    "x-outside-field", "y-outside-field",
])
def test_invalid_format_off_curve_and_out_of_field_public_keys_fail_closed(
    offline_case, mutation,
) -> None:
    value = _invalid_public_point(offline_case, mutation)
    assert valid_public_point(value) is False
    setup = offline_case.setup.model_dump(mode="json")
    setup["keys"][0]["public_key_hex"] = value
    raw = _wire(setup)
    reason = (
        "COAUTH_OFFLINE_KEY_INVALID" if mutation in {
            "off-curve-zero", "x-outside-field", "y-outside-field",
        } else "COAUTH_OFFLINE_INPUT_INVALID"
    )
    _assert_review_rejected(
        offline_case, reason, raw_public_setup=raw,
        trusted_setup_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _assert_sign_rejected(case, review, monkeypatch, reason: str, **updates) -> None:
    calls = []

    def forbidden_sign(*args, **kwargs):
        calls.append(True)
        raise AssertionError("SM2 signing must not be reached for rejected inputs")

    monkeypatch.setattr(offline, "sign_payload", forbidden_sign)
    arguments = _sign_arguments(case)
    arguments.update(updates)
    output = None
    with pytest.raises(offline.OfflineApprovalError) as error:
        output = offline.sign_approval(review, **arguments)
    assert error.value.reason_code == reason
    assert calls == []
    assert output is None


@pytest.mark.parametrize(("field", "value"), [
    ("role", "UNKNOWN_ROLE"), ("role", "enterprise_approver"), ("role", None),
    ("expected_subject_id", "synthetic-impostor"), ("expected_subject_id", None),
    ("expected_key_id", "synthetic-holder-key-01"), ("expected_key_id", True),
    ("expected_principal_id", "synthetic-untrusted-principal"), ("expected_principal_id", ""),
])
def test_signer_expectations_are_checked_before_any_sign_call(
    offline_case, monkeypatch, field, value,
) -> None:
    _assert_sign_rejected(
        offline_case, _review(offline_case), monkeypatch, "COAUTH_OFFLINE_SIGNER_MISMATCH",
        **{field: value},
    )


def test_other_role_cannot_use_the_enterprise_identity_and_dedicated_key(
    offline_case, monkeypatch,
) -> None:
    _assert_sign_rejected(
        offline_case, _review(offline_case), monkeypatch, "COAUTH_OFFLINE_SIGNER_MISMATCH",
        role=ROLES[1],
    )


@pytest.mark.parametrize("mutation", [
    "none", "boolean", "integer", "empty", "short", "long", "nonhex", "uppercase",
    "whitespace", "zero", "n-minus-one", "n", "above-n",
])
def test_private_key_format_and_scalar_boundaries_reject_before_any_sign_call(
    offline_case, monkeypatch, mutation,
) -> None:
    values = {
        "none": None, "boolean": True, "integer": 1, "empty": "", "short": "a" * 63,
        "long": "a" * 65, "nonhex": "g" * 64, "uppercase": "A" * 64,
        "whitespace": " " + "a" * 63, "zero": "0" * 64,
        "n-minus-one": f"{SM2_CURVE_ORDER - 1:064x}", "n": f"{SM2_CURVE_ORDER:064x}",
        "above-n": f"{SM2_CURVE_ORDER + 1:064x}",
    }
    _assert_sign_rejected(
        offline_case, _review(offline_case), monkeypatch, "COAUTH_OFFLINE_KEY_INVALID",
        private_key_hex=values[mutation],
    )


def test_valid_private_scalar_for_the_other_public_key_rejects_before_signing(
    offline_case, monkeypatch,
) -> None:
    enterprise_public = offline_case.keypairs[ROLES[0]].public_key_hex
    finance_public = offline_case.keypairs[ROLES[1]].public_key_hex
    assert enterprise_public != finance_public
    _assert_sign_rejected(
        offline_case, _review(offline_case), monkeypatch, "COAUTH_OFFLINE_PRIVATE_KEY_MISMATCH",
        private_key_hex=offline_case.keypairs[ROLES[1]].private_key_hex,
    )


def test_sign_self_verification_failure_returns_no_approval(offline_case, monkeypatch) -> None:
    review = _review(offline_case)
    real_sign = offline.sign_payload
    calls = []

    def tracked_real_sign(*args, **kwargs):
        calls.append(True)
        return real_sign(*args, **kwargs)

    def failed_self_verification(*args, **kwargs):
        return False

    monkeypatch.setattr(offline, "sign_payload", tracked_real_sign)
    monkeypatch.setattr(offline, "verify_payload", failed_self_verification)
    output = None
    with pytest.raises(offline.OfflineApprovalError) as error:
        output = _sign(offline_case, review)
    assert error.value.reason_code == "COAUTH_OFFLINE_SIGNATURE_INVALID"
    assert calls == [True]
    assert output is None


@pytest.mark.parametrize("mutation", ["raises", "bad-key-id", "bad-time", "bad-encoding"])
def test_signing_errors_or_returned_metadata_cannot_produce_output(
    offline_case, monkeypatch, mutation,
) -> None:
    review = _review(offline_case)
    real_sign = offline.sign_payload

    def failing_sign(*args, **kwargs):
        if mutation == "raises":
            raise ValueError("synthetic signing failure")
        signature = real_sign(*args, **kwargs)
        if mutation == "bad-key-id":
            signature["key_id"] = "synthetic-unregistered-key"
        elif mutation == "bad-time":
            signature["signed_at"] += 1
        else:
            signature["encoding"] = "DER"
        return signature

    monkeypatch.setattr(offline, "sign_payload", failing_sign)
    output = None
    with pytest.raises(offline.OfflineApprovalError) as error:
        output = _sign(offline_case, review)
    assert error.value.reason_code == "COAUTH_OFFLINE_SIGNATURE_INVALID"
    assert output is None


@pytest.mark.parametrize("operation", ["sign", "assemble"])
@pytest.mark.parametrize("now", [
    NOW - 1, NOW + 120, True, False, -1, MAX_SAFE_INTEGER + 1, 1.0, "1800000120", None,
])
def test_core_rechecks_explicit_fresh_now_and_rejects_backward_time(
    signed_offline_case, monkeypatch, operation, now,
) -> None:
    case, review, enterprise, finance = signed_offline_case
    if operation == "sign":
        _assert_sign_rejected(
            case, review, monkeypatch, "COAUTH_OFFLINE_TIME_INVALID", now=now,
        )
    else:
        _assert_assembly_rejected(
            review, enterprise, finance, "COAUTH_OFFLINE_TIME_INVALID", now=now,
        )


def test_sign_and_assemble_accept_fresh_now_later_than_the_initial_review(offline_case) -> None:
    case = offline_case
    review = _review(case)
    current_now = NOW + 10
    enterprise = _sign(case, review, role=ROLES[0], now=current_now)
    finance = _sign(case, review, role=ROLES[1], now=current_now)
    for evidence in (enterprise, finance):
        assert evidence.statement.approved_at == evidence.signature.signed_at == current_now
        _assert_real_signature(case, evidence)
    raw = offline.assemble_bundle(
        review, _wire(enterprise.model_dump(mode="json")), _wire(finance.model_dump(mode="json")),
        now=current_now,
    )
    assert _verify_bundle(case, raw, now=current_now).verified_at == current_now
    assert review.checked_at == NOW


@pytest.mark.parametrize("operation", ["sign", "assemble"])
def test_fresh_review_reparses_original_bytes_and_ignores_nested_model_mutation(
    signed_offline_case, operation,
) -> None:
    case, review, enterprise, finance = signed_offline_case
    original_task = case.task.model_dump(mode="json")
    original_payload = case.challenge.payload.model_dump(mode="json")
    original_bytes = (review.raw_challenge, review.raw_public_setup)
    review.task.capabilities.clear()
    review.challenge.task_capabilities.clear()
    review.setup.keys[0] = review.setup.keys[0].model_copy(update={
        "public_key_hex": case.keypairs[ROLES[1]].public_key_hex,
        "principal_id": "synthetic-mutated-principal", "status": "REVOKED",
    })
    assert review.task.model_dump(mode="json") != original_task
    assert review.setup.keys[0].status == "REVOKED"
    assert (review.raw_challenge, review.raw_public_setup) == original_bytes
    if operation == "sign":
        evidence = _sign(case, review)
        _assert_real_signature(case, evidence)
        assert evidence.statement.approval_payload_hash == case.challenge.approval_payload_hash
        enterprise = _wire(evidence.model_dump(mode="json"))
    raw = offline.assemble_bundle(review, enterprise, finance, now=NOW)
    assert parse_strict_json(raw)["payload"] == original_payload
    verified = _verify_bundle(case, raw, now=NOW)
    assert verified.approval_payload_hash == case.challenge.approval_payload_hash
    assert case.task.model_dump(mode="json") == original_task
    assert _review(case).task.model_dump(mode="json") == original_task


@pytest.mark.parametrize("operation", ["sign", "assemble"])
@pytest.mark.parametrize("mutation", [
    "challenge-bytes", "setup-bytes", "expected-task", "expected-hash",
])
def test_fresh_review_checks_original_byte_and_operator_binding_fields_again(
    signed_offline_case, monkeypatch, operation, mutation,
) -> None:
    case, review, enterprise, finance = signed_offline_case
    reason = "COAUTH_OFFLINE_TASK_BINDING_MISMATCH"
    if mutation == "challenge-bytes":
        document = case.challenge.model_dump(mode="json")
        document["payload"]["quotas"]["max_tool_calls"] += 1
        _rehash_challenge(document)
        review = replace(review, raw_challenge=_wire(document))
    elif mutation == "setup-bytes":
        review = replace(review, raw_public_setup=review.raw_public_setup + b"\n")
        reason = "COAUTH_OFFLINE_TRUST_PIN_MISMATCH"
    elif mutation == "expected-task":
        review = replace(review, expected_task_id="synthetic-other-task")
    else:
        review = replace(review, expected_approval_payload_hash="0" * 64)
    if operation == "sign":
        _assert_sign_rejected(case, review, monkeypatch, reason)
    else:
        _assert_assembly_rejected(review, enterprise, finance, reason)


@pytest.mark.parametrize("review", [None, {}, b"unchecked-review"])
def test_sign_requires_a_checked_review_before_it_can_reach_signing(
    offline_case, monkeypatch, review,
) -> None:
    _assert_sign_rejected(
        offline_case, review, monkeypatch, "COAUTH_OFFLINE_INPUT_INVALID",
    )


@pytest.mark.parametrize("review", [None, {}, b"unchecked-review"])
def test_assemble_requires_a_checked_review(signed_offline_case, review) -> None:
    _, _, enterprise, finance = signed_offline_case
    _assert_assembly_rejected(review, enterprise, finance, "COAUTH_OFFLINE_INPUT_INVALID")


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("mutation", [
    "invalid-utf8", "utf8-bom", "duplicate-root", "duplicate-nested", "extra-root",
    "extra-nested", "scientific", "decimal", "boolean", "false", "unsafe",
    "unsafe-negative", "negative", "null-number", "nan", "infinity", "empty",
    "whitespace", "array", "null", "oversize",
])
def test_assemble_rejects_strict_json_violations_in_each_single_approval(
    signed_offline_case, index, mutation,
) -> None:
    _, review, enterprise, finance = signed_offline_case
    approvals = [enterprise, finance]
    approvals[index] = _bad_document(approvals[index], mutation, time_field="approved_at")
    _assert_assembly_rejected(review, *approvals, "COAUTH_OFFLINE_INPUT_INVALID")


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("representation", ["text", "bytearray", "memoryview", "none"])
def test_assemble_requires_bytes_for_both_single_approvals(
    signed_offline_case, index, representation,
) -> None:
    _, review, enterprise, finance = signed_offline_case
    approvals = [enterprise, finance]
    raw = approvals[index]
    values = {
        "text": raw.decode("utf-8"), "bytearray": bytearray(raw),
        "memoryview": memoryview(raw), "none": None,
    }
    approvals[index] = values[representation]
    _assert_assembly_rejected(review, *approvals, "COAUTH_OFFLINE_INPUT_INVALID")


def test_assemble_accepts_two_maximum_size_inputs_and_bounds_the_canonical_output(
    signed_offline_case,
) -> None:
    case, review, enterprise, finance = signed_offline_case
    inputs = [raw + b" " * (MAX_BUNDLE_BYTES - len(raw)) for raw in (enterprise, finance)]
    assert len(inputs[0]) == len(inputs[1]) == MAX_BUNDLE_BYTES
    raw = offline.assemble_bundle(review, *inputs, now=NOW)
    assert len(raw) <= MAX_BUNDLE_BYTES
    assert raw == canonicalize(parse_strict_json(raw))
    verified = _verify_bundle(case, raw, now=NOW)
    assert verified.approval_payload_hash == case.challenge.approval_payload_hash


@pytest.mark.parametrize("mutation", ["swapped-files", "enterprise-twice", "finance-twice"])
def test_assemble_requires_one_file_for_each_role_in_the_correct_argument_order(
    signed_offline_case, mutation,
) -> None:
    _, review, enterprise, finance = signed_offline_case
    inputs = {
        "swapped-files": (finance, enterprise), "enterprise-twice": (enterprise, enterprise),
        "finance-twice": (finance, finance),
    }
    _assert_assembly_rejected(review, *inputs[mutation], "COAUTH_OFFLINE_APPROVAL_INVALID")


def test_two_genuine_signatures_for_different_task_hashes_cannot_be_assembled(
    signed_offline_case,
) -> None:
    case, review, enterprise, _ = signed_offline_case
    other = _make_case(case.keypairs, task_id="synthetic-task-offline-other")
    other_finance = _sign(other, role=ROLES[1])
    _assert_real_signature(other, other_finance)
    assert other_finance.statement.approval_payload_hash != case.challenge.approval_payload_hash
    _assert_assembly_rejected(
        review, enterprise, _wire(other_finance.model_dump(mode="json")),
        CoauthorizationReason.TASK_OR_POLICY_MISMATCH.value,
    )


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize(("path", "value", "reason"), [
    (("statement", "subject_id"), "synthetic-impostor", CoauthorizationReason.SIGNER_MISMATCH),
    (("statement", "key_id"), "synthetic-other-key", CoauthorizationReason.SIGNER_MISMATCH),
    (
        ("statement", "approval_payload_hash"), "0" * 64,
        CoauthorizationReason.TASK_OR_POLICY_MISMATCH,
    ),
    (("signature", "key_id"), "synthetic-other-key", CoauthorizationReason.INVALID_SIGNATURE),
    (("signature", "signed_at"), NOW + 1, CoauthorizationReason.INVALID_SIGNATURE),
    (("signature", "value"), "0" * 128, CoauthorizationReason.INVALID_SIGNATURE),
])
def test_assemble_rejects_tampering_and_inconsistent_signature_identity_metadata(
    signed_offline_case, index, path, value, reason,
) -> None:
    _, review, enterprise, finance = signed_offline_case
    approvals = [enterprise, finance]
    document = parse_strict_json(approvals[index])
    _set_path(document, path, value)
    approvals[index] = _wire(document)
    _assert_assembly_rejected(review, *approvals, reason.value)


def _resign_evidence(case: OfflineCase, document: dict, *, role: ApprovalRole, domain=None) -> dict:
    statement = document["statement"]
    pair = case.keypairs[role]
    document["signature"] = sign_payload(
        statement, domain_separator=COAUTHORIZATION_DOMAIN if domain is None else domain,
        key_id=statement["key_id"], key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex,
        signed_at=statement["approved_at"],
    )
    return document


@pytest.mark.parametrize("index", [0, 1])
def test_assemble_rejects_a_real_signature_from_the_wrong_signing_domain(
    signed_offline_case, index,
) -> None:
    case, review, enterprise, finance = signed_offline_case
    approvals = [enterprise, finance]
    document = _resign_evidence(
        case, parse_strict_json(approvals[index]), role=ROLES[index], domain=CAPABILITY_CREDENTIAL,
    )
    evidence = ApprovalEvidence.model_validate(document)
    _assert_real_signature(case, evidence, domain=CAPABILITY_CREDENTIAL)
    assert not verify_payload(
        document["statement"], document["signature"], domain_separator=COAUTHORIZATION_DOMAIN,
        expected_key_id=evidence.statement.key_id,
        expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=case.keypairs[ROLES[index]].public_key_hex,
    )
    approvals[index] = _wire(document)
    _assert_assembly_rejected(review, *approvals, CoauthorizationReason.INVALID_SIGNATURE.value)


@pytest.mark.parametrize("approved_at", [NOW - 61, NOW + 1])
def test_real_sm2_approvals_before_issuance_or_after_current_now_are_rejected(
    signed_offline_case, approved_at,
) -> None:
    case, review, enterprise, finance = signed_offline_case
    document = parse_strict_json(finance)
    document["statement"]["approved_at"] = approved_at
    _resign_evidence(case, document, role=ROLES[1])
    _assert_real_signature(case, ApprovalEvidence.model_validate(document))
    _assert_assembly_rejected(
        review, enterprise, _wire(document), CoauthorizationReason.APPROVAL_TIME_INVALID.value,
    )


def test_changing_both_time_fields_without_resigning_still_fails_real_sm2(
    signed_offline_case,
) -> None:
    _, review, enterprise, finance = signed_offline_case
    document = parse_strict_json(finance)
    document["statement"]["approved_at"] += 1
    document["signature"]["signed_at"] += 1
    _assert_assembly_rejected(
        review, enterprise, _wire(document), CoauthorizationReason.INVALID_SIGNATURE.value,
        now=NOW + 2,
    )


def test_signatures_cannot_be_reused_between_the_two_role_statements(signed_offline_case) -> None:
    _, review, enterprise, finance = signed_offline_case
    enterprise_document = parse_strict_json(enterprise)
    finance_document = parse_strict_json(finance)
    enterprise_document["signature"], finance_document["signature"] = (
        finance_document["signature"], enterprise_document["signature"],
    )
    _assert_assembly_rejected(
        review, _wire(enterprise_document), _wire(finance_document),
        CoauthorizationReason.INVALID_SIGNATURE.value,
    )


@pytest.mark.parametrize(("path", "value"), [
    (("signature", "algorithm"), "RSA"),
    (("signature", "key_purpose"), KeyPurpose.GATEWAY_EXECUTION_SIGNING.value),
    (("signature", "encoding"), "DER"),
    (("signature", "value"), "A" * 128), (("signature", "value"), "a" * 127),
    (("signature", "value"), "g" * 128), (("signature", "signed_at"), True),
    (("signature", "signed_at"), MAX_SAFE_INTEGER + 1),
    (("statement", "approved_at"), True), (("statement", "approved_at"), 1.5),
    (("statement", "schema_version"), "2.0"),
    (("statement", "statement_type"), "ROOT"),
    (("statement", "approval_purpose"), "GATEWAY_EXECUTION"),
    (("statement", "approval_payload_hash"), "A" * 64),
    (("statement", "role"), "ROOT_SIGNER"), (("statement", "subject_id"), ""),
])
def test_single_approval_schema_and_existing_evidence_contract_reject_profile_drift(
    signed_offline_case, path, value,
) -> None:
    _, review, enterprise, finance = signed_offline_case
    document = parse_strict_json(enterprise)
    _set_path(document, path, value)
    with pytest.raises(SchemaValidationError):
        SchemaStore(EXTENSION_SCHEMA_ROOT).validate("single-approval.schema.json", document)
    with pytest.raises(ContractValidationError):
        ApprovalEvidence.model_validate(document)
    _assert_assembly_rejected(
        review, _wire(document), finance, "COAUTH_OFFLINE_INPUT_INVALID",
    )


@pytest.mark.parametrize("mutation", [
    "extra-evidence", "extra-statement", "extra-signature",
    "missing-statement", "missing-signature",
])
def test_single_approval_schema_and_contract_have_the_same_closed_evidence_shape(
    signed_offline_case, mutation,
) -> None:
    _, review, enterprise, finance = signed_offline_case
    document = parse_strict_json(enterprise)
    if mutation.startswith("missing-"):
        del document[mutation.removeprefix("missing-")]
    else:
        target = document if mutation == "extra-evidence" else document[
            mutation.removeprefix("extra-")
        ]
        target["unexpected"] = True
    with pytest.raises(SchemaValidationError):
        SchemaStore(EXTENSION_SCHEMA_ROOT).validate("single-approval.schema.json", document)
    with pytest.raises(ContractValidationError):
        ApprovalEvidence.model_validate(document)
    _assert_assembly_rejected(
        review, enterprise, _wire(document), "COAUTH_OFFLINE_INPUT_INVALID",
    )


def test_role_selection_does_not_depend_on_the_public_key_list_order(signed_offline_case) -> None:
    case, _, enterprise, finance = signed_offline_case
    setup = case.setup.model_dump(mode="json")
    setup["keys"].reverse()
    review = _review_documents(case, setup=setup)
    for role in ROLES:
        evidence = _sign(case, review, role=role)
        assert evidence.statement.role == role
        _assert_real_signature(case, evidence)
    raw = offline.assemble_bundle(review, enterprise, finance, now=NOW)
    roles = [item["statement"]["role"] for item in parse_strict_json(raw)["approvals"]]
    assert roles == list(ROLES)
    assert _verify_bundle(case, raw, now=NOW).verified_at == NOW


def test_repeated_assembly_neither_consumes_the_challenge_nor_returns_a_root(
    signed_offline_case,
) -> None:
    case, review, enterprise, finance = signed_offline_case
    before = (
        case.task.model_dump(mode="json"), case.setup.model_dump(mode="json"),
        case.challenge.model_dump(mode="json"), review.task.model_dump(mode="json"),
        review.setup.model_dump(mode="json"), review.challenge.model_dump(mode="json"),
        review.raw_challenge, review.raw_public_setup,
    )
    first = offline.assemble_bundle(review, enterprise, finance, now=NOW)
    second = offline.assemble_bundle(review, enterprise, finance, now=NOW)
    assert first == second
    document = parse_strict_json(first)
    assert set(document) == {"payload", "approvals"}
    assert len(document["approvals"]) == 2
    root_fields = {"credential", "root_credential_id", "root_credential_hash", "reused"}
    assert not (root_fields & set(document))
    verified = _verify_bundle(case, first, now=NOW)
    assert verified.required_next_step == "TRANSACTIONAL_CHALLENGE_CONSUMPTION"
    assert case.task.status == review.task.status == "PENDING_AUTHORIZATION"
    assert case.challenge.challenge_status == review.challenge.challenge_status == "PENDING"
    assert before == (
        case.task.model_dump(mode="json"), case.setup.model_dump(mode="json"),
        case.challenge.model_dump(mode="json"), review.task.model_dump(mode="json"),
        review.setup.model_dump(mode="json"), review.challenge.model_dump(mode="json"),
        review.raw_challenge, review.raw_public_setup,
    )


def test_offline_source_and_its_local_dependency_graph_exclude_http_db_llm_and_issuance() -> None:
    # Inspect only the small, known pure dependency graph; never import service modules.
    modules = (
        "backend.coauthorization.offline", "backend.coauthorization.public_keys",
        "backend.coauthorization.contracts", "backend.coauthorization.verifier",
        "backend.authorization.contracts", "backend.common.enums", "backend.common.schema",
        "backend.common.error_codes", "backend.crypto.canonical_json", "backend.crypto.sm",
        "backend.crypto.strict_json", "backend.crypto.domains",
    )
    sources = [PROJECT_ROOT.joinpath(*module.split(".")).with_suffix(".py") for module in modules]
    sources.extend(PROJECT_ROOT / directory / "__init__.py" for directory in (
        "backend", "backend/coauthorization", "backend/authorization",
        "backend/common", "backend/crypto",
    ))
    forbidden_external = {
        "requests", "httpx", "aiohttp", "urllib", "socket", "fastapi", "starlette",
        "psycopg", "psycopg2", "sqlalchemy", "sqlite3", "redis", "boto3", "openai",
        "anthropic", "langchain", "importlib", "subprocess",
    }
    forbidden_calls = {
        "__import__", "import_module", "eval", "exec", "consume_challenge",
        "consume_pending_challenge", "issue_root", "issue_root_credential",
        "build_root_credential",
        "create_engine", "create_async_engine", "urlopen", "commit", "execute",
    }
    for path in sources:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0, (
                    f"review relative dependency before allowing it: {path}:{node.lineno}"
                )
                imported = [node.module or ""]
            else:
                imported = []
            for module in imported:
                assert module.split(".")[0] not in forbidden_external, (
                    f"offline external dependency: {path}:{node.lineno}: {module}"
                )
                if module.startswith("backend."):
                    assert module in modules, (
                        f"offline local dependency outside the reviewed graph: "
                        f"{path}:{node.lineno}: {module}"
                    )
            if isinstance(node, ast.Call):
                function = node.func
                name = function.id if isinstance(function, ast.Name) else (
                    function.attr if isinstance(function, ast.Attribute) else ""
                )
                assert name not in forbidden_calls, (
                    f"offline side effect: {path}:{node.lineno}: {name}"
                )
            if path.name in {"offline.py", "public_keys.py", "verifier.py"} and isinstance(
                node, (ast.Assign, ast.AnnAssign, ast.AugAssign),
            ):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                assert all(
                    not isinstance(target, ast.Attribute) or target.attr != "status"
                    for target in targets
                ), f"offline challenge/task status mutation: {path}:{node.lineno}"
