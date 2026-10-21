from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from backend.authorization.policy import build_root_capabilities
from backend.coauthorization.contracts import (
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
from backend.coauthorization.verifier import (
    EXTENSION_SCHEMA_ROOT,
    CoauthorizationError,
    CoauthorizationReason,
    approval_payload_hash,
    build_approval_payload,
    build_approval_statement,
    capabilities_hash,
    verify_coauthorization,
)
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import CAPABILITY_CREDENTIAL
from backend.crypto.sm import Sm2KeyPair, generate_keypair, sign_payload, sm3_hex, verify_payload

NOW = 1_800_000_120
ROLES: tuple[ApprovalRole, ApprovalRole] = ("ENTERPRISE_APPROVER", "FINANCE_APPROVER")


@dataclass
class ApprovalCase:
    task: TrustedTask
    policy: TrustedApprovalPolicy
    challenge: TrustedChallenge
    bundle: dict
    records: dict[str, RegisteredApprovalKey]
    keypairs: dict[str, Sm2KeyPair]

    def raw(self) -> bytes:
        return json.dumps(self.bundle, separators=(",", ":"), allow_nan=False).encode("utf-8")

    def registry(self, **lookup) -> RegisteredApprovalKey | None:
        assert lookup["now"] == NOW
        assert lookup["approval_purpose"] == APPROVAL_PURPOSE
        return self.records.get(lookup["key_id"])


@pytest.fixture(scope="module")
def keypairs() -> dict[str, Sm2KeyPair]:
    # Synthetic test identities use real SM2 key generation, never deployment key files.
    return {"enterprise-key-01": generate_keypair(), "finance-key-01": generate_keypair()}


def _sign(statement: dict, pair: Sm2KeyPair, *, domain: str = COAUTHORIZATION_DOMAIN) -> dict:
    return sign_payload(
        statement, domain_separator=domain,
        key_id=statement["key_id"], key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex,
        signed_at=statement["approved_at"],
    )


def _refresh_bundle(case: ApprovalCase) -> None:
    payload = build_approval_payload(
        task=case.task, policy=case.policy, challenge_id=case.challenge.challenge_id,
        approval_not_before=case.challenge.issued_at,
        approval_expires_at=case.challenge.expires_at,
    )
    challenge = case.challenge.model_dump(mode="json")
    challenge["approval_payload_hash"] = approval_payload_hash(payload)
    case.challenge = TrustedChallenge.model_validate(challenge)
    approvals = []
    for index, role in enumerate(ROLES):
        statement = build_approval_statement(
            payload=payload, role=role, approved_at=NOW - 20 + index
        ).model_dump(mode="json")
        approvals.append({
            "statement": statement,
            "signature": _sign(statement, case.keypairs[statement["key_id"]]),
        })
    case.bundle = {"payload": payload.model_dump(mode="json"), "approvals": approvals}


@pytest.fixture
def case(keypairs: dict[str, Sm2KeyPair]) -> ApprovalCase:
    task = TrustedTask.model_validate({
        "tenant_id": "tenant-A", "task_id": "TASK-APPROVAL-01",
        "ticket_id": "T10086", "customer_id": "C9527",
        "holder": {"agent_id": "agent-coordinator", "key_id": "agent-coordinator-key-01"},
        "capabilities": build_root_capabilities(
            ticket_id="T10086", customer_id="C9527", refund_total_fen=7000
        ),
        "quotas": {"refund_total_fen": 7000, "max_tool_calls": 4},
        "not_before": NOW - 100, "expires_at": NOW + 1800,
        "delegation_depth": 2, "status": "PENDING_AUTHORIZATION",
    })
    policy = TrustedApprovalPolicy.model_validate({
        "tenant_id": "tenant-A", "revision": "refund-approval-policy-v1",
        "required_signers": {
            "enterprise_approver": {"subject_id": "enterprise-approver", "key_id": "enterprise-key-01"},
            "finance_approver": {"subject_id": "finance-approver", "key_id": "finance-key-01"},
        },
        "not_before": NOW - 200, "expires_at": NOW + 2000,
    })
    challenge = TrustedChallenge.model_validate({
        "challenge_id": "challenge-01", "tenant_id": "tenant-A", "task_id": task.task_id,
        "policy_revision": policy.revision, "approval_payload_hash": "0" * 64,
        "issued_at": NOW - 60, "expires_at": NOW + 120, "status": "PENDING",
    })
    records = {}
    for role in ROLES:
        signer = policy.required_signers.for_role(role)
        records[signer.key_id] = RegisteredApprovalKey.model_validate({
            "tenant_id": "tenant-A", "subject_id": signer.subject_id,
            "principal_id": f"principal-{signer.subject_id}", "key_id": signer.key_id,
            "role": role, "approval_purpose": APPROVAL_PURPOSE,
            "signing_purpose": "AUTHORIZATION_ROOT_SIGNING", "algorithm": "SM2",
            "public_key_hex": keypairs[signer.key_id].public_key_hex,
            "status": "ACTIVE", "activated_at": NOW - 1000, "expires_at": NOW + 5000,
            "retired_at": None, "revoked_at": None, "compromised_at": None,
        })
    result = ApprovalCase(task, policy, challenge, {}, records, dict(keypairs))
    _refresh_bundle(result)
    return result


def _verify(case: ApprovalCase, **overrides):
    arguments = {
        "trusted_task": case.task, "trusted_policy": case.policy,
        "trusted_challenge": case.challenge, "now": NOW, "registry": case.registry,
    }
    arguments.update(overrides)
    return verify_coauthorization(case.raw(), **arguments)


def _reject(case: ApprovalCase, reason: CoauthorizationReason, **overrides) -> None:
    with pytest.raises(CoauthorizationError) as error:
        _verify(case, **overrides)
    assert error.value.reason_code == reason


def _replace_record(case: ApprovalCase, **updates) -> None:
    record = case.records["finance-key-01"].model_dump(mode="json")
    record.update(updates)
    case.records["finance-key-01"] = RegisteredApprovalKey.model_validate(record)


def _set_trusted_state(case: ApprovalCase, *, task_status: str, challenge_status: str) -> None:
    task = case.task.model_dump(mode="json")
    task["status"] = task_status
    case.task = TrustedTask.model_validate(task)
    challenge = case.challenge.model_dump(mode="json")
    challenge["status"] = challenge_status
    case.challenge = TrustedChallenge.model_validate(challenge)


def test_two_independent_real_sm2_signatures_verify_without_issuing_a_credential(case) -> None:
    result = _verify(case)
    assert result.approval_payload_hash == case.challenge.approval_payload_hash
    assert result.verified_subject_ids == ("enterprise-approver", "finance-approver")
    assert result.verified_key_ids == ("enterprise-key-01", "finance-key-01")
    assert result.verified_principal_ids == (
        "principal-enterprise-approver", "principal-finance-approver"
    )
    assert result.required_next_step == "TRANSACTIONAL_CHALLENGE_CONSUMPTION"
    assert case.task.status == "PENDING_AUTHORIZATION"
    assert case.challenge.status == "PENDING"


def test_both_statements_bind_one_canonical_task_digest(case) -> None:
    digest = sm3_hex(canonicalize(case.bundle["payload"]))
    assert {item["statement"]["approval_payload_hash"] for item in case.bundle["approvals"]} == {digest}
    for evidence in case.bundle["approvals"]:
        signer = case.records[evidence["statement"]["key_id"]]
        assert verify_payload(
            evidence["statement"], evidence["signature"],
            domain_separator=COAUTHORIZATION_DOMAIN, expected_key_id=signer.key_id,
            expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            public_key_hex=signer.public_key_hex,
        )


def test_canonical_hash_is_capability_order_invariant_but_constraint_sensitive(case) -> None:
    data = case.task.model_dump(mode="json")
    data["capabilities"].reverse()
    reordered = TrustedTask.model_validate(data)
    assert capabilities_hash(reordered) == capabilities_hash(case.task)
    refund = next(item for item in data["capabilities"] if item["tool"] == "refund.create")
    refund["constraints"]["single_max_fen"] -= 1
    narrowed = TrustedTask.model_validate(data)
    assert capabilities_hash(narrowed) != capabilities_hash(case.task)


def test_schema_documents_and_python_field_sets_agree_on_required_objects(case) -> None:
    store = SchemaStore(EXTENSION_SCHEMA_ROOT)
    for document in store.documents.values():
        Draft202012Validator.check_schema(document)
    store.validate("coauthorization-bundle.schema.json", case.bundle)
    store.validate("approval-payload.schema.json", case.bundle["payload"])
    for evidence in case.bundle["approvals"]:
        store.validate("approval-statement.schema.json", evidence["statement"])
    payload_schema = store.documents["approval-payload.schema.json"]
    statement_schema = store.documents["common.schema.json"]["$defs"]["approvalStatement"]
    bundle_schema = store.documents["coauthorization-bundle.schema.json"]
    for model, schema in (
        (ApprovalPayload, payload_schema), (ApprovalStatement, statement_schema),
        (CoauthorizationBundle, bundle_schema),
    ):
        assert set(model.model_fields) == set(schema["properties"]) == set(schema["required"])


@pytest.mark.parametrize("path", [
    ("payload",), ("payload", "quotas"), ("payload", "holder"),
    ("payload", "required_signers"), ("payload", "required_signers", "finance_approver"),
    ("approvals", 0), ("approvals", 1, "statement"), ("approvals", 1, "signature"),
])
def test_unknown_nested_fields_are_rejected(case, path) -> None:
    value = case.bundle
    for key in path:
        value = value[key]
    value["unexpected_permission"] = "unbounded"
    _reject(case, CoauthorizationReason.INVALID_BUNDLE)


@pytest.mark.parametrize("field", list(ApprovalPayload.model_fields))
def test_every_task_payload_field_is_required(case, field) -> None:
    del case.bundle["payload"][field]
    _reject(case, CoauthorizationReason.INVALID_BUNDLE)


@pytest.mark.parametrize("field", list(ApprovalStatement.model_fields))
def test_every_signed_statement_field_is_required(case, field) -> None:
    del case.bundle["approvals"][0]["statement"][field]
    _reject(case, CoauthorizationReason.INVALID_BUNDLE)


@pytest.mark.parametrize("value", [-1, 9_007_199_254_740_992, True, "7000", 1.0])
def test_quota_ambiguity_and_unsafe_numbers_are_rejected(case, value) -> None:
    case.bundle["payload"]["quotas"]["refund_total_fen"] = value
    _reject(case, CoauthorizationReason.INVALID_BUNDLE)


@pytest.mark.parametrize("mutation", [
    lambda bundle: bundle["approvals"].pop(),
    lambda bundle: bundle["approvals"].append(deepcopy(bundle["approvals"][0])),
    lambda bundle: bundle["approvals"][1]["statement"].update(role="ENTERPRISE_APPROVER"),
    lambda bundle: bundle["approvals"][1]["statement"].update(role="LLM_APPROVER"),
    lambda bundle: bundle.update(public_key="attacker-self-supplied-key"),
    lambda bundle: bundle["approvals"][0]["signature"].update(public_key_hex="1" * 128),
    lambda bundle: bundle["payload"]["holder"].update(agent_id="x" * 129),
    lambda bundle: bundle["approvals"][0]["signature"].update(value="a" * 129),
    lambda bundle: bundle["approvals"][0]["signature"].update(value="A" * 128),
    lambda bundle: bundle["approvals"][0]["signature"].update(key_purpose="AGENT_HOLDER_SIGNING"),
    lambda bundle: bundle["payload"].update(delegation_depth=17),
    lambda bundle: bundle["payload"].update(approval_purpose="CAPABILITY_CREDENTIAL"),
    lambda bundle: bundle["payload"].update(verifier_audience="secure-tool-gateway"),
])
def test_shape_roles_purpose_and_self_supplied_trust_are_rejected(case, mutation) -> None:
    mutation(case.bundle)
    _reject(case, CoauthorizationReason.INVALID_BUNDLE)


@pytest.mark.parametrize("transform", [
    lambda raw: raw.replace(b'"payload":', b'"payload":{},"payload":', 1),
    lambda raw: raw.replace(b'"refund_total_fen":7000', b'"refund_total_fen":7e3', 1),
    lambda raw: raw.replace(b'"refund_total_fen":7000', b'"refund_total_fen":NaN', 1),
    lambda raw: raw.replace(b'"refund_total_fen":7000', b'"refund_total_fen":' + b'9' * 5000, 1),
    lambda raw: raw + b"\xff",
    lambda raw: raw + b" " * MAX_BUNDLE_BYTES,
    lambda raw: b"[" * 2000 + b"0" + b"]" * 2000,
])
def test_raw_parser_preserves_duplicate_encoding_and_size_rejections(case, transform) -> None:
    with pytest.raises(CoauthorizationError) as error:
        verify_coauthorization(
            transform(case.raw()), trusted_task=case.task, trusted_policy=case.policy,
            trusted_challenge=case.challenge, now=NOW, registry=case.registry,
        )
    assert error.value.reason_code == CoauthorizationReason.INVALID_BUNDLE


@pytest.mark.parametrize(("field", "value"), [
    ("tenant_id", "tenant-B"), ("task_id", "TASK-OTHER"), ("ticket_id", "T-OTHER"),
    ("customer_id", "C-OTHER"), ("capabilities_hash", "0" * 64),
    ("policy_revision", "different-policy-v2"), ("challenge_id", "challenge-02"),
    ("delegation_depth", 3), ("expires_at", NOW + 1900),
    ("not_before", NOW - 101), ("approval_expires_at", NOW + 121),
])
def test_all_task_policy_and_challenge_payload_bindings_are_exact(case, field, value) -> None:
    case.bundle["payload"][field] = value
    _reject(case, CoauthorizationReason.TASK_OR_POLICY_MISMATCH)


@pytest.mark.parametrize("part", ["quotas", "holder", "required_signers"])
def test_nested_task_bindings_cannot_be_swapped(case, part) -> None:
    if part == "quotas":
        case.bundle["payload"][part]["max_tool_calls"] = 5
    elif part == "holder":
        case.bundle["payload"][part]["key_id"] = "other-holder-key"
    else:
        case.bundle["payload"][part]["finance_approver"]["subject_id"] = "other-finance"
    _reject(case, CoauthorizationReason.TASK_OR_POLICY_MISMATCH)


def test_current_task_capability_change_requires_new_approvals(case) -> None:
    task = case.task.model_dump(mode="json")
    next(item for item in task["capabilities"] if item["tool"] == "refund.create")[
        "constraints"
    ]["single_max_fen"] = 6000
    case.task = TrustedTask.model_validate(task)
    _reject(case, CoauthorizationReason.CHALLENGE_MISMATCH)


def test_current_policy_signer_change_even_at_same_revision_invalidates_challenge(case) -> None:
    policy = case.policy.model_dump(mode="json")
    policy["required_signers"]["finance_approver"]["key_id"] = "finance-rotated-key"
    case.policy = TrustedApprovalPolicy.model_validate(policy)
    _reject(case, CoauthorizationReason.CHALLENGE_MISMATCH)


def test_valid_sm2_signature_on_a_different_task_digest_is_not_common_authorization(case) -> None:
    finance = case.bundle["approvals"][1]
    finance["statement"]["approval_payload_hash"] = "f" * 64
    finance["signature"] = _sign(finance["statement"], case.keypairs["finance-key-01"])
    _reject(case, CoauthorizationReason.TASK_OR_POLICY_MISMATCH)


def test_signature_from_the_root_credential_domain_is_not_an_approval(case) -> None:
    finance = case.bundle["approvals"][1]
    finance["signature"] = _sign(
        finance["statement"], case.keypairs["finance-key-01"], domain=CAPABILITY_CREDENTIAL
    )
    _reject(case, CoauthorizationReason.INVALID_SIGNATURE)


def test_tampered_signature_is_rejected(case) -> None:
    case.bundle["approvals"][1]["signature"]["value"] = "0" * 128
    _reject(case, CoauthorizationReason.INVALID_SIGNATURE)


@pytest.mark.parametrize("field", ["key_id", "signed_at"])
def test_unsigned_outer_signature_metadata_cannot_override_signed_statement(case, field) -> None:
    signature = case.bundle["approvals"][1]["signature"]
    signature[field] = "enterprise-key-01" if field == "key_id" else NOW - 1
    _reject(case, CoauthorizationReason.INVALID_SIGNATURE)


def test_changing_both_time_fields_without_resigning_fails_real_sm2(case) -> None:
    evidence = case.bundle["approvals"][1]
    evidence["statement"]["approved_at"] += 1
    evidence["signature"]["signed_at"] += 1
    _reject(case, CoauthorizationReason.INVALID_SIGNATURE)


@pytest.mark.parametrize("approved_at", [NOW - 61, NOW + 1])
def test_validly_signed_prechallenge_or_future_approvals_are_rejected(case, approved_at) -> None:
    evidence = case.bundle["approvals"][1]
    evidence["statement"]["approved_at"] = approved_at
    evidence["signature"] = _sign(evidence["statement"], case.keypairs["finance-key-01"])
    _reject(case, CoauthorizationReason.APPROVAL_TIME_INVALID)


def test_role_swapping_cannot_attribute_one_subject_to_another_role(case) -> None:
    for index, role in enumerate(reversed(ROLES)):
        case.bundle["approvals"][index]["statement"]["role"] = role
    _reject(case, CoauthorizationReason.SIGNER_MISMATCH)


@pytest.mark.parametrize(("updates", "reason"), [
    ({"tenant_id": "tenant-B"}, CoauthorizationReason.UNTRUSTED_KEY),
    ({"subject_id": "impostor-finance"}, CoauthorizationReason.UNTRUSTED_KEY),
    ({"key_id": "unregistered-alias"}, CoauthorizationReason.UNTRUSTED_KEY),
    ({"role": "ENTERPRISE_APPROVER"}, CoauthorizationReason.UNTRUSTED_KEY),
    ({"status": "REVOKED", "revoked_at": NOW - 5}, CoauthorizationReason.KEY_NOT_ACTIVE),
    ({"status": "COMPROMISED", "compromised_at": NOW - 5}, CoauthorizationReason.KEY_NOT_ACTIVE),
    ({"status": "RETIRED", "retired_at": NOW - 5}, CoauthorizationReason.KEY_NOT_ACTIVE),
    ({"revoked_at": NOW - 5}, CoauthorizationReason.KEY_NOT_ACTIVE),
    ({"expires_at": NOW}, CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID),
    ({"activated_at": NOW + 1}, CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID),
])
def test_trusted_registry_binding_and_live_key_state_are_enforced(case, updates, reason) -> None:
    _replace_record(case, **updates)
    _reject(case, reason)


def test_two_registered_subject_aliases_cannot_count_as_two_principals(case) -> None:
    _replace_record(case, principal_id=case.records["enterprise-key-01"].principal_id)
    _reject(case, CoauthorizationReason.SAME_PRINCIPAL)


def test_two_key_ids_with_the_same_key_material_are_rejected_after_real_verification(case) -> None:
    case.keypairs["finance-key-01"] = case.keypairs["enterprise-key-01"]
    _replace_record(case, public_key_hex=case.keypairs["enterprise-key-01"].public_key_hex)
    _refresh_bundle(case)
    _reject(case, CoauthorizationReason.SAME_KEY)


def test_one_subject_with_two_independent_keys_still_does_not_satisfy_two_roles(case) -> None:
    policy = case.policy.model_dump(mode="json")
    policy["required_signers"]["finance_approver"]["subject_id"] = "enterprise-approver"
    case.policy = TrustedApprovalPolicy.model_validate(policy)
    _refresh_bundle(case)
    _reject(case, CoauthorizationReason.SAME_PRINCIPAL)


def test_one_key_id_assigned_to_two_different_subjects_is_rejected(case) -> None:
    policy = case.policy.model_dump(mode="json")
    policy["required_signers"]["finance_approver"]["key_id"] = "enterprise-key-01"
    case.policy = TrustedApprovalPolicy.model_validate(policy)
    _refresh_bundle(case)
    _reject(case, CoauthorizationReason.SAME_KEY)


def test_missing_registry_record_has_no_self_verification_fallback(case) -> None:
    del case.records["finance-key-01"]
    _reject(case, CoauthorizationReason.UNTRUSTED_KEY)


def test_registry_exception_is_fail_closed(case) -> None:
    def unavailable(**lookup):
        raise RuntimeError("test registry unavailable")

    _reject(case, CoauthorizationReason.REGISTRY_UNAVAILABLE, registry=unavailable)


def test_invalid_registry_purpose_cannot_be_injected_with_model_copy(case) -> None:
    case.records["finance-key-01"] = case.records["finance-key-01"].model_copy(
        update={"approval_purpose": "GATEWAY_EXECUTION"}
    )
    _reject(case, CoauthorizationReason.UNTRUSTED_KEY)


def test_registry_public_key_not_evidence_public_key_controls_verification(case) -> None:
    _replace_record(case, public_key_hex=case.keypairs["enterprise-key-01"].public_key_hex)
    _reject(case, CoauthorizationReason.INVALID_SIGNATURE)


@pytest.mark.parametrize("status", ["CONSUMED", "REVOKED"])
def test_trusted_consumed_or_revoked_challenge_snapshot_is_rejected(case, status) -> None:
    challenge = case.challenge.model_dump(mode="json")
    challenge["status"] = status
    case.challenge = TrustedChallenge.model_validate(challenge)
    _reject(case, CoauthorizationReason.CHALLENGE_NOT_PENDING)


def test_explicit_false_requires_transactional_challenge_consumption(case) -> None:
    result = _verify(case, allow_existing_authorization=False)
    assert result.required_next_step == "TRANSACTIONAL_CHALLENGE_CONSUMPTION"
    assert case.task.status == "PENDING_AUTHORIZATION"
    assert case.challenge.status == "PENDING"


@pytest.mark.parametrize("overrides", [{}, {"allow_existing_authorization": False}])
def test_default_mode_rejects_existing_authorized_consumed_snapshot(case, overrides) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    _reject(case, CoauthorizationReason.TASK_NOT_AUTHORIZABLE, **overrides)


def test_allow_existing_authorization_accepts_authorized_consumed_snapshot(case) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    result = _verify(case, allow_existing_authorization=True)
    assert result.approval_payload_hash == case.challenge.approval_payload_hash
    assert result.challenge_id == case.challenge.challenge_id
    assert result.verified_subject_ids == ("enterprise-approver", "finance-approver")
    assert result.verified_key_ids == ("enterprise-key-01", "finance-key-01")
    assert result.verified_principal_ids == (
        "principal-enterprise-approver", "principal-finance-approver"
    )
    assert result.verified_at == NOW
    assert result.required_next_step == "RETURN_EXISTING_AUTHORIZATION"
    assert case.task.status == "AUTHORIZED"
    assert case.challenge.status == "CONSUMED"


@pytest.mark.parametrize(("task_status", "challenge_status", "reason"), [
    ("PENDING_AUTHORIZATION", "PENDING", CoauthorizationReason.TASK_NOT_AUTHORIZABLE),
    ("PENDING_AUTHORIZATION", "CONSUMED", CoauthorizationReason.TASK_NOT_AUTHORIZABLE),
    ("AUTHORIZED", "PENDING", CoauthorizationReason.CHALLENGE_NOT_PENDING),
    ("AUTHORIZED", "REVOKED", CoauthorizationReason.CHALLENGE_NOT_PENDING),
    ("CLOSED", "CONSUMED", CoauthorizationReason.TASK_NOT_AUTHORIZABLE),
])
def test_allow_existing_authorization_requires_authorized_consumed_snapshot(
    case, task_status, challenge_status, reason
) -> None:
    _set_trusted_state(
        case, task_status=task_status, challenge_status=challenge_status
    )
    _reject(case, reason, allow_existing_authorization=True)


@pytest.mark.parametrize(("task_status", "challenge_status"), [
    ("PENDING_AUTHORIZATION", "PENDING"), ("AUTHORIZED", "CONSUMED"),
])
@pytest.mark.parametrize("value", [None, 0, 1, 0.0, 1.0, "true", "false", [], {}])
def test_allow_existing_authorization_must_be_a_bool(
    case, task_status, challenge_status, value
) -> None:
    _set_trusted_state(
        case, task_status=task_status, challenge_status=challenge_status
    )
    _reject(
        case, CoauthorizationReason.INVALID_TRUSTED_CONTEXT,
        allow_existing_authorization=value,
    )


@pytest.mark.parametrize("allow_existing", [False, True])
def test_client_bundle_cannot_set_allow_existing_authorization(case, allow_existing) -> None:
    if allow_existing:
        _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    case.bundle["allow_existing_authorization"] = True
    _reject(
        case, CoauthorizationReason.INVALID_BUNDLE,
        allow_existing_authorization=allow_existing,
    )


@pytest.mark.parametrize("context", ["task", "policy"])
def test_existing_authorization_rechecks_current_task_and_policy_bindings(case, context) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    if context == "task":
        task = case.task.model_dump(mode="json")
        next(item for item in task["capabilities"] if item["tool"] == "refund.create")[
            "constraints"
        ]["single_max_fen"] = 6000
        case.task = TrustedTask.model_validate(task)
    else:
        policy = case.policy.model_dump(mode="json")
        policy["required_signers"]["finance_approver"]["key_id"] = "finance-rotated-key"
        case.policy = TrustedApprovalPolicy.model_validate(policy)
    _reject(case, CoauthorizationReason.CHALLENGE_MISMATCH, allow_existing_authorization=True)


@pytest.mark.parametrize(("updates", "reason"), [
    ({"status": "REVOKED", "revoked_at": NOW - 5}, CoauthorizationReason.KEY_NOT_ACTIVE),
    ({"status": "COMPROMISED", "compromised_at": NOW - 5}, CoauthorizationReason.KEY_NOT_ACTIVE),
    ({"expires_at": NOW}, CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID),
    ({"activated_at": NOW + 1}, CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID),
])
def test_existing_authorization_rechecks_live_key_state_and_validity(case, updates, reason) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    _replace_record(case, **updates)
    _reject(case, reason, allow_existing_authorization=True)


def test_existing_authorization_rechecks_registry_public_key(case) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    _replace_record(case, public_key_hex=case.keypairs["enterprise-key-01"].public_key_hex)
    _reject(case, CoauthorizationReason.INVALID_SIGNATURE, allow_existing_authorization=True)


def test_existing_authorization_rechecks_task_expiry(case) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    task = case.task.model_dump(mode="json")
    task["expires_at"] = NOW
    case.task = TrustedTask.model_validate(task)
    _reject(
        case, CoauthorizationReason.TASK_EXPIRED_OR_NOT_YET_VALID,
        allow_existing_authorization=True,
    )


def test_existing_authorization_rechecks_policy_expiry(case) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    policy = case.policy.model_dump(mode="json")
    policy["expires_at"] = NOW
    case.policy = TrustedApprovalPolicy.model_validate(policy)
    _reject(
        case, CoauthorizationReason.POLICY_EXPIRED_OR_NOT_YET_VALID,
        allow_existing_authorization=True,
    )


@pytest.mark.parametrize("index", [0, 1])
def test_existing_authorization_rechecks_signature_integrity(case, index) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    case.bundle["approvals"][index]["signature"]["value"] = "0" * 128
    _reject(case, CoauthorizationReason.INVALID_SIGNATURE, allow_existing_authorization=True)


def test_existing_authorization_rechecks_challenge_expiry(case) -> None:
    _set_trusted_state(case, task_status="AUTHORIZED", challenge_status="CONSUMED")
    challenge = case.challenge.model_dump(mode="json")
    challenge["expires_at"] = NOW
    case.challenge = TrustedChallenge.model_validate(challenge)
    _refresh_bundle(case)
    _reject(
        case, CoauthorizationReason.CHALLENGE_EXPIRED_OR_NOT_YET_VALID,
        allow_existing_authorization=True,
    )


def test_repeated_pending_snapshot_verification_is_not_replay_prevention(case) -> None:
    first = _verify(case)
    second = _verify(case)
    assert first == second
    assert case.challenge.status == "PENDING"
    assert first.required_next_step == "TRANSACTIONAL_CHALLENGE_CONSUMPTION"


@pytest.mark.parametrize(("context", "now", "reason"), [
    ("task", NOW - 101, CoauthorizationReason.TASK_EXPIRED_OR_NOT_YET_VALID),
    ("task", NOW + 1800, CoauthorizationReason.TASK_EXPIRED_OR_NOT_YET_VALID),
    ("policy", NOW, CoauthorizationReason.POLICY_EXPIRED_OR_NOT_YET_VALID),
    ("challenge", NOW - 61, CoauthorizationReason.CHALLENGE_EXPIRED_OR_NOT_YET_VALID),
    ("challenge", NOW + 120, CoauthorizationReason.CHALLENGE_EXPIRED_OR_NOT_YET_VALID),
])
def test_half_open_validity_boundaries(case, context, now, reason) -> None:
    if context == "policy":
        policy = case.policy.model_dump(mode="json")
        policy["expires_at"] = NOW
        case.policy = TrustedApprovalPolicy.model_validate(policy)
    _reject(case, reason, now=now)


@pytest.mark.parametrize("status", ["AUTHORIZED", "CLOSED"])
def test_task_must_still_be_pending_authorization(case, status) -> None:
    task = case.task.model_dump(mode="json")
    task["status"] = status
    case.task = TrustedTask.model_validate(task)
    _reject(case, CoauthorizationReason.TASK_NOT_AUTHORIZABLE)


@pytest.mark.parametrize(("field", "value"), [
    ("task_id", "TASK-OTHER"), ("tenant_id", "tenant-B"),
    ("policy_revision", "old-policy-revision"), ("approval_payload_hash", "f" * 64),
])
def test_trusted_challenge_requires_exact_current_task_policy_and_digest(case, field, value) -> None:
    challenge = case.challenge.model_dump(mode="json")
    challenge[field] = value
    case.challenge = TrustedChallenge.model_validate(challenge)
    _reject(case, CoauthorizationReason.CHALLENGE_MISMATCH)


@pytest.mark.parametrize("invalid_now", [True, -1, 9_007_199_254_740_992, "1800000120", 1.0])
def test_now_is_explicit_trusted_integer_input_not_unsigned_client_time(case, invalid_now) -> None:
    _reject(case, CoauthorizationReason.INVALID_TRUSTED_CONTEXT, now=invalid_now)


@pytest.mark.parametrize("mutation", [
    lambda task: task["capabilities"].pop(),
    lambda task: task["capabilities"].__setitem__(1, deepcopy(task["capabilities"][0])),
    lambda task: task["capabilities"][0]["resources"].update(ticket_ids=["T-OTHER"]),
    lambda task: task["capabilities"][2]["resources"].update(customer_ids=["C-OTHER"]),
    lambda task: task["capabilities"][0]["resources"].update(ticket_ids=[]),
    lambda task: task["capabilities"][0].update(version="v2"),
    lambda task: task["capabilities"][2]["constraints"].update(single_max_fen=7001),
    lambda task: task["capabilities"][3]["constraints"].update(template_ids=["REFUND_SUCCESS", "OTHER"]),
    lambda task: task["capabilities"][0]["constraints"].update(unbounded=True),
])
def test_trusted_task_adapter_must_not_omit_or_expand_frozen_v1_capability_shape(case, mutation) -> None:
    task = case.task.model_dump(mode="json")
    mutation(task)
    with pytest.raises(ValidationError):
        TrustedTask.model_validate(task)


def test_mutated_trusted_context_is_revalidated_and_rejected_before_key_lookup(case, monkeypatch) -> None:
    original_bundle = case.raw()
    case.task = case.task.model_copy(update={"delegation_depth": True})
    registry = Mock(wraps=case.registry)
    signature_verifier = Mock(side_effect=AssertionError("mutated context reached signature verification"))
    monkeypatch.setattr("backend.coauthorization.verifier.verify_payload", signature_verifier)
    # Pydantic normalizes the constructed bool to 1; the signed depth-2 snapshot must still reject it.
    assert case.task.model_dump(mode="json")["delegation_depth"] == 1
    with pytest.raises(CoauthorizationError) as error:
        _verify(case, registry=registry)
    assert error.value.reason_code == CoauthorizationReason.CHALLENGE_MISMATCH
    assert str(error.value) == "trusted challenge does not bind the current task and policy snapshot"
    assert case.raw() == original_bundle
    registry.assert_not_called()
    signature_verifier.assert_not_called()


def test_challenge_window_outside_current_policy_is_rejected(case) -> None:
    challenge = case.challenge.model_dump(mode="json")
    challenge["expires_at"] = NOW + 2100
    case.challenge = TrustedChallenge.model_validate(challenge)
    _reject(case, CoauthorizationReason.INVALID_TRUSTED_CONTEXT)


def test_payload_preparation_rejects_cross_tenant_policy_and_unknown_role(case) -> None:
    policy = case.policy.model_dump(mode="json")
    policy["tenant_id"] = "tenant-B"
    with pytest.raises(ValueError):
        build_approval_payload(
            task=case.task, policy=TrustedApprovalPolicy.model_validate(policy),
            challenge_id="challenge-new", approval_not_before=NOW - 60,
            approval_expires_at=NOW + 120,
        )
    with pytest.raises(ValueError):
        build_approval_statement(
            payload=ApprovalPayload.model_validate(case.bundle["payload"]),
            role="UNTRUSTED_ROLE", approved_at=NOW,
        )
