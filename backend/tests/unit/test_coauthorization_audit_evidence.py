from __future__ import annotations

from copy import deepcopy

import pytest
from jsonschema import ValidationError

from backend.authorization.policy import build_root_capabilities
from backend.coauthorization import audit
from backend.coauthorization.contracts import (
    COAUTHORIZATION_DOMAIN,
    TrustedApprovalPolicy,
    TrustedTask,
)
from backend.coauthorization.verifier import build_approval_payload, build_approval_statement
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto import sm
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import CAPABILITY_CREDENTIAL
from backend.crypto.sm import Sm2KeyPair, generate_keypair, sign_payload, signed_object_hash, sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER

NOW = 1_800_000_120
ROLES = ("ENTERPRISE_APPROVER", "FINANCE_APPROVER")
INVALID_MESSAGE = "^invalid coauthorization audit evidence$"
EVIDENCE_FIELDS = {
    "schema_version", "record_type", "tenant_id", "task_id", "challenge_id",
    "policy_revision", "approval_payload_hash", "bundle_hash", "signed_bundle",
    "root_credential_id", "root_credential_hash", "credential", "authorized_at",
}


@pytest.fixture(scope="module")
def test_keys() -> dict[str, Sm2KeyPair]:
    # These keys exist only in test memory; no deployment key material is read.
    return {
        key_id: generate_keypair()
        for key_id in ("enterprise-test-key", "finance-test-key", "authority-test-key")
    }


def _sign_inputs(
    inputs: dict, keys: dict[str, Sm2KeyPair], *, root_domain: str = CAPABILITY_CREDENTIAL
) -> None:
    for evidence in inputs["signed_bundle"]["approvals"]:
        statement = evidence["statement"]
        pair = keys[statement["key_id"]]
        evidence["signature"] = sign_payload(
            statement, domain_separator=COAUTHORIZATION_DOMAIN,
            key_id=statement["key_id"], key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex,
            signed_at=statement["approved_at"],
        )
    root = inputs["credential"]["payload"]
    pair = keys[root["issuer"]["key_id"]]
    inputs["credential"]["signature"] = sign_payload(
        root, domain_separator=root_domain,
        key_id=root["issuer"]["key_id"], key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex,
        signed_at=root["issued_at"],
    )


@pytest.fixture
def audit_inputs(test_keys) -> dict:
    task = TrustedTask.model_validate({
        "tenant_id": "tenant-A", "task_id": "TASK-AUDIT-01",
        "ticket_id": "T10086", "customer_id": "C9527",
        "holder": {"agent_id": "agent-coordinator", "key_id": "holder-test-key"},
        "capabilities": build_root_capabilities(
            ticket_id="T10086", customer_id="C9527", refund_total_fen=7000
        ),
        "quotas": {"refund_total_fen": 7000, "max_tool_calls": 4},
        "not_before": NOW - 100, "expires_at": NOW + 1800,
        "delegation_depth": 2, "status": "PENDING_AUTHORIZATION",
    })
    policy = TrustedApprovalPolicy.model_validate({
        "tenant_id": task.tenant_id, "revision": "approval-policy-v1",
        "required_signers": {
            "enterprise_approver": {
                "subject_id": "enterprise-test-subject", "key_id": "enterprise-test-key",
            },
            "finance_approver": {
                "subject_id": "finance-test-subject", "key_id": "finance-test-key",
            },
        },
        "not_before": NOW - 200, "expires_at": NOW + 2000,
    })
    payload = build_approval_payload(
        task=task, policy=policy, challenge_id="challenge-audit-01",
        approval_not_before=NOW - 60, approval_expires_at=NOW + 120,
    )
    bundle = {
        "payload": payload.model_dump(mode="json"),
        "approvals": [
            {"statement": build_approval_statement(
                payload=payload, role=role, approved_at=NOW - 20 + index
            ).model_dump(mode="json")}
            for index, role in enumerate(ROLES)
        ],
    }
    task_document = task.model_dump(mode="json")
    root = {
        "schema_version": "1.0", "credential_id": "cred-root-audit-01",
        "credential_type": "ROOT",
        "issuer": {"subject_id": "authority-test-subject", "key_id": "authority-test-key"},
        **{field: task_document[field] for field in (
            "holder", "tenant_id", "task_id", "capabilities", "quotas",
            "not_before", "expires_at", "delegation_depth",
        )},
        "verifier_audience": "secure-tool-gateway",
        "parent_credential_id": None, "parent_credential_hash": None,
        "issued_at": NOW - 5,
    }
    inputs = {"signed_bundle": bundle, "credential": {"payload": root}, "authorized_at": NOW}
    _sign_inputs(inputs, test_keys)
    return inputs


def _reject(document: dict) -> None:
    with pytest.raises(ValueError, match=INVALID_MESSAGE):
        audit.validate_authorization_audit_evidence(document)


def _set_value(document: dict, path: tuple, value) -> None:
    target = document
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = value


def _rehash(document: dict, *, bind_statements: bool = False) -> None:
    bundle = document["signed_bundle"]
    document["approval_payload_hash"] = sm3_hex(canonicalize(bundle["payload"]))
    if bind_statements:
        for evidence in bundle["approvals"]:
            evidence["statement"]["approval_payload_hash"] = document["approval_payload_hash"]
    document["bundle_hash"] = sm3_hex(canonicalize(bundle))
    document["root_credential_hash"] = signed_object_hash(document["credential"])


def test_synthetic_real_sm2_signatures_and_evidence_contract(audit_inputs, test_keys) -> None:
    for evidence in audit_inputs["signed_bundle"]["approvals"]:
        statement = evidence["statement"]
        assert sm.verify_payload(
            statement, evidence["signature"], domain_separator=COAUTHORIZATION_DOMAIN,
            expected_key_id=statement["key_id"],
            expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            public_key_hex=test_keys[statement["key_id"]].public_key_hex,
        )
    root = audit_inputs["credential"]
    assert sm.verify_payload(
        root["payload"], root["signature"], domain_separator=CAPABILITY_CREDENTIAL,
        expected_key_id="authority-test-key",
        expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=test_keys["authority-test-key"].public_key_hex,
    )
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    assert set(document) == EVIDENCE_FIELDS
    assert document["schema_version"] == "1.0"
    assert document["record_type"] == "COAUTH_ROOT_AUTHORIZED_V1"
    assert document["authorized_at"] == NOW
    assert document["signed_bundle"] == audit_inputs["signed_bundle"]
    assert document["credential"] == root
    assert document["approval_payload_hash"] == sm3_hex(canonicalize(
        document["signed_bundle"]["payload"]
    ))
    assert document["bundle_hash"] == sm3_hex(canonicalize(document["signed_bundle"]))
    assert document["root_credential_hash"] == signed_object_hash(root)
    assert audit.validate_authorization_audit_evidence(document) is None
    audit.load_authorization_audit_schemas().validate(
        "authorization-audit-evidence.schema.json", document
    )


def test_evidence_is_an_independent_snapshot_and_helper_does_not_sign(audit_inputs, monkeypatch) -> None:
    original = deepcopy(audit_inputs)

    def forbidden(*args, **kwargs):
        pytest.fail("audit helpers must not generate keys, sign or perform SM2 verification")

    for name in ("generate_keypair", "sign_payload", "verify_payload"):
        monkeypatch.setattr(sm, name, forbidden)
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    audit.validate_authorization_audit_evidence(document)
    assert audit_inputs == original
    audit_inputs["credential"]["payload"]["quotas"]["max_tool_calls"] = 99
    audit_inputs["signed_bundle"]["approvals"][0]["statement"]["subject_id"] = "changed"
    assert document["credential"] == original["credential"]
    assert document["signed_bundle"] == original["signed_bundle"]


def test_set_canonicalization_preserves_root_hash_when_capabilities_are_reordered(audit_inputs) -> None:
    original = audit.make_authorization_audit_evidence(**audit_inputs)
    audit_inputs["credential"]["payload"]["capabilities"].reverse()
    reordered = audit.make_authorization_audit_evidence(**audit_inputs)
    assert reordered["root_credential_hash"] == original["root_credential_hash"]
    assert reordered["bundle_hash"] == original["bundle_hash"]


def test_signature_domain_is_an_upstream_crypto_check(audit_inputs, test_keys) -> None:
    _sign_inputs(audit_inputs, test_keys, root_domain=COAUTHORIZATION_DOMAIN)
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    assert audit.validate_authorization_audit_evidence(document) is None
    root = document["credential"]
    assert not sm.verify_payload(
        root["payload"], root["signature"], domain_separator=CAPABILITY_CREDENTIAL,
        expected_key_id="authority-test-key",
        expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=test_keys["authority-test-key"].public_key_hex,
    )


@pytest.mark.parametrize("field", ["approval_payload_hash", "bundle_hash", "root_credential_hash"])
def test_outer_hash_tampering_is_rejected(audit_inputs, field) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    digest = document[field]
    document[field] = ("1" if digest[0] == "0" else "0") + digest[1:]
    _reject(document)


@pytest.mark.parametrize("field", [
    "tenant_id", "task_id", "challenge_id", "policy_revision", "root_credential_id",
])
def test_outer_identifiers_bind_exactly_to_nested_evidence(audit_inputs, field) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document[field] = "different-valid-id"
    _reject(document)


@pytest.mark.parametrize(("path", "value"), [
    (("tenant_id",), "tenant-B"), (("task_id",), "TASK-OTHER"),
    (("holder", "agent_id"), "agent-other"), (("holder", "key_id"), "other-holder-key"),
    (("quotas", "refund_total_fen"), 7001), (("quotas", "max_tool_calls"), 5),
    (("not_before",), NOW - 101), (("expires_at",), NOW + 1801),
    (("delegation_depth",), 3),
    (("capabilities", 0, "resources", "ticket_ids"), ["T-OTHER"]),
    (("capabilities", 2, "resources", "customer_ids"), ["C-OTHER"]),
    (("capabilities", 2, "constraints", "single_max_fen"), 6999),
    (("capabilities", 3, "constraints", "template_ids"), ["OTHER_TEMPLATE"]),
])
def test_rehashing_tampered_root_scope_cannot_bypass_approval_binding(
    audit_inputs, path, value
) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    _set_value(document["credential"]["payload"], path, value)
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize("field", ["ticket_id", "customer_id"])
def test_payload_resource_ids_bind_after_all_digests_are_recomputed(audit_inputs, field) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document["signed_bundle"]["payload"][field] = "different-resource"
    _rehash(document, bind_statements=True)
    _reject(document)


def test_refund_limit_cannot_exceed_equal_root_and_approval_budgets(audit_inputs) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document["signed_bundle"]["payload"]["quotas"]["refund_total_fen"] = 6000
    document["credential"]["payload"]["quotas"]["refund_total_fen"] = 6000
    _rehash(document, bind_statements=True)
    _reject(document)


@pytest.mark.parametrize("mutation", [
    lambda capabilities: capabilities.pop(),
    lambda capabilities: capabilities.__setitem__(1, deepcopy(capabilities[0])),
    lambda capabilities: capabilities[0].update(tool="ticket.write"),
    lambda capabilities: capabilities[0].update(version="v2"),
    lambda capabilities: capabilities[0]["resources"].update(ticket_ids=["T10086", "T-OTHER"]),
])
def test_approval_profile_is_enforced_beyond_the_frozen_root_schema(audit_inputs, mutation) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    capabilities = document["credential"]["payload"]["capabilities"]
    mutation(capabilities)
    document["signed_bundle"]["payload"]["capabilities_hash"] = sm3_hex(canonicalize({
        "capabilities": capabilities,
    }))
    _rehash(document, bind_statements=True)
    _reject(document)


@pytest.mark.parametrize("path", [
    (), ("signed_bundle",), ("signed_bundle", "payload"),
    ("signed_bundle", "payload", "quotas"), ("signed_bundle", "payload", "holder"),
    ("signed_bundle", "payload", "required_signers"),
    ("signed_bundle", "payload", "required_signers", "enterprise_approver"),
    ("signed_bundle", "approvals", 0), ("signed_bundle", "approvals", 0, "statement"),
    ("signed_bundle", "approvals", 1, "signature"),
    ("credential",), ("credential", "payload"), ("credential", "payload", "issuer"),
    ("credential", "payload", "holder"), ("credential", "payload", "quotas"),
    ("credential", "payload", "capabilities", 0), ("credential", "signature"),
])
def test_extra_fields_and_embedded_public_keys_are_rejected(audit_inputs, path) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    target = document
    for field in path:
        target = target[field]
    target["public_key_hex"] = "a" * 128
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize("field", sorted(EVIDENCE_FIELDS))
def test_every_evidence_field_is_required(audit_inputs, field) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    del document[field]
    _reject(document)


@pytest.mark.parametrize("path", [
    ("schema_version",), ("signed_bundle", "payload", "schema_version"),
    ("signed_bundle", "approvals", 0, "statement", "schema_version"),
    ("credential", "payload", "schema_version"),
])
def test_evidence_and_nested_frozen_versions_cannot_be_upgraded_to_v2(audit_inputs, path) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    _set_value(document, path, "2.0")
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize(("path", "value"), [
    (("record_type",), "COAUTH_ROOT_AUTHORIZED_V2"),
    (("signed_bundle", "payload", "approval_purpose"), "CAPABILITY_CREDENTIAL"),
    (("signed_bundle", "payload", "verifier_audience"), "secure-tool-gateway"),
    (("signed_bundle", "payload", "payload_type"), "OTHER_APPROVAL"),
    (("signed_bundle", "approvals", 0, "statement", "approval_purpose"), "OTHER_PURPOSE"),
    (("credential", "payload", "credential_type"), "DELEGATION"),
    (("credential", "payload", "verifier_audience"), "other-verifier"),
    (("credential", "payload", "issuer", "subject_id"), ""),
    (("credential", "payload", "issuer", "key_id"), "other-issuer-key"),
    (("credential", "signature", "key_id"), "other-signing-key"),
    (("credential", "signature", "key_purpose"), "AGENT_HOLDER_SIGNING"),
    (("credential", "signature", "algorithm"), "RSA"),
    (("credential", "signature", "encoding"), "DER"),
    (("credential", "signature", "value"), "a" * 127),
    (("credential", "signature", "value"), "A" * 128),
    (("credential", "signature", "domain_separator"), CAPABILITY_CREDENTIAL),
    (("credential", "signature", "payload_hash"), "a" * 64),
])
def test_purpose_audience_root_type_and_signature_metadata_are_strict(audit_inputs, path, value) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    _set_value(document, path, value)
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize("mutation", [
    lambda approvals: approvals.pop(),
    lambda approvals: approvals.append(deepcopy(approvals[0])),
    lambda approvals: approvals[1]["statement"].update(role="ENTERPRISE_APPROVER"),
    lambda approvals: approvals[1]["statement"].update(role="UNKNOWN_ROLE"),
])
def test_exactly_one_approval_per_role_is_required(audit_inputs, mutation) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    mutation(document["signed_bundle"]["approvals"])
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize("field", ["subject_id", "key_id", "approval_payload_hash"])
@pytest.mark.parametrize("index", [0, 1])
def test_each_approval_binds_its_required_signer_and_payload(audit_inputs, index, field) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    statement = document["signed_bundle"]["approvals"][index]["statement"]
    statement[field] = "a" * 64 if field == "approval_payload_hash" else "different-signer"
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize(("field", "value"), [
    ("key_id", "other-approval-key"), ("signed_at", NOW - 18),
    ("key_purpose", "AGENT_HOLDER_SIGNING"), ("encoding", "DER"),
])
@pytest.mark.parametrize("index", [0, 1])
def test_each_approval_signature_metadata_matches_its_statement(
    audit_inputs, index, field, value
) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document["signed_bundle"]["approvals"][index]["signature"][field] = value
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize("field", ["subject_id", "key_id"])
def test_two_roles_cannot_share_a_subject_or_key_id(audit_inputs, field) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    bundle = document["signed_bundle"]
    signers = bundle["payload"]["required_signers"]
    signers["finance_approver"][field] = signers["enterprise_approver"][field]
    finance = bundle["approvals"][1]
    finance["statement"][field] = signers["finance_approver"][field]
    if field == "key_id":
        finance["signature"]["key_id"] = signers["finance_approver"][field]
    _rehash(document, bind_statements=True)
    _reject(document)


@pytest.mark.parametrize("authorized_at", [NOW - 61, NOW - 6, NOW + 120])
def test_authorization_time_is_in_window_and_after_root_signing(
    audit_inputs, authorized_at
) -> None:
    audit_inputs["authorized_at"] = authorized_at
    with pytest.raises(ValueError, match=INVALID_MESSAGE):
        audit.make_authorization_audit_evidence(**audit_inputs)


@pytest.mark.parametrize("approved_at", [NOW - 61, NOW - 4, NOW + 120])
@pytest.mark.parametrize("index", [0, 1])
def test_approval_time_is_in_window_and_not_after_root_signing(
    audit_inputs, index, approved_at
) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    evidence = document["signed_bundle"]["approvals"][index]
    evidence["statement"]["approved_at"] = approved_at
    evidence["signature"]["signed_at"] = approved_at
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize("signed_at", [NOW - 61, NOW - 20, NOW + 1, NOW + 120])
def test_root_signing_time_is_in_window_and_follows_both_approvals(
    audit_inputs, signed_at
) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document["credential"]["payload"]["issued_at"] = signed_at
    document["credential"]["signature"]["signed_at"] = signed_at
    _rehash(document)
    _reject(document)


def test_root_issued_at_must_equal_its_signature_time(audit_inputs) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document["credential"]["payload"]["issued_at"] += 1
    _rehash(document)
    _reject(document)


@pytest.mark.parametrize("timestamp", [NOW - 60, NOW + 119])
def test_half_open_window_accepts_equal_approval_root_and_authorization_times(
    audit_inputs, test_keys, timestamp
) -> None:
    for evidence in audit_inputs["signed_bundle"]["approvals"]:
        evidence["statement"]["approved_at"] = timestamp
    audit_inputs["credential"]["payload"]["issued_at"] = timestamp
    audit_inputs["authorized_at"] = timestamp
    _sign_inputs(audit_inputs, test_keys)
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    assert audit.validate_authorization_audit_evidence(document) is None


@pytest.mark.parametrize(("field", "value"), [
    ("approval_not_before", NOW - 101), ("approval_expires_at", NOW + 1801),
    ("approval_expires_at", NOW - 60), ("expires_at", NOW - 100),
])
def test_approval_window_is_nonempty_and_contained_in_task_window(
    audit_inputs, field, value
) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document["signed_bundle"]["payload"][field] = value
    _rehash(document, bind_statements=True)
    _reject(document)


@pytest.mark.parametrize("value", [
    True, -1, MAX_SAFE_INTEGER + 1, "7000", 7000.0, float("nan"), float("inf"),
])
def test_quotas_follow_strict_json_safe_integer_profile(audit_inputs, value) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document["signed_bundle"]["payload"]["quotas"]["refund_total_fen"] = value
    _reject(document)


@pytest.mark.parametrize("value", [True, -1, MAX_SAFE_INTEGER + 1, "1800000120", NOW + 0.0])
def test_authorized_at_is_a_strict_safe_integer(audit_inputs, value) -> None:
    audit_inputs["authorized_at"] = value
    with pytest.raises(ValueError, match=INVALID_MESSAGE):
        audit.make_authorization_audit_evidence(**audit_inputs)


@pytest.mark.parametrize("value", [None, [], "{}", {1: "non-string-key"}])
def test_validator_rejects_non_documents_and_non_json_keys(value) -> None:
    _reject(value)


@pytest.mark.parametrize("field", ["signed_bundle", "credential"])
@pytest.mark.parametrize("value", [None, [], "{}", {"payload": None}])
def test_builder_rejects_malformed_inputs_with_the_fixed_message(
    audit_inputs, field, value
) -> None:
    audit_inputs[field] = value
    with pytest.raises(ValueError, match=INVALID_MESSAGE):
        audit.make_authorization_audit_evidence(**audit_inputs)


@pytest.mark.parametrize("constant", ["MAX_EVIDENCE_BYTES", "MAX_BUNDLE_BYTES"])
def test_byte_limits_accept_exact_size_and_reject_one_byte_less(
    audit_inputs, monkeypatch, constant
) -> None:
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    target = document if constant == "MAX_EVIDENCE_BYTES" else document["signed_bundle"]
    size = len(canonicalize(target, normalize_sets=False))
    monkeypatch.setattr(audit, constant, size)
    assert audit.validate_authorization_audit_evidence(document) is None
    assert audit.make_authorization_audit_evidence(**audit_inputs) == document
    monkeypatch.setattr(audit, constant, size - 1)
    _reject(document)
    with pytest.raises(ValueError, match=INVALID_MESSAGE):
        audit.make_authorization_audit_evidence(**audit_inputs)


def test_actual_evidence_limit_is_65536_bytes(audit_inputs) -> None:
    assert audit.MAX_EVIDENCE_BYTES == 65_536
    document = audit.make_authorization_audit_evidence(**audit_inputs)
    document["oversized"] = "x" * 65_536
    _reject(document)


def test_outbox_id_is_stable_hash_based_and_fits_maximum_identifier_length() -> None:
    root_id = "r" * 128
    expected = "OUTBOX-COAUTH-" + sm3_hex(root_id.encode("utf-8"))
    assert audit.authorization_audit_outbox_id(root_id) == expected
    assert audit.authorization_audit_outbox_id(root_id) == expected
    assert len(expected) == 78
    assert (
        audit.authorization_audit_outbox_id("root-a")
        != audit.authorization_audit_outbox_id("root-b")
    )


@pytest.mark.parametrize("root_id", [None, True, "", "bad id", "root\n", "r" * 129])
def test_outbox_id_rejects_invalid_root_identifiers(root_id) -> None:
    with pytest.raises(ValueError, match=INVALID_MESSAGE):
        audit.authorization_audit_outbox_id(root_id)


@pytest.fixture
def audit_event(audit_inputs) -> dict:
    evidence = audit.make_authorization_audit_evidence(**audit_inputs)
    return {
        "schema_version": "2.0", "event_sequence": 1, "event_id": "AUDIT-COAUTH-01",
        "execution_id": None, "event_type": "COAUTH_ROOT_AUTHORIZED", "timestamp": NOW,
        "payload_hash": sm3_hex(canonicalize(evidence)),
        "evidence_reference": audit.authorization_audit_outbox_id(evidence["root_credential_id"]),
        "previous_event_hash": "0" * 64, "event_hash": "a" * 64,
    }


def test_v2_event_matches_v1_fields_but_frozen_v1_rejects_coauthorization(audit_event) -> None:
    assert audit.COAUTHORIZATION_AUDIT_EVENT_TYPE == "COAUTH_ROOT_AUTHORIZED"
    assert audit.COAUTHORIZATION_AUDIT_SCHEMA_VERSION == "2.0"
    schemas = audit.load_authorization_audit_schemas()
    schemas.validate("audit-event-v2.schema.json", audit_event)
    frozen = SchemaStore()
    assert set(schemas.documents["audit-event-v2.schema.json"]["properties"]) == set(
        frozen.documents["audit-event.schema.json"]["properties"]
    )
    for version in ("1.0", "2.0"):
        with pytest.raises(ValidationError):
            frozen.validate("audit-event.schema.json", {**audit_event, "schema_version": version})
    frozen.validate("audit-event.schema.json", {
        **audit_event, "schema_version": "1.0", "event_type": "RECEIPT_SIGNED",
    })


@pytest.mark.parametrize(("field", "value"), [
    ("schema_version", "1.0"), ("event_type", "RECEIPT_SIGNED"),
    ("execution_id", "EXEC-OTHER"), ("event_sequence", 0),
    ("event_sequence", True), ("event_sequence", MAX_SAFE_INTEGER + 1),
    ("timestamp", -1), ("timestamp", MAX_SAFE_INTEGER + 1),
    ("event_hash", "A" * 64), ("event_id", "x" * 129), ("extra", "forbidden"),
])
def test_v2_event_rejects_other_versions_types_execution_ids_and_extra_fields(
    audit_event, field, value
) -> None:
    audit_event[field] = value
    with pytest.raises(ValidationError):
        audit.load_authorization_audit_schemas().validate("audit-event-v2.schema.json", audit_event)
