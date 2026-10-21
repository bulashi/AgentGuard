"""UNRUN synthetic source tests; four SM2 keypairs exist only in test memory.

No deployment or crypto proof is claimed. Public schema reads remain permitted.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from backend.audit.service import AuditService
from backend.coauthorization import evidence_verifier as verifier
from backend.coauthorization.audit import make_authorization_audit_evidence
from backend.coauthorization.contracts import APPROVAL_PURPOSE, COAUTHORIZATION_DOMAIN
from backend.common.enums import KeyPurpose
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_CHECKPOINT, CAPABILITY_CREDENTIAL
from backend.crypto.sm import generate_keypair, sign_payload, signed_object_hash, sm3_hex
from backend.tests.unit.test_coauthorization_audit_evidence import (
    NOW,
    _sign_inputs,
    audit_inputs as audit_inputs,
)

KEY_IDS = ("enterprise-test-key", "finance-test-key", "authority-test-key", "checkpoint-test-key")
FALSE_CLAIMS = (
    "authorizes_execution", "proves_current_revocation", "proves_challenge_consumption",
    "proves_business_side_effects", "proves_real_principal_independence",
    "proves_all_independent_anchors", "proves_other_event_payloads",
    "proves_latest_chain_head", "proves_trusted_wall_clock",
)
ZERO_HASH = "0" * 64


@pytest.fixture(scope="module")
def test_keys():
    keys = {key_id: generate_keypair() for key_id in KEY_IDS}
    assert len({pair.public_key_hex for pair in keys.values()}) == 4
    return keys


def _sign(case, payload, metadata, domain, *, pair_id=None):
    pair = case["keys"][pair_id or metadata["key_id"]]
    return sign_payload(
        payload, domain_separator=domain, key_id=metadata["key_id"],
        key_purpose=KeyPurpose(metadata["key_purpose"]), signed_at=metadata["signed_at"],
        private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex,
    )


def _hash_prefix(case, *, reanchor=False):
    events = case["package"]["audit_events"]
    previous = ZERO_HASH
    for sequence, event in enumerate(events, start=1):
        event.update(event_sequence=sequence, previous_event_hash=previous)
        event["event_hash"] = AuditService._event_hash(
            {name: value for name, value in event.items() if name != "event_hash"}
        )
        previous = event["event_hash"]
    if reanchor:
        checkpoint = case["checkpoint"]
        checkpoint["payload"].update(latest_event_sequence=len(events), latest_event_hash=previous)
        checkpoint["signature"] = _sign(
            case, checkpoint["payload"], checkpoint["signature"], AUDIT_CHECKPOINT,
        )


@pytest.fixture
def evidence_case(audit_inputs, test_keys):
    # Reuse the existing build_root_capabilities/approval payload/statement fixture.
    evidence = make_authorization_audit_evidence(**audit_inputs)
    payload = evidence["signed_bundle"]["payload"]
    policy = {
        "tenant_id": payload["tenant_id"], "revision": payload["policy_revision"],
        "required_signers": deepcopy(payload["required_signers"]),
        "not_before": NOW - 200, "expires_at": NOW + 2000,
    }
    approval_keys = []
    for index, approval in enumerate(evidence["signed_bundle"]["approvals"]):
        statement = approval["statement"]
        approval_keys.append({
            "tenant_id": payload["tenant_id"], "subject_id": statement["subject_id"],
            "principal_id": f"synthetic-principal-{index}", "key_id": statement["key_id"],
            "role": statement["role"], "approval_purpose": APPROVAL_PURPOSE,
            "signing_purpose": "AUTHORIZATION_ROOT_SIGNING", "algorithm": "SM2",
            "public_key_hex": test_keys[statement["key_id"]].public_key_hex,
            "status": "ACTIVE", "activated_at": NOW - 1000, "expires_at": NOW + 5000,
            "retired_at": None, "revoked_at": None, "compromised_at": None,
        })
    runtime_keys = {}
    for name, key_id, subject_id, purpose in (
        ("root_signer", KEY_IDS[2], "authority-test-subject", "AUTHORIZATION_ROOT_SIGNING"),
        ("checkpoint_signer", KEY_IDS[3], "audit-checkpoint-signer", "AUDIT_CHECKPOINT_SIGNING"),
    ):
        runtime_keys[name] = {
            "key_id": key_id, "subject_id": subject_id, "key_purpose": purpose,
            "algorithm": "SM2", "public_key_hex": test_keys[key_id].public_key_hex,
            "status": "ACTIVE", "activated_at": NOW - 1000,
        }
    events = [{
        "schema_version": "2.0" if index == 2 else "1.0",
        "event_sequence": index, "event_id": f"SYNTHETIC-EVENT-{index}",
        "execution_id": None if index == 2 else f"SYNTHETIC-EXEC-{index}",
        "event_type": "COAUTH_ROOT_AUTHORIZED" if index == 2 else "RESULT_RETRIEVAL_DENIED",
        "timestamp": NOW + index,
        "payload_hash": sm3_hex(canonicalize(evidence if index == 2 else {"synthetic": index})),
        "evidence_reference": evidence["root_credential_id"] if index == 2 else f"OTHER-{index}",
        "previous_event_hash": ZERO_HASH, "event_hash": ZERO_HASH,
    } for index in range(1, 4)]
    case = {
        "keys": test_keys,
        "package": {"schema_version": "1.0", "record_type": "COAUTHORIZATION_EVIDENCE_PACKAGE_V1",
                    "authorization_evidence": evidence, "audit_events": events},
        "trust": {"schema_version": "1.0", "record_type": "PINNED_PUBLIC_VERIFICATION_CONTEXT_V1",
                  "approval_setup": {"policy": policy, "keys": approval_keys}, **runtime_keys},
        "checkpoint": {
            "payload": {"schema_version": "1.0", "checkpoint_sequence": 7,
                        "latest_event_sequence": 3, "latest_event_hash": ZERO_HASH,
                        "timestamp": NOW + 10},
            "signature": {"key_id": KEY_IDS[3], "key_purpose": "AUDIT_CHECKPOINT_SIGNING",
                          "signed_at": NOW + 10},
        },
    }
    _hash_prefix(case, reanchor=True)
    return case


def _refresh_evidence(case):
    old = case["package"]["authorization_evidence"]
    evidence = make_authorization_audit_evidence(
        signed_bundle=old["signed_bundle"], credential=old["credential"],
        authorized_at=old["authorized_at"],
    )
    case["package"]["authorization_evidence"] = evidence
    case["package"]["audit_events"][1]["payload_hash"] = sm3_hex(canonicalize(evidence))
    _hash_prefix(case, reanchor=True)


def _arguments(case):
    raw = {name: json.dumps(case[name], separators=(",", ":"), allow_nan=False).encode("utf-8")
           for name in ("package", "trust", "checkpoint")}
    evidence = case["package"]["authorization_evidence"]
    return {
        "raw_package": raw["package"], "raw_trust_context": raw["trust"],
        "trusted_context_sha256": hashlib.sha256(raw["trust"]).hexdigest(),
        "raw_checkpoint": raw["checkpoint"],
        "trusted_checkpoint_sha256": hashlib.sha256(raw["checkpoint"]).hexdigest(),
        "expected_task_id": evidence["task_id"],
        "expected_root_credential_id": evidence["root_credential_id"],
        "expected_approval_payload_hash": evidence["approval_payload_hash"],
        "observed_at": NOW + 20,
    }


def _reject(case, reason, **overrides):
    with pytest.raises(verifier.EvidenceVerificationError) as error:
        verifier.verify_evidence_package(**(_arguments(case) | overrides))
    assert error.value.reason_code == "COAUTH_EVIDENCE_" + reason


@pytest.mark.parametrize("observed_at", [NOW + 20, NOW + 6000], ids=["open", "expired"])
def test_complete_mixed_prefix_and_expired_historical_approvals(evidence_case, observed_at):
    arguments = _arguments(evidence_case) | {"observed_at": observed_at}
    evidence = evidence_case["package"]["authorization_evidence"]
    result = verifier.verify_evidence_package(**arguments)
    assert [event["schema_version"] for event in evidence_case["package"]["audit_events"]] == [
        "1.0", "2.0", "1.0",
    ]
    assert result == {
        "schema_version": "1.0", "verified": True,
        "verification_scope": "COAUTHORIZATION_SIGNATURES_AND_PINNED_AUDIT_PREFIX",
        "task_id": evidence["task_id"], "root_credential_id": evidence["root_credential_id"],
        "approval_payload_hash": evidence["approval_payload_hash"],
        "root_credential_hash": evidence["root_credential_hash"],
        "authorized_at_claim": NOW, "observed_at": observed_at,
        "verified_subject_ids": ["enterprise-test-subject", "finance-test-subject"],
        "verified_principal_ids": ["synthetic-principal-0", "synthetic-principal-1"],
        "checked_events": 3, "authorization_event_sequence": 2, "checkpoint_sequence": 7,
        "checkpoint_latest_event_sequence": 3,
        "trusted_context_sha256": arguments["trusted_context_sha256"],
        "trusted_checkpoint_sha256": arguments["trusted_checkpoint_sha256"],
        "package_sha256": hashlib.sha256(arguments["raw_package"]).hexdigest(),
        **dict.fromkeys(FALSE_CLAIMS, False),
    }
    verifier.evidence_schemas().validate("verified-result.schema.json", result)
    for claim in FALSE_CLAIMS:
        assert result[claim] is False
    if observed_at == NOW + 6000:
        assert observed_at > evidence["signed_bundle"]["payload"]["approval_expires_at"]
        assert observed_at > evidence["credential"]["payload"]["expires_at"]
        assert all(key["expires_at"] < observed_at and key["status"] == "ACTIVE"
                   for key in evidence_case["trust"]["approval_setup"]["keys"])


@pytest.mark.parametrize("raw_name,pin_name", [
    ("raw_trust_context", "trusted_context_sha256"),
    ("raw_checkpoint", "trusted_checkpoint_sha256"),
])
@pytest.mark.parametrize("attack", ["changed-bytes", "wrong-external-pin"])
def test_external_byte_pins_are_required(evidence_case, raw_name, pin_name, attack):
    arguments = _arguments(evidence_case)
    update = {raw_name: arguments[raw_name] + b" "} if attack == "changed-bytes" else {
        pin_name: ZERO_HASH,
    }
    _reject(evidence_case, "TRUST_PIN_MISMATCH", **update)


@pytest.mark.parametrize("field,value", [
    ("expected_task_id", "OTHER-TASK"), ("expected_root_credential_id", "OTHER-ROOT"),
    ("expected_approval_payload_hash", ZERO_HASH),
])
def test_caller_expectations_bind_task_root_and_payload(evidence_case, field, value):
    _reject(evidence_case, "EXPECTATION_MISMATCH", **{field: value})


@pytest.mark.parametrize("target", [0, 1, "root", "checkpoint"])
@pytest.mark.parametrize("attack", ["wrong-key", "wrong-domain"])
def test_replaced_signatures_with_all_public_digests_rebuilt(evidence_case, target, attack):
    evidence = evidence_case["package"]["authorization_evidence"]
    if target == "checkpoint":
        signed, domain, other_key = evidence_case["checkpoint"], AUDIT_CHECKPOINT, KEY_IDS[2]
    elif target == "root":
        signed, domain, other_key = evidence["credential"], CAPABILITY_CREDENTIAL, KEY_IDS[3]
    else:
        signed = evidence["signed_bundle"]["approvals"][target]
        domain, other_key = COAUTHORIZATION_DOMAIN, KEY_IDS[1 - target]
    wrong_domain = (
        COAUTHORIZATION_DOMAIN if domain == CAPABILITY_CREDENTIAL else CAPABILITY_CREDENTIAL
    )
    signed["signature"] = _sign(
        evidence_case, signed["statement" if isinstance(target, int) else "payload"],
        signed["signature"], wrong_domain if attack == "wrong-domain" else domain,
        pair_id=other_key if attack == "wrong-key" else None,
    )
    if target != "checkpoint":
        _refresh_evidence(evidence_case)
    _reject(evidence_case, "APPROVAL_INVALID" if isinstance(target, int) else "SIGNATURE_INVALID")


@pytest.mark.parametrize("path,value,reason", [
    (("approval_setup", "keys", 1, "principal_id"), "synthetic-principal-0",
     "TRUST_CONTEXT_INVALID"),
    (("approval_setup", "keys", 1, "public_key_hex"), KEY_IDS[0], "TRUST_CONTEXT_INVALID"),
    (("root_signer", "public_key_hex"), KEY_IDS[0], "TRUST_CONTEXT_INVALID"),
    (("checkpoint_signer", "public_key_hex"), KEY_IDS[2], "TRUST_CONTEXT_INVALID"),
    (("checkpoint_signer", "key_id"), KEY_IDS[2], "TRUST_CONTEXT_INVALID"),
    (("checkpoint_signer", "public_key_hex"), "0" * 128, "TRUST_CONTEXT_INVALID"),
])
def test_same_principal_reused_keys_and_invalid_points(evidence_case, path, value, reason):
    target = evidence_case["trust"]
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = evidence_case["keys"][value].public_key_hex if (
        path[-1] == "public_key_hex" and value in KEY_IDS
    ) else value
    _reject(evidence_case, reason)


@pytest.mark.parametrize("attack,reason", [
    ("genesis-truncated", "PREFIX_INVALID"), ("tail-truncated", "PREFIX_INVALID"),
    ("middle-truncated", "PREFIX_INVALID"), ("reordered", "PREFIX_INVALID"),
    ("altered", "PREFIX_INVALID"), ("missing-target", "AUDIT_BINDING_INVALID"),
    ("duplicate-target", "AUDIT_BINDING_INVALID"), ("wrong-target-hash", "AUDIT_BINDING_INVALID"),
    ("preauthorization-event", "AUDIT_BINDING_INVALID"),
    ("target-downgraded", "AUDIT_BINDING_INVALID"),
    ("rehash-original-anchor", "AUDIT_BINDING_INVALID"),
])
def test_complete_prefix_and_unique_target_binding(evidence_case, attack, reason):
    events = evidence_case["package"]["audit_events"]
    if attack.endswith("truncated"):
        events.pop({"genesis-truncated": 0, "tail-truncated": 2, "middle-truncated": 1}[attack])
    elif attack == "reordered":
        events.reverse()
    elif attack in {"altered", "rehash-original-anchor"}:
        events[0]["payload_hash"] = ZERO_HASH
    elif attack == "missing-target":
        events[1]["evidence_reference"] = "OTHER-ROOT"
    elif attack == "duplicate-target":
        events[2] = deepcopy(events[1])
        events[2]["event_id"] = "SYNTHETIC-DUPLICATE-TARGET"
    elif attack == "wrong-target-hash":
        events[1]["payload_hash"] = ZERO_HASH
    elif attack == "preauthorization-event":
        events[1]["timestamp"] = NOW - 1
    elif attack == "target-downgraded":
        events[1].update(schema_version="1.0", event_type="AUTHORIZATION_DENIED")
    if not attack.endswith("truncated") and attack not in {"reordered", "altered"}:
        _hash_prefix(evidence_case, reanchor=attack != "rehash-original-anchor")
    _reject(evidence_case, reason)


@pytest.mark.parametrize("part,path,value", [
    ("package", ("schema_version",), "0.9"),
    ("package", ("authorization_evidence", "schema_version"), "0.9"),
    ("package", ("audit_events", 1, "schema_version"), "1.0"),
    ("package", ("trusted_context_sha256",), ZERO_HASH),
    ("package", ("authorization_evidence", "signed_bundle", "public_key_hex"), "untrusted"),
    ("trust", ("schema_version",), "0.9"),
    ("trust", ("approval_setup", "keys", 0, "status"), "RETIRED"),
    ("trust", ("root_signer", "status"), "REVOKED"),
    ("trust", ("checkpoint_signer", "status"), "COMPROMISED"),
    ("trust", ("root_signer", "expires_at"), NOW + 5000),
    ("trust", ("checkpoint_signer", "expires_at"), NOW + 5000),
    ("trust", ("root_signer", "private_key_hex"), "unsupported-synthetic-field"),
    ("checkpoint", ("payload", "schema_version"), "0.9"),
    ("checkpoint", ("signature", "domain_separator"), AUDIT_CHECKPOINT),
])
def test_schema_downgrades_unknown_fields_and_nonactive_snapshots(evidence_case, part, path, value):
    target = evidence_case[part]
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    _reject(evidence_case, "CHECKPOINT_INVALID" if part == "checkpoint" else "INPUT_INVALID")


@pytest.mark.parametrize("part", ["package", "trust", "checkpoint"])
@pytest.mark.parametrize("attack", ["duplicate-raw-json", "float", "oversize"])
def test_strict_raw_json_and_actual_byte_limits(evidence_case, part, attack):
    raw_name, pin_name, limit = {
        "package": ("raw_package", None, verifier.MAX_PACKAGE_BYTES),
        "trust": ("raw_trust_context", "trusted_context_sha256", verifier.MAX_TRUST_BYTES),
        "checkpoint": ("raw_checkpoint", "trusted_checkpoint_sha256",
                       verifier.MAX_CHECKPOINT_BYTES),
    }[part]
    original = _arguments(evidence_case)[raw_name]
    if attack == "duplicate-raw-json":
        raw = original.replace(b'"schema_version":"1.0"',
                               b'"schema_version":"1.0","schema_version":"1.0"', 1)
    elif attack == "float":
        field, value = {"package": ("authorized_at", NOW), "trust": ("activated_at", NOW - 1000),
                        "checkpoint": ("timestamp", NOW + 10)}[part]
        token = f'"{field}":{value}'.encode("ascii")
        raw = original.replace(token, token + b".0", 1)
    else:
        raw = original + b" " * limit
    assert raw != original
    updates = {raw_name: raw}
    if pin_name:
        updates[pin_name] = hashlib.sha256(raw).hexdigest()
    reason = "TRUST_PIN_MISMATCH" if attack == "oversize" and pin_name else (
        "CHECKPOINT_INVALID" if part == "checkpoint" else "INPUT_INVALID"
    )
    _reject(evidence_case, reason, **updates)


@pytest.mark.parametrize("target,activated_at,reason", [
    ("root_signer", NOW - 4, "SIGNATURE_INVALID"),
    ("checkpoint_signer", NOW + 11, "SIGNATURE_INVALID"),
    ("approver", NOW - 19, "TRUST_CONTEXT_INVALID"),
])
def test_signing_before_key_activation(evidence_case, target, activated_at, reason):
    key = evidence_case["trust"]["approval_setup"]["keys"][0] if target == "approver" else (
        evidence_case["trust"][target]
    )
    key["activated_at"] = activated_at
    _reject(evidence_case, reason)


@pytest.mark.parametrize("attack", ["unsigned-time-mismatch", "future-checkpoint"])
def test_checkpoint_timestamp_and_signature_metadata(evidence_case, attack):
    checkpoint = evidence_case["checkpoint"]
    if attack == "unsigned-time-mismatch":
        checkpoint["signature"]["signed_at"] += 1
    else:
        checkpoint["payload"]["timestamp"] = NOW + 21
        checkpoint["signature"]["signed_at"] = NOW + 21
        _hash_prefix(evidence_case, reanchor=True)
    _reject(evidence_case, "CHECKPOINT_INVALID")


@pytest.mark.parametrize("ttl", [0, 1, 3600, 3601])
def test_approval_ttl_boundaries_with_resigned_evidence(evidence_case, ttl):
    evidence = evidence_case["package"]["authorization_evidence"]
    bundle, root = evidence["signed_bundle"], evidence["credential"]
    bundle["payload"].update(approval_not_before=NOW, approval_expires_at=NOW + ttl,
                             expires_at=NOW + 5000)
    root["payload"].update(issued_at=NOW, expires_at=NOW + 5000)
    evidence_case["trust"]["approval_setup"]["policy"]["expires_at"] = NOW + 4500
    evidence["approval_payload_hash"] = sm3_hex(canonicalize(bundle["payload"]))
    for approval in bundle["approvals"]:
        approval["statement"].update(
            approved_at=NOW, approval_payload_hash=evidence["approval_payload_hash"],
        )
    _sign_inputs({"signed_bundle": bundle, "credential": root}, evidence_case["keys"])
    evidence.update(
        bundle_hash=sm3_hex(canonicalize(bundle)), root_credential_hash=signed_object_hash(root),
    )
    evidence_case["package"]["audit_events"][1]["payload_hash"] = sm3_hex(canonicalize(evidence))
    _hash_prefix(evidence_case, reanchor=True)
    if ttl in (1, 3600):
        assert verifier.verify_evidence_package(**_arguments(evidence_case))["verified"] is True
    else:
        _reject(evidence_case, "BINDING_INVALID")


def test_no_signing_private_key_loading_or_live_io(evidence_case, monkeypatch):
    arguments = _arguments(evidence_case)

    def forbidden(*args, **kwargs):
        pytest.fail("verification must not sign, load private keys, or access live state")

    for target in (
        "backend.crypto.sm.sign_payload", "backend.crypto.sm.sign_message",
        "backend.crypto.sm.generate_keypair", "backend.authorization.credential.sign_payload",
        "backend.identity.key_lifecycle.sign_payload",
        "backend.identity.key_lifecycle.FilePrivateKeyStore.load", "backend.audit.service.connect",
        "backend.state.database.connect", "backend.state.database.psycopg.connect",
        "backend.identity.key_registry.connect",
        "socket.create_connection", "socket.socket.connect", "socket.socket.connect_ex",
    ):
        monkeypatch.setattr(target, forbidden)
    assert verifier.verify_evidence_package(**arguments)["verified"] is True
    assert _arguments(evidence_case) == arguments


def test_result_schema_failure_refuses_a_verification_result(evidence_case, monkeypatch):
    schemas = verifier.evidence_schemas()
    stricter = deepcopy(schemas.documents["verified-result.schema.json"])
    stricter["properties"]["verified"] = {"const": False}
    monkeypatch.setitem(schemas.documents, "verified-result.schema.json", stricter)
    _reject(evidence_case, "RESULT_INVALID")
