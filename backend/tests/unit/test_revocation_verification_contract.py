from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as SchemaValidationError
from pydantic import ValidationError

from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.ui_api.revocation_verification import (
    VerifyRevokedRequest,
    persisted_refund_action,
    refund_chain,
    verify_revoked,
)
from backend.ui_api.service import UiApiError
from scripts.export_revocation_contracts import DESTINATION, exports


@pytest.mark.parametrize("document", [
    {}, {"confirmed": False}, {"confirmed": 1}, {"confirmed": "true"},
    {"confirmed": True, "credential_chain": []}, {"confirmed": True, "holder_key_id": "ROOT-key"},
])
def test_probe_requires_explicit_confirmation_and_never_accepts_browser_authority(document):
    with pytest.raises(ValidationError):
        VerifyRevokedRequest.model_validate(document)


def test_saved_extension_exports_match_actual_routes_and_strict_models():
    import json

    for name, document in exports().items():
        assert json.loads((DESTINATION / name).read_text("utf-8")) == document
        if name.endswith(".schema.json"):
            Draft202012Validator.check_schema(document)


def credentials():
    return [
        {
            "credential_id": identifier, "parent_credential_id": parent,
            "holder_agent_id": role, "not_before": 100, "expires_at": 200,
            "revoked_at": revoked, "capabilities": [{"tool": "refund.create"}],
        }
        for identifier, parent, role, revoked in [
            ("ROOT-one", None, "agent-coordinator", 140),
            ("CASE-one", "ROOT-one", "agent-case", None),
            ("LEAF-one", "CASE-one", "agent-refund", None),
        ]
    ]


@pytest.mark.parametrize("change", [
    "task_missing", "task_mismatch", "credential_missing", "not_revoked", "expired",
    "future", "orphan", "cycle", "duplicate", "different_role", "no_refund_capability",
])
def test_unavailable_or_invalid_revoked_chain_cannot_contact_agent_or_sign(monkeypatch, change):
    document = {"task": {"task_id": "TASK-one"}, "credentials": credentials()}
    if change == "task_missing":
        document = None
    elif change == "task_mismatch":
        document["task"]["task_id"] = "TASK-other"
    elif change == "credential_missing":
        document["credentials"][0]["credential_id"] = "ROOT-other"
    elif change == "not_revoked":
        document["credentials"][0]["revoked_at"] = None
    elif change in {"expired", "future"}:
        field = "expires_at" if change == "expired" else "not_before"
        document["credentials"][2][field] = 150 if change == "expired" else 151
    elif change == "orphan":
        document["credentials"][1]["parent_credential_id"] = "MISSING-parent"
    elif change == "cycle":
        document["credentials"][1]["parent_credential_id"] = "LEAF-one"
    elif change == "duplicate":
        document["credentials"].append(deepcopy(document["credentials"][0]))
    elif change == "different_role":
        document["credentials"][1]["holder_agent_id"] = "agent-knowledge"
    else:
        document["credentials"][2]["capabilities"] = [{"tool": "ticket.read"}]
    monkeypatch.setattr("backend.ui_api.revocation_verification.now_unix", lambda: 150)
    forbidden = Mock(side_effect=AssertionError(
        "no request signing or database retrieval is allowed",
    ))
    monkeypatch.setattr("backend.ui_api.revocation_verification.connect", forbidden)
    monkeypatch.setattr("backend.ui_api.revocation_verification.attempt", forbidden)
    ui = SimpleNamespace(store=SimpleNamespace(task_snapshot=lambda _: document))
    with pytest.raises(UiApiError):
        refund_chain(ui, "TASK-one", "ROOT-one")
    forbidden.assert_not_called()


def test_pending_workflow_blocks_independent_probe_before_any_request(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("pending workflow cannot start another probe"))
    monkeypatch.setattr("backend.ui_api.revocation_verification.refund_chain", forbidden)
    ui = SimpleNamespace(store=SimpleNamespace(has_pending_workflows=lambda: True))
    with pytest.raises(UiApiError) as failure:
        verify_revoked(ui, "TASK-one", "ROOT-one")
    assert failure.value.reason_code == "SECURITY_PROOF_BUSY"
    forbidden.assert_not_called()


def committed_refund_snapshot():
    chain = [{"payload": {"task_id": "TASK-one"}}]
    snapshot = {
        "task": {"task_id": "TASK-one"},
        "executions": [{
            "execution_id": "EXEC-one", "tool_service": "refund-service",
            "tool_name": "refund.create", "state": "COMMITTED", "decision": "ALLOW",
            "receipt_status": "SIGNED", "credential_chain_hash": sm3_hex(canonicalize(chain)),
            "business_action_id": "ACTION-one", "business_effect_id": "REFUND-one",
        }],
        "receipts": [{
            "execution_id": "EXEC-one", "receipt_type": "EXECUTION_RESULT",
            "decision": "ALLOW", "receipt_status": "SIGNED", "signature": {"valid": True},
            "source_verification": {
                "profile": "RECEIPT_EXECUTION_BINDING_V1", "schema_valid": True,
                "stored_hash_valid": True, "row_binding_valid": True,
                "execution_binding_valid": True,
            },
        }],
        "business_effects": {"refunds": [{
            "execution_id": "EXEC-one", "refund_id": "REFUND-one", "status": "COMMITTED",
        }]},
    }
    return chain, snapshot


def test_revocation_reuses_only_the_action_bound_to_its_completed_refund_and_signed_receipt():
    chain, snapshot = committed_refund_snapshot()
    ui = SimpleNamespace(store=SimpleNamespace(task_snapshot=lambda _: snapshot))
    assert persisted_refund_action(ui, chain) == "ACTION-one"


@pytest.mark.parametrize("change", [
    "missing_task", "cross_task", "chain_hash", "tool", "not_committed", "decision",
    "action_missing", "receipt_pending", "refund_execution", "refund_effect", "refund_status",
    "receipt_execution", "receipt_signature", "receipt_profile", "receipt_source",
    "receipt_binding", "receipt_decision", "receipt_type", "receipt_final",
])
def test_corrupted_persisted_refund_cannot_supply_a_revocation_probe_action(change):
    chain, snapshot = committed_refund_snapshot()
    execution, receipt = snapshot["executions"][0], snapshot["receipts"][0]
    refund = snapshot["business_effects"]["refunds"][0]
    if change == "missing_task":
        snapshot = None
    elif change == "cross_task":
        snapshot["task"]["task_id"] = "TASK-other"
    elif change == "chain_hash":
        execution["credential_chain_hash"] = "0" * 64
    elif change == "tool":
        execution["tool_name"] = "notification.send"
    elif change == "not_committed":
        execution["state"] = "DENIED"
    elif change == "decision":
        execution["decision"] = "DENY"
    elif change == "action_missing":
        execution["business_action_id"] = None
    elif change == "receipt_pending":
        execution["receipt_status"] = "PENDING"
    elif change == "refund_execution":
        refund["execution_id"] = "EXEC-other"
    elif change == "refund_effect":
        refund["refund_id"] = "REFUND-other"
    elif change == "refund_status":
        refund["status"] = "PENDING"
    elif change == "receipt_execution":
        receipt["execution_id"] = "EXEC-other"
    elif change == "receipt_signature":
        receipt["signature"]["valid"] = False
    elif change == "receipt_profile":
        receipt["source_verification"]["profile"] = "other"
    elif change == "receipt_source":
        receipt["source_verification"]["stored_hash_valid"] = False
    elif change == "receipt_binding":
        receipt["source_verification"]["execution_binding_valid"] = False
    elif change == "receipt_decision":
        receipt["decision"] = "DENY"
    elif change == "receipt_type":
        receipt["receipt_type"] = "AUTHORIZATION_DENIAL"
    else:
        receipt["receipt_status"] = "PENDING"
    ui = SimpleNamespace(store=SimpleNamespace(task_snapshot=lambda _: snapshot))
    with pytest.raises(UiApiError) as failure:
        persisted_refund_action(ui, chain)
    assert failure.value.reason_code == "CONTROLLED_RESULT_INVALID"


def test_unprocessed_revocation_probe_keeps_normal_business_resolution():
    chain, snapshot = committed_refund_snapshot()
    snapshot["business_effects"]["refunds"] = []
    snapshot["executions"] = snapshot["receipts"] = []
    ui = SimpleNamespace(store=SimpleNamespace(task_snapshot=lambda _: snapshot))
    assert persisted_refund_action(ui, chain) is None


@pytest.mark.parametrize("field,value", [
    ("task_id", "x" * 129), ("reason_code", "arbitrary message"),
    ("observed_at_ms", -1), ("observed_at_ms", 9_007_199_254_740_992),
    ("holder_proof_valid", "true"), ("new_holder_proof", False),
    ("request_hash", "bad"), ("unknown", "extra"),
])
def test_response_schema_refuses_ambiguous_or_unbounded_public_fields(field, value):
    document = {
        "schema_version": "1.0", "task_id": "TASK-contract", "credential_id": "ROOT-contract",
        "status": "PASS", "reason_code": "ANCESTOR_REVOKED", "request_id": "REQ-contract",
        "request_hash": "a" * 64, "holder_key_id": "agent-refund-key-01",
        "holder_proof_valid": True, "chain_signature_valid": True,
        "receipt_valid": True, "record_binding_valid": True,
        "execution_id": "EXEC-contract", "receipt_id": "RCPT-contract",
        "before": {"refund_rows": 0, "notification_rows": 0, "refund_amount_fen": 0},
        "after": {"refund_rows": 0, "notification_rows": 0, "refund_amount_fen": 0},
        "budget_unchanged": True, "new_holder_proof": True, "observed_at_ms": 1000,
    }
    document[field] = value
    with pytest.raises(SchemaValidationError):
        Draft202012Validator(exports()["verify-revoked-response.schema.json"]).validate(document)
