from __future__ import annotations

from copy import deepcopy
from typing import Any
from unittest.mock import Mock

import pytest

from backend.common.schema import PROJECT_ROOT, SchemaStore
from backend.crypto.sm import signed_object_hash
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.ui_api.evidence_binding import credential_source_verification, receipt_source_verification
from backend.ui_api.store import UiReadStore


# Shape-valid synthetic signatures, never evidence of SM2 verification or a real DB.
def _signature(key: str, purpose: str, at: int) -> dict[str, Any]:
    return {
        "algorithm": "SM2", "key_id": key, "key_purpose": purpose,
        "encoding": "SM2_RS_HEX_128_LOWERCASE", "value": "0" * 128, "signed_at": at,
    }


def _credential(kind: str = "ROOT") -> tuple[dict[str, Any], dict[str, Any]]:
    root = kind == "ROOT"
    payload = {
        "schema_version": "1.0", "credential_id": "credential-test", "credential_type": kind,
        "issuer": {"subject_id": "issuer-test", "key_id": "issuer-key-test"},
        "holder": {"agent_id": "agent-test", "key_id": "holder-key-test"},
        "tenant_id": "tenant-test", "task_id": "task-test", "verifier_audience": "secure-tool-gateway",
        "capabilities": [{
            "service": "refund-service", "tool": "refund.create", "version": "v1",
            "resources": {"ticket_ids": ["ticket-test"], "customer_ids": ["customer-test"]},
            "constraints": {"single_max_fen": 7000},
        }],
        "quotas": {"refund_total_fen": 7000, "max_tool_calls": 4},
        "not_before": 10, "expires_at": 100, "issued_at": 10, "delegation_depth": 2,
        "parent_credential_id": None if root else "parent-test",
        "parent_credential_hash": None if root else "a" * 64,
    }
    signed = {"payload": payload, "signature": _signature(
        "issuer-key-test", "AUTHORIZATION_ROOT_SIGNING" if root else "AGENT_HOLDER_SIGNING", 10,
    )}
    metadata = {
        key: value for key, value in payload.items()
        if key not in {"issuer", "holder", "capabilities", "quotas", "schema_version"}
    }
    metadata.update({
        "issuer_subject_id": "issuer-test", "issuer_key_id": "issuer-key-test",
        "holder_agent_id": "agent-test", "holder_key_id": "holder-key-test",
        "signed_object_hash": signed_object_hash(signed),
    })
    return signed, metadata


def _receipt(state: str = "COMMITTED") -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    denied = state == "DENIED"
    committed = state == "COMMITTED"
    result = {"refund_id": "refund-test", "amount_fen": 7000} if committed else None
    execution = {
        "execution_id": "execution-test", "tenant_id": "tenant-test", "task_id": "task-test",
        "request_hash": "a" * 64, "credential_chain_hash": "b" * 64,
        "tool_service": "refund-service", "tool_name": "refund.create", "tool_version": "v1",
        "parameter_hash": "c" * 64, "decision": "DENY" if denied else "ALLOW",
        "reason_code": "PARAMETER_CONSTRAINT_VIOLATION" if denied else None,
        "business_action_id": "action-test", "state": state, "created_at": 10,
        "updated_at": 30, "terminal_at": 12, "terminal_state": state,
        "decision_at": 11, "decision_value": "DENY" if denied else "ALLOW",
        "business_effect_id": "refund-test" if committed else None,
        "business_result_hash": signed_object_hash(result) if committed else None,
        "result": result,
    }
    payload = {
        "schema_version": "1.0", "receipt_id": "receipt-test",
        "receipt_type": "AUTHORIZATION_DENIAL" if denied else "EXECUTION_RESULT",
        "request_id": "request-test",
        **{
            key: value for key, value in execution.items()
            if key not in {
                "state", "created_at", "updated_at", "terminal_at", "terminal_state", "result", "reason_code",
                "decision_at", "decision_value",
            }
        },
        "reason_code": execution["reason_code"] if denied else "ALLOWED",
        "business_idempotency_key": "d" * 64,
        "budget_reserved": 0, "budget_committed": 0 if denied else 7000 if committed else 0,
        "started_at": 10, "finished_at": 12, "decision_at": 11,
        "business_effect_finalized_at": None if denied else 12,
        "receipt_issued_at": 20, "receipt_signing_key_id": "receipt-key-test",
    }
    signed = {"payload": payload, "signature": _signature("receipt-key-test", "EXECUTION_RECEIPT_SIGNING", 20)}
    metadata = {key: payload[key] for key in ("receipt_id", "execution_id", "receipt_type", "decision", "reason_code")}
    metadata.update({"receipt_hash": signed_object_hash(signed), "receipt_status": "SIGNED"})
    return signed, metadata, execution


def _receipt_row(
    signed: dict[str, Any], metadata: dict[str, Any], execution: dict[str, Any],
) -> tuple[Any, ...]:
    return (
        metadata["receipt_id"], metadata["execution_id"], metadata["receipt_type"], metadata["decision"],
        metadata["reason_code"], signed, metadata["receipt_hash"], metadata["receipt_status"], 15,
        *(execution[key] for key in (
            "tenant_id", "task_id", "request_hash", "credential_chain_hash", "tool_service", "tool_name",
            "tool_version", "parameter_hash", "state", "decision", "reason_code", "business_action_id",
            "business_effect_id", "business_result_hash", "result", "created_at", "terminal_at", "terminal_state",
            "decision_at", "decision_value",
        )),
    )


@pytest.mark.parametrize("kind", ["ROOT", "DELEGATION"])
def test_credential_shape_hash_and_metadata_binding(kind: str) -> None:
    signed, metadata = _credential(kind)
    result = credential_source_verification(signed, metadata, SchemaStore())
    assert result == {
        "schema_version": "1.0", "profile": "CREDENTIAL_ROW_BINDING_V1", "schema_valid": True,
        "stored_hash_valid": True, "row_binding_valid": True, "execution_binding_valid": None,
    }


@pytest.mark.parametrize("field", [
    "credential_id", "credential_type", "parent_credential_id", "parent_credential_hash",
    "issuer_subject_id", "issuer_key_id", "holder_agent_id", "holder_key_id",
    "not_before", "expires_at", "delegation_depth", "issued_at", "tenant_id", "task_id", "verifier_audience",
])
def test_changed_credential_metadata_does_not_inherit_valid_signed_source(field: str) -> None:
    signed, metadata = _credential("DELEGATION")
    value = metadata[field]
    metadata[field] = value + 1 if type(value) is int else "changed"
    result = credential_source_verification(signed, metadata, SchemaStore())
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
def test_receipt_matches_terminal_execution(state: str) -> None:
    signed, metadata, execution = _receipt(state)
    assert {"terminal_at", "terminal_state", "updated_at", "decision_value"}.isdisjoint(signed["payload"])
    assert signed["payload"]["started_at"] == execution["created_at"] < execution["decision_at"]
    assert signed["payload"]["decision_at"] == execution["decision_at"]
    assert signed["payload"]["decision"] == execution["decision"] == execution["decision_value"]
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result == {
        "schema_version": "1.0", "profile": "RECEIPT_EXECUTION_BINDING_V1", "schema_valid": True,
        "stored_hash_valid": True, "row_binding_valid": True, "execution_binding_valid": True,
    }


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("field", ["terminal_at", "terminal_state"])
def test_legacy_receipt_without_terminal_metadata_is_not_time_verified(state: str, field: str) -> None:
    signed, metadata, execution = _receipt(state)
    original = deepcopy(signed)
    execution["updated_at"] = signed["payload"]["finished_at"]
    del execution[field]
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result == {
        "schema_version": "1.0", "profile": "RECEIPT_EXECUTION_BINDING_V1", "schema_valid": True,
        "stored_hash_valid": True, "row_binding_valid": True, "execution_binding_valid": False,
    }
    assert signed == original


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("field,value", [
    ("terminal_at", None), ("terminal_at", True), ("terminal_at", False),
    ("terminal_at", 12.0), ("terminal_at", "12"), ("terminal_at", []), ("terminal_at", {}),
    ("terminal_at", -1), ("terminal_at", MAX_SAFE_INTEGER + 1),
    ("terminal_state", None), ("terminal_state", True), ("terminal_state", []),
    ("terminal_state", {}), ("terminal_state", "RECONCILING"),
])
def test_receipt_rejects_unreliable_terminal_metadata(state: str, field: str, value: Any) -> None:
    signed, metadata, execution = _receipt(state)
    execution[field] = value
    execution["updated_at"] = signed["payload"]["finished_at"]
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("terminal_at", [False, True])
def test_boolean_terminal_time_is_not_its_equal_signed_integer(state: str, terminal_at: bool) -> None:
    signed, metadata, execution = _receipt(state)
    execution.update({"created_at": 0, "decision_at": 0, "terminal_at": terminal_at})
    signed["payload"].update({
        "started_at": 0, "decision_at": 0, "finished_at": int(terminal_at),
        "business_effect_finalized_at": None if state == "DENIED" else int(terminal_at),
    })
    metadata["receipt_hash"] = signed_object_hash(signed)
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state,terminal_state", [
    ("COMMITTED", "RELEASED"), ("COMMITTED", "DENIED"),
    ("RELEASED", "COMMITTED"), ("RELEASED", "DENIED"),
    ("DENIED", "COMMITTED"), ("DENIED", "RELEASED"),
])
def test_receipt_terminal_state_must_match_current_state(state: str, terminal_state: str) -> None:
    signed, metadata, execution = _receipt(state)
    execution["terminal_state"] = terminal_state
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("created_at,decision_at,terminal_at,issued_at,valid", [
    (0, 0, 0, 0, True), (10, 10, 10, 10, True), (10, 11, 12, 20, True),
    (10, 10, 12, 12, True), (10, 12, 12, 20, True),
    (10, 10, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, True),
    (10, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, True),
    (MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, True),
    (10, 11, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, True),
    (10, 10, 9, 20, False), (10, 10, 21, 20, False),
    (10, 9, 12, 20, False), (10, 13, 12, 20, False),
    (10, 11, 12, 10, False),
])
def test_receipt_terminal_time_is_bounded_by_creation_and_issuance(
    state: str, created_at: int, decision_at: int, terminal_at: int, issued_at: int, valid: bool,
) -> None:
    signed, metadata, execution = _receipt(state)
    execution.update({"created_at": created_at, "decision_at": decision_at, "terminal_at": terminal_at})
    signed["payload"].update({
        "started_at": created_at, "decision_at": decision_at, "finished_at": terminal_at,
        "business_effect_finalized_at": None if state == "DENIED" else terminal_at,
        "receipt_issued_at": issued_at,
    })
    signed["signature"]["signed_at"] = issued_at
    metadata["receipt_hash"] = signed_object_hash(signed)
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is valid


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("missing_fields", [
    ("decision_at",), ("decision_value",), ("decision_at", "decision_value"),
])
def test_missing_decision_source_does_not_validate_execution_binding(
    state: str, missing_fields: tuple[str, ...],
) -> None:
    signed, metadata, execution = _receipt(state)
    original = deepcopy(signed)
    for field in missing_fields:
        del execution[field]
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False
    assert signed == original


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("field,value", [
    ("decision_at", None), ("decision_at", True), ("decision_at", False),
    ("decision_at", 11.0), ("decision_at", "11"), ("decision_at", []),
    ("decision_at", {}), ("decision_at", -1),
    ("decision_at", MAX_SAFE_INTEGER + 1),
    ("decision_value", None), ("decision_value", True), ("decision_value", False),
    ("decision_value", 11), ("decision_value", 11.0), ("decision_value", []),
    ("decision_value", {}), ("decision_value", "changed"), ("decision_value", ""),
])
def test_receipt_rejects_unreliable_decision_metadata(state: str, field: str, value: Any) -> None:
    signed, metadata, execution = _receipt(state)
    execution[field] = value
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("mismatch", ["decision_value", "decision", "payload"])
def test_decision_value_must_match_execution_and_signed_decision(state: str, mismatch: str) -> None:
    signed, metadata, execution = _receipt(state)
    if mismatch == "payload":
        signed, metadata, _ = _receipt("RELEASED" if state == "DENIED" else "DENIED")
    else:
        execution[mismatch] = "ALLOW" if state == "DENIED" else "DENY"
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
def test_consistent_decision_must_match_terminal_state(state: str) -> None:
    signed, metadata, execution = _receipt(state)
    terminal_state = "RELEASED" if state == "DENIED" else "DENIED"
    execution.update({"state": terminal_state, "terminal_state": terminal_state})
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("decision_at", [False, True])
def test_boolean_decision_time_is_not_its_equal_signed_integer(state: str, decision_at: bool) -> None:
    signed, metadata, execution = _receipt(state)
    execution.update({"created_at": 0, "decision_at": decision_at, "terminal_at": 1})
    signed["payload"].update({
        "started_at": 0, "decision_at": int(decision_at), "finished_at": 1,
        "business_effect_finalized_at": None if state == "DENIED" else 1,
    })
    metadata["receipt_hash"] = signed_object_hash(signed)
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("field,value", [("started_at", 11), ("decision_at", 10), ("decision_at", 12)])
def test_signed_creation_and_decision_times_match_their_own_sources(state: str, field: str, value: int) -> None:
    signed, metadata, execution = _receipt(state)
    signed["payload"][field] = value
    metadata["receipt_hash"] = signed_object_hash(signed)
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("finished_at", [11, 21])
def test_receipt_finished_at_must_equal_terminal_time(state: str, finished_at: int) -> None:
    signed, metadata, execution = _receipt(state)
    signed["payload"]["finished_at"] = finished_at
    metadata["receipt_hash"] = signed_object_hash(signed)
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is True
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state,finalized_at", [
    ("COMMITTED", None), ("COMMITTED", 11), ("COMMITTED", 21),
    ("RELEASED", None), ("RELEASED", 11), ("RELEASED", 21), ("DENIED", 12),
])
def test_receipt_business_effect_time_must_match_terminal_state(state: str, finalized_at: Any) -> None:
    signed, metadata, execution = _receipt(state)
    signed["payload"]["business_effect_finalized_at"] = finalized_at
    metadata["receipt_hash"] = signed_object_hash(signed)
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is (state != "DENIED")
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is (state != "DENIED")
    assert result["execution_binding_valid"] is False


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("updated_at", [0, 12, 20, 100])
def test_receipt_maintenance_time_does_not_change_terminal_binding(state: str, updated_at: int) -> None:
    signed, metadata, execution = _receipt(state)
    original = deepcopy(signed)
    schemas = SchemaStore()
    expected = receipt_source_verification(signed, metadata, execution, schemas)
    assert expected["execution_binding_valid"] is True
    execution["updated_at"] = updated_at
    assert receipt_source_verification(signed, metadata, execution, schemas) == expected
    assert signed == original


@pytest.mark.parametrize("field", ["receipt_id", "execution_id", "receipt_type", "decision", "reason_code", "receipt_status"])
def test_receipt_columns_do_not_inherit_a_different_valid_payload(field: str) -> None:
    signed, metadata, execution = _receipt()
    metadata[field] = "changed"
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["stored_hash_valid"] is True
    assert result["row_binding_valid"] is False


@pytest.mark.parametrize("field", [
    "execution_id", "tenant_id", "task_id", "request_hash", "credential_chain_hash",
    "tool_service", "tool_name", "tool_version", "parameter_hash", "decision", "business_action_id",
    "business_effect_id", "business_result_hash", "state", "created_at",
])
def test_receipt_rejects_changed_execution_binding(field: str) -> None:
    signed, metadata, execution = _receipt()
    execution[field] = 11 if field == "created_at" else "changed"
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is False


def test_receipt_recomputes_stored_result_not_only_the_copied_digest() -> None:
    signed, metadata, execution = _receipt()
    execution["result"]["amount_fen"] = 1
    assert receipt_source_verification(signed, metadata, execution, SchemaStore())["execution_binding_valid"] is False
    signed, metadata, execution = _receipt()
    execution["business_result_hash"] = None
    assert receipt_source_verification(signed, metadata, execution, SchemaStore())["execution_binding_valid"] is True


@pytest.mark.parametrize("value", [True, "10", None])
def test_integer_row_binding_does_not_coerce_types(value: Any) -> None:
    signed, metadata = _credential()
    metadata["not_before"] = value
    assert credential_source_verification(signed, metadata, SchemaStore())["row_binding_valid"] is False
    signed, metadata, execution = _receipt()
    execution["created_at"] = value
    assert receipt_source_verification(signed, metadata, execution, SchemaStore())["execution_binding_valid"] is False


@pytest.mark.parametrize("value", [True, [], {}, None, "UNKNOWN"])
def test_unreliable_execution_state_does_not_get_a_terminal_binding(value: Any) -> None:
    signed, metadata, execution = _receipt()
    execution["state"] = value
    assert receipt_source_verification(signed, metadata, execution, SchemaStore())["execution_binding_valid"] is False


def test_missing_fields_and_wrong_signed_timestamp_fail_closed() -> None:
    signed, metadata = _credential()
    del metadata["holder_key_id"]
    assert credential_source_verification(signed, metadata, SchemaStore())["row_binding_valid"] is False
    signed, metadata, execution = _receipt()
    del execution["request_hash"]
    assert receipt_source_verification(signed, metadata, execution, SchemaStore())["execution_binding_valid"] is False
    signed, metadata, execution = _receipt()
    signed["signature"]["signed_at"] = 21
    metadata["receipt_hash"] = signed_object_hash(signed)
    assert receipt_source_verification(signed, metadata, execution, SchemaStore())["row_binding_valid"] is False


def test_missing_nullable_fields_are_not_treated_as_explicit_null() -> None:
    signed, metadata = _credential()
    del metadata["parent_credential_id"]
    assert credential_source_verification(signed, metadata, SchemaStore())["row_binding_valid"] is False
    signed, metadata, execution = _receipt("DENIED")
    del execution["business_effect_id"]
    assert receipt_source_verification(signed, metadata, execution, SchemaStore())["execution_binding_valid"] is False


@pytest.mark.parametrize("bad_signed", [None, [], {}, {"payload": {}, "signature": {}}, {"payload": {"issued_at": 10.0}}])
def test_invalid_signed_shapes_do_not_get_binding_flags(bad_signed: Any) -> None:
    _, metadata, execution = _receipt()
    result = receipt_source_verification(bad_signed, metadata, execution, SchemaStore())
    assert result["schema_valid"] is False
    assert result["row_binding_valid"] is False
    assert result["execution_binding_valid"] is False


def test_mismatched_stored_hash_is_a_separate_flag() -> None:
    signed, metadata, execution = _receipt()
    metadata["receipt_hash"] = "f" * 64
    result = receipt_source_verification(signed, metadata, execution, SchemaStore())
    assert result["stored_hash_valid"] is False
    assert result["row_binding_valid"] is True
    assert result["execution_binding_valid"] is True


def test_store_keeps_cryptographic_result_separate_from_row_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    signed, metadata, execution = _receipt()
    metadata["receipt_id"] = "wrong-displayed-id"
    row = _receipt_row(signed, metadata, execution)
    monkeypatch.setattr(UiReadStore, "_verify_signed", staticmethod(lambda *_args, **_kwargs: True))
    projection = UiReadStore("unused-test-only")._receipt_projection(None, row)
    assert projection["signature"]["valid"] is True  # Deliberately mocked, not real SM2.
    assert projection["source_verification"]["row_binding_valid"] is False
    assert projection["created_at"] == 15  # Row creation is not required to equal the signed issuance time.
    assert "value" not in projection["signature"]


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("crypto_valid", [False, True])
@pytest.mark.parametrize("execution_fields,valid", [
    ({"terminal_at": 12}, True),
    ({"terminal_at": None, "terminal_state": None}, False),
    ({"terminal_at": True}, False), ({"terminal_at": 12.0}, False),
    ({"terminal_at": 9}, False), ({"terminal_at": 21}, False),
    ({"terminal_state": None}, False), ({"terminal_state": "changed"}, False),
    ({"decision_at": 11}, True),
    ({"decision_at": None, "decision_value": None}, False),
    ({"decision_at": None}, False), ({"decision_value": None}, False),
    ({"decision_at": True}, False), ({"decision_at": False}, False),
    ({"decision_at": 11.0}, False), ({"decision_at": "11"}, False),
    ({"decision_at": 10}, False), ({"decision_at": 12}, False),
    ({"decision_at": -1}, False), ({"decision_at": MAX_SAFE_INTEGER + 1}, False),
    ({"decision_value": True}, False), ({"decision_value": 11}, False),
    ({"decision_value": []}, False), ({"decision_value": {}}, False),
    ({"decision_value": "changed"}, False),
])
def test_store_execution_time_binding_preserves_original_and_separate_crypto_result(
    monkeypatch: pytest.MonkeyPatch, state: str, crypto_valid: bool,
    execution_fields: dict[str, Any], valid: bool,
) -> None:
    signed, metadata, execution = _receipt(state)
    original = deepcopy(signed)
    execution.update(execution_fields)
    verify = Mock(return_value=crypto_valid)
    monkeypatch.setattr(UiReadStore, "_verify_signed", staticmethod(verify))
    projection = UiReadStore("unused-test-only")._receipt_projection(
        None, _receipt_row(signed, metadata, execution),
    )
    assert projection["source_verification"] == {
        "schema_version": "1.0", "profile": "RECEIPT_EXECUTION_BINDING_V1", "schema_valid": True,
        "stored_hash_valid": True, "row_binding_valid": True, "execution_binding_valid": valid,
    }
    assert projection["signature"]["valid"] is crypto_valid  # Mocked, not real SM2 verification.
    verify.assert_called_once()
    assert verify.call_args.args[1] is signed
    assert signed == original
    assert set(projection) == {
        "receipt_id", "execution_id", "receipt_type", "decision", "reason_code", "receipt_hash",
        "receipt_status", "created_at", "source_verification", "signature",
    }
    assert {"terminal_at", "terminal_state", "updated_at", "decision_value"}.isdisjoint(signed["payload"])


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("crypto_valid", [False, True])
@pytest.mark.parametrize("shape", ["legacy", "missing", "null", "boolean", "string", "extra_decision_value"])
def test_store_legacy_receipt_and_invalid_shapes_keep_original_crypto_verification_independent(
    monkeypatch: pytest.MonkeyPatch, state: str, crypto_valid: bool, shape: str,
) -> None:
    signed, metadata, execution = _receipt(state)
    signed["payload"]["decision_at"] = execution["created_at"]
    execution.update({"decision_at": None, "decision_value": None})
    if shape == "missing":
        del signed["payload"]["decision_at"]
    elif shape == "null":
        signed["payload"]["decision_at"] = None
    elif shape == "boolean":
        signed["payload"]["decision_at"] = True
    elif shape == "string":
        signed["payload"]["decision_at"] = "10"
    elif shape == "extra_decision_value":
        signed["payload"]["decision_value"] = execution["decision"]
    metadata["receipt_hash"] = signed_object_hash(signed)
    original = deepcopy(signed)
    verify = Mock(return_value=crypto_valid)
    monkeypatch.setattr(UiReadStore, "_verify_signed", staticmethod(verify))
    projection = UiReadStore("unused-test-only")._receipt_projection(
        None, _receipt_row(signed, metadata, execution),
    )
    assert projection["source_verification"] == {
        "schema_version": "1.0", "profile": "RECEIPT_EXECUTION_BINDING_V1", "schema_valid": shape == "legacy",
        "stored_hash_valid": True, "row_binding_valid": shape == "legacy", "execution_binding_valid": False,
    }
    assert projection["signature"]["valid"] is crypto_valid  # Mocked, not real SM2 verification.
    verify.assert_called_once()
    assert verify.call_args.args[1] is signed
    assert signed == original
    assert set(projection) == {
        "receipt_id", "execution_id", "receipt_type", "decision", "reason_code", "receipt_hash",
        "receipt_status", "created_at", "source_verification", "signature",
    }


def test_credential_store_uses_original_types_and_appended_context_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    signed, metadata = _credential()
    row = (
        metadata["credential_id"], "ROOT", None, None, metadata["signed_object_hash"], signed,
        metadata["issuer_subject_id"], metadata["issuer_key_id"], "changed-holder", metadata["holder_key_id"],
        10, 100, 2, 10, None, None, 10, metadata["tenant_id"], metadata["task_id"], metadata["verifier_audience"],
    )
    monkeypatch.setattr(UiReadStore, "_verify_signed", staticmethod(lambda *_args, **_kwargs: True))
    projection = UiReadStore("unused-test-only")._credential_projection(None, row)
    assert projection["signature"]["valid"] is True  # Mocked on purpose.
    assert projection["stored_hash_valid"] is True
    assert projection["source_verification"]["row_binding_valid"] is False


def test_additive_metadata_conforms_to_its_separate_schema() -> None:
    schemas = SchemaStore()
    extension = SchemaStore(PROJECT_ROOT / "protocol" / "extensions" / "evidence-projection-v1")
    signed, metadata = _credential()
    extension.validate("source-verification.schema.json", credential_source_verification(signed, metadata, schemas))
    signed, metadata, execution = _receipt()
    extension.validate("source-verification.schema.json", receipt_source_verification(signed, metadata, execution, schemas))
    malformed = deepcopy(receipt_source_verification(signed, metadata, execution, schemas))
    malformed["execution_binding_valid"] = None
    assert list(extension.validator("source-verification.schema.json").iter_errors(malformed))
