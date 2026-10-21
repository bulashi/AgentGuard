from __future__ import annotations

from copy import deepcopy

import pytest
from jsonschema import ValidationError

from backend.audit.prefix_contracts import validate_event_core
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.revocation.audit import audit_schemas, revocation_outbox_id
from backend.ui_api.store import UiReadStore


def audit_row():
    # Contract fixture only; not an integration result or an authorization object.
    evidence = {
        "schema_version": "1.0",
        "record_type": "CREDENTIAL_REVOKED_V1",
        "credential_id": "ROOT-contract",
        "credential_type": "ROOT",
        "parent_credential_id": None,
        "task_id": "TASK-contract",
        "revoked_at": 100,
        "revoked_by": "native-operator",
        "reason": "停止办理",
    }
    digest = sm3_hex(canonicalize(evidence))
    return [
        1,
        "EVENT-contract",
        None,
        "CREDENTIAL_REVOKED",
        101,
        digest,
        "ROOT-contract",
        "0" * 64,
        "a" * 64,
        "4.0",
        evidence,
        revocation_outbox_id("ROOT-contract"),
        None,
        "CREDENTIAL_REVOKED",
        "ROOT-contract",
        digest,
        100,
        "APPENDED",
    ]


def test_credential_revocation_projection_has_versioned_bound_evidence():
    result = UiReadStore._audit_projection(audit_row())
    assert result["evidence_binding_valid"] is True
    assert result["credential_revocation_evidence"]["task_id"] == "TASK-contract"
    assert result["execution_id"] is None
    validate_event_core(
        {
            key: result[key]
            for key in (
                "schema_version",
                "event_sequence",
                "event_id",
                "execution_id",
                "event_type",
                "timestamp",
                "payload_hash",
                "evidence_reference",
                "previous_event_hash",
                "event_hash",
            )
        }
    )


@pytest.mark.parametrize(
    "index,value",
    [
        (2, "EXEC-wrong"),
        (4, 99),
        (5, "b" * 64),
        (6, "ROOT-other"),
        (9, "1.0"),
        (11, "OUTBOX-OTHER"),
        (12, "EXEC-wrong"),
        (13, "OTHER"),
        (14, "ROOT-other"),
        (15, "b" * 64),
        (16, 99),
        (17, "PENDING"),
    ],
)
def test_credential_revocation_projection_refuses_mismatched_metadata(index, value):
    row = audit_row()
    row[index] = value
    result = UiReadStore._audit_projection(row)
    assert result["evidence_binding_valid"] is False
    assert result["credential_revocation_evidence"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("revoked_at", True),
        ("revoked_at", -1),
        ("revoked_at", "100"),
        ("record_type", "OTHER"),
        ("credential_type", "ADMIN"),
        ("unknown", "data"),
    ],
)
def test_credential_revocation_projection_refuses_wrong_evidence_types(field, value):
    row = deepcopy(audit_row())
    row[10][field] = value
    result = UiReadStore._audit_projection(row)
    assert result["evidence_binding_valid"] is False


def cancellation_evidence():
    return {
        "schema_version": "1.0",
        "record_type": "DISPATCH_CANCELLED_V1",
        "cancellation_id": "CANCEL-contract",
        "execution_id": "EXEC-contract",
        "denial_execution_id": "DENY-contract",
        "task_id": "TASK-contract",
        "request_id": "REQ-contract",
        "request_hash": "a" * 64,
        "credential_chain_hash": "b" * 64,
        "admission_decision": "ALLOW",
        "dispatch_decision": "DENY",
        "reason_code": "KEY_REVOKED",
        "cancelled_at": 100,
        "released_budgets": [
            {"credential_id": "ROOT-contract", "quota_type": "max_tool_calls", "amount": 1}
        ],
        "revocations": [
            {
                "credential_id": "ROOT-contract",
                "revoked_at": 99,
                "reason": "停止读取",
                "revoked_by": "native-operator",
            }
        ],
    }


def test_dispatch_cancellation_accepts_one_applicable_read_only_budget():
    audit_schemas().validate("dispatch-cancellation-evidence.schema.json", cancellation_evidence())


@pytest.mark.parametrize(
    "change", ["no-budget", "boolean-amount", "negative-amount", "unknown-quota", "extra-field"]
)
def test_dispatch_cancellation_still_rejects_invalid_budget_evidence(change):
    evidence = cancellation_evidence()
    if change == "no-budget":
        evidence["released_budgets"] = []
    elif change == "boolean-amount":
        evidence["released_budgets"][0]["amount"] = True
    elif change == "negative-amount":
        evidence["released_budgets"][0]["amount"] = -1
    elif change == "unknown-quota":
        evidence["released_budgets"][0]["quota_type"] = "unknown"
    else:
        evidence["extra"] = "data"
    with pytest.raises(ValidationError):
        audit_schemas().validate("dispatch-cancellation-evidence.schema.json", evidence)
