"""Stored-history boundaries; zero signatures below are format-only fixtures."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from fastapi.testclient import TestClient
from psycopg import OperationalError, errors

import backend.authorization.app as authority_app
import backend.coauthorization.review as review_module
import backend.coauthorization.verifier as verifier_module
import backend.crypto.sm as sm_module
from backend.authorization.policy import build_root_capabilities
from backend.coauthorization.contracts import (
    ApprovalPayload,
    CoauthorizationBundle,
    CoauthorizationTaskReview,
)
from backend.coauthorization.review import CoauthorizationReadService
from backend.coauthorization.verifier import (
    CoauthorizationError,
    CoauthorizationReason,
    approval_payload_hash,
    build_approval_statement,
)
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER

NOW = 1_800_000_120
TASK_ID = "TASK-APPROVAL-01"
HISTORY_PATH = f"/extensions/coauthorization/v1/tasks/{TASK_ID}"


def _stored_case(
    *, challenge_id: str = "challenge-01", status: str = "PENDING",
    refund_total_fen: int = 7_000,
) -> tuple[dict, dict]:
    capabilities = build_root_capabilities(
        ticket_id="T10086", customer_id="C9527", refund_total_fen=refund_total_fen,
    )
    payload = ApprovalPayload.model_validate({
        "schema_version": "1.0", "payload_type": "COAUTHORIZATION_TASK_APPROVAL",
        "approval_purpose": "TASK_COAUTHORIZATION_APPROVAL_V1",
        "verifier_audience": "agentguard-root-authorization",
        "tenant_id": "tenant-A", "task_id": TASK_ID,
        "ticket_id": "T10086", "customer_id": "C9527",
        "capabilities_hash": sm3_hex(canonicalize({"capabilities": capabilities})),
        "quotas": {"refund_total_fen": refund_total_fen, "max_tool_calls": 4},
        "holder": {"agent_id": "agent-coordinator", "key_id": "agent-coordinator-key-01"},
        "not_before": NOW - 100, "expires_at": NOW + 1_800,
        "delegation_depth": 2, "policy_revision": "refund-approval-policy-v1",
        "required_signers": {
            "enterprise_approver": {"subject_id": "enterprise-approver", "key_id": "enterprise-key-01"},
            "finance_approver": {"subject_id": "finance-approver", "key_id": "finance-key-01"},
        },
        "challenge_id": challenge_id,
        "approval_not_before": NOW - 60, "approval_expires_at": NOW + 120,
    })
    task = {
        "task_id": TASK_ID, "tenant_id": payload.tenant_id,
        "ticket_id": payload.ticket_id, "customer_id": payload.customer_id,
        "status": "AUTHORIZED" if status == "CONSUMED" else "PENDING_AUTHORIZATION",
    }
    row = {
        "challenge_id": challenge_id, "task_id": TASK_ID, "tenant_id": payload.tenant_id,
        "policy_revision": payload.policy_revision,
        "approval_payload": payload.model_dump(mode="json"),
        "approval_payload_hash": approval_payload_hash(payload),
        "issued_at": payload.approval_not_before, "expires_at": payload.approval_expires_at,
        "status": status, "consumed_at": None, "revoked_at": None,
        "bundle_hash": None, "signed_bundle": None,
        "root_credential_id": None, "root_credential_hash": None,
        "associated_task_id": None, "associated_root_id": None,
        "associated_payload_hash": None, "associated_bundle_hash": None,
        "enterprise_subject_id": None, "enterprise_key_id": None,
        "finance_subject_id": None, "finance_key_id": None, "authorized_at": None,
        "stored_root_id": None, "stored_root_task_id": None, "stored_root_tenant_id": None,
        "stored_root_type": None, "stored_root_object": None, "stored_root_hash": None,
    }
    if status == "REVOKED":
        row["revoked_at"] = NOW - 5
    if status == "CONSUMED":
        approvals = []
        for index, role in enumerate(("ENTERPRISE_APPROVER", "FINANCE_APPROVER")):
            statement = build_approval_statement(
                payload=payload, role=role, approved_at=NOW - 20 + index,
            ).model_dump(mode="json")
            approvals.append({
                "statement": statement,
                "signature": {
                    "algorithm": "SM2", "key_id": statement["key_id"],
                    "key_purpose": "AUTHORIZATION_ROOT_SIGNING",
                    "encoding": "SM2_RS_HEX_128_LOWERCASE",
                    # Legal encoding only: no real signature or key is generated.
                    "value": "0" * 128, "signed_at": statement["approved_at"],
                },
            })
        bundle = CoauthorizationBundle.model_validate({
            "payload": payload.model_dump(mode="json"), "approvals": approvals,
        }).model_dump(mode="json")
        bundle_hash = sm3_hex(canonicalize(bundle))
        credential = {
            "payload": {
                "schema_version": "1.0", "credential_id": "root-01", "credential_type": "ROOT",
                "issuer": {"subject_id": "authority", "key_id": "authority-key-01"},
                "holder": payload.holder.model_dump(mode="json"),
                "tenant_id": payload.tenant_id, "task_id": payload.task_id,
                "verifier_audience": "secure-tool-gateway", "capabilities": capabilities,
                "quotas": payload.quotas.model_dump(mode="json"),
                "not_before": payload.not_before, "expires_at": payload.expires_at,
                "delegation_depth": payload.delegation_depth,
                "parent_credential_id": None, "parent_credential_hash": None, "issued_at": NOW - 10,
            },
            "signature": {
                "algorithm": "SM2", "key_id": "authority-key-01",
                "key_purpose": "AUTHORIZATION_ROOT_SIGNING", "encoding": "SM2_RS_HEX_128_LOWERCASE",
                "value": "0" * 128, "signed_at": NOW - 10,
            },
        }
        root_hash = signed_object_hash(credential)
        row.update({
            "consumed_at": NOW - 10, "bundle_hash": bundle_hash, "signed_bundle": bundle,
            "root_credential_id": "root-01", "root_credential_hash": root_hash,
            "associated_task_id": TASK_ID, "associated_root_id": "root-01",
            "associated_payload_hash": row["approval_payload_hash"],
            "associated_bundle_hash": bundle_hash,
            "enterprise_subject_id": "enterprise-approver", "enterprise_key_id": "enterprise-key-01",
            "finance_subject_id": "finance-approver", "finance_key_id": "finance-key-01",
            "authorized_at": NOW - 10,
            "stored_root_id": "root-01", "stored_root_task_id": payload.task_id,
            "stored_root_tenant_id": payload.tenant_id, "stored_root_type": "ROOT",
            "stored_root_object": credential, "stored_root_hash": root_hash,
        })
    return task, row


@pytest.fixture(autouse=True)
def no_live_authorization(monkeypatch: pytest.MonkeyPatch):
    guards = []
    for module, name in (
        (verifier_module, "verify_coauthorization"), (verifier_module, "verify_payload"),
        (sm_module, "verify_payload"), (sm_module, "sign_payload"),
        (authority_app, "RootAuthorizationService"), (authority_app, "CoauthorizationService"),
    ):
        guard = Mock(side_effect=AssertionError("history must not construct or verify live authorization"))
        monkeypatch.setattr(module, name, guard)
        guards.append(guard)
    yield
    for guard in guards:
        guard.assert_not_called()


def _snapshot(monkeypatch, task, rows, *, observed_at=NOW):
    connection = MagicMock(name="history-connection")
    connection.__enter__.return_value = connection
    transaction = MagicMock(name="history-transaction")
    connection.transaction.return_value = transaction
    cursor = MagicMock(name="history-cursor")
    cursor.__enter__.return_value = cursor
    connection.cursor.return_value = cursor
    cursor.fetchone.return_value = task
    cursor.fetchall.return_value = rows
    statements = []
    active = False

    def enter_transaction():
        nonlocal active
        active = True
        return transaction

    def exit_transaction(*_args):
        nonlocal active
        active = False
        return False

    def execute(sql, params=None):
        assert active, "snapshot SQL must run within the same transaction"
        statements.append((" ".join(sql.split()), params))
        return cursor

    def observe():
        assert active, "observed_at must be taken before leaving the snapshot"
        cursor.fetchall.assert_called_once_with()
        return observed_at

    transaction.__enter__.side_effect = enter_transaction
    transaction.__exit__.side_effect = exit_transaction
    connection.execute.side_effect = execute
    cursor.execute.side_effect = execute
    connect = Mock(return_value=connection)
    monkeypatch.setattr(review_module, "connect", connect)
    clock = Mock(side_effect=observe)
    subject = CoauthorizationReadService("mock-history-database", clock=clock)
    return SimpleNamespace(
        subject=subject, connection=connection, cursor=cursor, statements=statements,
        connect=connect, clock=clock, transaction=transaction,
    )


@pytest.mark.parametrize("row_count,offset", [(0, 0), (20, 0), (21, 0), (21, 20)])
def test_history_uses_one_read_only_snapshot_and_bounded_offset_page(monkeypatch, row_count, offset) -> None:
    task, _ = _stored_case()
    rows = [_stored_case(challenge_id=f"challenge-{index:02d}")[1] for index in range(row_count)]
    snapshot = _snapshot(monkeypatch, task, rows)

    result = snapshot.subject.task_history(TASK_ID, offset=offset)

    assert snapshot.statements[0] == (
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY", None,
    )
    assert len(snapshot.statements) == 3
    task_sql, task_params = snapshot.statements[1]
    history_sql, history_params = snapshot.statements[2]
    assert "FROM tasks WHERE task_id = %s" in task_sql
    assert task_params == (TASK_ID,)
    assert "FROM coauthorization_challenges AS challenge" in history_sql
    assert "LEFT JOIN coauthorization_authorizations AS approval" in history_sql
    assert "ON approval.challenge_id = challenge.challenge_id" in history_sql
    assert "LEFT JOIN credentials AS root ON root.credential_id = challenge.root_credential_id" in history_sql
    for alias in (
        "stored_root_id", "stored_root_task_id", "stored_root_tenant_id",
        "stored_root_type", "stored_root_object", "stored_root_hash",
    ):
        assert f"AS {alias}" in history_sql
    assert "WHERE challenge.task_id = %s AND challenge.tenant_id = %s" in history_sql
    assert "ORDER BY challenge.issued_at DESC, challenge.challenge_id DESC LIMIT 21 OFFSET %s" in history_sql
    assert history_params == (TASK_ID, task["tenant_id"], offset)
    for sql, _params in snapshot.statements[1:]:
        assert sql.startswith("SELECT ")
        for forbidden in (
            "INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "TRUNCATE ",
            "FOR UPDATE", "KEY_REGISTRY", "REVOCATION", "PRIVATE",
        ):
            assert forbidden not in sql.upper()
    snapshot.connect.assert_called_once_with("mock-history-database")
    snapshot.connection.transaction.assert_called_once_with()
    snapshot.connection.execute.assert_called_once_with(
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
    )
    assert snapshot.cursor.execute.call_count == 2
    snapshot.clock.assert_called_once_with()
    assert result.task_id == TASK_ID
    assert result.task_status == task["status"]
    assert result.observed_at == NOW
    assert result.offset == offset
    assert result.limit == 20
    assert result.has_more is (row_count > 20)
    assert [item.challenge_id for item in result.items] == [row["challenge_id"] for row in rows[:20]]
    assert result.observation_kind == "STORED_EVIDENCE_NOT_REVALIDATED"
    assert "current_valid" not in result.model_dump(mode="json")


def test_twenty_first_row_is_only_a_pagination_sentinel(monkeypatch) -> None:
    task, _ = _stored_case()
    rows = [_stored_case(challenge_id=f"challenge-{index:02d}")[1] for index in range(20)]
    snapshot = _snapshot(monkeypatch, task, rows + [{"not_an_evidence_entry": True}])
    result = snapshot.subject.task_history(TASK_ID, offset=20)
    assert result.has_more is True
    assert len(result.items) == 20


@pytest.mark.parametrize("refund_total_fen", [0, 7_000, 50_000])
def test_entry_reconstructs_exact_four_tool_scope_from_stored_payload(refund_total_fen) -> None:
    task, row = _stored_case(refund_total_fen=refund_total_fen)
    entry = CoauthorizationReadService("never-connect")._entry(task, row, NOW)
    capabilities = [item.model_dump(mode="json") for item in entry.task_capabilities]
    assert capabilities == build_root_capabilities(
        ticket_id=task["ticket_id"], customer_id=task["customer_id"], refund_total_fen=refund_total_fen,
    )
    assert {item["tool"] for item in capabilities} == {
        "ticket.read", "knowledge.read_associated", "refund.create", "notification.send_template",
    }
    assert sm3_hex(canonicalize({"capabilities": capabilities})) == entry.payload.capabilities_hash
    assert approval_payload_hash(entry.payload) == entry.approval_payload_hash
    refund = next(item for item in capabilities if item["tool"] == "refund.create")
    assert refund["resources"] == {"ticket_ids": ["T10086"], "customer_ids": ["C9527"]}
    assert refund["constraints"]["single_max_fen"] == min(20_000, refund_total_fen)


@pytest.mark.parametrize("observed_at,state", [
    (NOW - 61, "NOT_YET_VALID"), (NOW - 60, "OPEN"),
    (NOW + 119, "OPEN"), (NOW + 120, "EXPIRED"),
])
@pytest.mark.parametrize("status", ["PENDING", "REVOKED", "CONSUMED"])
def test_window_state_is_an_observation_not_current_signature_validity(observed_at, state, status) -> None:
    task, row = _stored_case(status=status)
    entry = CoauthorizationReadService("never-connect")._entry(task, row, observed_at)
    assert entry.window_state == state
    assert entry.challenge_status == status
    assert not {"current_valid", "signature_valid", "key_active", "root_revoked"} & entry.model_dump().keys()


@pytest.mark.parametrize("status", ["PENDING", "REVOKED"])
def test_unconsumed_history_has_no_signed_or_root_authorization_evidence(status) -> None:
    task, row = _stored_case(status=status)
    entry = CoauthorizationReadService("never-connect")._entry(task, row, NOW)
    assert entry.signed_bundle is None
    assert entry.bundle_hash is None
    assert entry.consumed_at is None
    assert entry.root_credential_id is None
    assert entry.root_credential_hash is None
    assert (entry.revoked_at is not None) is (status == "REVOKED")


def test_consumed_history_preserves_complete_format_only_bundle_without_reverification(monkeypatch) -> None:
    task, row = _stored_case(status="CONSUMED")
    task["status"] = "CLOSED"
    snapshot = _snapshot(monkeypatch, task, [row], observed_at=NOW + 120)
    result = snapshot.subject.task_history(TASK_ID)
    entry = result.items[0]
    assert entry.challenge_status == "CONSUMED"
    assert entry.window_state == "EXPIRED"
    assert result.task_status == "CLOSED"
    assert result.observation_kind == "STORED_EVIDENCE_NOT_REVALIDATED"
    assert entry.signed_bundle.model_dump(mode="json") == row["signed_bundle"]
    assert all(approval.signature.value == "0" * 128 for approval in entry.signed_bundle.approvals)
    assert entry.bundle_hash == sm3_hex(canonicalize(row["signed_bundle"]))
    assert entry.root_credential_id == row["root_credential_id"]
    assert entry.root_credential_hash == row["root_credential_hash"]
    assert entry.root_credential_hash == signed_object_hash(row["stored_root_object"])


@pytest.mark.parametrize("field,value", [
    ("approval_payload_hash", "0" * 64), ("task_id", "another-task"),
    ("tenant_id", "another-tenant"), ("policy_revision", "another-policy"),
    ("challenge_id", "another-challenge"), ("issued_at", NOW - 59), ("expires_at", NOW + 121),
])
def test_entry_rejects_challenge_digest_metadata_and_window_tampering(field, value) -> None:
    task, row = _stored_case()
    row[field] = value
    with pytest.raises(ValueError):
        CoauthorizationReadService("never-connect")._entry(task, row, NOW)


@pytest.mark.parametrize("field,value", [
    ("task_id", "another-task"), ("tenant_id", "another-tenant"),
    ("ticket_id", "another-ticket"), ("customer_id", "another-customer"),
])
def test_entry_rejects_cross_task_stored_payload_even_with_recomputed_digest(field, value) -> None:
    task, row = _stored_case()
    row["approval_payload"][field] = value
    if field in {"task_id", "tenant_id"}:
        row[field] = value
    row["approval_payload_hash"] = approval_payload_hash(ApprovalPayload.model_validate(row["approval_payload"]))
    with pytest.raises(ValueError):
        CoauthorizationReadService("never-connect")._entry(task, row, NOW)


def test_entry_rejects_scope_digest_that_does_not_match_fixed_policy() -> None:
    task, row = _stored_case()
    capabilities = build_root_capabilities(ticket_id="T10086", customer_id="C9527", refund_total_fen=7_000)
    next(item for item in capabilities if item["tool"] == "refund.create")["constraints"]["single_max_fen"] -= 1
    row["approval_payload"]["capabilities_hash"] = sm3_hex(canonicalize({"capabilities": capabilities}))
    row["approval_payload_hash"] = approval_payload_hash(ApprovalPayload.model_validate(row["approval_payload"]))
    with pytest.raises(ValueError, match="scope cannot be reconstructed"):
        CoauthorizationReadService("never-connect")._entry(task, row, NOW)


@pytest.mark.parametrize("field,value", [
    ("associated_task_id", "another-task"), ("associated_root_id", "another-root"),
    ("associated_payload_hash", "0" * 64), ("associated_bundle_hash", "0" * 64),
    ("enterprise_subject_id", "another-enterprise"), ("enterprise_key_id", "another-enterprise-key"),
    ("finance_subject_id", "another-finance"), ("finance_key_id", "another-finance-key"),
    ("authorized_at", NOW - 9), ("root_credential_id", "another-root"),
])
def test_consumed_entry_rejects_root_association_tampering(field, value) -> None:
    task, row = _stored_case(status="CONSUMED")
    row[field] = value
    with pytest.raises(ValueError, match="root association"):
        CoauthorizationReadService("never-connect")._entry(task, row, NOW)


@pytest.mark.parametrize("field,value", [
    ("stored_root_id", "another-root"), ("stored_root_task_id", "another-task"),
    ("stored_root_tenant_id", "another-tenant"), ("stored_root_type", "DELEGATED"),
    ("stored_root_hash", "0" * 64), ("root_credential_hash", "0" * 64),
    ("stored_root_object", None), ("stored_root_id", None),
])
def test_consumed_history_rejects_actual_root_columns_and_missing_object(monkeypatch, field, value) -> None:
    task, row = _stored_case(status="CONSUMED")
    row[field] = value
    snapshot = _snapshot(monkeypatch, task, [row])
    with pytest.raises(CoauthorizationError) as caught:
        snapshot.subject.task_history(TASK_ID)
    assert caught.value.reason_code is CoauthorizationReason.STORED_EVIDENCE_INVALID


@pytest.mark.parametrize("path,value", [
    (("credential_type",), "DELEGATED"), (("credential_id",), "another-root"),
    (("task_id",), "another-task"), (("tenant_id",), "another-tenant"),
    (("holder", "agent_id"), "another-holder"), (("holder", "key_id"), "another-holder-key"),
    (("quotas", "refund_total_fen"), 6_999), (("quotas", "max_tool_calls"), 5),
    (("not_before",), NOW - 99), (("expires_at",), NOW + 1_799), (("delegation_depth",), 1),
    (("capabilities", 0, "resources", "ticket_ids"), ["another-ticket"]),
    (("capabilities", 2, "constraints", "single_max_fen"), 6_999),
    (("capabilities", 3, "constraints", "template_ids"), ["another-template"]),
])
def test_consumed_history_rejects_root_object_scope_with_recomputed_hash(monkeypatch, path, value) -> None:
    task, row = _stored_case(status="CONSUMED")
    target = row["stored_root_object"]["payload"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = deepcopy(value)
    digest = signed_object_hash(row["stored_root_object"])
    row["stored_root_hash"] = digest
    row["root_credential_hash"] = digest
    snapshot = _snapshot(monkeypatch, task, [row])
    with pytest.raises(CoauthorizationError) as caught:
        snapshot.subject.task_history(TASK_ID)
    assert caught.value.reason_code is CoauthorizationReason.STORED_EVIDENCE_INVALID


@pytest.mark.parametrize("field,value", [
    ("key_id", "another-authority-key"), ("key_purpose", "AGENT_HOLDER_SIGNING"), ("signed_at", NOW - 9),
])
def test_consumed_history_rejects_root_signature_metadata_with_recomputed_hash(monkeypatch, field, value) -> None:
    task, row = _stored_case(status="CONSUMED")
    row["stored_root_object"]["signature"][field] = value
    row["stored_root_hash"] = signed_object_hash(row["stored_root_object"])
    row["root_credential_hash"] = row["stored_root_hash"]
    snapshot = _snapshot(monkeypatch, task, [row])
    with pytest.raises(CoauthorizationError) as caught:
        snapshot.subject.task_history(TASK_ID)
    assert caught.value.reason_code is CoauthorizationReason.STORED_EVIDENCE_INVALID


def test_consumed_history_does_not_cryptographically_verify_format_only_root_or_approvals() -> None:
    task, row = _stored_case(status="CONSUMED")
    row["stored_root_object"]["signature"]["value"] = "1" * 128
    row["stored_root_hash"] = signed_object_hash(row["stored_root_object"])
    row["root_credential_hash"] = row["stored_root_hash"]
    row["signed_bundle"]["approvals"][0]["signature"]["value"] = "1" * 128
    row["bundle_hash"] = sm3_hex(canonicalize(row["signed_bundle"]))
    row["associated_bundle_hash"] = row["bundle_hash"]
    entry = CoauthorizationReadService("never-connect")._entry(task, row, NOW)
    assert entry.signed_bundle.approvals[0].signature.value == "1" * 128
    assert entry.root_credential_hash == row["stored_root_hash"]


@pytest.mark.parametrize("rehash", [False, True])
def test_consumed_entry_rejects_bundle_digest_or_payload_tampering(rehash) -> None:
    task, row = _stored_case(status="CONSUMED")
    row["signed_bundle"]["payload"]["holder"]["agent_id"] = "another-holder"
    if rehash:
        row["bundle_hash"] = sm3_hex(canonicalize(row["signed_bundle"]))
        row["associated_bundle_hash"] = row["bundle_hash"]
    with pytest.raises(ValueError):
        CoauthorizationReadService("never-connect")._entry(task, row, NOW)


@pytest.mark.parametrize("approval_index", [0, 1])
@pytest.mark.parametrize("section,field,value", [
    ("statement", "subject_id", "another-approver"),
    ("statement", "key_id", "another-approval-key"),
    ("statement", "approval_payload_hash", "0" * 64),
    ("signature", "key_id", "another-signature-key"),
    ("signature", "signed_at", NOW - 18),
    ("statement", "approved_at", NOW - 61),
    ("statement", "approved_at", NOW - 9),
])
def test_consumed_signer_metadata_tampering_has_stored_evidence_reason(
    monkeypatch, approval_index, section, field, value,
) -> None:
    task, row = _stored_case(status="CONSUMED")
    evidence = row["signed_bundle"]["approvals"][approval_index]
    evidence[section][field] = value
    if section == "statement" and field == "approved_at":
        evidence["signature"]["signed_at"] = value
    if section == "statement" and field == "key_id":
        evidence["signature"]["key_id"] = value
    # Keep both stored bundle digests consistent to isolate metadata validation.
    row["bundle_hash"] = sm3_hex(canonicalize(row["signed_bundle"]))
    row["associated_bundle_hash"] = row["bundle_hash"]
    snapshot = _snapshot(monkeypatch, task, [row])
    with pytest.raises(CoauthorizationError) as caught:
        snapshot.subject.task_history(TASK_ID)
    assert caught.value.reason_code is CoauthorizationReason.STORED_EVIDENCE_INVALID
    assert "another-approver" not in str(caught.value)


@pytest.mark.parametrize("approved_at", [NOW - 60, NOW - 10])
def test_consumed_metadata_accepts_issuance_and_consumption_time_boundaries(approved_at) -> None:
    task, row = _stored_case(status="CONSUMED")
    for evidence in row["signed_bundle"]["approvals"]:
        evidence["statement"]["approved_at"] = approved_at
        evidence["signature"]["signed_at"] = approved_at
    row["bundle_hash"] = sm3_hex(canonicalize(row["signed_bundle"]))
    row["associated_bundle_hash"] = row["bundle_hash"]
    entry = CoauthorizationReadService("never-connect")._entry(task, row, NOW)
    assert all(item.statement.approved_at == approved_at for item in entry.signed_bundle.approvals)


@pytest.mark.parametrize("field", [
    "consumed_at", "bundle_hash", "signed_bundle", "root_credential_id", "root_credential_hash",
])
def test_consumed_entry_requires_all_stored_authorization_fields(field) -> None:
    task, row = _stored_case(status="CONSUMED")
    row[field] = None
    with pytest.raises(ValueError):
        CoauthorizationReadService("never-connect")._entry(task, row, NOW)


@pytest.mark.parametrize("changes", [
    {"associated_task_id": TASK_ID}, {"root_credential_id": "root-01"},
    {"bundle_hash": "a" * 64}, {"consumed_at": NOW - 10},
    {"revoked_at": NOW - 5}, {"status": "REVOKED"},
])
def test_pending_entry_rejects_fabricated_consumption_or_revocation_metadata(changes) -> None:
    task, row = _stored_case()
    row.update(changes)
    with pytest.raises(ValueError):
        CoauthorizationReadService("never-connect")._entry(task, row, NOW)


def test_corrupt_row_fails_the_whole_history_instead_of_becoming_empty(monkeypatch) -> None:
    task, valid = _stored_case()
    _, corrupt = _stored_case(challenge_id="challenge-corrupt")
    corrupt["approval_payload"]["private_key"] = "FORBIDDEN_TEST_DATA"
    snapshot = _snapshot(monkeypatch, task, [valid, corrupt])
    with pytest.raises(CoauthorizationError) as caught:
        snapshot.subject.task_history(TASK_ID)
    assert caught.value.reason_code is CoauthorizationReason.STORED_EVIDENCE_INVALID
    assert "FORBIDDEN_TEST_DATA" not in str(caught.value)


def test_missing_task_fails_before_reading_challenge_rows(monkeypatch) -> None:
    snapshot = _snapshot(monkeypatch, None, [])
    with pytest.raises(CoauthorizationError) as caught:
        snapshot.subject.task_history(TASK_ID)
    assert caught.value.reason_code is CoauthorizationReason.TASK_NOT_AUTHORIZABLE
    assert len(snapshot.statements) == 2
    snapshot.cursor.fetchall.assert_not_called()
    snapshot.clock.assert_not_called()


@pytest.mark.parametrize("offset", [-1, 1_000_001, True, 1.0, "20"])
def test_invalid_offset_fails_before_connecting(monkeypatch, offset) -> None:
    connect = Mock(side_effect=AssertionError("invalid offset must not reach storage"))
    monkeypatch.setattr(review_module, "connect", connect)
    with pytest.raises(CoauthorizationError) as caught:
        CoauthorizationReadService("never-connect").task_history(TASK_ID, offset=offset)
    assert caught.value.reason_code is CoauthorizationReason.INVALID_TRUSTED_CONTEXT
    connect.assert_not_called()


@pytest.mark.parametrize("observed_at", [-1, MAX_SAFE_INTEGER + 1, True, 1.0])
def test_invalid_observation_clock_never_produces_history(monkeypatch, observed_at) -> None:
    task, row = _stored_case()
    snapshot = _snapshot(monkeypatch, task, [row], observed_at=observed_at)
    with pytest.raises(CoauthorizationError) as caught:
        snapshot.subject.task_history(TASK_ID)
    assert caught.value.reason_code is CoauthorizationReason.INVALID_TRUSTED_CONTEXT


@pytest.mark.parametrize("mutation", [
    lambda data: data.update(task_id="another-task"),
    lambda data: data["items"].append(deepcopy(data["items"][0])),
    lambda data: data["items"][0].update(window_state="EXPIRED"),
    lambda data: data.update(observation_kind="CURRENT_SIGNATURES_VALID"),
    lambda data: data.update(current_valid=True),
])
def test_task_review_contract_rejects_cross_task_duplicates_or_fresh_validity_claims(mutation) -> None:
    task, row = _stored_case()
    entry = CoauthorizationReadService("never-connect")._entry(task, row, NOW)
    data = CoauthorizationTaskReview(
        task_id=TASK_ID, task_status=task["status"], observed_at=NOW,
        offset=0, has_more=False, items=[entry],
    ).model_dump(mode="json")
    mutation(data)
    with pytest.raises(ValueError):
        CoauthorizationTaskReview.model_validate(data)


def _authority_client(read_service, *, enabled=False):
    root = Mock(spec=[])
    writer = Mock(spec=["create_challenge", "authorize_task"])
    client = TestClient(authority_app.make_app(
        settings=SimpleNamespace(coauthorization_required=enabled), service=root,
        coauthorization_service=writer, coauthorization_read_service=read_service,
    ))
    return client, root, writer


@pytest.mark.parametrize("enabled", [False, True])
def test_authority_history_uses_injected_reader_even_when_write_flag_is_disabled(enabled) -> None:
    task, row = _stored_case()
    entry = CoauthorizationReadService("never-connect")._entry(task, row, NOW)
    history = CoauthorizationTaskReview(
        task_id=TASK_ID, task_status=task["status"], observed_at=NOW,
        offset=20, has_more=False, items=[entry],
    )
    reader = Mock(spec=["task_history"])
    reader.task_history.return_value = history
    client, root, writer = _authority_client(reader, enabled=enabled)
    response = client.get(HISTORY_PATH, params={"offset": 20})
    assert response.status_code == 200
    assert response.json() == history.model_dump(mode="json")
    reader.task_history.assert_called_once_with(TASK_ID, offset=20)
    assert root.mock_calls == []
    assert writer.mock_calls == []


@pytest.mark.parametrize("error,status,code", [
    (OperationalError("FORBIDDEN_STORAGE_DETAILS"), 503, "COAUTH_REGISTRY_UNAVAILABLE"),
    (errors.UndefinedTable("FORBIDDEN_STORAGE_DETAILS"), 503, "COAUTH_REGISTRY_UNAVAILABLE"),
    (CoauthorizationError(CoauthorizationReason.STORED_EVIDENCE_INVALID, "stored approval evidence is inconsistent"),
     503, "COAUTH_STORED_EVIDENCE_INVALID"),
    (CoauthorizationError(CoauthorizationReason.INVALID_TRUSTED_CONTEXT, "invalid server time"),
     403, "COAUTH_INVALID_TRUSTED_CONTEXT"),
])
def test_authority_history_failure_does_not_return_empty_or_success_history(error, status, code) -> None:
    reader = Mock(spec=["task_history"])
    reader.task_history.side_effect = error
    client, root, writer = _authority_client(reader)
    response = client.get(HISTORY_PATH)
    assert response.status_code == status
    assert set(response.json()) == {"reason_code", "message"}
    assert response.json()["reason_code"] == code
    assert "FORBIDDEN_STORAGE_DETAILS" not in response.text
    assert "items" not in response.json()
    reader.task_history.assert_called_once_with(TASK_ID, offset=0)
    assert root.mock_calls == []
    assert writer.mock_calls == []


@pytest.mark.parametrize("task_id,offset", [
    ("invalid!id", "0"), ("a" * 129, "0"),
    (TASK_ID, "-1"), (TASK_ID, "1000001"), (TASK_ID, "1.5"), (TASK_ID, "not-an-integer"),
])
def test_authority_history_rejects_bad_path_and_offset_before_reader(task_id, offset) -> None:
    reader = Mock(spec=["task_history"])
    client, root, writer = _authority_client(reader)
    response = client.get(f"/extensions/coauthorization/v1/tasks/{task_id}", params={"offset": offset})
    assert response.status_code == 400
    assert response.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"
    assert reader.mock_calls == []
    assert root.mock_calls == []
    assert writer.mock_calls == []
