from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from backend.admission.service import AdmissionService
from backend.audit.service import AuditService
from backend.common.enums import KeyPurpose
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex
from backend.gateway.contracts import RequestEnvelopeModel
from backend.gateway.dispatch import DispatchResult, GatewayDispatchService, _ToolDispatchFailure
from backend.gateway.service import SecureGatewayService
from backend.receipt.service import ReceiptService
from backend.revocation.audit import revocation_outbox_id
from backend.revocation.contracts import RevokeCredentialRequest
from backend.revocation.service import RevocationService
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case
from backend.tests.integration.test_admission_postgres import (
    CASE_URL,
    COORDINATOR_URL,
    DATABASE_URL,
    HOLDER_KEY_ID,
    _admit,
    _budget_snapshot,
    _capability,
    _create_root,
    _delegate,
    _leaf_chain,
    _refund_action,
    _request,
)
from backend.tests.integration.test_dispatch_postgres import _dispatch
from backend.tests.integration.test_receipt_audit_postgres import _verify_receipt
from backend.tests.integration.test_recovery_postgres import _recover

pytestmark = [pytest.mark.integration]


def pending_refund(suffix="R4", *, chain_data=None, second_slot=False):
    leaf, chain, task_id, credential_ids = chain_data or _leaf_chain()
    business = business_test_case()
    action = _refund_action(task_id, second_slot=second_slot)
    request = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business["ticket_id"],
            "customer_id": business["customer_id"],
            "amount_fen": 7_000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-{suffix}",
        credential_chain=chain,
    )
    response = _admit(request)
    assert response.status_code == 200, response.text
    return request, chain, credential_ids, response.json()


def dispatcher():
    assert DATABASE_URL
    gateway = SecureGatewayService(database_url=DATABASE_URL)
    return GatewayDispatchService(
        gateway,
        AdmissionService(gateway),
        tool_urls={
            ("refund-service", "refund.create"): os.environ["AGENTGUARD_REFUND_TOOL_URL"],
        },
        gateway_key_id="gateway-key-01",
        gateway_private_key_file=os.environ["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"],
    )


def issue(execution_id):
    receipt_key = Path(os.environ["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"]).with_name(
        "receipt.private"
    )
    receipt = ReceiptService(DATABASE_URL, private_key_file=str(receipt_key)).issue(execution_id)
    _verify_receipt(receipt)
    return receipt


def assert_cancelled(request, credential_ids, body, reason, *, reservation_count=6):
    assert DATABASE_URL
    with connect(DATABASE_URL) as connection:
        original = connection.execute(
            "SELECT state, decision, decision_at, terminal_state::text FROM execution_records "
            "WHERE execution_id = %s",
            (body["execution_id"],),
        ).fetchone()
        cancellation = connection.execute(
            "SELECT denial_execution_id, evidence FROM dispatch_cancellations WHERE execution_id = %s",
            (body["execution_id"],),
        ).fetchone()
        assert cancellation is not None
        attempts = connection.execute(
            "SELECT count(*) FROM tool_execution_attempts WHERE execution_id = %s",
            (body["execution_id"],),
        ).fetchone()[0]
        effects = connection.execute(
            "SELECT count(*) FROM refunds WHERE execution_id = %s",
            (body["execution_id"],),
        ).fetchone()[0]
        reservations = connection.execute(
            "SELECT count(*), count(*) FILTER (WHERE status = 'RELEASED') "
            "FROM execution_budget_reservations WHERE execution_id = %s",
            (body["execution_id"],),
        ).fetchone()
        idempotency = connection.execute(
            "SELECT status FROM idempotency_records WHERE execution_id = %s",
            (body["execution_id"],),
        ).fetchone()
    assert original[0:2] == ("RELEASED", "ALLOW") and original[2] is not None
    assert original[3] == "RELEASED"
    assert attempts == effects == 0
    assert reservations == (reservation_count, reservation_count)
    assert idempotency == (("RELEASED",) if request["business_action_id"] is not None else None)
    assert all(row[3] == row[4] == 0 for row in _budget_snapshot(credential_ids))
    receipt = issue(str(cancellation[0]))
    assert receipt["payload"]["request_id"] == request["request_id"]
    assert receipt["payload"]["request_hash"] == sm3_hex(canonicalize(request))
    assert receipt["payload"]["decision"] == "DENY"
    assert receipt["payload"]["reason_code"] == reason
    original_receipt = issue(body["execution_id"])
    assert original_receipt["payload"]["decision"] == "ALLOW"
    assert original_receipt["payload"]["business_effect_id"] is None
    assert cancellation[1]["dispatch_decision"] == "DENY"
    return cancellation


@pytest.mark.parametrize("chain_depth", [0, 2], ids=["root-read", "delegated-read"])
def test_read_only_revocation_releases_only_applicable_call_budgets(chain_depth):
    if chain_depth:
        leaf, chain, task_id, ids = _leaf_chain()
    else:
        leaf = _create_root()
        chain = [leaf]
        task_id = leaf["payload"]["task_id"]
        ids = [leaf["payload"]["credential_id"]]
    request = _request(
        leaf,
        tool_service="ticket-service",
        tool_name="ticket.read",
        parameters={"ticket_id": business_test_case()["ticket_id"]},
        business_action_id=None,
        request_id=f"{task_id}-R4-READ",
        credential_chain=chain,
    )
    if not chain_depth:
        private_key = (
            Path(os.environ["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"])
            .with_name("agent-coordinator.private")
            .read_text(encoding="ascii")
            .strip()
        )
        request["holder_key_id"] = "agent-coordinator-key-01"
        request["holder_proof"]["signature"] = sign_payload(
            request["holder_proof"]["payload"],
            domain_separator=HOLDER_PROOF,
            key_id=request["holder_key_id"],
            key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            private_key_hex=private_key,
            public_key_hex=derive_public_key(private_key),
            signed_at=request["issued_at"],
        )
    admitted = _admit(request)
    assert admitted.status_code == 200, admitted.text
    RevocationService(DATABASE_URL).revoke(
        ids[0], RevokeCredentialRequest(reason="停止后续工单读取", revoked_by="authorized-operator")
    )
    cancellation = assert_cancelled(
        request,
        ids,
        admitted.json(),
        "ANCESTOR_REVOKED" if chain_depth else "KEY_REVOKED",
        reservation_count=len(chain),
    )
    assert len(cancellation[1]["released_budgets"]) == len(chain)
    assert all(
        item["quota_type"] == "max_tool_calls" and item["amount"] == 1
        for item in cancellation[1]["released_budgets"]
    )
    audit = AuditService(DATABASE_URL)
    audit.append_pending(max_events=10_000)
    assert audit.verify(include_independent_checkpoint=False)["valid"] is True


@pytest.mark.parametrize("target", [0, 1, 2], ids=["root", "intermediate", "leaf"])
def test_revocation_cancels_admitted_execution_and_releases_all_budgets(target):
    request, chain, ids, body = pending_refund()
    credential_id = chain[target]["payload"]["credential_id"]
    command = RevokeCredentialRequest(reason="企业取消本次办理", revoked_by="authorized-operator")
    revocation = RevocationService(DATABASE_URL)
    first = revocation.revoke(credential_id, command)
    second = revocation.revoke(credential_id, command)
    assert first == second
    reason = "KEY_REVOKED" if target == 2 else "ANCESTOR_REVOKED"
    cancellation = assert_cancelled(request, ids, body, reason)
    assert_cancelled(request, ids, body, reason)
    with connect(DATABASE_URL) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM dispatch_cancellations WHERE execution_id = %s",
                (body["execution_id"],),
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM audit_outbox WHERE outbox_event_id = %s",
                (revocation_outbox_id(credential_id),),
            ).fetchone()[0]
            == 1
        )
        original_times = connection.execute(
            "SELECT decision_at, terminal_at FROM execution_records WHERE execution_id = %s",
            (body["execution_id"],),
        ).fetchone()
    audit = AuditService(DATABASE_URL)
    audit.append_pending(max_events=10_000)
    assert audit.verify(include_independent_checkpoint=False)["valid"] is True
    with connect(DATABASE_URL) as connection:
        assert (
            connection.execute(
                "SELECT decision_at, terminal_at FROM execution_records WHERE execution_id = %s",
                (body["execution_id"],),
            ).fetchone()
            == original_times
        )
    assert cancellation[1]["revocations"][0]["credential_id"] == credential_id


@pytest.mark.parametrize("target", [0, 1, 2])
def test_dispatch_rechecks_committed_revocation_before_any_tool_envelope(target):
    request, chain, ids, body = pending_refund("R4-DISPATCH")
    credential_id = chain[target]["payload"]["credential_id"]
    # Commit exactly at the R4 boundary without invoking the cancellation sweep.
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            "SELECT credential_id FROM credentials WHERE credential_id = %s FOR UPDATE",
            (credential_id,),
        )
        connection.execute(
            "INSERT INTO credential_revocations (credential_id, revoked_at, revocation_reason, revoked_by) "
            "VALUES (%s, %s, 'R4 explicit transaction', 'test-controller')",
            (credential_id, now_unix()),
        )
    service = dispatcher()
    command = service._command_for_admitted_request(
        RequestEnvelopeModel.model_validate(request), body
    )
    assert command is not None
    result = service._mark_dispatched(command, request_hash=sm3_hex(canonicalize(request)))
    assert isinstance(result, DispatchResult) and result.status_code == 403
    reason = "KEY_REVOKED" if target == 2 else "ANCESTOR_REVOKED"
    assert result.body["decision"] == "DENY" and result.body["reason_code"] == reason
    assert_cancelled(request, ids, body, reason)


def test_revocation_commit_wins_against_a_waiting_dispatch(record_testsuite_property):
    request, chain, ids, body = pending_refund("R4-RACE")
    service = dispatcher()
    command = service._command_for_admitted_request(
        RequestEnvelopeModel.model_validate(request), body
    )
    assert command is not None
    result, failures = [], []

    def attempt():
        try:
            result.append(
                service._mark_dispatched(command, request_hash=sm3_hex(canonicalize(request)))
            )
        except Exception as error:
            failures.append(error)

    credential_id = chain[0]["payload"]["credential_id"]
    blocked_pids = []
    with connect(DATABASE_URL) as connection, connection.transaction():
        blocker_pid = connection.execute("SELECT pg_backend_pid()").fetchone()[0]
        connection.execute(
            "SELECT credential_id FROM credentials WHERE credential_id = %s FOR UPDATE",
            (credential_id,),
        )
        thread = threading.Thread(target=attempt)
        thread.start()
        deadline = time.monotonic() + 10
        with connect(DATABASE_URL) as observer:
            observer.autocommit = True
            while time.monotonic() < deadline and not failures:
                blocked_pids = [
                    row[0]
                    for row in observer.execute(
                        "SELECT pid FROM pg_stat_activity WHERE datname = current_database() "
                        "AND %s = ANY(pg_blocking_pids(pid)) AND query LIKE '%%credentials%%'",
                        (blocker_pid,),
                    ).fetchall()
                ]
                if blocked_pids:
                    break
                time.sleep(0.025)
        connection.execute(
            "INSERT INTO credential_revocations (credential_id, revoked_at, revocation_reason, revoked_by) "
            "VALUES (%s, %s, 'R4 lock ordering', 'test-controller')",
            (credential_id, now_unix()),
        )
    thread.join(timeout=20)
    record_testsuite_property("dispatch_revocation_blocking_backend_pids", repr(blocked_pids))
    assert blocked_pids, "dispatch must actually wait for the locked credential transaction"
    assert not thread.is_alive() and not failures
    assert len(result) == 1 and isinstance(result[0], DispatchResult)
    assert_cancelled(request, ids, body, "ANCESTOR_REVOKED")


def test_revocation_after_dispatch_does_not_release_unknown_or_recall_effect():
    request, chain, ids, body = pending_refund("R4-UNKNOWN")
    service = dispatcher()
    command = service._command_for_admitted_request(
        RequestEnvelopeModel.model_validate(request), body
    )
    assert command is not None
    envelope = service._mark_dispatched(command, request_hash=sm3_hex(canonicalize(request)))
    assert envelope is not None and not isinstance(envelope, DispatchResult)
    tool_response = service._call_tool(envelope)
    assert tool_response.outcome == "SUCCESS"
    assert service._mark_unknown(command.execution_id) == "UNKNOWN"
    before = _budget_snapshot(ids)
    RevocationService(DATABASE_URL).revoke(
        chain[0]["payload"]["credential_id"],
        RevokeCredentialRequest(reason="停止新办理", revoked_by="operator"),
    )
    assert _budget_snapshot(ids) == before
    with connect(DATABASE_URL) as connection:
        assert (
            connection.execute(
                "SELECT state FROM execution_records WHERE execution_id = %s",
                (command.execution_id,),
            ).fetchone()[0]
            == "UNKNOWN"
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM dispatch_cancellations WHERE execution_id = %s",
                (command.execution_id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM refunds WHERE execution_id = %s", (command.execution_id,)
            ).fetchone()[0]
            == 1
        )
    recovered = _recover(command.execution_id, now_unix())
    assert recovered.status_code == 200, recovered.text
    decision = recovered.json()["decisions"][0]
    assert decision["state"] == "COMMITTED"
    _verify_receipt(decision["receipt"])
    assert decision["receipt"]["payload"]["decision"] == "ALLOW"
    assert decision["receipt"]["payload"]["business_effect_id"] == tool_response.business_effect_id
    after = _budget_snapshot(ids)
    assert all(row[3] == 0 for row in after)
    assert all(row[4] == (7_000 if row[1] == "refund_total_fen" else 1) for row in after)
    assert _recover(command.execution_id, now_unix()).json()["decisions"] == []
    assert _budget_snapshot(ids) == after


def test_concurrent_root_revocation_cancels_each_shared_budget_branch_exactly_once(
    record_testsuite_property,
):
    root = _create_root()
    task_id = root["payload"]["task_id"]
    branches = []
    for number in range(2):
        intermediate = _delegate(
            COORDINATOR_URL,
            root,
            holder_agent_id="agent-case",
            holder_key_id="agent-case-key-01",
            capabilities=[_capability(root, "ticket.read"), _capability(root, "refund.create")],
            refund_total_fen=15_000,
            max_tool_calls=3,
        )
        leaf = _delegate(
            CASE_URL,
            intermediate,
            holder_agent_id="agent-refund",
            holder_key_id=HOLDER_KEY_ID,
            capabilities=[_capability(intermediate, "refund.create")],
            refund_total_fen=10_000,
            max_tool_calls=2,
        )
        chain = [root, intermediate, leaf]
        ids = [item["payload"]["credential_id"] for item in chain]
        branches.append(
            pending_refund(
                f"R4-BRANCH-{number}",
                chain_data=(leaf, chain, task_id, ids),
                second_slot=bool(number),
            )
        )
    all_ids = sorted({identifier for branch in branches for identifier in branch[2]})
    before = _budget_snapshot(all_ids)
    root_id = root["payload"]["credential_id"]
    assert [row[3] for row in before if row[0] == root_id and row[1] == "refund_total_fen"] == [
        14_000
    ]
    command = RevokeCredentialRequest(reason="统一停止两个分支", revoked_by="authorized-operator")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(lambda _: RevocationService(DATABASE_URL).revoke(root_id, command), range(4))
        )
    assert all(result == results[0] for result in results)
    for request, _, ids, body in branches:
        assert_cancelled(request, ids, body, "ANCESTOR_REVOKED")
    with connect(DATABASE_URL) as connection:
        counts = connection.execute(
            "SELECT count(*), count(DISTINCT execution_id), count(DISTINCT denial_execution_id) "
            "FROM dispatch_cancellations WHERE evidence->>'task_id' = %s",
            (task_id,),
        ).fetchone()
        reservations = connection.execute(
            "SELECT count(*), count(*) FILTER (WHERE status = 'RELEASED') "
            "FROM execution_budget_reservations WHERE execution_id = ANY(%s)",
            ([branch[3]["execution_id"] for branch in branches],),
        ).fetchone()
    record_testsuite_property("shared_root_reserved_before_fen", 14_000)
    record_testsuite_property("cancelled_executions_and_unique_denials", repr(counts))
    record_testsuite_property("released_reservations", repr(reservations))
    assert counts == (2, 2, 2) and reservations == (12, 12)
    after = _budget_snapshot(all_ids)
    assert all(row[3] == row[4] == 0 for row in after)
    RevocationService(DATABASE_URL).revoke(root_id, command)
    assert _budget_snapshot(all_ids) == after


def test_revoked_unknown_without_effect_requires_tool_reconciliation_and_blocks_late_effect():
    request, chain, ids, body = pending_refund("R4-NO-EFFECT")
    service = dispatcher()
    command = service._command_for_admitted_request(
        RequestEnvelopeModel.model_validate(request), body
    )
    envelope = service._mark_dispatched(command, request_hash=sm3_hex(canonicalize(request)))
    assert envelope is not None and not isinstance(envelope, DispatchResult)
    assert service._mark_unknown(command.execution_id) == "UNKNOWN"
    reserved = _budget_snapshot(ids)
    RevocationService(DATABASE_URL).revoke(
        chain[0]["payload"]["credential_id"],
        RevokeCredentialRequest(reason="结果核验前停止新办理", revoked_by="operator"),
    )
    assert _budget_snapshot(ids) == reserved
    recovered = _recover(command.execution_id, now_unix())
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["decisions"][0]["state"] == "RELEASED"
    assert all(row[3] == row[4] == 0 for row in _budget_snapshot(ids))
    with pytest.raises(_ToolDispatchFailure):
        service._call_tool(envelope)
    with connect(DATABASE_URL) as connection:
        assert connection.execute(
            "SELECT count(*) FROM refunds WHERE execution_id = %s", (command.execution_id,)
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM tool_execution_attempts WHERE execution_id = %s",
            (command.execution_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM dispatch_cancellations WHERE execution_id = %s",
            (command.execution_id,),
        ).fetchone() == (0,)


def test_revoked_fresh_request_is_denied_without_repeating_business_effect():
    leaf, chain, task_id, ids = _leaf_chain()
    action = _refund_action(task_id)
    business = business_test_case()
    request = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business["ticket_id"],
            "customer_id": business["customer_id"],
            "amount_fen": 7_000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-R4-FRESH",
        credential_chain=chain,
    )
    RevocationService(DATABASE_URL).revoke(
        chain[0]["payload"]["credential_id"],
        RevokeCredentialRequest(reason="撤销新请求", revoked_by="operator"),
    )
    response = _dispatch(request)
    assert response.status_code == 403, response.text
    assert response.json()["reason_code"] == "ANCESTOR_REVOKED"
    _verify_receipt(response.json()["receipt"])
    assert all(row[3] == row[4] == 0 for row in _budget_snapshot(ids))
