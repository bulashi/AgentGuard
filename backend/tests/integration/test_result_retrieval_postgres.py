from __future__ import annotations

import os
from uuid import uuid4

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import sign_payload, sm3_hex
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case
from backend.tests.integration.test_admission_postgres import (
    DATABASE_URL,
    GATEWAY_URL,
    HOLDER_KEY_ID,
    HOLDER_PRIVATE_KEY,
    HOLDER_PUBLIC_KEY,
    _leaf_chain,
    _refund_action,
    _request,
)
from backend.tests.integration.test_dispatch_postgres import _dispatch

pytestmark = [pytest.mark.integration]

AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")
REVOCATION_URL = os.getenv("AGENTGUARD_REVOCATION_URL")
AUDIT_URL = os.getenv("AGENTGUARD_AUDIT_SERVICE_URL")
CHECKPOINT_URL = os.getenv("AGENTGUARD_CHECKPOINT_SERVICE_URL")
HOLDER_PRIVATE_KEY_FILE = os.getenv("AGENTGUARD_HOLDER_PRIVATE_KEY_FILE")

if not all(
    (
        DATABASE_URL,
        GATEWAY_URL,
        AUTHORITY_URL,
        REVOCATION_URL,
        AUDIT_URL,
        CHECKPOINT_URL,
        HOLDER_PRIVATE_KEY_FILE,
    )
):
    pytest.skip(
        "PostgreSQL result retrieval test environment is not active", allow_module_level=True
    )


def _retrieval_request(
    credential: dict[str, object],
    chain: list[dict[str, object]],
    *,
    request_id: str,
    execution_id: str | None = None,
    receipt_id: str | None = None,
    task_id: str | None = None,
    issued_at: int | None = None,
) -> dict[str, object]:
    assert (execution_id is None) != (receipt_id is None)
    timestamp = now_unix() if issued_at is None else issued_at
    target = {"execution_id": execution_id, "receipt_id": receipt_id}
    chain_hash = sm3_hex(canonicalize(chain))
    holder_payload = {
        "schema_version": "1.0",
        "credential_chain_hash": chain_hash,
        "task_id": task_id or credential["payload"]["task_id"],
        "tool_service": "secure-tool-gateway",
        "tool_name": "gateway.result_retrieve",
        "tool_version": "v1",
        "canonical_parameter_hash": sm3_hex(canonicalize(target)),
        "request_id": request_id,
        "issued_at": timestamp,
        "business_action_id": None,
    }
    signature = sign_payload(
        holder_payload,
        domain_separator=HOLDER_PROOF,
        key_id=HOLDER_KEY_ID,
        key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        private_key_hex=HOLDER_PRIVATE_KEY,
        public_key_hex=HOLDER_PUBLIC_KEY,
        signed_at=timestamp,
    )
    return {
        "schema_version": "1.0",
        "credential_chain": chain,
        "holder_proof": {"payload": holder_payload, "signature": signature},
        "task_id": task_id or credential["payload"]["task_id"],
        "execution_id": execution_id,
        "receipt_id": receipt_id,
        "request_id": request_id,
        "issued_at": timestamp,
    }


def _retrieve(path: str, request: dict[str, object]) -> httpx.Response:
    assert GATEWAY_URL is not None
    with httpx.Client(base_url=GATEWAY_URL, timeout=20) as client:
        return client.post(path, json=request)


def _snapshot(execution_id: str, credential_ids: list[str]) -> dict[str, object]:
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        execution = connection.execute(
            """
            SELECT state, result, business_effect_id, business_result_hash, receipt_status
            FROM execution_records WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        counts = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM tool_execution_attempts WHERE execution_id = %s),
                (SELECT count(*) FROM refunds WHERE execution_id = %s),
                (SELECT count(*) FROM execution_budget_reservations WHERE execution_id = %s),
                (SELECT count(*) FROM execution_receipts WHERE execution_id = %s),
                (SELECT count(*) FROM result_retrieval_requests WHERE execution_id = %s)
            """,
            (execution_id, execution_id, execution_id, execution_id, execution_id),
        ).fetchone()
        outbox = connection.execute(
            "SELECT count(*) FROM audit_outbox WHERE evidence_reference LIKE %s",
            (f"{execution_id}%",),
        ).fetchone()
        retrieval_total = connection.execute(
            "SELECT count(*) FROM result_retrieval_requests"
        ).fetchone()
    return {
        "execution": tuple(execution) if execution is not None else None,
        "counts": tuple(counts) if counts is not None else None,
        "budget": tuple(row for row in _budget_snapshot(credential_ids)),
        "retrieval_total": int(retrieval_total[0]),
        "execution_outbox": int(outbox[0]),
    }


def _budget_snapshot(credential_ids: list[str]) -> list[tuple[object, ...]]:
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        rows = connection.execute(
            """
            SELECT credential_id, quota_type, limit_value, reserved_value,
                   committed_value, version
            FROM credential_budget_state
            WHERE credential_id = ANY(%s)
            ORDER BY credential_id, quota_type
            """,
            (credential_ids,),
        ).fetchall()
    return [tuple(row) for row in rows]


def _append_audit() -> dict[str, object]:
    assert AUDIT_URL is not None
    with httpx.Client(base_url=AUDIT_URL, timeout=20) as client:
        response = client.post(
            "/internal/audit/append",
            headers={"X-AgentGuard-Internal": "phase12-test"},
            json={"max_events": 10_000},
        )
    assert response.status_code == 200, response.text
    return response.json()


def _verify_audit() -> httpx.Response:
    assert AUDIT_URL is not None
    with httpx.Client(base_url=AUDIT_URL, timeout=20) as client:
        return client.post(
            "/audit/verify",
            json={"from_sequence": 1, "include_independent_checkpoint": True},
        )


def _run_checkpoint() -> dict[str, object]:
    assert CHECKPOINT_URL is not None
    with httpx.Client(base_url=CHECKPOINT_URL, timeout=20) as client:
        response = client.post(
            "/internal/checkpoint/run",
            headers={"X-AgentGuard-Internal": "phase12-test"},
        )
    assert response.status_code == 200, response.text
    return response.json()


def test_result_and_receipt_retrieval_are_read_only_and_non_replayable() -> None:
    leaf, chain, task_id, credential_ids = _leaf_chain()
    action = _refund_action(task_id)
    request = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 7_000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-RETRIEVAL-EXECUTION-{uuid4().hex[:8]}",
        credential_chain=chain,
    )
    dispatched = _dispatch(request)
    assert dispatched.status_code == 200, dispatched.text
    body = dispatched.json()
    assert body["state"] == "COMMITTED"
    execution_id = str(body["execution_id"])
    receipt = body["receipt"]
    assert isinstance(receipt, dict)
    receipt_id = str(receipt["payload"]["receipt_id"])

    before = _snapshot(execution_id, credential_ids)
    result_request = _retrieval_request(
        leaf,
        chain,
        execution_id=execution_id,
        request_id=f"{task_id}-RETRIEVE-RESULT-{uuid4().hex[:8]}",
    )
    result_response = _retrieve("/gateway/results/retrieve", result_request)
    assert result_response.status_code == 200, result_response.text
    result_body = result_response.json()
    assert result_body["execution_id"] == execution_id
    assert result_body["state"] == "COMMITTED"
    assert result_body["result"] == before["execution"][1]

    after_result = _snapshot(execution_id, credential_ids)
    assert after_result["execution"] == before["execution"]
    assert after_result["counts"][:4] == before["counts"][:4]
    assert after_result["counts"][4] == before["counts"][4] + 1
    assert after_result["budget"] == before["budget"]
    assert after_result["retrieval_total"] == before["retrieval_total"] + 1

    receipt_request = _retrieval_request(
        leaf,
        chain,
        receipt_id=receipt_id,
        request_id=f"{task_id}-RETRIEVE-RECEIPT-{uuid4().hex[:8]}",
    )
    receipt_response = _retrieve("/gateway/receipts/retrieve", receipt_request)
    assert receipt_response.status_code == 200, receipt_response.text
    assert receipt_response.json() == receipt

    after_receipt = _snapshot(execution_id, credential_ids)
    assert after_receipt["execution"] == before["execution"]
    assert after_receipt["counts"][:4] == before["counts"][:4]
    assert after_receipt["counts"][4] == before["counts"][4] + 2
    assert after_receipt["budget"] == before["budget"]
    assert after_receipt["retrieval_total"] == before["retrieval_total"] + 2

    replay = _retrieve("/gateway/results/retrieve", result_request)
    assert replay.status_code == 403, replay.text
    assert replay.json()["reason_code"] == "REPLAY_DETECTED"
    after_replay = _snapshot(execution_id, credential_ids)
    assert after_replay["execution"] == before["execution"]
    assert after_replay["counts"][:4] == before["counts"][:4]
    assert after_replay["counts"][4] == before["counts"][4] + 2
    assert after_replay["budget"] == before["budget"]
    assert after_replay["retrieval_total"] == before["retrieval_total"] + 2


def test_retrieval_rechecks_freshness_target_binding_and_revocation() -> None:
    leaf, chain, task_id, _credential_ids = _leaf_chain()
    action = _refund_action(task_id)
    request = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 6_000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-RETRIEVAL-REVOKE-BASE-{uuid4().hex[:8]}",
        credential_chain=chain,
    )
    dispatched = _dispatch(request)
    assert dispatched.status_code == 200, dispatched.text
    execution_id = str(dispatched.json()["execution_id"])

    stale = _retrieval_request(
        leaf,
        chain,
        execution_id=execution_id,
        request_id=f"{task_id}-RETRIEVE-STALE-{uuid4().hex[:8]}",
        issued_at=now_unix() - 600,
    )
    stale_response = _retrieve("/gateway/results/retrieve", stale)
    assert stale_response.status_code == 403, stale_response.text
    assert stale_response.json()["reason_code"] == "REQUEST_STALE"

    other_leaf, other_chain, other_task_id, _ = _leaf_chain()
    cross_task = _retrieval_request(
        other_leaf,
        other_chain,
        execution_id=execution_id,
        task_id=other_task_id,
        request_id=f"{other_task_id}-RETRIEVE-CROSS-{uuid4().hex[:8]}",
    )
    cross_response = _retrieve("/gateway/results/retrieve", cross_task)
    assert cross_response.status_code == 403, cross_response.text
    assert cross_response.json()["reason_code"] in {
        "CROSS_TASK",
        "RESULT_ACCESS_DENIED",
    }

    assert REVOCATION_URL is not None
    root_id = str(chain[0]["payload"]["credential_id"])
    with httpx.Client(base_url=REVOCATION_URL, timeout=20) as client:
        revoked = client.post(
            f"/credentials/{root_id}/revoke",
            headers={"X-AgentGuard-Internal": "revocation-authority"},
            json={"reason": "phase12-retrieval-recheck", "revoked_by": "phase12-test"},
        )
    assert revoked.status_code == 200, revoked.text

    revoked_request = _retrieval_request(
        leaf,
        chain,
        execution_id=execution_id,
        request_id=f"{task_id}-RETRIEVE-REVOKED-{uuid4().hex[:8]}",
    )
    revoked_response = _retrieve("/gateway/results/retrieve", revoked_request)
    assert revoked_response.status_code == 403, revoked_response.text
    assert revoked_response.json()["reason_code"] == "ANCESTOR_REVOKED"


def test_retrieval_allow_and_deny_enter_audited_chain() -> None:
    assert DATABASE_URL is not None
    _append_audit()
    _run_checkpoint()
    leaf, chain, task_id, _ = _leaf_chain()
    action = _refund_action(task_id)
    dispatched = _dispatch(
        _request(
            leaf,
            tool_service="refund-service",
            tool_name="refund.create",
            parameters={
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "amount_fen": 5_000,
            },
            business_action_id=str(action["business_action_id"]),
            request_id=f"{task_id}-RETRIEVAL-AUDIT-BASE-{uuid4().hex[:8]}",
            credential_chain=chain,
        )
    )
    assert dispatched.status_code == 200, dispatched.text
    execution_id = str(dispatched.json()["execution_id"])
    allowed_request_id = f"{task_id}-RETRIEVE-AUDIT-ALLOW-{uuid4().hex[:8]}"
    denied_request_id = f"{task_id}-RETRIEVE-AUDIT-DENY-{uuid4().hex[:8]}"
    allowed_request = _retrieval_request(
        leaf, chain, execution_id=execution_id, request_id=allowed_request_id,
    )
    allowed = _retrieve("/gateway/results/retrieve", allowed_request)
    assert allowed.status_code == 200, allowed.text
    denied = _retrieve(
        "/gateway/results/retrieve",
        _retrieval_request(
            leaf,
            chain,
            execution_id="EXEC-NOT-FOUND",
            request_id=denied_request_id,
        ),
    )
    assert denied.status_code == 403, denied.text
    assert denied.json()["reason_code"] == "RESULT_ACCESS_DENIED"
    replay = _retrieve("/gateway/results/retrieve", allowed_request)
    assert replay.status_code == 403, replay.text
    assert replay.json()["reason_code"] == "REPLAY_DETECTED"
    assert "result" not in replay.json() and "receipt" not in replay.json()

    # A worker may have appended the events already; check the chain rather than this batch size.
    _append_audit()
    _run_checkpoint()
    verified = _verify_audit()
    assert verified.status_code == 200, verified.text
    assert verified.json()["valid"] is True
    assert verified.json()["rollback_detected"] is False

    with connect(DATABASE_URL) as connection:
        events = connection.execute(
            """
            SELECT e.event_type, o.payload->>'retrieval_request_id'
            FROM audit_events e JOIN audit_outbox o USING (outbox_event_id)
            WHERE o.payload->>'retrieval_request_id' = ANY(%s)
            ORDER BY e.event_type, o.payload->>'retrieval_request_id'
            """,
            ([allowed_request_id, denied_request_id],),
        ).fetchall()
    assert events == [
        ("RESULT_RETRIEVAL_ALLOWED", allowed_request_id),
        ("RESULT_RETRIEVAL_DENIED", allowed_request_id),
        ("RESULT_RETRIEVAL_DENIED", denied_request_id),
    ]
