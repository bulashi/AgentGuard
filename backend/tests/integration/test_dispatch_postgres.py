from __future__ import annotations

from copy import deepcopy

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import sign_payload
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case
from backend.tests.integration.test_admission_postgres import (
    DATABASE_URL,
    GATEWAY_URL,
    HOLDER_KEY_ID,
    HOLDER_PRIVATE_KEY,
    HOLDER_PUBLIC_KEY,
    _budget_snapshot,
    _leaf_chain,
    _refund_action,
    _request,
)

pytestmark = [pytest.mark.integration]


def _dispatch(request: dict[str, object]) -> httpx.Response:
    assert GATEWAY_URL is not None
    with httpx.Client(base_url=GATEWAY_URL, timeout=20) as client:
        return client.post("/gateway/dispatch", json=request)


def _resign_request(request: dict[str, object]) -> None:
    proof = request["holder_proof"]
    assert isinstance(proof, dict)
    payload = proof["payload"]
    assert isinstance(payload, dict)
    proof["signature"] = sign_payload(
        payload,
        domain_separator=HOLDER_PROOF,
        key_id=HOLDER_KEY_ID,
        key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        private_key_hex=HOLDER_PRIVATE_KEY,
        public_key_hex=HOLDER_PUBLIC_KEY,
        signed_at=int(request["issued_at"]),
    )


def test_gateway_dispatch_commits_once_and_settles_three_level_budgets() -> None:
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
        request_id=f"{task_id}-DISPATCH-FIRST",
        credential_chain=chain,
    )

    response = _dispatch(request)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "COMMITTED"
    assert body["decision"] == "ALLOW"
    assert body["reason_code"] == "ALLOWED"
    assert body["admission_outcome"] == "NEW_EXECUTION"
    execution_id = body["execution_id"]

    snapshot = _budget_snapshot(credential_ids)
    assert (
        sum(
            1
            for row in snapshot
            if row[1] == "refund_total_fen" and row[3] == 0 and row[4] == 7_000
        )
        == 3
    )
    assert (
        sum(1 for row in snapshot if row[1] == "max_tool_calls" and row[3] == 0 and row[4] == 1)
        == 3
    )

    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        execution = connection.execute(
            """
            SELECT state, business_effect_id, result IS NOT NULL,
                   created_at, decision_at, decision_value::text, terminal_at, terminal_state::text
            FROM execution_records WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        attempts = connection.execute(
            """
            SELECT count(*), min(status), min(tool_outcome)
            FROM tool_execution_attempts WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        reservations = connection.execute(
            """
            SELECT count(*), count(*) FILTER (WHERE status = 'COMMITTED')
            FROM execution_budget_reservations WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        effects = connection.execute(
            "SELECT count(*) FROM refunds WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        received_at = connection.execute(
            "SELECT received_at FROM tool_execution_attempts WHERE execution_id = %s",
            (execution_id,),
        ).fetchall()
    assert execution is not None
    assert execution[0] == "COMMITTED"
    assert execution[1] is not None
    assert execution[2] is True
    assert execution[5] == "ALLOW" and execution[7] == "COMMITTED"
    assert all(type(execution[index]) is int for index in (3, 4, 6))
    assert 0 <= execution[3] <= execution[4] <= execution[6] <= MAX_SAFE_INTEGER
    assert attempts == (1, "COMPLETED", "SUCCESS")
    assert reservations == (6, 6)
    assert effects == (1,)
    assert len(received_at) == 1 and type(received_at[0][0]) is int
    assert execution[4] <= received_at[0][0] <= execution[6]
    original_times = execution[3:]

    retry = deepcopy(request)
    retry["request_id"] = f"{task_id}-DISPATCH-RETRY"
    retry_proof = retry["holder_proof"]
    assert isinstance(retry_proof, dict)
    retry_payload = retry_proof["payload"]
    assert isinstance(retry_payload, dict)
    retry_payload["request_id"] = retry["request_id"]
    _resign_request(retry)
    repeated = _dispatch(retry)
    assert repeated.status_code == 200, repeated.text
    repeated_body = repeated.json()
    assert repeated_body["execution_id"] == execution_id
    assert repeated_body["state"] == "COMMITTED"
    assert repeated_body["admission_outcome"] == "IDEMPOTENT_RETURN"
    assert _budget_snapshot(credential_ids) == snapshot

    with connect(DATABASE_URL) as connection:
        repeated_counts = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM tool_execution_attempts WHERE execution_id = %s),
                (SELECT count(*) FROM refunds WHERE execution_id = %s),
                (SELECT count(*) FROM execution_budget_reservations WHERE execution_id = %s)
            """,
            (execution_id, execution_id, execution_id),
        ).fetchone()
        repeated_times = connection.execute(
            """
            SELECT created_at, decision_at, decision_value::text, terminal_at, terminal_state::text
            FROM execution_records WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
    assert repeated_counts == (1, 1, 6)
    assert repeated_times == original_times

    replay = _dispatch(request)
    assert replay.status_code == 403
    assert replay.json()["reason_code"] == "REPLAY_DETECTED"
    assert _budget_snapshot(credential_ids) == snapshot
