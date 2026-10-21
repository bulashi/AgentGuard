from __future__ import annotations

import os

import httpx
import pytest

from backend.common.error_codes import ReasonCode
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case
from backend.tests.integration.test_admission_postgres import (
    DATABASE_URL,
    _admit,
    _leaf_chain,
    _refund_action,
    _request,
)
from backend.tools.contracts import EnvelopePayload
from backend.tools.store import PostgresToolStore, ToolExecutionError

RECOVERY_URL = os.getenv("AGENTGUARD_RECOVERY_URL")

pytestmark = [pytest.mark.integration]

if not RECOVERY_URL:
    pytest.skip("PostgreSQL recovery test environment is not active", allow_module_level=True)


def _recover(execution_id: str, current_time: int) -> httpx.Response:
    assert RECOVERY_URL is not None
    with httpx.Client(base_url=RECOVERY_URL, timeout=20) as client:
        return client.post(
            "/internal/recovery/run",
            headers={"X-AgentGuard-Internal": "recovery-trigger"},
            json={"execution_id": execution_id, "current_time": current_time},
        )


def _make_admitted(*, request_id_suffix: str) -> tuple[dict[str, object], list[str]]:
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
        request_id=f"{task_id}-{request_id_suffix}",
        credential_chain=chain,
    )
    admitted = _admit(request)
    assert admitted.status_code == 200, admitted.text
    body = admitted.json()
    assert body["state"] == "ADMITTED"
    return body, credential_ids


def _force_stale(
    execution_id: str,
    *,
    current_time: int,
    state: str = "DISPATCHED",
    tool_service: str | None = None,
) -> None:
    assert DATABASE_URL is not None
    assert state in {"ADMITTED", "DISPATCHED"}
    stale_at = current_time - 120
    with connect(DATABASE_URL) as connection, connection.transaction():
        if tool_service is None:
            connection.execute(
                """
                UPDATE execution_records
                SET state = %s, created_at = LEAST(created_at, %s), updated_at = %s
                WHERE execution_id = %s
                """,
                (state, stale_at, stale_at, execution_id),
            )
        else:
            connection.execute(
                """
                UPDATE execution_records
                SET state = %s, tool_service = %s, tool_name = 'offline.execute',
                    created_at = LEAST(created_at, %s), updated_at = %s
                WHERE execution_id = %s
                """,
                (state, tool_service, stale_at, stale_at, execution_id),
            )
        connection.execute(
            """
            UPDATE idempotency_records
            SET status = %s, created_at = LEAST(created_at, %s), updated_at = %s
            WHERE execution_id = %s
            """,
            (state, stale_at, stale_at, execution_id),
        )


def _execution_row(execution_id: str) -> tuple[object, ...]:
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        row = connection.execute(
            """
            SELECT state, parameter_hash, business_effect_id, result IS NOT NULL
            FROM execution_records
            WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
    assert row is not None
    return tuple(row)


def _assert_no_future_audit_outbox(execution_id: str) -> None:
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        future = connection.execute(
            """
            SELECT count(*) FROM audit_outbox
            WHERE execution_id = %s
              AND created_at > EXTRACT(EPOCH FROM clock_timestamp())::bigint + 5
            """,
            (execution_id,),
        ).fetchone()
    assert future == (0,)


def test_admitted_timeout_releases_without_dispatch() -> None:
    body, credential_ids = _make_admitted(request_id_suffix="RECOVERY-RELEASE")
    execution_id = str(body["execution_id"])
    assert DATABASE_URL is not None
    current_time = now_unix()
    _force_stale(execution_id, current_time=current_time, state="ADMITTED")

    assert RECOVERY_URL is not None
    with httpx.Client(base_url=RECOVERY_URL, timeout=20) as client:
        denied = client.post(
            "/internal/recovery/run",
            json={"execution_id": execution_id, "current_time": current_time},
        )
    assert denied.status_code == 403

    recovered = _recover(execution_id, current_time)
    assert recovered.status_code == 200, recovered.text
    decision = recovered.json()["decisions"][0]
    assert decision["state"] == "RELEASED"
    assert _execution_row(execution_id)[0] == "RELEASED"

    with connect(DATABASE_URL) as connection:
        reservations = connection.execute(
            """
            SELECT count(*), count(*) FILTER (WHERE status = 'RELEASED')
            FROM execution_budget_reservations WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        budget = connection.execute(
            """
            SELECT count(*) FILTER (WHERE reserved_value <> 0 OR committed_value <> 0)
            FROM credential_budget_state WHERE credential_id = ANY(%s)
            """,
            (credential_ids,),
        ).fetchone()
        effects = connection.execute(
            "SELECT count(*) FROM refunds WHERE execution_id = %s", (execution_id,)
        ).fetchone()
    assert reservations == (6, 6)
    assert budget == (0,)
    assert effects == (0,)
    _assert_no_future_audit_outbox(execution_id)


def test_recovery_commits_existing_effect_once_with_matching_hash() -> None:
    body, credential_ids = _make_admitted(request_id_suffix="RECOVERY-COMMIT")
    execution_id = str(body["execution_id"])
    assert DATABASE_URL is not None
    current_time = now_unix()
    with connect(DATABASE_URL) as connection:
        execution = connection.execute(
            """
            SELECT tenant_id, task_id, business_action_id, parameter_hash
            FROM execution_records WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        idem = connection.execute(
            """
            SELECT business_idempotency_key FROM idempotency_records WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
    assert execution is not None and idem is not None
    tenant_id, task_id, action_id, parameter_hash = (str(value) for value in execution)
    business_key = str(idem[0])
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            """
            INSERT INTO refunds (
                refund_id, execution_id, business_action_id, business_idempotency_key,
                parameter_hash, tenant_id, task_id, ticket_id, customer_id, amount_fen,
                status, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'C9527', 7000, 'COMMITTED', %s)
            """,
            (
                f"REFUND-RECOVERY-{execution_id}",
                execution_id,
                action_id,
                business_key,
                parameter_hash,
                tenant_id,
                task_id,
                business_test_case()["ticket_id"],
                current_time - 1,
            ),
        )
    _force_stale(execution_id, current_time=current_time)

    recovered = _recover(execution_id, current_time)
    assert recovered.status_code == 200, recovered.text
    decision = recovered.json()["decisions"][0]
    assert decision["state"] == "COMMITTED"
    assert decision["business_effect_id"] == f"REFUND-RECOVERY-{execution_id}"
    assert _execution_row(execution_id)[0] == "COMMITTED"
    assert isinstance(decision["result"], dict)
    assert decision["result"]["execution_id"] == execution_id
    assert decision["result"]["tenant_id"] == tenant_id
    assert decision["result"]["task_id"] == task_id
    assert decision["result"]["business_action_id"] == action_id
    assert decision["result"]["business_idempotency_key"] == business_key
    assert decision["result"]["parameter_hash"] == parameter_hash
    assert decision["result"]["refund_id"] == decision["business_effect_id"]

    with connect(DATABASE_URL) as connection:
        reservations = connection.execute(
            """
            SELECT count(*), count(*) FILTER (WHERE status = 'COMMITTED')
            FROM execution_budget_reservations WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        budget = connection.execute(
            """
            SELECT count(*) FILTER (WHERE reserved_value <> 0 OR committed_value <> 7000)
            FROM credential_budget_state
            WHERE credential_id = ANY(%s) AND quota_type = 'refund_total_fen'
            """,
            (credential_ids,),
        ).fetchone()
        effects = connection.execute(
            "SELECT count(*) FROM refunds WHERE execution_id = %s", (execution_id,)
        ).fetchone()
        stored_result = connection.execute(
            "SELECT result, business_result_hash FROM execution_records WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
    assert reservations == (6, 6)
    assert budget == (0,)
    assert effects == (1,)
    assert stored_result is not None and stored_result[0] == decision["result"]
    assert stored_result[1] == sm3_hex(canonicalize(decision["result"]))
    _assert_no_future_audit_outbox(execution_id)


def test_released_execution_rejects_late_first_tool_effect() -> None:
    body, credential_ids = _make_admitted(request_id_suffix="RECOVERY-LATE-FIRST")
    execution_id = str(body["execution_id"])
    command = body["validated_command"]
    assert isinstance(command, dict)
    assert DATABASE_URL is not None
    current_time = now_unix()
    payload = EnvelopePayload(
        schema_version="1.0",
        execution_id=execution_id,
        execution_attempt_id=f"ATTEMPT-LATE-{execution_id}",
        request_hash=str(body["request_hash"]),
        tenant_id=str(command["tenant_id"]),
        task_id=str(command["task_id"]),
        tool_service=str(command["tool_service"]),
        tool_name=str(command["tool_name"]),
        tool_version=str(command["tool_version"]),
        canonical_validated_parameters=command["validated_parameters"],
        business_action_id=command["business_action_id"],
        business_idempotency_key=command["business_idempotency_key"],
        parameter_hash=str(command["parameter_hash"]),
        issued_at=current_time,
        expires_at=current_time + 30,
        gateway_key_id="gateway-key-01",
    )
    _force_stale(execution_id, current_time=current_time)
    recovered = _recover(execution_id, current_time)
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["decisions"][0]["state"] == "RELEASED"
    assert now_unix() <= payload.expires_at

    # Exercise the storage barrier after envelope validation, not an HTTP signature path.
    with pytest.raises(ToolExecutionError) as caught:
        PostgresToolStore(DATABASE_URL).execute("refund", payload, "0" * 64)
    assert caught.value.reason_code == ReasonCode.TOOL_NOT_ALLOWED
    assert _execution_row(execution_id)[0] == "RELEASED"
    with connect(DATABASE_URL) as connection:
        effects = connection.execute(
            "SELECT count(*) FROM refunds WHERE execution_id = %s", (execution_id,)
        ).fetchone()
        attempts = connection.execute(
            "SELECT count(*) FROM tool_execution_attempts WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        budget = connection.execute(
            """
            SELECT count(*) FILTER (WHERE reserved_value <> 0 OR committed_value <> 0)
            FROM credential_budget_state WHERE credential_id = ANY(%s)
            """,
            (credential_ids,),
        ).fetchone()
    assert effects == (0,)
    assert attempts == (0,)
    assert budget == (0,)


def test_recovery_bounds_unknown_state_and_keeps_reserved_budget() -> None:
    body, credential_ids = _make_admitted(request_id_suffix="RECOVERY-FINAL")
    execution_id = str(body["execution_id"])
    current_time = now_unix()
    _force_stale(execution_id, current_time=current_time, tool_service="offline-service")

    first = _recover(execution_id, current_time).json()["decisions"][0]
    second = _recover(execution_id, current_time).json()["decisions"][0]
    third = _recover(execution_id, current_time).json()["decisions"][0]
    assert first["state"] == "RECONCILING"
    assert second["state"] == "RECONCILING"
    assert third["state"] == "RECOVERY_FAILED_FINAL"
    assert third["manual_review_required"] is True
    assert _execution_row(execution_id)[0] == "RECOVERY_FAILED_FINAL"

    with connect(DATABASE_URL) as connection:
        budget = connection.execute(
            """
            SELECT count(*) FILTER (WHERE reserved_value <> 7000 OR committed_value <> 0)
            FROM credential_budget_state
            WHERE credential_id = ANY(%s) AND quota_type = 'refund_total_fen'
            """,
            (credential_ids,),
        ).fetchone()
        reservation = connection.execute(
            """
            SELECT count(*) FILTER (WHERE status = 'RESERVED')
            FROM execution_budget_reservations WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        audit = connection.execute(
            """
            SELECT count(*) FROM audit_outbox
            WHERE execution_id = %s AND event_type = 'RECOVERY_FAILED_FINAL'
            """,
            (execution_id,),
        ).fetchone()
        effects = connection.execute(
            "SELECT count(*) FROM refunds WHERE execution_id = %s", (execution_id,)
        ).fetchone()
    assert budget == (0,)
    assert reservation == (6,)
    assert audit == (1,)
    assert effects == (0,)
    _assert_no_future_audit_outbox(execution_id)
