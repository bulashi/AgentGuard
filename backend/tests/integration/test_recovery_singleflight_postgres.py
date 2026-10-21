"""Real PG/SM2/HTTP recovery checks with an event-controlled lost-result boundary.

The refund is executed once by the real tool before its gateway settlement is
withheld. Only the timing of reconciliation and later UNKNOWN replies are
injected. No live database or model endpoint is permitted by this module.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
from typing import Any

import httpx
import pytest

from backend.admission.service import AdmissionService
from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import InternalAuthenticator
from backend.common.time import now_unix
from backend.gateway.contracts import ValidatedToolCommandModel
from backend.gateway.dispatch import GatewayDispatchService
from backend.gateway.service import SecureGatewayService
from backend.recovery.service import RecoveryService
from backend.state.database import connect
from backend.tests.integration.test_admission_postgres import DATABASE_URL
from backend.tests.integration.test_recovery_postgres import _force_stale, _make_admitted
from backend.tools.contracts import GatewayExecutionEnvelopeModel, ReconcileResponse

pytestmark = [pytest.mark.integration]

REQUIRED_ENVIRONMENT = (
    "AGENTGUARD_DATABASE_URL",
    "AGENTGUARD_REFUND_TOOL_URL",
    "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE",
)
if any(not os.getenv(name) for name in REQUIRED_ENVIRONMENT):
    pytest.skip("isolated PostgreSQL recovery environment is not active", allow_module_level=True)


def _subject(service_class: type[RecoveryService] = RecoveryService) -> RecoveryService:
    assert DATABASE_URL is not None
    return service_class(
        DATABASE_URL,
        internal_auth=InternalAuthenticator(
            service_id="recovery-worker",
            keys_json="{}",
            required=False,
        ),
        tool_urls={
            ("refund-service", "refund.create"): os.environ["AGENTGUARD_REFUND_TOOL_URL"],
        },
        max_attempts=3,
        deadline_seconds=300,
        stale_execution_seconds=30,
    )


def _execute_without_gateway_settlement() -> tuple[str, int]:
    """Create a real authorized refund; withhold only its gateway settlement."""
    assert DATABASE_URL is not None
    admitted, _ = _make_admitted(request_id_suffix="SINGLEFLIGHT")
    execution_id = str(admitted["execution_id"])
    command = ValidatedToolCommandModel.model_validate(admitted["validated_command"])
    gateway = SecureGatewayService(database_url=DATABASE_URL)
    dispatch = GatewayDispatchService(
        gateway,
        AdmissionService(gateway),
        tool_urls={},
        gateway_key_id="gateway-key-01",
        gateway_private_key_file=os.environ["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"],
    )
    envelope = dispatch._mark_dispatched(command, request_hash=str(admitted["request_hash"]))
    assert isinstance(envelope, GatewayExecutionEnvelopeModel)
    with httpx.Client(timeout=10, trust_env=False) as client:
        executed = client.post(
            os.environ["AGENTGUARD_REFUND_TOOL_URL"].rstrip("/") + "/internal/execute",
            json=envelope.model_dump(mode="json"),
        )
    assert executed.status_code == 200, executed.text
    assert executed.json()["result"]["amount_fen"] == 7000
    timestamp = now_unix()
    _force_stale(execution_id, current_time=timestamp)
    before = _snapshot(execution_id)
    assert before["state"] == "DISPATCHED"
    assert before["refund_count"] == 1 and before["refund_sum_fen"] == 7000
    assert before["tool_attempt_count"] == 1
    assert before["reservations"] == {"RESERVED": 6}
    return execution_id, timestamp


def _snapshot(execution_id: str) -> dict[str, Any]:
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        execution = connection.execute(
            "SELECT state::text, business_effect_id FROM execution_records WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        recovery = connection.execute(
            "SELECT recovery_attempt_count, manual_review_required "
            "FROM execution_recovery_records WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        refund = connection.execute(
            "SELECT count(*), COALESCE(sum(amount_fen), 0) FROM refunds WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        tool_attempts = connection.execute(
            "SELECT count(*) FROM tool_execution_attempts WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        reservations = connection.execute(
            "SELECT status::text, count(*) FROM execution_budget_reservations "
            "WHERE execution_id = %s GROUP BY status ORDER BY status",
            (execution_id,),
        ).fetchall()
        quota = connection.execute(
            "SELECT b.quota_type, b.reserved_value, b.committed_value "
            "FROM credential_budget_state b "
            "JOIN execution_budget_reservations r "
            "ON r.credential_id = b.credential_id AND r.quota_type = b.quota_type "
            "WHERE r.execution_id = %s ORDER BY b.credential_id, b.quota_type",
            (execution_id,),
        ).fetchall()
    assert execution is not None and refund is not None and tool_attempts is not None
    return {
        "execution_id": execution_id,
        "state": execution[0],
        "business_effect_id": execution[1],
        "attempt_count": 0 if recovery is None else recovery[0],
        "manual_review_required": False if recovery is None else recovery[1],
        "refund_count": refund[0],
        "refund_sum_fen": int(refund[1]),
        "tool_attempt_count": tool_attempts[0],
        "reservations": dict(reservations),
        "quota": [[kind, int(reserved), int(committed)] for kind, reserved, committed in quota],
    }


def _controlled_overlap(service_class: type[RecoveryService] = RecoveryService) -> dict[str, Any]:
    """Also reusable by the separate archived-source reproduction process."""
    execution_id, timestamp = _execute_without_gateway_settlement()
    subject = _subject(service_class)
    real_query = subject._query_tool
    first_query_entered, release_query = Event(), Event()
    counter_lock = Lock()
    query_count = 0

    def blocked_first_query(row: dict[str, Any]) -> ReconcileResponse:
        nonlocal query_count
        with counter_lock:
            query_count += 1
            ordinal = query_count
        if ordinal == 1:
            first_query_entered.set()
            assert release_query.wait(15), "test coordinator did not release the real query"
            return real_query(row)
        # Model an overlapping query whose result is temporarily unknown. This
        # branch is unreachable under the repaired single-execution claim.
        return ReconcileResponse(
            execution_id=execution_id,
            status="UNKNOWN",
            reason_code=ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
        )

    subject._query_tool = blocked_first_query  # type: ignore[method-assign]
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(
            subject.recover_once, execution_id=execution_id, current_time=timestamp
        )
        try:
            assert first_query_entered.wait(8), "first recovery did not reach its query boundary"
            second = subject.recover_once(execution_id=execution_id, current_time=timestamp)
            third = subject.recover_once(execution_id=execution_id, current_time=timestamp)
            while_blocked = _snapshot(execution_id)
        finally:
            release_query.set()
        recovered = first.result(timeout=20)
    assert recovered is not None
    return {
        "query_count": query_count,
        "duplicate_results": [
            None if value is None else value.body["state"] for value in (second, third)
        ],
        "while_first_query_blocked": while_blocked,
        "first_result_state": recovered.body["state"],
        "final": _snapshot(execution_id),
    }


def _assert_committed_once(snapshot: dict[str, Any], *, attempts: int) -> None:
    assert snapshot["state"] == "COMMITTED"
    assert snapshot["attempt_count"] == attempts
    assert snapshot["manual_review_required"] is False
    assert snapshot["refund_count"] == 1 and snapshot["refund_sum_fen"] == 7000
    assert snapshot["tool_attempt_count"] == 1
    assert snapshot["reservations"] == {"COMMITTED": 6}
    assert len(snapshot["quota"]) == 6
    assert all(
        reserved == 0 and committed == (7000 if quota_type == "refund_total_fen" else 1)
        for quota_type, reserved, committed in snapshot["quota"]
    )


def test_duplicate_recovery_cannot_spend_attempts_while_first_query_is_pending() -> None:
    observed = _controlled_overlap()
    print("PG_RECOVERY_SINGLEFLIGHT " + json.dumps(observed, sort_keys=True))
    assert observed["query_count"] == 1
    assert observed["duplicate_results"] == [None, None]
    blocked = observed["while_first_query_blocked"]
    assert blocked["state"] == "RECONCILING" and blocked["attempt_count"] == 1
    assert blocked["manual_review_required"] is False
    assert blocked["reservations"] == {"RESERVED": 6}
    assert observed["first_result_state"] == "COMMITTED"
    _assert_committed_once(observed["final"], attempts=1)


def test_recovery_claim_is_released_after_query_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    execution_id, timestamp = _execute_without_gateway_settlement()
    subject = _subject()
    real_query = subject._query_tool

    def interrupted_query(row: dict[str, Any]) -> ReconcileResponse:
        del row
        raise RuntimeError("test-only interrupted reconciliation")

    monkeypatch.setattr(subject, "_query_tool", interrupted_query)
    with pytest.raises(RuntimeError, match="test-only interrupted"):
        subject.recover_once(execution_id=execution_id, current_time=timestamp)
    interrupted = _snapshot(execution_id)
    assert interrupted["state"] == "RECONCILING" and interrupted["attempt_count"] == 1
    assert interrupted["reservations"] == {"RESERVED": 6}
    monkeypatch.setattr(subject, "_query_tool", real_query)
    recovered = subject.recover_once(execution_id=execution_id, current_time=timestamp)
    assert recovered is not None and recovered.body["state"] == "COMMITTED"
    final = _snapshot(execution_id)
    print("PG_RECOVERY_CLAIM_EXCEPTION " + json.dumps(final, sort_keys=True))
    _assert_committed_once(final, attempts=2)
