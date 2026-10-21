"""Decision-time source regressions, authored without execution or collection.

Synthetic rows and transaction markers record control-flow intent, not durable
rollback, locking, signatures or PostgreSQL evidence. Schema/key checks are faked.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import backend.admission.service as admission_module
from backend.admission.service import AdmissionService
from backend.common.error_codes import ReasonCode
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.gateway.contracts import RequestEnvelopeModel
from backend.gateway.service import GatewayError


class RecordingConnection:
    def __init__(self, decision_at=120, *, existing=None) -> None:
        self.decision_at = decision_at
        self.existing = existing
        self.statements = []
        self.transactions = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    @contextmanager
    def transaction(self):
        self.transactions.append("BEGIN")
        try:
            yield self
        except Exception:
            self.transactions.append("ROLLBACK")
            raise
        else:
            self.transactions.append("COMMIT")

    def execute(self, query, parameters=()):
        sql = " ".join(query.split())
        self.statements.append((sql, parameters))
        if "FROM execution_requests" in sql:
            row = None
        elif sql.startswith("SELECT execution_id FROM idempotency_records"):
            row = None if self.existing is None else (self.existing[1],)
        elif sql.startswith("SELECT execution_id FROM execution_records"):
            row = (parameters[0],)
        elif "FROM idempotency_records" in sql:
            row = self.existing
        elif sql.startswith("INSERT INTO execution_records"):
            assert "RETURNING decision_at" in sql
            row = (self.decision_at,)
        elif "clock_timestamp()" in sql:
            row = (self.decision_at,)
        else:
            raise AssertionError(f"unexpected admission SQL: {sql}")
        return SimpleNamespace(fetchone=lambda: row)


def _case(monkeypatch, *, decision_at=120, existing=None, quotas=True):
    chain = [{"payload": {"credential_id": f"CRED-{index}", "not_before": 100, "expires_at": 200}}
             for index in range(3)]
    task = SimpleNamespace(tenant_id="TENANT-DECISION", task_id="TASK-DECISION", expires_at=200)
    request = RequestEnvelopeModel(
        schema_version="1.0", credential_chain=deepcopy(chain), task_id=task.task_id,
        tool_service="refund-service", tool_name="refund.create", tool_version="v1",
        canonical_parameters={"ticket_id": "TICKET-DECISION", "customer_id": "CUSTOMER-DECISION", "amount_fen": 1},
        request_id="REQUEST-DECISION", issued_at=100, holder_key_id="HOLDER-DECISION",
        business_action_id="ACTION-DECISION", holder_proof={"fixture_marker": "not-a-real-proof"},
    )
    gateway = SimpleNamespace(
        database_url="unit-only-admission", schemas=Mock(spec=["validate"]),
        freshness_window_seconds=60, allowed_clock_skew_seconds=5,
        _verify_chain_and_binding=Mock(return_value=chain), _load_task=Mock(return_value=task),
        _verify_holder_proof=Mock(), _verify_request_identity=Mock(),
        _resolve_capability=Mock(return_value={}), _verify_parameters=Mock(),
        _verify_business_action=Mock(), _credential_chain_hash=Mock(return_value="2" * 64),
        _business_idempotency_key=Mock(return_value="3" * 64),
    )
    connection = RecordingConnection(decision_at, existing=existing)
    monkeypatch.setattr(admission_module, "connect", Mock(return_value=connection))
    subject = AdmissionService(gateway)
    reserve = Mock(return_value=[("CRED-0", "max_tool_calls", 1)] if quotas else None)
    register = Mock()
    reservations = Mock()
    monkeypatch.setattr(subject, "_reserve_budgets", reserve)
    monkeypatch.setattr(subject, "_register_request", register)
    monkeypatch.setattr(subject, "_insert_reservations", reservations)
    return SimpleNamespace(
        subject=subject, request=request, chain=chain, task=task, gateway=gateway,
        connection=connection, reserve=reserve, register=register, reservations=reservations,
    )


@pytest.mark.parametrize("decision_at,reason", [
    (99, ReasonCode.REQUEST_STALE), (161, ReasonCode.REQUEST_STALE),
    (False, ReasonCode.REQUEST_STALE), (True, ReasonCode.REQUEST_STALE),
    (120.0, ReasonCode.REQUEST_STALE), ("120", ReasonCode.REQUEST_STALE),
    (MAX_SAFE_INTEGER + 1, ReasonCode.REQUEST_STALE),
])
@pytest.mark.parametrize("quotas", [False, True])
def test_new_execution_rejects_invalid_final_clock_before_durable_registration(
    monkeypatch, decision_at, reason, quotas,
) -> None:
    case = _case(monkeypatch, decision_at=decision_at, quotas=quotas)
    with pytest.raises(GatewayError) as captured:
        case.subject.admit_request(case.request, current_time=100)
    assert captured.value.reason_code is reason
    assert case.connection.transactions == ["BEGIN", "ROLLBACK"]  # Fake marker, not PG rollback.
    case.reserve.assert_called_once()
    case.register.assert_not_called()
    case.reservations.assert_not_called()


@pytest.mark.parametrize("expired", ["task", 0, 1, 2])
@pytest.mark.parametrize("quotas", [False, True])
def test_expiry_during_lock_wait_aborts_new_allow_or_budget_denial(monkeypatch, expired, quotas) -> None:
    case = _case(monkeypatch, decision_at=120, quotas=quotas)
    if expired == "task":
        case.task.expires_at = 119
    else:
        case.chain[expired]["payload"]["expires_at"] = 119
    with pytest.raises(GatewayError) as captured:
        case.subject.admit_request(case.request, current_time=100)
    assert captured.value.reason_code is ReasonCode.CREDENTIAL_EXPIRED
    assert case.connection.transactions == ["BEGIN", "ROLLBACK"]
    case.register.assert_not_called()
    case.reservations.assert_not_called()


@pytest.mark.parametrize("decision_at", [100, 120, 160])
def test_fresh_decision_boundaries_allow_final_time_not_entry_time(monkeypatch, decision_at) -> None:
    case = _case(monkeypatch, decision_at=decision_at)
    # Avoid an idempotency SQL write: this fixture isolates the new admission boundary.
    case.gateway._business_idempotency_key.return_value = None
    result = case.subject.admit_request(case.request, current_time=100)
    assert result.status_code == 200 and result.body["state"] == "ADMITTED"
    assert case.connection.transactions == ["BEGIN", "COMMIT"]
    case.register.assert_called_once()
    case.reservations.assert_called_once()
    assert case.gateway._verify_chain_and_binding.call_count == 2
    assert case.gateway._verify_chain_and_binding.call_args.args[2] == decision_at
    assert all(call.kwargs["lock"] is True for call in case.gateway._verify_chain_and_binding.call_args_list)


@pytest.mark.parametrize("conflict", [False, True])
def test_existing_execution_is_rechecked_without_replacing_original_decision(monkeypatch, conflict) -> None:
    case = _case(monkeypatch, decision_at=161, existing=("other" if conflict else "unused", "EXEC-OLD", "COMMITTED"))
    # The existing digest comes from the real canonical helper during a future run.
    case.connection.existing = (
        "0" * 64 if conflict else admission_module.sm3_hex(admission_module.canonicalize(case.request.canonical_parameters)),
        "EXEC-OLD", "COMMITTED",
    )
    existing = {"execution_id": "EXEC-OLD", "state": "COMMITTED", "decision": "ALLOW"}
    load = Mock(return_value=existing)
    monkeypatch.setattr(case.subject, "_existing_decision", load)
    with pytest.raises(GatewayError) as captured:
        case.subject.admit_request(case.request, current_time=100)
    assert captured.value.reason_code is ReasonCode.REQUEST_STALE
    assert case.connection.transactions == ["BEGIN", "ROLLBACK"]
    assert existing == {"execution_id": "EXEC-OLD", "state": "COMMITTED", "decision": "ALLOW"}
    case.reserve.assert_not_called()
    assert not any(sql.startswith("INSERT INTO execution_records") for sql, _ in case.connection.statements)


@pytest.mark.parametrize("conflict", [False, True])
def test_existing_execution_rechecks_freshness_after_execution_row_wait(monkeypatch, conflict) -> None:
    case = _case(monkeypatch, decision_at=120, existing=("unused", "EXEC-OLD", "COMMITTED"))
    case.connection.existing = (
        "0" * 64 if conflict else admission_module.sm3_hex(admission_module.canonicalize(case.request.canonical_parameters)),
        "EXEC-OLD", "COMMITTED",
    )
    original = {"execution_id": "EXEC-OLD", "state": "COMMITTED", "decision": "ALLOW"}

    def after_simulated_wait(*_args, **_kwargs):
        case.connection.decision_at = 161
        return original

    load = Mock(side_effect=after_simulated_wait)
    monkeypatch.setattr(case.subject, "_existing_decision", load)
    with pytest.raises(GatewayError) as captured:
        case.subject.admit_request(case.request, current_time=100)
    assert captured.value.reason_code is ReasonCode.REQUEST_STALE
    load.assert_called_once()
    assert case.connection.transactions == ["BEGIN", "ROLLBACK"]
    assert original == {"execution_id": "EXEC-OLD", "state": "COMMITTED", "decision": "ALLOW"}
    case.reserve.assert_not_called()


@pytest.mark.parametrize("received_at", [False, True, 100.0, "100"])
def test_final_check_rejects_non_integer_received_time(monkeypatch, received_at) -> None:
    case = _case(monkeypatch)
    with pytest.raises(GatewayError) as captured:
        case.subject._recheck_decision_time(
            case.request, case.chain, case.task, received_at=received_at, decision_at=120,
        )
    assert captured.value.reason_code is ReasonCode.REQUEST_STALE
