"""Result-binding regression sources, authored without execution or collection.

Connections and tool transport are fakes; these cases do not establish HTTP or
PostgreSQL behavior. Real canonical JSON and SM3 are called only by test helpers
or tests during a future authorized run. No persisted keys or settings are used.
"""

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

import backend.gateway.dispatch as dispatch_module
from backend.common.error_codes import ReasonCode
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.gateway.contracts import RequestEnvelopeModel, ValidatedToolCommandModel
from backend.gateway.dispatch import GatewayDispatchService, _ToolDispatchFailure
from backend.tools.contracts import ToolExecutionResponse

DATABASE_URL = "mock-dispatch-result-binding-database"
CURRENT_TIME = 200
OBSERVED_TIME = 300
CLOCK_QUERY = "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
SETTLEMENT_EXECUTION_QUERY = (
    "SELECT state, business_action_id, updated_at FROM execution_records "
    "WHERE execution_id = %s FOR UPDATE"
)
SETTLEMENT_RESERVATION_QUERY = (
    "SELECT credential_id, quota_type, amount, updated_at FROM execution_budget_reservations "
    "WHERE execution_id = %s AND status = 'RESERVED' "
    "ORDER BY credential_id, quota_type FOR UPDATE"
)
SETTLEMENT_BUDGET_QUERY = (
    "SELECT credential_id, quota_type, updated_at FROM credential_budget_state "
    "WHERE credential_id = ANY(%s) ORDER BY credential_id, quota_type FOR UPDATE"
)
SETTLEMENT_IDEMPOTENCY_QUERY = (
    "SELECT business_idempotency_key, parameter_hash, status, updated_at "
    "FROM idempotency_records WHERE execution_id = %s FOR UPDATE"
)
SETTLEMENT_ACTION_QUERY = (
    "SELECT updated_at FROM business_actions WHERE business_action_id = %s FOR UPDATE"
)
UNKNOWN_EXECUTION_QUERY = (
    "SELECT state, updated_at FROM execution_records WHERE execution_id = %s FOR UPDATE"
)
UNKNOWN_IDEMPOTENCY_QUERY = (
    "SELECT status, updated_at FROM idempotency_records WHERE execution_id = %s FOR UPDATE"
)
UNKNOWN_RECOVERY_QUERY = (
    "SELECT updated_at FROM execution_recovery_records WHERE execution_id = %s FOR UPDATE"
)
TOOLS = {
    "refund": ("refund-service", "refund.create"),
    "notification": ("notification-service", "notification.send_template"),
    "ticket": ("ticket-service", "ticket.read"),
    "knowledge": ("knowledge-service", "knowledge.read_associated"),
}
EFFECT_FIELDS = {"refund": "refund_id", "notification": "notification_id"}
RESULT_METADATA_FIELDS = (
    "execution_id", "tenant_id", "task_id", "business_action_id",
    "business_idempotency_key", "parameter_hash",
)


class FakeCursor:
    def __init__(self, row=None, *, rows=(), rowcount: int = 1) -> None:
        self.row = row
        self.rows = rows
        self.rowcount = rowcount

    def fetchone(self):
        return self.row

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(self, command: ValidatedToolCommandModel) -> None:
        self.state = "DISPATCHED"
        self.action_id = command.business_action_id
        self.execution_updated_at = CURRENT_TIME
        self.idempotency_row = (
            None if command.business_idempotency_key is None else (
                command.business_idempotency_key, command.parameter_hash,
                "DISPATCHED", CURRENT_TIME,
            )
        )
        self.action_row = None if self.action_id is None else (CURRENT_TIME,)
        self.recovery_row = None
        self.recovery_deadline = None
        reservations = [
            ("CREDENTIAL-ROOT", "max_tool_calls", 1),
            ("CREDENTIAL-LEAF", "max_tool_calls", 1),
        ]
        if (command.tool_service, command.tool_name) == TOOLS["refund"]:
            reservations.extend([
                ("CREDENTIAL-ROOT", "refund_total_fen", 250),
                ("CREDENTIAL-LEAF", "refund_total_fen", 250),
            ])
        self.reservations = tuple(sorted(reservations))
        self.reservation_rows = tuple(
            (*reservation, CURRENT_TIME) for reservation in self.reservations
        )
        self.budget_rows = tuple(
            (credential_id, quota_type, CURRENT_TIME)
            for credential_id, quota_type, _amount in self.reservations
        )
        self.clock_row = (OBSERVED_TIME,)
        self.budget_update_fail_pairs: set[tuple[str, str]] = set()
        self.statements: list[tuple[str, tuple[Any, ...]]] = []
        self.entries = 0
        self.transactions = 0

    def __enter__(self):
        self.entries += 1
        return self

    def __exit__(self, *_args):
        return False

    def transaction(self):
        self.transactions += 1
        return nullcontext(self)

    def execute(self, query: str, parameters: tuple[Any, ...] = ()):
        sql = " ".join(query.split())
        self.statements.append((sql, parameters))
        if sql == CLOCK_QUERY:
            return FakeCursor(self.clock_row)
        if sql == SETTLEMENT_EXECUTION_QUERY:
            return FakeCursor((self.state, self.action_id, self.execution_updated_at))
        if sql == SETTLEMENT_RESERVATION_QUERY:
            return FakeCursor(rows=self.reservation_rows)
        if sql == SETTLEMENT_BUDGET_QUERY:
            return FakeCursor(rows=self.budget_rows)
        if sql == SETTLEMENT_IDEMPOTENCY_QUERY:
            return FakeCursor(self.idempotency_row)
        if sql == SETTLEMENT_ACTION_QUERY:
            return FakeCursor(self.action_row)
        if sql == UNKNOWN_EXECUTION_QUERY:
            return FakeCursor((self.state, self.execution_updated_at))
        if sql == UNKNOWN_IDEMPOTENCY_QUERY:
            return FakeCursor(
                None if self.idempotency_row is None else self.idempotency_row[2:]
            )
        if sql == UNKNOWN_RECOVERY_QUERY:
            return FakeCursor(self.recovery_row)
        if sql == "SELECT state FROM execution_records WHERE execution_id = %s":
            return FakeCursor((self.state,))
        if sql.startswith("UPDATE credential_budget_state"):
            pair = (parameters[3], parameters[4])
            return FakeCursor(None if pair in self.budget_update_fail_pairs else (parameters[3],))
        if sql.startswith("UPDATE execution_records SET state = 'COMMITTED'"):
            self.state = "COMMITTED"
            self.execution_updated_at = parameters[3]
        elif sql.startswith("UPDATE execution_records SET state = 'UNKNOWN'"):
            self.state = "UNKNOWN"
            self.execution_updated_at = parameters[1]
        elif sql.startswith("UPDATE idempotency_records SET status = 'COMMITTED'"):
            if self.idempotency_row is not None:
                self.idempotency_row = (*self.idempotency_row[:2], "COMMITTED", parameters[2])
        elif sql.startswith("UPDATE idempotency_records SET status = 'UNKNOWN'"):
            if self.idempotency_row is not None and self.idempotency_row[2] == "DISPATCHED":
                self.idempotency_row = (*self.idempotency_row[:2], "UNKNOWN", parameters[0])
        elif sql.startswith("UPDATE business_actions"):
            self.action_row = (parameters[0],)
        elif sql.startswith("INSERT INTO execution_recovery_records"):
            assert "ON CONFLICT (execution_id) DO NOTHING" in sql
            if self.recovery_row is None:
                self.recovery_row = (parameters[4],)
                self.recovery_deadline = parameters[2]
        elif not sql.startswith((
            "UPDATE execution_budget_reservations",
        )):
            raise AssertionError(f"unexpected dispatch SQL: {sql}")
        return FakeCursor()


def _digest(result: dict[str, Any]) -> str:
    return sm3_hex(canonicalize(result))


def _command(kind: str = "refund") -> ValidatedToolCommandModel:
    service, tool = TOOLS[kind]
    parameters = {"ticket_id": "TICKET-RESULT-BINDING"}
    if kind == "refund":
        parameters.update(customer_id="CUSTOMER-RESULT-BINDING", amount_fen=250)
    elif kind == "notification":
        parameters = {
            "customer_id": "CUSTOMER-RESULT-BINDING",
            "template_id": "REFUND_SUCCESS",
            "related_business_effect_id": "REFUND-RESULT-BINDING",
        }
    return ValidatedToolCommandModel(
        schema_version="1.0", execution_id="EXEC-RESULT-BINDING",
        tenant_id="TENANT-RESULT-BINDING", task_id="TASK-RESULT-BINDING",
        tool_service=service, tool_name=tool, tool_version="v1",
        validated_parameters=parameters, parameter_hash=_digest(parameters),
        business_action_id="ACTION-RESULT-BINDING" if kind in EFFECT_FIELDS else None,
        business_idempotency_key="c" * 64 if kind in EFFECT_FIELDS else None,
    )


def _response(kind: str = "refund", **changes: Any) -> ToolExecutionResponse:
    if kind in EFFECT_FIELDS:
        effect = f"{kind.upper()}-RESULT-BINDING"
        result = {EFFECT_FIELDS[kind]: effect, "status": "SUCCESS", "count": 1}
    else:
        effect = None
        result = {} if kind == "ticket" else {"documents": []}
    response = ToolExecutionResponse(
        execution_id="EXEC-RESULT-BINDING", execution_attempt_id="ATTEMPT-RESULT-BINDING",
        outcome="SUCCESS", reason_code="ALLOWED", result=result,
        business_effect_id=effect, business_result_hash=_digest(result),
    )
    return response.model_copy(update=changes)


def _body(command: ValidatedToolCommandModel) -> dict[str, Any]:
    return {
        "execution_id": command.execution_id, "state": "ADMITTED", "decision": "ALLOW",
        "reason_code": "ALLOWED", "admission_outcome": "NEW_EXECUTION",
        "request_hash": "1" * 64, "credential_chain_hash": "2" * 64,
        "validated_command": command.model_dump(mode="json"), "receipt": None,
    }


def _subject(monkeypatch: pytest.MonkeyPatch, command: ValidatedToolCommandModel):
    connection = FakeConnection(command)
    connect = Mock(return_value=connection)
    monkeypatch.setattr(dispatch_module, "connect", connect)
    subject = GatewayDispatchService(
        SimpleNamespace(database_url=DATABASE_URL),
        SimpleNamespace(admit_request=Mock()), tool_urls={},
        gateway_key_id="unused-shape-key", gateway_private_key_file="unused-key-not-read",
    )
    return subject, connection, connect


def _assert_rejected_before_transaction(monkeypatch, command, response) -> None:
    subject, connection, connect = _subject(monkeypatch, command)
    reservations_before = connection.reservations

    with pytest.raises(_ToolDispatchFailure):
        subject._settle_success(
            command, body=_body(command), tool_response=response,
        )

    connect.assert_not_called()
    assert connection.entries == connection.transactions == 0
    assert connection.statements == []
    assert connection.state == "DISPATCHED"
    assert connection.reservations == reservations_before


@pytest.mark.parametrize(("field", "value"), [
    ("execution_id", "EXEC-OTHER"),
    ("outcome", "FAILED_NO_EFFECT"),
    ("outcome", "UNKNOWN"),
    ("reason_code", "TOOL_EXECUTION_UNKNOWN"),
    ("reason_code", ""),
    ("result", None),
    ("business_result_hash", "0" * 64),
    ("business_result_hash", "A" * 64),
    ("business_result_hash", "not-a-digest"),
    ("business_result_hash", ""),
])
def test_invalid_response_never_opens_settlement_transaction(monkeypatch, field, value) -> None:
    _assert_rejected_before_transaction(
        monkeypatch, _command(), _response(**{field: value}),
    )


@pytest.mark.parametrize("value", [
    0.0, float("nan"), float("inf"), 2**53, -(2**53),
    {1: "non-string-key"}, b"unsupported-bytes", ("unsupported-tuple",), "\ud800",
])
@pytest.mark.parametrize("stored_hash", [None, "0" * 64])
def test_noncanonical_result_is_rejected_even_with_provided_hash(
    monkeypatch, value, stored_hash,
) -> None:
    response = _response(result={"value": value}, business_result_hash=stored_hash)
    _assert_rejected_before_transaction(monkeypatch, _command(), response)


@pytest.mark.parametrize("kind", list(TOOLS))
def test_changed_result_cannot_reuse_previous_tool_digest(monkeypatch, kind) -> None:
    original = _response(kind)
    changed = dict(original.result)
    changed["tampered"] = True
    response = original.model_copy(update={"result": changed})
    assert response.business_result_hash != _digest(changed)
    _assert_rejected_before_transaction(monkeypatch, _command(kind), response)


@pytest.mark.parametrize(("field", "value"), [
    ("execution_id", "EXEC-OTHER"),
    ("tenant_id", "TENANT-OTHER"),
    ("task_id", "TASK-OTHER"),
    ("business_action_id", "ACTION-OTHER"),
    ("business_idempotency_key", "d" * 64),
    ("parameter_hash", "4" * 64),
    ("execution_id", None),
])
def test_present_result_metadata_must_exactly_match_command(monkeypatch, field, value) -> None:
    command = _command()
    original = _response()
    result = dict(original.result)
    result[field] = value
    assert value != getattr(command, field)
    response = original.model_copy(update={
        "result": result, "business_result_hash": _digest(result),
    })
    _assert_rejected_before_transaction(monkeypatch, command, response)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("failure", [
    "missing-effect", "empty-effect", "missing-result-id", "null-result-id",
    "empty-result-id", "both-empty", "different-result-id", "wrong-id-field", "numeric-result-id",
])
def test_side_effect_result_id_must_equal_nonempty_effect(monkeypatch, kind, failure) -> None:
    response = _response(kind)
    effect = response.business_effect_id
    result = dict(response.result)
    field = EFFECT_FIELDS[kind]
    if failure == "missing-effect":
        effect = None
    elif failure == "empty-effect":
        effect = ""
    elif failure == "both-empty":
        effect = result[field] = ""
    elif failure == "missing-result-id":
        result.pop(field)
    elif failure == "wrong-id-field":
        result.pop(field)
        result["notification_id" if kind == "refund" else "refund_id"] = effect
    else:
        result[field] = {
            "null-result-id": None, "empty-result-id": "",
            "different-result-id": "EFFECT-OTHER", "numeric-result-id": 1,
        }[failure]
        if failure == "numeric-result-id":
            effect = "1"
    response = response.model_copy(update={
        "result": result, "business_effect_id": effect, "business_result_hash": _digest(result),
    })
    _assert_rejected_before_transaction(monkeypatch, _command(kind), response)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("field", ["business_action_id", "business_idempotency_key"])
@pytest.mark.parametrize("value", [None, ""])
def test_side_effect_requires_action_and_idempotency_key(monkeypatch, kind, field, value) -> None:
    # model_copy bypasses schema checks to exercise the settlement guard itself.
    command = _command(kind).model_copy(update={field: value})
    _assert_rejected_before_transaction(monkeypatch, command, _response(kind))


@pytest.mark.parametrize("kind", ["ticket", "knowledge"])
@pytest.mark.parametrize("effect", ["EFFECT-UNEXPECTED", ""])
def test_readonly_response_requires_null_effect(monkeypatch, kind, effect) -> None:
    _assert_rejected_before_transaction(
        monkeypatch, _command(kind), _response(kind, business_effect_id=effect),
    )


@pytest.mark.parametrize("kind", ["ticket", "knowledge"])
@pytest.mark.parametrize("field", ["business_action_id", "business_idempotency_key"])
@pytest.mark.parametrize("empty", [False, True])
def test_readonly_command_requires_null_action_and_key(monkeypatch, kind, field, empty) -> None:
    value = "" if empty else "ACTION-OTHER" if field == "business_action_id" else "d" * 64
    command = _command(kind).model_copy(update={field: value})
    _assert_rejected_before_transaction(monkeypatch, command, _response(kind))


@pytest.mark.parametrize("kind", list(TOOLS))
@pytest.mark.parametrize("missing_hash", [False, True])
@pytest.mark.parametrize("include_metadata", [False, True])
def test_valid_result_settles_and_binds_actual_canonical_digest(
    monkeypatch, kind, missing_hash, include_metadata,
) -> None:
    command = _command(kind)
    response = _response(kind)
    if include_metadata:
        result_value = dict(response.result)
        result_value.update({field: getattr(command, field) for field in RESULT_METADATA_FIELDS})
        response = response.model_copy(update={
            "result": result_value, "business_result_hash": _digest(result_value),
        })
    else:
        assert not any(field in response.result for field in RESULT_METADATA_FIELDS)
    expected_hash = _digest(dict(reversed(list(response.result.items()))))
    if missing_hash:
        response = response.model_copy(update={"business_result_hash": None})
    subject, connection, connect = _subject(monkeypatch, command)

    result = subject._settle_success(
        command, body=_body(command), tool_response=response,
    )

    connect.assert_called_once_with(DATABASE_URL)
    assert connection.entries == connection.transactions == 1
    assert result["state"] == connection.state == "COMMITTED"
    assert result["reason_code"] == ReasonCode.ALLOWED.value
    writes = [params for sql, params in connection.statements
              if sql.startswith("UPDATE execution_records SET state = 'COMMITTED'")]
    assert len(writes) == 1
    stored_result, effect, stored_hash, timestamp, execution_id = writes[0]
    assert stored_result.obj == response.result
    if not include_metadata:
        assert not any(field in stored_result.obj for field in RESULT_METADATA_FIELDS)
    assert effect == response.business_effect_id
    assert stored_hash == expected_hash
    assert (timestamp, execution_id) == (OBSERVED_TIME, command.execution_id)
    budget_writes = [params for sql, params in connection.statements
                     if sql.startswith("UPDATE credential_budget_state")]
    assert budget_writes == [
        (amount, amount, OBSERVED_TIME, credential, quota, amount)
        for credential, quota, amount in connection.reservations
    ]
    commits = [params for sql, params in connection.statements
               if sql.startswith("UPDATE execution_budget_reservations")]
    assert commits == [
        (OBSERVED_TIME, command.execution_id, credential, quota)
        for credential, quota, _amount in connection.reservations
    ]
    assert not any("state = 'UNKNOWN'" in sql for sql, _params in connection.statements)
    assert sum(sql == CLOCK_QUERY for sql, _params in connection.statements) == 1


@pytest.mark.parametrize("failure", [
    "call", "execution-id", "outcome", "reason", "null-result", "digest",
    "noncanonical-result", "effect-id",
])
def test_dispatch_failure_marks_unknown_keeps_reservations_and_never_repeats_tool(
    monkeypatch, failure,
) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    body = _body(command)
    subject.admission.admit_request.return_value = SimpleNamespace(body=body, status_code=200)
    envelope = object()
    mark_dispatched = Mock(side_effect=[envelope, None])
    monkeypatch.setattr(subject, "_mark_dispatched", mark_dispatched)
    monkeypatch.setattr(subject, "_stored_request_hash", Mock(return_value=body["request_hash"]))
    changes = {
        "execution-id": {"execution_id": "EXEC-OTHER"},
        "outcome": {"outcome": "UNKNOWN"},
        "reason": {"reason_code": "TOOL_EXECUTION_UNKNOWN"},
        "null-result": {"result": None},
        "digest": {"business_result_hash": "0" * 64},
        "noncanonical-result": {"result": {"value": 1.5}},
        "effect-id": {"business_effect_id": "EFFECT-OTHER"},
    }
    tool = Mock(return_value=_response(**changes.get(failure, {})))
    if failure == "call":
        tool.side_effect = _ToolDispatchFailure("fake transport failure")
    monkeypatch.setattr(subject, "_call_tool", tool)
    settle = Mock(wraps=subject._settle_success)
    monkeypatch.setattr(subject, "_settle_success", settle)
    request = RequestEnvelopeModel(
        schema_version="1.0", credential_chain=[{}], task_id=command.task_id,
        tool_service=command.tool_service, tool_name=command.tool_name, tool_version="v1",
        canonical_parameters=command.validated_parameters, request_id="REQUEST-RESULT-BINDING",
        issued_at=CURRENT_TIME, holder_key_id="unused-holder-key", holder_proof={},
        business_action_id=command.business_action_id,
    )
    reservations_before = connection.reservations

    result = subject.dispatch(request, current_time=CURRENT_TIME)
    repeated = subject.dispatch(request, current_time=CURRENT_TIME + 1)

    assert result.status_code == 502
    assert result.body["state"] == connection.state == "UNKNOWN"
    assert result.body["reason_code"] == ReasonCode.TOOL_EXECUTION_UNKNOWN.value
    assert result.body["receipt"] is None
    assert repeated.body["state"] == "UNKNOWN"
    tool.assert_called_once_with(envelope)
    assert settle.call_count == (0 if failure == "call" else 1)
    assert mark_dispatched.call_count == 2
    assert connection.transactions == 1
    assert connection.reservations == reservations_before
    assert all("COMMITTED" not in sql and "RELEASED" not in sql
               for sql, _params in connection.statements)
    assert not any("credential_budget_state" in sql or "execution_budget_reservations" in sql
                   or "business_actions" in sql for sql, _params in connection.statements)
    unknown_updates = [params for sql, params in connection.statements
                       if sql.startswith("UPDATE execution_records SET state = 'UNKNOWN'")]
    assert unknown_updates == [
        (ReasonCode.TOOL_EXECUTION_UNKNOWN.value, OBSERVED_TIME, command.execution_id),
    ]
    assert any("SET state = 'UNKNOWN', reason_code = %s, updated_at = %s" in sql
               for sql, _params in connection.statements)
    assert sum(sql.startswith("INSERT INTO execution_recovery_records")
               for sql, _params in connection.statements) == 1
    assert connection.recovery_deadline == OBSERVED_TIME + subject.recovery_deadline_seconds
    assert sum(sql == CLOCK_QUERY for sql, _params in connection.statements) == 1
