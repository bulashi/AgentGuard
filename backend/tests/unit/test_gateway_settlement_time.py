"""Settlement-time unit sources, authored without execution or collection.

SQL rows and clocks are fakes. These cases do not establish PostgreSQL locking,
transaction rollback, transport, or cryptographic correctness. No persisted keys
or settings are used.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from backend.common.error_codes import ReasonCode
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.gateway.dispatch import GatewayDispatchService
from backend.gateway.service import GatewayError
from backend.tests.unit.test_dispatch_result_binding import (
    CLOCK_QUERY,
    CURRENT_TIME,
    OBSERVED_TIME,
    SETTLEMENT_ACTION_QUERY,
    SETTLEMENT_BUDGET_QUERY,
    SETTLEMENT_EXECUTION_QUERY,
    SETTLEMENT_IDEMPOTENCY_QUERY,
    SETTLEMENT_RESERVATION_QUERY,
    UNKNOWN_EXECUTION_QUERY,
    UNKNOWN_IDEMPOTENCY_QUERY,
    UNKNOWN_RECOVERY_QUERY,
    FakeCursor,
    _body,
    _command,
    _response,
    _subject,
)

INVALID_CLOCK_ROWS = [
    None, (None,), (True,), ("200",), (200.0,), (float("nan"),),
    (float("inf"),), (-1,), (MAX_SAFE_INTEGER + 1,),
]
SETTLEMENT_TIME_ROWS = ["execution", "reservation", "budget", "idempotency", "action"]


class ClockConnection:
    def __init__(self, row) -> None:
        self.row = row
        self.statements: list[str] = []

    def execute(self, query: str):
        sql = " ".join(query.split())
        assert sql == CLOCK_QUERY
        self.statements.append(sql)
        return FakeCursor(self.row)


@pytest.mark.parametrize("timestamp", [0, CURRENT_TIME, MAX_SAFE_INTEGER])
def test_dispatch_clock_accepts_only_database_safe_integer_rows(timestamp) -> None:
    connection = ClockConnection((timestamp,))

    assert GatewayDispatchService._dispatch_clock(connection) == timestamp

    assert connection.statements == [CLOCK_QUERY]


@pytest.mark.parametrize("row", INVALID_CLOCK_ROWS)
def test_dispatch_clock_rejects_missing_or_invalid_database_rows(row) -> None:
    connection = ClockConnection(row)

    with pytest.raises(GatewayError) as failure:
        GatewayDispatchService._dispatch_clock(connection)

    assert failure.value.reason_code == ReasonCode.EXECUTION_ENVELOPE_EXPIRED
    assert failure.value.status_code == 409
    assert connection.statements == [CLOCK_QUERY]


def _writes(connection, prefix: str):
    return [parameters for sql, parameters in connection.statements if sql.startswith(prefix)]


def _assert_no_writes(connection) -> None:
    assert all(sql.startswith("SELECT ") for sql, _parameters in connection.statements)
    assert connection.state == "DISPATCHED"
    assert connection.idempotency_row[2] == "DISPATCHED"
    assert connection.recovery_deadline is None


def _invoke(subject, command, operation: str):
    if operation == "settlement":
        return subject._settle_success(command, body=_body(command), tool_response=_response())
    assert operation == "unknown"
    return subject._mark_unknown(command.execution_id)


def _advance_clock_after_lock(monkeypatch, connection, last_lock: str, timestamp: int) -> None:
    execute = connection.execute

    def after_lock(query: str, parameters=()):
        cursor = execute(query, parameters)
        if " ".join(query.split()) == last_lock:
            connection.clock_row = (timestamp,)
        return cursor

    monkeypatch.setattr(connection, "execute", after_lock)


def _set_settlement_row_time(connection, row: str, timestamp) -> None:
    if row == "execution":
        connection.execution_updated_at = timestamp
    elif row == "reservation":
        connection.reservation_rows = (
            (*connection.reservation_rows[0][:3], timestamp), *connection.reservation_rows[1:],
        )
    elif row == "budget":
        connection.budget_rows = (
            (*connection.budget_rows[0][:2], timestamp), *connection.budget_rows[1:],
        )
    elif row == "idempotency":
        connection.idempotency_row = (*connection.idempotency_row[:3], timestamp)
    else:
        assert row == "action"
        connection.action_row = (timestamp,)


@pytest.mark.parametrize("kind", ["refund", "ticket"])
def test_settlement_samples_clock_after_all_locks_and_stamps_every_write(monkeypatch, kind) -> None:
    command = _command(kind)
    subject, connection, _connect = _subject(monkeypatch, command)
    locks = [SETTLEMENT_EXECUTION_QUERY, SETTLEMENT_RESERVATION_QUERY, SETTLEMENT_BUDGET_QUERY]
    if kind == "refund":
        locks.extend([SETTLEMENT_IDEMPOTENCY_QUERY, SETTLEMENT_ACTION_QUERY])
    observed_at = OBSERVED_TIME + 20
    connection.clock_row = (CURRENT_TIME + 1,)
    _advance_clock_after_lock(monkeypatch, connection, locks[-1], observed_at)
    clock = Mock(wraps=subject._dispatch_clock)
    monkeypatch.setattr(subject, "_dispatch_clock", clock)

    result = subject._settle_success(command, body=_body(command), tool_response=_response(kind))

    assert result["state"] == connection.state == "COMMITTED"
    clock.assert_called_once_with(connection)
    reads = [(sql, parameters) for sql, parameters in connection.statements if sql.startswith("SELECT ")]
    assert [sql for sql, _parameters in reads] == [*locks, CLOCK_QUERY]
    assert [sql for sql, _parameters in connection.statements[:len(locks) + 1]] == [*locks, CLOCK_QUERY]
    assert dict(reads)[SETTLEMENT_BUDGET_QUERY] == (
        sorted({credential for credential, _quota, _amount in connection.reservations}),
    )
    assert _writes(connection, "UPDATE credential_budget_state") == [
        (amount, amount, observed_at, credential, quota, amount)
        for credential, quota, amount in connection.reservations
    ]
    assert _writes(connection, "UPDATE execution_budget_reservations") == [
        (observed_at, command.execution_id, credential, quota)
        for credential, quota, _amount in connection.reservations
    ]
    assert _writes(connection, "UPDATE execution_records")[0][3] == observed_at
    if kind == "refund":
        assert _writes(connection, "UPDATE idempotency_records")[0][2] == observed_at
        assert _writes(connection, "UPDATE business_actions") == [(observed_at, command.business_action_id)]
    else:
        assert _writes(connection, "UPDATE idempotency_records") == []
        assert _writes(connection, "UPDATE business_actions") == []
    assert not any("RELEASED" in sql for sql, _parameters in connection.statements)


@pytest.mark.parametrize("timestamp", [0, CURRENT_TIME, MAX_SAFE_INTEGER])
def test_settlement_accepts_clock_equal_to_every_locked_row_time(monkeypatch, timestamp) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.execution_updated_at = timestamp
    connection.reservation_rows = tuple((*row[:3], timestamp) for row in connection.reservation_rows)
    connection.budget_rows = tuple((*row[:2], timestamp) for row in connection.budget_rows)
    connection.idempotency_row = (*connection.idempotency_row[:3], timestamp)
    connection.action_row = (timestamp,)
    connection.clock_row = (timestamp,)

    result = subject._settle_success(command, body=_body(command), tool_response=_response())

    assert result["state"] == connection.state == "COMMITTED"
    assert connection.execution_updated_at == timestamp
    assert all(parameters[2] == timestamp
               for parameters in _writes(connection, "UPDATE credential_budget_state"))


@pytest.mark.parametrize("row", SETTLEMENT_TIME_ROWS)
def test_settlement_uses_each_locked_row_as_clock_lower_bound(monkeypatch, row) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    _set_settlement_row_time(connection, row, OBSERVED_TIME + 1)

    with pytest.raises(GatewayError) as failure:
        subject._settle_success(command, body=_body(command), tool_response=_response())

    assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert failure.value.status_code == 502
    assert str(failure.value) == "execution clock precedes stored state"
    assert sum(sql == CLOCK_QUERY for sql, _parameters in connection.statements) == 1
    _assert_no_writes(connection)


@pytest.mark.parametrize("row", SETTLEMENT_TIME_ROWS)
@pytest.mark.parametrize("timestamp", [None, True, -1, "200", 200.0, MAX_SAFE_INTEGER + 1])
def test_settlement_rejects_invalid_stored_times_before_reading_clock(monkeypatch, row, timestamp) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    _set_settlement_row_time(connection, row, timestamp)

    with pytest.raises(GatewayError) as failure:
        subject._settle_success(command, body=_body(command), tool_response=_response())

    assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert failure.value.status_code == 502
    assert str(failure.value) == "stored execution clock is invalid"
    assert not any(sql == CLOCK_QUERY for sql, _parameters in connection.statements)
    _assert_no_writes(connection)


@pytest.mark.parametrize("operation", ["settlement", "unknown"])
@pytest.mark.parametrize("row", INVALID_CLOCK_ROWS)
def test_invalid_clock_never_fabricates_observation_or_releases_budget(monkeypatch, operation, row) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.clock_row = row

    with pytest.raises(GatewayError) as failure:
        _invoke(subject, command, operation)

    assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert failure.value.status_code == 502
    assert str(failure.value) == "trusted execution clock is unavailable"
    assert isinstance(failure.value.__cause__, GatewayError)
    assert failure.value.__cause__.reason_code == ReasonCode.EXECUTION_ENVELOPE_EXPIRED
    _assert_no_writes(connection)


def test_second_success_observation_never_settles_budget_or_calls_tool_again(monkeypatch) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    tool = Mock(side_effect=AssertionError("settlement must not execute a tool"))
    monkeypatch.setattr(subject, "_call_tool", tool)
    first = subject._settle_success(command, body=_body(command), tool_response=_response())
    first_statements = list(connection.statements)
    connection.clock_row = None
    connection.execution_updated_at = None

    repeated = subject._settle_success(command, body=_body(command), tool_response=_response())

    assert first["state"] == repeated["state"] == connection.state == "COMMITTED"
    assert connection.idempotency_row[2] == "COMMITTED"
    assert connection.statements == [
        *first_statements, (SETTLEMENT_EXECUTION_QUERY, (command.execution_id,)),
    ]
    assert len(_writes(connection, "UPDATE credential_budget_state")) == len(connection.reservations)
    tool.assert_not_called()


@pytest.mark.parametrize("state", ["UNKNOWN", "RECONCILING"])
def test_success_cannot_overwrite_non_dispatched_execution(monkeypatch, state) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.state = state
    connection.clock_row = None

    with pytest.raises(GatewayError) as failure:
        subject._settle_success(command, body=_body(command), tool_response=_response())

    assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert failure.value.status_code == 502
    assert connection.state == state
    assert connection.statements == [(SETTLEMENT_EXECUTION_QUERY, (command.execution_id,))]


@pytest.mark.parametrize("missing_index", [0, -1])
def test_missing_reserved_budget_pair_is_rejected_before_clock_and_writes(monkeypatch, missing_index) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    missing_pair = connection.budget_rows[missing_index][:2]
    connection.budget_rows = tuple(row for row in connection.budget_rows if row[:2] != missing_pair)

    with pytest.raises(GatewayError) as failure:
        subject._settle_success(command, body=_body(command), tool_response=_response())

    assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert failure.value.status_code == 502
    assert str(failure.value) == "budget state disappeared before settlement"
    assert not any(sql == CLOCK_QUERY for sql, _parameters in connection.statements)
    _assert_no_writes(connection)


def test_budget_update_failure_reaches_budget_guard_with_valid_clock(monkeypatch) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.budget_update_fail_pairs.add(connection.reservations[0][:2])

    with pytest.raises(GatewayError) as failure:
        subject._settle_success(command, body=_body(command), tool_response=_response())

    assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert failure.value.status_code == 502
    assert str(failure.value) == "budget reservation cannot be settled safely"
    assert sum(sql == CLOCK_QUERY for sql, _parameters in connection.statements) == 1
    credential, quota, amount = connection.reservations[0]
    assert _writes(connection, "UPDATE credential_budget_state") == [
        (amount, amount, OBSERVED_TIME, credential, quota, amount),
    ]
    assert all(sql.startswith(("SELECT ", "UPDATE credential_budget_state "))
               for sql, _parameters in connection.statements)
    assert connection.state == connection.idempotency_row[2] == "DISPATCHED"


@pytest.mark.parametrize("action_id", [None, "ACTION-OTHER"])
def test_stored_action_mismatch_reaches_action_guard_with_valid_time(monkeypatch, action_id) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.action_id = action_id

    with pytest.raises(GatewayError) as failure:
        subject._settle_success(command, body=_body(command), tool_response=_response())

    assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert str(failure.value) == "stored execution action differs from the dispatched command"
    assert connection.statements == [(SETTLEMENT_EXECUTION_QUERY, (command.execution_id,))]
    _assert_no_writes(connection)


@pytest.mark.parametrize("mismatch", ["missing", "key", "hash", "status"])
def test_stored_idempotency_mismatch_reaches_guard_with_valid_time(monkeypatch, mismatch) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    if mismatch == "missing":
        connection.idempotency_row = None
    else:
        row = list(connection.idempotency_row)
        index, value = {"key": (0, "d" * 64), "hash": (1, "4" * 64), "status": (2, "COMMITTED")}[mismatch]
        row[index] = value
        connection.idempotency_row = tuple(row)
    before = connection.idempotency_row

    with pytest.raises(GatewayError) as failure:
        subject._settle_success(command, body=_body(command), tool_response=_response())

    assert failure.value.reason_code == ReasonCode.IDEMPOTENCY_CONFLICT
    assert failure.value.status_code == 409
    assert str(failure.value) == "settlement differs from the dispatched business idempotency record"
    assert connection.idempotency_row == before
    assert connection.state == "DISPATCHED"
    assert all(sql.startswith("SELECT ") for sql, _parameters in connection.statements)
    assert not any(sql == CLOCK_QUERY for sql, _parameters in connection.statements)


@pytest.mark.parametrize("kind", ["refund", "ticket"])
def test_unknown_samples_after_all_locks_and_sets_deadline_from_observation(monkeypatch, kind) -> None:
    command = _command(kind)
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.clock_row = (CURRENT_TIME + 1,)
    observed_at = OBSERVED_TIME + 30
    _advance_clock_after_lock(monkeypatch, connection, UNKNOWN_RECOVERY_QUERY, observed_at)
    clock = Mock(wraps=subject._dispatch_clock)
    monkeypatch.setattr(subject, "_dispatch_clock", clock)
    reservations_before = connection.reservations

    state = subject._mark_unknown(command.execution_id)

    assert state == connection.state == "UNKNOWN"
    clock.assert_called_once_with(connection)
    reads = [sql for sql, _parameters in connection.statements if sql.startswith("SELECT ")]
    assert reads == [UNKNOWN_EXECUTION_QUERY, UNKNOWN_IDEMPOTENCY_QUERY, UNKNOWN_RECOVERY_QUERY, CLOCK_QUERY]
    assert [sql for sql, _parameters in connection.statements[:4]] == reads
    assert _writes(connection, "UPDATE execution_records") == [
        (ReasonCode.TOOL_EXECUTION_UNKNOWN.value, observed_at, command.execution_id),
    ]
    assert _writes(connection, "UPDATE idempotency_records") == [(observed_at, command.execution_id)]
    assert _writes(connection, "INSERT INTO execution_recovery_records") == [
        (command.execution_id, subject.recovery_max_attempts,
         observed_at + subject.recovery_deadline_seconds, observed_at, observed_at),
    ]
    assert connection.recovery_row == (observed_at,)
    assert connection.recovery_deadline == observed_at + subject.recovery_deadline_seconds
    assert connection.reservations == reservations_before
    assert not any("budget" in sql or "RELEASED" in sql for sql, _parameters in connection.statements)
    if kind == "ticket":
        assert connection.idempotency_row is None
    else:
        assert connection.idempotency_row[2:] == ("UNKNOWN", observed_at)


@pytest.mark.parametrize("state", ["COMMITTED", "UNKNOWN", "RECONCILING", "RELEASED"])
def test_unknown_early_return_preserves_real_state_without_clock_or_other_locks(monkeypatch, state) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.state = state
    connection.execution_updated_at = None
    connection.idempotency_row = (*connection.idempotency_row[:2], state, CURRENT_TIME)
    connection.recovery_row = (CURRENT_TIME,)
    connection.recovery_deadline = CURRENT_TIME + 50
    connection.clock_row = None
    before = (connection.idempotency_row, connection.recovery_row, connection.recovery_deadline,
              connection.reservations, connection.budget_rows)

    observed_state = subject._mark_unknown(command.execution_id)

    assert observed_state == connection.state == state
    assert connection.statements == [(UNKNOWN_EXECUTION_QUERY, (command.execution_id,))]
    assert (connection.idempotency_row, connection.recovery_row, connection.recovery_deadline,
            connection.reservations, connection.budget_rows) == before


@pytest.mark.parametrize("row", ["execution", "idempotency", "recovery"])
@pytest.mark.parametrize("timestamp", [OBSERVED_TIME + 1, None, True, -1, 200.0, MAX_SAFE_INTEGER + 1])
def test_unknown_rejects_regressed_or_invalid_locked_row_time_without_budget_release(
    monkeypatch, row, timestamp,
) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    if row == "execution":
        connection.execution_updated_at = timestamp
    elif row == "idempotency":
        connection.idempotency_row = (*connection.idempotency_row[:3], timestamp)
    else:
        connection.recovery_row = (timestamp,)
    before = (connection.execution_updated_at, connection.idempotency_row, connection.recovery_row,
              connection.reservations, connection.budget_rows)

    with pytest.raises(GatewayError) as failure:
        subject._mark_unknown(command.execution_id)

    assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert failure.value.status_code == 502
    is_regression = timestamp == OBSERVED_TIME + 1 and type(timestamp) is int
    assert str(failure.value) == (
        "execution clock precedes stored state" if is_regression else "stored execution clock is invalid"
    )
    assert sum(sql == CLOCK_QUERY for sql, _parameters in connection.statements) == int(is_regression)
    _assert_no_writes(connection)
    assert (connection.execution_updated_at, connection.idempotency_row, connection.recovery_row,
            connection.reservations, connection.budget_rows) == before
    assert not any("budget" in sql for sql, _parameters in connection.statements)


@pytest.mark.parametrize("state", ["ADMITTED", "COMMITTED", "UNKNOWN"])
def test_unknown_rejects_disagreeing_idempotency_state_before_observation(monkeypatch, state) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.idempotency_row = (*connection.idempotency_row[:2], state, CURRENT_TIME)
    before = connection.idempotency_row

    with pytest.raises(GatewayError) as failure:
        subject._mark_unknown(command.execution_id)

    assert failure.value.reason_code == ReasonCode.IDEMPOTENCY_CONFLICT
    assert failure.value.status_code == 409
    assert str(failure.value) == "failed execution and business state disagree"
    assert connection.state == "DISPATCHED"
    assert connection.idempotency_row == before
    assert connection.statements == [
        (UNKNOWN_EXECUTION_QUERY, (command.execution_id,)),
        (UNKNOWN_IDEMPOTENCY_QUERY, (command.execution_id,)),
    ]


@pytest.mark.parametrize("overflows", [False, True])
def test_new_recovery_deadline_requires_safe_integer_without_budget_release(monkeypatch, overflows) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    observed_at = MAX_SAFE_INTEGER - subject.recovery_deadline_seconds + int(overflows)
    connection.clock_row = (observed_at,)

    if overflows:
        with pytest.raises(GatewayError) as failure:
            subject._mark_unknown(command.execution_id)
        assert failure.value.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN
        assert failure.value.status_code == 502
        assert str(failure.value) == "recovery deadline overflows the safe time range"
        _assert_no_writes(connection)
    else:
        assert subject._mark_unknown(command.execution_id) == "UNKNOWN"
        assert connection.recovery_deadline == MAX_SAFE_INTEGER
        assert _writes(connection, "INSERT INTO execution_recovery_records")[0][2] == MAX_SAFE_INTEGER
    assert connection.reservations == tuple(row[:3] for row in connection.reservation_rows)
    assert not any("budget" in sql or "RELEASED" in sql for sql, _parameters in connection.statements)


@pytest.mark.parametrize("observed_at", [OBSERVED_TIME, MAX_SAFE_INTEGER])
def test_existing_recovery_never_inserts_or_resets_deadline_even_near_clock_limit(monkeypatch, observed_at) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    connection.recovery_row = (CURRENT_TIME + 10,)
    connection.recovery_deadline = CURRENT_TIME + 50
    connection.clock_row = (observed_at,)
    recovery_before = (connection.recovery_row, connection.recovery_deadline)

    assert subject._mark_unknown(command.execution_id) == "UNKNOWN"

    assert connection.execution_updated_at == observed_at
    assert connection.idempotency_row[2:] == ("UNKNOWN", observed_at)
    assert (connection.recovery_row, connection.recovery_deadline) == recovery_before
    assert _writes(connection, "INSERT INTO execution_recovery_records") == []
    assert _writes(connection, "UPDATE execution_recovery_records") == []
    assert not any("budget" in sql or "RELEASED" in sql for sql, _parameters in connection.statements)
    statements_before_repeat = list(connection.statements)
    connection.clock_row = None

    assert subject._mark_unknown(command.execution_id) == "UNKNOWN"

    assert connection.statements == [
        *statements_before_repeat, (UNKNOWN_EXECUTION_QUERY, (command.execution_id,)),
    ]
    assert (connection.recovery_row, connection.recovery_deadline) == recovery_before


def test_first_recovery_insert_conflict_keeps_existing_deadline(monkeypatch) -> None:
    command = _command()
    subject, connection, _connect = _subject(monkeypatch, command)
    execute = connection.execute
    existing_deadline = CURRENT_TIME + 50

    def insert_after_missing_row(query: str, parameters=()):
        cursor = execute(query, parameters)
        if " ".join(query.split()) == UNKNOWN_RECOVERY_QUERY:
            # The SELECT cursor stays empty while a competing INSERT becomes visible.
            connection.recovery_row = (CURRENT_TIME + 10,)
            connection.recovery_deadline = existing_deadline
        return cursor

    monkeypatch.setattr(connection, "execute", insert_after_missing_row)

    assert subject._mark_unknown(command.execution_id) == "UNKNOWN"

    inserts = [(sql, parameters) for sql, parameters in connection.statements
               if sql.startswith("INSERT INTO execution_recovery_records")]
    assert len(inserts) == 1
    assert "ON CONFLICT (execution_id) DO NOTHING" in inserts[0][0]
    assert inserts[0][1][2] == OBSERVED_TIME + subject.recovery_deadline_seconds
    assert connection.recovery_deadline == existing_deadline
    assert _writes(connection, "UPDATE execution_recovery_records") == []
    assert not any("budget" in sql or "RELEASED" in sql for sql, _parameters in connection.statements)
