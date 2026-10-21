"""Native PostgreSQL terminal-time sources, authored without execution.

The database cases use only the configured AgentGuard database URL when a future
authorized run opts in. Each case creates a task and execution row with synthetic
identifiers inside a force-rollback transaction. No actor configuration, key
material, service, browser, Docker marker, or receipt endpoint is used.

The pre-migration legacy boundary cannot be manufactured after migration 0017 is
installed. Its nullable, non-backfilled contract is therefore checked against the
bounded migration SQL text, while all trigger behavior below is checked against
real PostgreSQL rows and transactions during a future run.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from psycopg import Error, sql
from psycopg.types.json import Jsonb

from backend.state.database import connect

pytestmark = pytest.mark.integration

MAX_SAFE_INTEGER = 9_007_199_254_740_991
FINAL_STATES = ("DENIED", "COMMITTED", "RELEASED")
NONFINAL_STATES = (
    "RECEIVED", "ADMITTED", "DISPATCHED", "UNKNOWN", "RECONCILING", "RECOVERY_FAILED_FINAL",
)
MIGRATION_PATH = (
    Path(__file__).resolve().parents[3]
    / "database" / "migrations" / "main" / "0017_execution_terminal_time.sql"
)


def _wall_clock(connection) -> int:
    row = connection.execute(
        "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
    ).fetchone()
    assert row is not None
    return int(row[0])


@pytest.fixture
def terminal_case() -> Iterator[SimpleNamespace]:
    database_url = os.getenv("AGENTGUARD_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_DATABASE_URL is not configured")
    suffix = uuid4().hex
    task_id = f"TASK-TERMINAL-{suffix}"
    with connect(database_url) as connection:
        with connection.transaction(force_rollback=True):
            created_at = _wall_clock(connection) - 60
            connection.execute(
                """
                INSERT INTO tasks (
                    task_id, tenant_id, ticket_id, customer_id, refund_total_fen,
                    max_tool_calls, expires_at, status, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, 1000, 10, %s, 'PENDING_AUTHORIZATION', %s, %s)
                """,
                (
                    task_id, "TENANT-TERMINAL", "TICKET-TERMINAL", "CUSTOMER-TERMINAL",
                    MAX_SAFE_INTEGER, created_at, created_at,
                ),
            )
            yield SimpleNamespace(
                connection=connection, task_id=task_id, created_at=created_at,
            )
        assert connection.execute(
            "SELECT count(*) FROM execution_records WHERE task_id = %s", (task_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM tasks WHERE task_id = %s", (task_id,),
        ).fetchone() == (0,)


def _insert_execution(
    case,
    state: str = "RECEIVED",
    *,
    terminal_at: int | None = None,
    terminal_state: str | None = None,
    created_at: int | None = None,
) -> str:
    execution_id = f"EXEC-TERMINAL-{uuid4().hex}"
    created_at = case.created_at if created_at is None else created_at
    case.connection.execute(
        """
        INSERT INTO execution_records (
            execution_id, initial_request_id, request_hash, credential_chain_hash,
            tenant_id, task_id, tool_service, tool_name, tool_version, parameter_hash,
            state, decision, reason_code, receipt_status, result, created_at, updated_at,
            terminal_at, terminal_state
        )
        VALUES (%s, %s, %s, %s, %s, %s, 'ticket-service', 'ticket.read', 'v1', %s,
                %s::execution_state, %s::authorization_decision, %s, 'NOT_REQUIRED',
                %s, %s, %s, %s, %s::execution_state)
        """,
        (
            execution_id, f"REQUEST-{execution_id}", "1" * 64, "2" * 64,
            "TENANT-TERMINAL", case.task_id, "3" * 64, state,
            "DENY" if state == "DENIED" else "ALLOW",
            "TOOL_NOT_ALLOWED" if state == "DENIED" else "ALLOWED",
            Jsonb({}) if state == "COMMITTED" else None, created_at, created_at,
            terminal_at, terminal_state,
        ),
    )
    return execution_id


def _read_execution(case, execution_id: str):
    return case.connection.execute(
        """
        SELECT state::text, terminal_at, terminal_state::text,
               created_at, updated_at, receipt_status::text
        FROM execution_records WHERE execution_id = %s
        """,
        (execution_id,),
    ).fetchone()


def _transition(case, execution_id: str, state: str) -> None:
    case.connection.execute(
        """
        UPDATE execution_records
        SET state = %s::execution_state, decision = %s::authorization_decision,
            reason_code = %s, result = %s, updated_at = %s
        WHERE execution_id = %s
        """,
        (
            state, "DENY" if state == "DENIED" else "ALLOW",
            "TOOL_NOT_ALLOWED" if state == "DENIED" else "ALLOWED",
            Jsonb({}) if state == "COMMITTED" else None,
            case.created_at + 1, execution_id,
        ),
    )


def _assert_capture(case, execution_id: str, state: str, lower: int, upper: int):
    observed = _read_execution(case, execution_id)
    assert observed is not None
    assert observed[0] == observed[2] == state
    assert type(observed[1]) is int
    assert lower <= observed[1] <= upper
    assert observed[3] <= observed[1] <= MAX_SAFE_INTEGER
    assert observed[4] >= observed[1]
    assert observed[5] == "PENDING"
    return observed


@contextmanager
def _expect_database_rejection(connection) -> Iterator[None]:
    with pytest.raises(Error) as captured:
        with connection.transaction():
            yield
    assert captured.value.sqlstate == "22023"


@pytest.mark.parametrize("state", FINAL_STATES)
def test_insert_final_execution_captures_database_wall_clock(terminal_case, state) -> None:
    case = terminal_case
    lower = _wall_clock(case.connection)
    execution_id = _insert_execution(case, state)
    upper = _wall_clock(case.connection)
    observed = _assert_capture(case, execution_id, state, lower, upper)
    assert observed[1] > case.created_at


@pytest.mark.parametrize("state", NONFINAL_STATES)
def test_nonfinal_insert_does_not_create_a_terminal_time(terminal_case, state) -> None:
    case = terminal_case
    lower = _wall_clock(case.connection)
    execution_id = _insert_execution(case, state)
    upper = _wall_clock(case.connection)
    observed = _read_execution(case, execution_id)
    assert observed is not None
    assert observed[:4] == (state, None, None, case.created_at)
    assert observed[5] == "NOT_REQUIRED"
    if state == "ADMITTED":
        assert lower <= observed[4] <= upper
    else:
        assert observed[4] == case.created_at


@pytest.mark.parametrize("state", FINAL_STATES)
def test_first_update_to_terminal_captures_after_nonfinal_transitions(terminal_case, state) -> None:
    case = terminal_case
    execution_id = _insert_execution(case)
    # Keep the legacy denial path unadmitted so it does not rewrite a captured ALLOW.
    intermediates = ("DISPATCHED", "UNKNOWN", "RECONCILING")
    if state != "DENIED":
        intermediates = ("ADMITTED", *intermediates)
    for intermediate in intermediates:
        lower = _wall_clock(case.connection)
        _transition(case, execution_id, intermediate)
        upper = _wall_clock(case.connection)
        observed = _read_execution(case, execution_id)
        assert observed is not None
        assert observed[:4] == (intermediate, None, None, case.created_at)
        assert observed[5] == "NOT_REQUIRED"
        if intermediate == "ADMITTED":
            assert lower <= observed[4] <= upper
        else:
            assert observed[4] == case.created_at + 1
    lower = _wall_clock(case.connection)
    _transition(case, execution_id, state)
    upper = _wall_clock(case.connection)
    observed = _assert_capture(case, execution_id, state, lower, upper)
    assert observed[1] > case.created_at + 1


@pytest.mark.parametrize("state", FINAL_STATES)
def test_receipt_maintenance_does_not_change_terminal_time_or_state(terminal_case, state) -> None:
    case = terminal_case
    execution_id = _insert_execution(case, state)
    first = _read_execution(case, execution_id)
    assert first is not None
    for index, status in enumerate(("FAILED_RETRYABLE", "PENDING", "SIGNED"), start=1):
        updated_at = first[1] + 600 + index
        case.connection.execute(
            """
            UPDATE execution_records
            SET receipt_status = %s::receipt_status, updated_at = %s, state = state
            WHERE execution_id = %s
            """,
            (status, updated_at, execution_id),
        )
        observed = _read_execution(case, execution_id)
        assert observed is not None
        assert observed[:4] == first[:4]
        assert observed[4:] == (updated_at, status)


@pytest.mark.parametrize("state", ("RECEIVED", *FINAL_STATES))
@pytest.mark.parametrize(("terminal_at", "terminal_state"), [
    (0, None), (None, "COMMITTED"), (0, "COMMITTED"),
])
def test_terminal_fields_cannot_be_supplied_on_insert(
    terminal_case, state, terminal_at, terminal_state,
) -> None:
    case = terminal_case
    with _expect_database_rejection(case.connection):
        _insert_execution(
            case, state, terminal_at=terminal_at, terminal_state=terminal_state,
        )
    assert case.connection.execute(
        "SELECT count(*) FROM execution_records WHERE task_id = %s", (case.task_id,),
    ).fetchone() == (0,)


@pytest.mark.parametrize("assignment", [
    "terminal_at = 0",
    "terminal_state = 'COMMITTED'",
    "terminal_at = 0, terminal_state = 'COMMITTED'",
    "state = 'COMMITTED', terminal_at = 0, terminal_state = 'COMMITTED'",
])
def test_terminal_fields_cannot_be_supplied_on_nonfinal_update(terminal_case, assignment) -> None:
    case = terminal_case
    execution_id = _insert_execution(case)
    before = _read_execution(case, execution_id)
    with _expect_database_rejection(case.connection):
        case.connection.execute(
            sql.SQL("UPDATE execution_records SET {} WHERE execution_id = %s").format(
                sql.SQL(assignment),
            ),
            (execution_id,),
        )
    assert _read_execution(case, execution_id) == before


@pytest.mark.parametrize("state", FINAL_STATES)
@pytest.mark.parametrize("assignment", [
    "terminal_at = terminal_at + 1",
    "terminal_at = NULL",
    "terminal_state = NULL",
    "terminal_at = NULL, terminal_state = NULL",
    "terminal_state = CASE WHEN terminal_state = 'DENIED' THEN 'COMMITTED' "
    "ELSE 'DENIED' END::execution_state",
    "state = CASE WHEN state = 'DENIED' THEN 'COMMITTED' ELSE 'DENIED' END::execution_state",
    "state = 'RECEIVED'",
    "state = 'RECOVERY_FAILED_FINAL'",
])
def test_terminal_fields_and_known_final_state_are_immutable(
    terminal_case, state, assignment,
) -> None:
    case = terminal_case
    execution_id = _insert_execution(case, state)
    before = _read_execution(case, execution_id)
    with _expect_database_rejection(case.connection):
        case.connection.execute(
            sql.SQL("UPDATE execution_records SET {} WHERE execution_id = %s").format(
                sql.SQL(assignment),
            ),
            (execution_id,),
        )
    assert _read_execution(case, execution_id) == before


@pytest.mark.parametrize("state", FINAL_STATES)
def test_terminal_capture_is_discarded_with_transition_rollback(terminal_case, state) -> None:
    case = terminal_case
    execution_id = _insert_execution(case)
    before = _read_execution(case, execution_id)
    with case.connection.transaction(force_rollback=True):
        lower = _wall_clock(case.connection)
        _transition(case, execution_id, state)
        upper = _wall_clock(case.connection)
        _assert_capture(case, execution_id, state, lower, upper)
    assert _read_execution(case, execution_id) == before
    assert before[1:3] == (None, None)


@pytest.mark.parametrize("state", FINAL_STATES)
def test_final_insert_is_visible_inside_transaction_and_absent_after_rollback(
    terminal_case, state,
) -> None:
    case = terminal_case
    with case.connection.transaction(force_rollback=True):
        lower = _wall_clock(case.connection)
        execution_id = _insert_execution(case, state)
        upper = _wall_clock(case.connection)
        _assert_capture(case, execution_id, state, lower, upper)
    assert _read_execution(case, execution_id) is None


def test_database_clock_cannot_capture_before_execution_creation(terminal_case) -> None:
    case = terminal_case
    future_created_at = _wall_clock(case.connection) + 3_600
    with _expect_database_rejection(case.connection):
        _insert_execution(case, "COMMITTED", created_at=future_created_at)
    assert case.connection.execute(
        "SELECT count(*) FROM execution_records WHERE task_id = %s", (case.task_id,),
    ).fetchone() == (0,)


def test_legacy_null_terminal_boundary_is_checked_from_bounded_migration_text() -> None:
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    source = re.sub(r"--[^\n]*", "", source)
    normalized = " ".join(source.split()).lower()
    schema, function = normalized.split("create function capture_execution_terminal_time()", 1)
    function = function.split("$$;", 1)[0]
    assert re.search(r"add column terminal_at bigint\s*,", schema)
    assert re.search(r"add column terminal_state execution_state\s*,", schema)
    assert "(terminal_at is null and terminal_state is null)" in schema
    assert not re.search(
        r"\b(?:update|insert\s+into|delete\s+from)\s+(?:public\.)?execution_records\b",
        source, flags=re.IGNORECASE,
    )
    assert (
        "entering_terminal := new.state in ('denied', 'committed', 'released') "
        "and old.state not in ('denied', 'committed', 'released');"
    ) in function
    guarded = function.split("if entering_terminal then", 1)[1]
    assert "observed_at := floor(extract(epoch from clock_timestamp()))::bigint;" in guarded
    assert "new.terminal_at := observed_at;" in guarded
    assert "new.terminal_state := new.state;" in guarded
    assert len(re.findall(r"\bnew\.terminal_at\s*:=", function)) == 1
    assert len(re.findall(r"\bnew\.terminal_state\s*:=", function)) == 1
    assert "transaction_timestamp()" not in function
