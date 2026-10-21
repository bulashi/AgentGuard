"""Native PostgreSQL authorization-decision-time sources, authored without execution.

The database cases use only the explicitly supplied AgentGuard database URL when
a future authorized run opts in. Each case creates synthetic task and execution
rows inside a force-rollback transaction. No actor configuration, key material,
service, browser, Docker marker, receipt endpoint, or project config is read.

Existing decisions remain unobserved. The migration text boundary below checks
that the new nullable pair is not backfilled from created_at or another column.
These are trigger cases, not Admission-service or receipt issuance evidence.
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

from backend.state.database import connect

pytestmark = pytest.mark.integration

MAX_SAFE_INTEGER = 9_007_199_254_740_991
DECISION_CASES = (("ADMITTED", "ALLOW"), ("DENIED", "DENY"))
NON_DECISION_STATES = (
    "RECEIVED", "DISPATCHED", "UNKNOWN", "RECONCILING",
    "COMMITTED", "RELEASED", "RECOVERY_FAILED_FINAL",
)
_UNSET_DECISION = object()
MIGRATION_PATH = (
    Path(__file__).resolve().parents[3]
    / "database" / "migrations" / "main" / "0018_execution_decision_time.sql"
)


def _wall_clock(connection) -> int:
    row = connection.execute(
        "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
    ).fetchone()
    assert row is not None
    return int(row[0])


@pytest.fixture
def decision_case() -> Iterator[SimpleNamespace]:
    database_url = os.environ.get("AGENTGUARD_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_DATABASE_URL is not configured")
    suffix = uuid4().hex
    task_id = f"TASK-DECISION-{suffix}"
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
                    task_id, "TENANT-DECISION", "TICKET-DECISION", "CUSTOMER-DECISION",
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
    decision=_UNSET_DECISION,
    decision_at: int | None = None,
    decision_value: str | None = None,
    created_at: int | None = None,
) -> str:
    execution_id = f"EXEC-DECISION-{uuid4().hex}"
    created_at = case.created_at if created_at is None else created_at
    if decision is _UNSET_DECISION:
        decision = "DENY" if state == "DENIED" else "ALLOW"
    case.connection.execute(
        """
        INSERT INTO execution_records (
            execution_id, initial_request_id, request_hash, credential_chain_hash,
            tenant_id, task_id, tool_service, tool_name, tool_version, parameter_hash,
            state, decision, reason_code, receipt_status, result, created_at, updated_at,
            decision_at, decision_value
        )
        VALUES (%s, %s, %s, %s, %s, %s, 'ticket-service', 'ticket.read', 'v1', %s,
                %s::execution_state, %s::authorization_decision, %s, 'NOT_REQUIRED',
                %s, %s, %s, %s, %s::authorization_decision)
        """,
        (
            execution_id, f"REQUEST-{execution_id}", "1" * 64, "2" * 64,
            "TENANT-DECISION", case.task_id, "3" * 64, state, decision,
            "TOOL_NOT_ALLOWED" if decision == "DENY" else "ALLOWED",
            None, created_at, created_at, decision_at, decision_value,
        ),
    )
    return execution_id


def _read_execution(case, execution_id: str):
    return case.connection.execute(
        """
        SELECT state::text, decision::text, decision_at, decision_value::text,
               terminal_at, terminal_state::text, created_at, updated_at,
               receipt_status::text
        FROM execution_records WHERE execution_id = %s
        """,
        (execution_id,),
    ).fetchone()


def _transition(case, execution_id: str, state: str) -> None:
    decision = "DENY" if state == "DENIED" else "ALLOW"
    case.connection.execute(
        """
        UPDATE execution_records
        SET state = %s::execution_state, decision = %s::authorization_decision,
            reason_code = %s, result = %s, updated_at = %s
        WHERE execution_id = %s
        """,
        (
            state, decision, "TOOL_NOT_ALLOWED" if state == "DENIED" else "ALLOWED",
            None, case.created_at + 1, execution_id,
        ),
    )


def _assert_decision_capture(
    case, execution_id: str, state: str, decision: str, lower: int, upper: int,
):
    observed = _read_execution(case, execution_id)
    assert observed is not None
    assert observed[0:2] == (state, decision)
    assert type(observed[2]) is int
    assert observed[3] == decision
    assert lower <= observed[2] <= upper
    assert observed[6] <= observed[2] <= observed[7] <= MAX_SAFE_INTEGER
    if observed[4] is not None:
        assert observed[2] <= observed[4]
        assert observed[5] == state
    return observed


@contextmanager
def _expect_database_rejection(connection) -> Iterator[None]:
    with pytest.raises(Error) as captured:
        with connection.transaction():
            yield
    assert captured.value.sqlstate == "22023"


@pytest.mark.parametrize(("state", "decision"), DECISION_CASES)
def test_insert_admission_or_denial_captures_database_decision_clock(
    decision_case, state, decision,
) -> None:
    case = decision_case
    lower = _wall_clock(case.connection)
    execution_id = _insert_execution(case, state, decision=decision)
    upper = _wall_clock(case.connection)

    observed = _assert_decision_capture(case, execution_id, state, decision, lower, upper)
    assert observed[2] > case.created_at
    if state == "ADMITTED":
        assert observed[4:6] == (None, None)
    else:
        assert type(observed[4]) is int
        assert observed[5] == state


@pytest.mark.parametrize(("state", "decision"), DECISION_CASES)
def test_received_transition_captures_first_decision_clock(
    decision_case, state, decision,
) -> None:
    case = decision_case
    execution_id = _insert_execution(case, decision="DENY" if decision == "ALLOW" else "ALLOW")
    before = _read_execution(case, execution_id)
    assert before is not None
    assert before[2:4] == (None, None)

    lower = _wall_clock(case.connection)
    _transition(case, execution_id, state)
    upper = _wall_clock(case.connection)

    observed = _assert_decision_capture(case, execution_id, state, decision, lower, upper)
    assert observed[2] > case.created_at


@pytest.mark.parametrize("state", NON_DECISION_STATES)
@pytest.mark.parametrize("transition", [False, True])
def test_non_admission_state_does_not_invent_decision_source(
    decision_case, state, transition,
) -> None:
    case = decision_case
    execution_id = _insert_execution(case, "RECEIVED" if transition else state)
    if transition:
        _transition(case, execution_id, state)
    observed = _read_execution(case, execution_id)
    assert observed is not None
    assert observed[0] == state
    assert observed[2:4] == (None, None)


@pytest.mark.parametrize("terminal_state", ["DENIED", "COMMITTED", "RELEASED"])
def test_decision_pair_survives_maintenance_retry_and_terminal_transition(
    decision_case, terminal_state,
) -> None:
    case = decision_case
    execution_id = _insert_execution(case)
    state = "DENIED" if terminal_state == "DENIED" else "ADMITTED"
    decision = "DENY" if terminal_state == "DENIED" else "ALLOW"
    lower = _wall_clock(case.connection)
    _transition(case, execution_id, state)
    upper = _wall_clock(case.connection)
    first = _assert_decision_capture(case, execution_id, state, decision, lower, upper)
    decision_pair = first[2:4]

    for status in ("PENDING", "FAILED_RETRYABLE", "PENDING"):
        case.connection.execute(
            """
            UPDATE execution_records
            SET receipt_status = %s::receipt_status, updated_at = %s
            WHERE execution_id = %s
            """,
            (status, first[7] + 600, execution_id),
        )
        maintained = _read_execution(case, execution_id)
        assert maintained is not None
        assert maintained[2:4] == decision_pair
        assert maintained[0] == state
        assert maintained[4:6] == first[4:6]

    if terminal_state == "DENIED":
        return
    for intermediate in ("DISPATCHED", "UNKNOWN", "RECONCILING", "UNKNOWN", "RECONCILING"):
        _transition(case, execution_id, intermediate)
        retried = _read_execution(case, execution_id)
        assert retried is not None
        assert retried[2:4] == decision_pair
        assert retried[0] == intermediate
        assert retried[4:6] == (None, None)

    terminal_lower = _wall_clock(case.connection)
    _transition(case, execution_id, terminal_state)
    terminal_upper = _wall_clock(case.connection)
    terminal = _read_execution(case, execution_id)
    assert terminal is not None
    assert terminal[0:2] == (terminal_state, "ALLOW")
    assert terminal[2:4] == decision_pair
    assert type(terminal[4]) is int
    assert terminal[5] == terminal_state
    assert terminal_lower <= terminal[4] <= terminal_upper
    assert terminal[2] <= terminal[4]
    case.connection.execute(
        """
        UPDATE execution_records
        SET receipt_status = 'SIGNED', updated_at = %s
        WHERE execution_id = %s
        """,
        (terminal[4] + 600, execution_id),
    )
    maintained = _read_execution(case, execution_id)
    assert maintained is not None
    assert maintained[:7] == terminal[:7]
    assert maintained[8] == "SIGNED"


@pytest.mark.parametrize("state", ["RECEIVED", "ADMITTED", "DENIED"])
@pytest.mark.parametrize(("decision_at", "decision_value"), [
    (0, None), (None, "ALLOW"), (0, "ALLOW"),
])
def test_decision_fields_cannot_be_supplied_on_insert(
    decision_case, state, decision_at, decision_value,
) -> None:
    case = decision_case
    with _expect_database_rejection(case.connection):
        _insert_execution(
            case, state, decision="DENY" if state == "DENIED" else "ALLOW",
            decision_at=decision_at, decision_value=decision_value,
        )
    assert case.connection.execute(
        "SELECT count(*) FROM execution_records WHERE task_id = %s", (case.task_id,),
    ).fetchone() == (0,)


@pytest.mark.parametrize("assignment", [
    "decision_at = 0",
    "decision_value = 'ALLOW'",
    "decision_at = 0, decision_value = 'ALLOW'",
    "state = 'ADMITTED', decision = 'ALLOW', decision_at = 0, decision_value = 'ALLOW'",
])
def test_decision_fields_cannot_be_supplied_on_received_update(decision_case, assignment) -> None:
    case = decision_case
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


@pytest.mark.parametrize(("state", "decision"), DECISION_CASES)
@pytest.mark.parametrize("assignment", [
    "decision_at = decision_at + 1",
    "decision_at = NULL",
    "decision_value = NULL",
    "decision_at = NULL, decision_value = NULL",
    "decision_value = CASE WHEN decision_value = 'ALLOW' THEN 'DENY' "
    "ELSE 'ALLOW' END::authorization_decision",
    "decision = CASE WHEN decision = 'ALLOW' THEN 'DENY' "
    "ELSE 'ALLOW' END::authorization_decision",
    "decision = NULL",
])
def test_captured_decision_pair_and_decision_cannot_be_changed_or_cleared(
    decision_case, state, decision, assignment,
) -> None:
    case = decision_case
    execution_id = _insert_execution(case)
    _transition(case, execution_id, state)
    before = _read_execution(case, execution_id)
    assert before is not None
    assert type(before[2]) is int and before[3] == decision

    with _expect_database_rejection(case.connection):
        case.connection.execute(
            sql.SQL("UPDATE execution_records SET {} WHERE execution_id = %s").format(
                sql.SQL(assignment),
            ),
            (execution_id,),
        )
    assert _read_execution(case, execution_id) == before


@pytest.mark.parametrize(("state", "decision"), [
    ("ADMITTED", "DENY"), ("DENIED", "ALLOW"), ("ADMITTED", None), ("DENIED", None),
])
@pytest.mark.parametrize("transition", [False, True])
def test_admission_state_requires_matching_nonnull_decision(
    decision_case, state, decision, transition,
) -> None:
    case = decision_case
    execution_id = _insert_execution(case) if transition else None
    before = _read_execution(case, execution_id) if execution_id is not None else None
    with _expect_database_rejection(case.connection):
        if transition:
            case.connection.execute(
                """
                UPDATE execution_records
                SET state = %s::execution_state, decision = %s::authorization_decision
                WHERE execution_id = %s
                """,
                (state, decision, execution_id),
            )
        else:
            _insert_execution(case, state, decision=decision)
    if transition:
        assert _read_execution(case, execution_id) == before
    else:
        assert case.connection.execute(
            "SELECT count(*) FROM execution_records WHERE task_id = %s", (case.task_id,),
        ).fetchone() == (0,)


@pytest.mark.parametrize(("state", "decision"), DECISION_CASES)
def test_decision_capture_is_discarded_with_transition_rollback(
    decision_case, state, decision,
) -> None:
    case = decision_case
    execution_id = _insert_execution(case)
    before = _read_execution(case, execution_id)
    assert before is not None and before[2:4] == (None, None)

    with case.connection.transaction(force_rollback=True):
        lower = _wall_clock(case.connection)
        _transition(case, execution_id, state)
        upper = _wall_clock(case.connection)
        _assert_decision_capture(case, execution_id, state, decision, lower, upper)

    assert _read_execution(case, execution_id) == before
    assert before[2:4] == (None, None)


@pytest.mark.parametrize(("state", "decision"), DECISION_CASES)
@pytest.mark.parametrize("transition", [False, True])
def test_database_clock_cannot_capture_before_execution_creation(
    decision_case, state, decision, transition,
) -> None:
    case = decision_case
    future_created_at = _wall_clock(case.connection) + 3_600
    execution_id = (
        _insert_execution(case, created_at=future_created_at) if transition else None
    )
    before = _read_execution(case, execution_id) if execution_id is not None else None
    with _expect_database_rejection(case.connection):
        if transition:
            _transition(
                SimpleNamespace(connection=case.connection, created_at=future_created_at),
                execution_id, state,
            )
        else:
            _insert_execution(case, state, decision=decision, created_at=future_created_at)
    if transition:
        assert _read_execution(case, execution_id) == before
    else:
        assert case.connection.execute(
            "SELECT count(*) FROM execution_records WHERE task_id = %s", (case.task_id,),
        ).fetchone() == (0,)


def test_legacy_null_decision_boundary_is_checked_from_bounded_migration_text() -> None:
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    source = re.sub(r"--[^\n]*", "", source)
    normalized = " ".join(source.split()).lower()
    schema, function = normalized.split(
        "create function capture_execution_decision_time()", 1,
    )
    function = function.split("$$;", 1)[0]
    assert re.search(r"add column decision_at bigint\s*,", schema)
    assert re.search(r"add column decision_value authorization_decision\s*,", schema)
    assert "(decision_at is null and decision_value is null)" in schema
    assert "decision_at between created_at and 9007199254740991" in schema
    assert "decision is not null" in schema
    assert "decision_value = decision" in schema
    assert "(terminal_at is null or decision_at <= terminal_at)" in schema
    assert not re.search(
        r"\b(?:update|insert\s+into|delete\s+from)\s+(?:public\.)?execution_records\b",
        source, flags=re.IGNORECASE,
    )
    assert "if tg_op = 'insert' then" in function
    assert "old.state = 'received'" in function
    guarded = function.split("if entering_decision then", 1)[1]
    assert "observed_at := floor(extract(epoch from clock_timestamp()))::bigint;" in guarded
    assert "new.decision_at := observed_at;" in guarded
    assert "new.decision_value := new.decision;" in guarded
    assert "observed_at < new.created_at or observed_at > 9007199254740991" in guarded
    assert len(re.findall(r"\bnew\.decision_at\s*:=", function)) == 1
    assert len(re.findall(r"\bnew\.decision_value\s*:=", function)) == 1
    assert "transaction_timestamp()" not in function
