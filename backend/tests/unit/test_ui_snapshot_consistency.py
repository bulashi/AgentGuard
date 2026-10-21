"""Snapshot call-contract tests using mocked connections and projections.

Mocks are not cryptographic or PostgreSQL consistency evidence. These source
cases are authored without running tests, collecting tests, or importing the
project in an interpreter during authoring.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, call

import pytest

import backend.ui_api.store as store_module
from backend.ui_api.store import UiReadStore

DATABASE_URL = "mock-ui-snapshot-database"
TASK_ID = "TASK-SNAPSHOT-MOCK"
SNAPSHOT_TRANSACTION = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
TASK_ROW = (
    TASK_ID,
    "TENANT-MOCK",
    "TICKET-MOCK",
    "CUSTOMER-MOCK",
    1_000,
    4,
    2_000,
    "AUTHORIZED",
    1_000,
    1_001,
)


def _snapshot(
    monkeypatch: pytest.MonkeyPatch,
    *,
    task_exists: bool = True,
    setup_error: Exception | None = None,
    cancellation_rows: list | None = None,
) -> SimpleNamespace:
    connection = MagicMock(
        name="ui-snapshot-connection",
        spec=["__enter__", "__exit__", "execute"],
    )
    active = False

    def enter():
        nonlocal active
        active = True
        return connection

    def exit_context(*_args):
        nonlocal active
        active = False
        return False

    connection.__enter__.side_effect = enter
    connection.__exit__.side_effect = exit_context
    connect = Mock(return_value=connection)
    monkeypatch.setattr(store_module, "connect", connect)

    # Projection-only rows intentionally contain no signed objects or keys.
    credential_rows = [("CREDENTIAL-ROOT-MOCK",), ("CREDENTIAL-LEAF-MOCK",)]
    receipt_rows = [("RECEIPT-MOCK",)]
    rows_by_query = {
        "FROM tasks WHERE task_id = %s": [TASK_ROW] if task_exists else [],
        "FROM credentials c": credential_rows,
        "FROM credential_budget_state b": [
            ("CREDENTIAL-ROOT-MOCK", "TOOL_CALLS", 4, 1, 1, 2),
        ],
        "FROM execution_records WHERE task_id = %s": [],
        "FROM dispatch_cancellations dc": cancellation_rows or [],
        "FROM execution_receipts r": receipt_rows,
        "FROM refunds WHERE task_id = %s": [],
        "FROM notifications WHERE task_id = %s": [],
        "FROM audit_events a": [],
        "FROM agent_workflow_runs WHERE task_id = %s": [
            (
                "RUN-MOCK",
                "deterministic",
                "NORMAL",
                "rules-mock",
                "COMPLETED",
                None,
                1_000,
                2_000,
                3_000,
                2_000,
            ),
        ],
        "FROM agent_workflow_events WHERE run_id = %s": [],
    }
    statements = []

    def execute(sql, params=None):
        assert active, "snapshot SQL must use the active context connection"
        normalized = " ".join(sql.split())
        statements.append((normalized, params))
        if normalized == SNAPSHOT_TRANSACTION:
            if setup_error is not None:
                raise setup_error
            return MagicMock(name="transaction-setup-result")
        matches = [rows for fragment, rows in rows_by_query.items() if fragment in normalized]
        assert len(matches) == 1, f"unexpected snapshot SQL: {normalized}"
        rows = matches[0]
        cursor = MagicMock(name="ui-snapshot-cursor")

        def fetchone():
            assert active, "snapshot rows must be fetched before context exit"
            return rows[0] if rows else None

        def fetchall():
            assert active, "snapshot rows must be fetched before context exit"
            return list(rows)

        cursor.fetchone.side_effect = fetchone
        cursor.fetchall.side_effect = fetchall
        return cursor

    connection.execute.side_effect = execute
    subject = UiReadStore(DATABASE_URL)

    def credential_projection(used_connection, row):
        assert active and used_connection is connection
        return {"credential_id": row[0]}

    def receipt_projection(used_connection, row):
        assert active and used_connection is connection
        return {"receipt_id": row[0]}

    business_context = {"ticket": None, "documents": []}

    def business_projection(used_connection, task):
        assert active and used_connection is connection
        assert task is TASK_ROW
        return business_context

    credential = Mock(side_effect=credential_projection)
    receipt = Mock(side_effect=receipt_projection)
    business = Mock(side_effect=business_projection)
    monkeypatch.setattr(subject, "_credential_projection", credential)
    monkeypatch.setattr(subject, "_receipt_projection", receipt)
    monkeypatch.setattr(subject, "_business_context", business)
    # Keep workflow SQL real (against the mock) and spy on its connection.
    workflow = Mock(wraps=subject._workflow_runs)
    monkeypatch.setattr(subject, "_workflow_runs", workflow)
    return SimpleNamespace(
        subject=subject,
        connection=connection,
        connect=connect,
        statements=statements,
        credential=credential,
        receipt=receipt,
        business=business,
        workflow=workflow,
        business_context=business_context,
        credential_rows=credential_rows,
        receipt_rows=receipt_rows,
    )


def test_snapshot_sets_read_only_repeatable_read_before_first_data_select(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(monkeypatch)

    result = snapshot.subject.task_snapshot(TASK_ID)

    assert result is not None
    assert snapshot.connection.execute.call_args_list[0] == call(SNAPSHOT_TRANSACTION)
    assert snapshot.statements[0] == (SNAPSHOT_TRANSACTION, None)
    task_sql, task_params = snapshot.statements[1]
    assert task_sql.startswith("SELECT ")
    assert "FROM tasks WHERE task_id = %s" in task_sql
    assert task_params == (TASK_ID,)


def test_existing_task_projections_and_helpers_share_one_context_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(monkeypatch)

    result = snapshot.subject.task_snapshot(TASK_ID)

    snapshot.connect.assert_called_once_with(DATABASE_URL)
    snapshot.connection.__enter__.assert_called_once_with()
    snapshot.connection.__exit__.assert_called_once_with(None, None, None)
    assert snapshot.credential.call_args_list == [
        call(snapshot.connection, row) for row in snapshot.credential_rows
    ]
    assert snapshot.receipt.call_args_list == [
        call(snapshot.connection, row) for row in snapshot.receipt_rows
    ]
    snapshot.business.assert_called_once_with(snapshot.connection, TASK_ROW)
    snapshot.workflow.assert_called_once_with(snapshot.connection, TASK_ID)
    assert result is not None
    assert result["task"]["task_id"] == TASK_ID
    assert result["business_context"] is snapshot.business_context
    assert result["workflow_runs"][0]["run_id"] == "RUN-MOCK"
    assert any("FROM agent_workflow_events" in sql for sql, _ in snapshot.statements)
    assert result["credentials"][0]["budgets"][0]["remaining"] == 2


def test_dispatch_cancellation_projection_is_task_bound_in_the_same_read_only_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = {"record_type": "DISPATCH_CANCELLED_V1", "task_id": TASK_ID}
    row = (
        "CANCEL-MOCK",
        "EXEC-MOCK",
        "DENY-MOCK",
        "REQ-MOCK",
        "a" * 64,
        "b" * 64,
        "ANCESTOR_REVOKED",
        1_200,
        evidence,
    )
    snapshot = _snapshot(monkeypatch, cancellation_rows=[row])
    result = snapshot.subject.task_snapshot(TASK_ID)
    statements = [
        (sql, params)
        for sql, params in snapshot.statements
        if "FROM dispatch_cancellations dc" in sql
    ]
    assert len(statements) == 1
    query, parameters = statements[0]
    assert parameters == (TASK_ID,)
    assert "JOIN execution_records e USING (execution_id)" in query
    assert "WHERE e.task_id = %s" in query
    assert snapshot.statements[0] == (SNAPSHOT_TRANSACTION, None)
    snapshot.connect.assert_called_once_with(DATABASE_URL)
    assert result["dispatch_cancellations"] == [
        {
            "cancellation_id": row[0],
            "execution_id": row[1],
            "denial_execution_id": row[2],
            "request_id": row[3],
            "request_hash": row[4],
            "credential_chain_hash": row[5],
            "reason_code": row[6],
            "cancelled_at": row[7],
            "evidence": evidence,
        }
    ]


def test_missing_task_still_sets_snapshot_transaction_and_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(monkeypatch, task_exists=False)

    assert snapshot.subject.task_snapshot(TASK_ID) is None

    snapshot.connect.assert_called_once_with(DATABASE_URL)
    snapshot.connection.__enter__.assert_called_once_with()
    snapshot.connection.__exit__.assert_called_once_with(None, None, None)
    assert snapshot.connection.execute.call_args_list[0] == call(SNAPSHOT_TRANSACTION)
    assert len(snapshot.statements) == 2
    assert snapshot.statements[0] == (SNAPSHOT_TRANSACTION, None)
    assert "FROM tasks WHERE task_id = %s" in snapshot.statements[1][0]
    assert snapshot.statements[1][1] == (TASK_ID,)
    for helper in (snapshot.credential, snapshot.receipt, snapshot.business, snapshot.workflow):
        helper.assert_not_called()


@pytest.mark.parametrize("error_type", [RuntimeError, PermissionError])
def test_snapshot_setup_failure_propagates_without_fallback_reads(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    error = error_type("mock transaction setup rejected")
    snapshot = _snapshot(monkeypatch, setup_error=error)

    with pytest.raises(error_type, match="mock transaction setup rejected") as captured:
        snapshot.subject.task_snapshot(TASK_ID)

    assert captured.value is error
    snapshot.connect.assert_called_once_with(DATABASE_URL)
    snapshot.connection.execute.assert_called_once_with(SNAPSHOT_TRANSACTION)
    assert snapshot.statements == [(SNAPSHOT_TRANSACTION, None)]
    snapshot.connection.__exit__.assert_called_once()
    assert snapshot.connection.__exit__.call_args.args[0] is error_type
    assert snapshot.connection.__exit__.call_args.args[1] is error
    for helper in (snapshot.credential, snapshot.receipt, snapshot.business, snapshot.workflow):
        helper.assert_not_called()


def test_snapshot_recorded_sql_is_select_only_after_transaction_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(monkeypatch)

    snapshot.subject.task_snapshot(TASK_ID)

    assert snapshot.statements[0] == (SNAPSHOT_TRANSACTION, None)
    assert len(snapshot.statements) > 2
    for sql, _params in snapshot.statements[1:]:
        assert sql.startswith("SELECT ")
        assert ";" not in sql, "snapshot must not send stacked SQL statements"
        assert (
            re.search(
                r"\b(?:INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|TRUNCATE|"
                r"COPY|CALL|DO|GRANT|REVOKE|LOCK|VACUUM)\b",
                sql,
                flags=re.IGNORECASE,
            )
            is None
        )
