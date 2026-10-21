"""Terminal receipt-recovery behavior using isolated service and client fakes.

All rows and responses are synthetic; fakes only record branches and SQL intent.
They do not establish live transaction, locking, persistence, or signature proof.
"""

from __future__ import annotations

import json
from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import httpx
import pytest

import backend.receipt.client as receipt_client_module
import backend.recovery.service as recovery_module
from backend.common.internal_auth import InternalAuthenticator
from backend.receipt.client import ReceiptClient
from backend.recovery.service import RecoveryService


class FakeConnection:
    def __init__(self, rows=(), row=None) -> None:
        self.rows = rows
        self.row = row
        self.statements: list[tuple[str, tuple[Any, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def transaction(self):
        return nullcontext(self)

    def execute(self, query: str, parameters: tuple[Any, ...]):
        self.statements.append((" ".join(query.split()), parameters))
        return SimpleNamespace(fetchall=lambda: self.rows, fetchone=lambda: self.row)


def _service(monkeypatch: pytest.MonkeyPatch, *, receipt_url="http://receipt.invalid"):
    subject = RecoveryService(
        "unit-only-database", tool_urls={}, receipt_url=receipt_url,
        internal_auth=InternalAuthenticator(
            service_id="recovery-worker", keys_json="{}", required=False,
        ),
    )
    connection = FakeConnection()
    monkeypatch.setattr(recovery_module, "connect", Mock(return_value=connection))
    return subject, connection


def _terminal_row(state: str, receipt_status: str = "PENDING") -> dict[str, Any]:
    decision = "DENY" if state == "DENIED" else "ALLOW"
    return {
        "execution_id": "EXEC-TERMINAL", "state": state, "receipt_status": receipt_status,
        "terminal_at": 100, "terminal_state": state,
        "decision": decision, "decision_at": 80, "decision_value": decision,
    }


@pytest.mark.parametrize("state", ["DENIED", "COMMITTED", "RELEASED"])
@pytest.mark.parametrize("status", ["NOT_REQUIRED", "PENDING", "FAILED_RETRYABLE"])
def test_known_terminal_prepares_receipt_only_without_business_recovery(
    monkeypatch: pytest.MonkeyPatch, state: str, status: str,
) -> None:
    subject, connection = _service(monkeypatch)
    row = _terminal_row(state, status)
    load = Mock(return_value=row)
    monkeypatch.setattr(subject, "_load_execution", load)

    prepared = subject._prepare_execution(execution_id=row["execution_id"], current_time=200)

    assert prepared == {"action": "RECEIPT_ONLY", "execution_id": row["execution_id"]}
    load.assert_called_once_with(connection, row["execution_id"], lock=True)
    assert connection.statements == []
    assert row == _terminal_row(state, status)


@pytest.mark.parametrize("state", ["DENIED", "COMMITTED", "RELEASED"])
@pytest.mark.parametrize("mutation", [
    "signed", "missing-time", "wrong-state", "disabled",
    "missing-decision-at", "missing-decision-value", "null-decision-at",
    "null-decision-value", "null-decision-pair", "wrong-decision-value", "changed-decision",
])
def test_terminal_without_receipt_recovery_eligibility_does_not_invent_a_time(
    monkeypatch: pytest.MonkeyPatch, state: str, mutation: str,
) -> None:
    subject, connection = _service(
        monkeypatch, receipt_url="" if mutation == "disabled" else "http://receipt.invalid",
    )
    row = _terminal_row(state)
    if mutation == "signed":
        row["receipt_status"] = "SIGNED"
    elif mutation == "missing-time":
        row["terminal_at"] = None
        row["terminal_state"] = None
    elif mutation == "wrong-state":
        row["terminal_state"] = "UNKNOWN"
    elif mutation == "missing-decision-at":
        row.pop("decision_at")
    elif mutation == "missing-decision-value":
        row.pop("decision_value")
    elif mutation == "null-decision-at":
        row["decision_at"] = None
    elif mutation == "null-decision-value":
        row["decision_value"] = None
    elif mutation == "null-decision-pair":
        row["decision_at"] = row["decision_value"] = None
    elif mutation in {"wrong-decision-value", "changed-decision"}:
        field = "decision_value" if mutation == "wrong-decision-value" else "decision"
        row[field] = "ALLOW" if state == "DENIED" else "DENY"
    before = deepcopy(row)
    monkeypatch.setattr(subject, "_load_execution", Mock(return_value=row))

    assert subject._prepare_execution(execution_id=row["execution_id"], current_time=200) is None
    assert row == before
    assert connection.statements == []


@pytest.mark.parametrize("state", ["DENIED", "COMMITTED", "RELEASED"])
def test_recover_terminal_receipt_only_never_queries_or_settles_business(
    monkeypatch: pytest.MonkeyPatch, state: str,
) -> None:
    subject, connection = _service(monkeypatch)
    prepare = Mock(return_value={"action": "RECEIPT_ONLY", "execution_id": "EXEC-TERMINAL"})
    body = {"execution_id": "EXEC-TERMINAL", "state": state, "receipt": None}
    receipt_body = {**body, "receipt": {"unit_marker": "signed-response-shape-only"}}
    load = Mock(return_value=body)
    attach = Mock(return_value=receipt_body)
    query = Mock(side_effect=AssertionError("receipt recovery must not query the business tool"))
    settle = Mock(side_effect=AssertionError("receipt recovery must not settle budgets again"))
    monkeypatch.setattr(subject, "_prepare_execution", prepare)
    monkeypatch.setattr(subject, "_execution_claim", lambda execution_id: nullcontext(execution_id))
    monkeypatch.setattr(subject, "_load_decision", load)
    monkeypatch.setattr(subject, "_with_receipt", attach)
    monkeypatch.setattr(subject, "_query_tool", query)
    monkeypatch.setattr(subject, "_settle_reconciliation", settle)

    result = subject.recover_once(execution_id="EXEC-TERMINAL", current_time=200)

    assert result is not None and result.body == receipt_body
    prepare.assert_called_once_with(execution_id="EXEC-TERMINAL", current_time=200)
    load.assert_called_once_with("EXEC-TERMINAL")
    attach.assert_called_once_with(body, 200)
    query.assert_not_called()
    settle.assert_not_called()
    assert connection.statements == []


def test_scan_includes_known_terminal_receipts_but_prioritizes_business_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject, connection = _service(monkeypatch)
    connection.rows = [("EXEC-TERMINAL",)]
    recover = Mock(return_value=None)
    monkeypatch.setattr(subject, "recover_once", recover)

    assert subject.scan_once(current_time=200) == []

    assert len(connection.statements) == 1
    sql, params = connection.statements[0]
    assert "e.receipt_status IN ('NOT_REQUIRED', 'PENDING', 'FAILED_RETRYABLE')" in sql
    assert "e.terminal_at IS NOT NULL AND e.terminal_state = e.state" in sql
    assert "e.decision_at IS NOT NULL AND e.decision_value = e.decision" in sql
    assert (
        "ORDER BY CASE WHEN e.state IN ('DENIED', 'COMMITTED', 'RELEASED') THEN 1 ELSE 0 END"
    ) in sql
    assert params == (170, 170, True)
    recover.assert_called_once_with(execution_id="EXEC-TERMINAL", current_time=200)


@pytest.mark.parametrize("state", ["DENIED", "COMMITTED", "RELEASED"])
@pytest.mark.parametrize("lock", [False, True])
def test_load_execution_appends_decision_pair_after_terminal_pair(
    monkeypatch: pytest.MonkeyPatch, state: str, lock: bool,
) -> None:
    subject, connection = _service(monkeypatch)
    decision = "DENY" if state == "DENIED" else "ALLOW"
    fields = {
        "execution_id": "EXEC-TERMINAL", "request_hash": "1" * 64,
        "credential_chain_hash": "2" * 64, "tenant_id": "TENANT-TERMINAL",
        "task_id": "TASK-TERMINAL", "tool_service": "ticket-service",
        "tool_name": "ticket.read", "tool_version": "v1", "parameter_hash": "3" * 64,
        "state": state, "decision": decision,
        "reason_code": "TOOL_NOT_ALLOWED" if state == "DENIED" else "ALLOWED",
        "business_action_id": None, "result": {} if state == "COMMITTED" else None,
        "business_effect_id": None, "business_result_hash": None, "updated_at": 600,
        "business_idempotency_key": None, "receipt_status": "FAILED_RETRYABLE",
        "terminal_at": 100, "terminal_state": state,
        "decision_at": 80, "decision_value": decision,
    }
    connection.row = tuple(fields.values())

    loaded = subject._load_execution(connection, fields["execution_id"], lock=lock)

    assert loaded == fields
    assert len(connection.statements) == 1
    query, params = connection.statements[0]
    assert (
        "e.terminal_at, e.terminal_state::text, e.decision_at, e.decision_value::text "
        "FROM execution_records e"
    ) in query
    assert ("FOR UPDATE OF e" in query) is lock
    assert params == (fields["execution_id"],)


@pytest.mark.parametrize("state", ["DENIED", "COMMITTED", "RELEASED"])
@pytest.mark.parametrize("entry_time", [0, 10**9])
def test_receipt_query_never_transmits_old_entry_time(
    monkeypatch: pytest.MonkeyPatch, state: str, entry_time: int,
) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert json.loads(request.content) == {"execution_id": "EXEC-TERMINAL"}
        return httpx.Response(200, json={"receipt": {"unit_marker": "not-crypto-proof"}})

    real_client = httpx.Client

    def factory(**kwargs):
        assert kwargs["trust_env"] is False
        return real_client(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(recovery_module.httpx, "Client", factory)
    subject = RecoveryService(
        "unit-only-database", tool_urls={}, receipt_url="http://receipt.invalid",
        internal_auth=InternalAuthenticator(
            service_id="recovery-worker", keys_json="{}", required=False,
        ),
    )
    body = {"execution_id": "EXEC-TERMINAL", "state": state, "receipt": None}

    result = subject._with_receipt(body, entry_time)

    assert result["receipt"] == {"unit_marker": "not-crypto-proof"}
    assert body["receipt"] is None
    assert len(requests) == 1
    assert requests[0].url.path == "/internal/receipts/issue"


def test_gateway_receipt_client_keeps_legacy_keyword_but_not_the_client_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert json.loads(request.content) == {"execution_id": "EXEC-TERMINAL"}
        return httpx.Response(200, json={"receipt": {"unit_marker": "not-crypto-proof"}})

    real_client = httpx.Client
    monkeypatch.setattr(
        receipt_client_module.httpx, "Client",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(handle), **kwargs
        ),
    )
    subject = ReceiptClient(
        "http://receipt.invalid", timeout_seconds=1,
        internal_auth=InternalAuthenticator(
            service_id="secure-gateway", keys_json="{}", required=False,
        ),
    )

    assert subject.issue("EXEC-TERMINAL", current_time=1) == {"unit_marker": "not-crypto-proof"}
    assert len(requests) == 1
