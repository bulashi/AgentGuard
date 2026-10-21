"""Receipt result-binding sources, authored without execution or collection.

Only the selected execution row and budget totals are faked. Signing and failure
persistence are intercepted before key access. Canonical JSON and SM3 references
run only inside test helpers or tests during a future authorized run; these cases
do not establish PostgreSQL aggregation, transaction, or signature correctness.
"""

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

import backend.receipt.service as receipt_module
from backend.common.error_codes import ReasonCode
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.receipt.service import ReceiptError, ReceiptService

DATABASE_URL = "mock-receipt-result-binding-database"
CURRENT_TIME = 200
EXISTING_RECEIPT = ("RECEIPT-RESULT-BINDING", None, "PENDING")
TOOLS = {
    "refund": ("refund-service", "refund.create"),
    "notification": ("notification-service", "notification.send_template"),
    "ticket": ("ticket-service", "ticket.read"),
    "knowledge": ("knowledge-service", "knowledge.read_associated"),
}
EFFECT_FIELDS = {"refund": "refund_id", "notification": "notification_id"}
# Match ReceiptService.issue, including the joined key and both trusted time pairs.
ROW_FIELDS = (
    "execution_id", "request_id", "request_hash", "credential_chain_hash",
    "tenant_id", "task_id", "tool_service", "tool_name", "tool_version", "parameter_hash",
    "state", "decision", "reason_code", "receipt_status", "business_action_id", "result",
    "business_effect_id", "business_result_hash", "created_at", "updated_at",
    "business_idempotency_key", "terminal_at", "terminal_state",
    "decision_at", "decision_value",
)


class FakeCursor:
    def __init__(self, row=None) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, row: tuple[Any, ...], totals: tuple[int, int]) -> None:
        self.row = row
        self.totals = totals
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

    def execute(self, query: str, parameters: tuple[Any, ...]):
        sql = " ".join(query.split())
        self.statements.append((sql, parameters))
        if sql.startswith("SELECT ") and "FROM execution_records e" in sql:
            assert (
                "i.business_idempotency_key, e.terminal_at, e.terminal_state::text, "
                "e.decision_at, e.decision_value::text"
            ) in sql
            return FakeCursor(self.row)
        if sql.startswith("SELECT ") and "FROM execution_receipts" in sql:
            return FakeCursor()
        if sql.startswith("SELECT ") and "FROM execution_budget_reservations" in sql:
            assert "SUM(amount)" in sql
            return FakeCursor(self.totals)
        raise AssertionError(f"unexpected receipt SQL: {sql}")


def _digest(result: dict[str, Any]) -> str:
    return sm3_hex(canonicalize(result))


def _row(kind: str = "refund", **changes: Any) -> tuple[Any, ...]:
    service, tool = TOOLS[kind]
    if kind in EFFECT_FIELDS:
        effect = f"{kind.upper()}-RESULT-BINDING"
        result = {EFFECT_FIELDS[kind]: effect, "status": "SUCCESS", "count": 1}
    else:
        effect = None
        result = {} if kind == "ticket" else {"documents": []}
    fields = {
        "execution_id": "EXEC-RESULT-BINDING", "request_id": "REQUEST-RESULT-BINDING",
        "request_hash": "1" * 64, "credential_chain_hash": "2" * 64,
        "tenant_id": "TENANT-RESULT-BINDING", "task_id": "TASK-RESULT-BINDING",
        "tool_service": service, "tool_name": tool, "tool_version": "v1",
        "parameter_hash": "3" * 64, "state": "COMMITTED", "decision": "ALLOW",
        "reason_code": "ALLOWED", "receipt_status": "PENDING",
        "business_action_id": "ACTION-RESULT-BINDING" if kind in EFFECT_FIELDS else None,
        "result": result, "business_effect_id": effect, "business_result_hash": None,
        "created_at": 100, "updated_at": 150,
        "business_idempotency_key": "c" * 64 if kind in EFFECT_FIELDS else None,
        "terminal_at": 150, "terminal_state": changes.get("state", "COMMITTED"),
        "decision_at": 120,
        "decision_value": "DENY" if changes.get("state") == "DENIED" else "ALLOW",
    }
    fields.update(changes)
    return tuple(fields[field] for field in ROW_FIELDS)


def _noncommitted_row(state: str, **changes: Any) -> tuple[Any, ...]:
    fields = {
        "state": state, "decision": "DENY" if state == "DENIED" else "ALLOW",
        "reason_code": ReasonCode.BUSINESS_ACTION_INVALID.value if state == "DENIED" else "ALLOWED",
        "result": None, "business_effect_id": None, "business_result_hash": None,
    }
    fields.update(changes)
    return _row(**fields)


def _subject(monkeypatch: pytest.MonkeyPatch, row, *, totals=(0, 9)) -> SimpleNamespace:
    connection = FakeConnection(row, totals)
    connect = Mock(return_value=connection)
    monkeypatch.setattr(receipt_module, "connect", connect)
    schemas = Mock(spec=["validate"])
    subject = ReceiptService(
        DATABASE_URL, private_key_file="unused-key-not-read", schemas=schemas,
    )
    sign = Mock(side_effect=AssertionError("invalid receipt must fail before signing"))
    failed = Mock()
    monkeypatch.setattr(subject, "_sign", sign)
    monkeypatch.setattr(subject, "_mark_failed", failed)
    return SimpleNamespace(
        subject=subject, connection=connection, connect=connect,
        sign=sign, failed=failed, schemas=schemas,
    )


def _assert_payload_rejected(monkeypatch, row, *, totals=(0, 9)) -> None:
    assert len(row) == 25 and row[21:23] == (150, row[10])
    assert row[23:] == (120, "DENY" if row[10] == "DENIED" else "ALLOW")
    assert row[18] <= row[23] <= row[21] <= CURRENT_TIME
    case = _subject(monkeypatch, row, totals=totals)

    with pytest.raises(ReceiptError) as captured:
        case.subject._build_payload(case.connection, row, CURRENT_TIME, EXISTING_RECEIPT)

    assert captured.value.reason_code is ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert captured.value.status_code == 409
    assert case.connection.row == row
    assert case.connection.totals == totals
    assert all(sql.startswith("SELECT ") for sql, _params in case.connection.statements)
    assert sum("FROM execution_budget_reservations" in sql
               for sql, _params in case.connection.statements) == 1
    case.connect.assert_not_called()
    case.sign.assert_not_called()
    case.failed.assert_not_called()


def _assert_issue_rejected(monkeypatch, row, *, totals=(0, 9)) -> None:
    assert len(row) == 25 and row[21:23] == (150, row[10])
    assert row[23:] == (120, "DENY" if row[10] == "DENIED" else "ALLOW")
    assert row[18] <= row[23] <= row[21] <= CURRENT_TIME
    case = _subject(monkeypatch, row, totals=totals)

    with pytest.raises(ReceiptError) as captured:
        case.subject.issue(row[0], current_time=CURRENT_TIME)

    assert captured.value.reason_code is ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert captured.value.status_code == 409
    case.connect.assert_called_once_with(DATABASE_URL)
    assert case.connection.entries == case.connection.transactions == 1
    case.sign.assert_not_called()
    case.schemas.validate.assert_not_called()
    case.failed.assert_called_once_with(row[0], CURRENT_TIME)
    assert case.connection.row == row
    assert case.connection.totals == totals
    assert all(sql.startswith("SELECT ") for sql, _params in case.connection.statements)
    assert sum("FROM execution_records e" in sql
               for sql, _params in case.connection.statements) == 1
    assert sum("FROM execution_receipts" in sql
               for sql, _params in case.connection.statements) == 1
    assert sum("FROM execution_budget_reservations" in sql
               for sql, _params in case.connection.statements) == 1


@pytest.mark.parametrize("kind", list(TOOLS))
@pytest.mark.parametrize("stored_hash", ["0" * 64, "A" * 64, "not-a-digest", ""])
def test_committed_stored_digest_must_match_actual_result(monkeypatch, kind, stored_hash) -> None:
    row = _row(kind, business_result_hash=stored_hash)
    assert stored_hash != _digest(row[15])
    _assert_payload_rejected(monkeypatch, row)


@pytest.mark.parametrize("kind", list(TOOLS))
def test_changed_result_cannot_reuse_previous_stored_digest(monkeypatch, kind) -> None:
    original = _row(kind)
    changed = dict(original[15])
    changed["tampered"] = True
    row = _row(kind, result=changed, business_result_hash=_digest(original[15]))
    _assert_payload_rejected(monkeypatch, row)


@pytest.mark.parametrize("kind", list(TOOLS))
@pytest.mark.parametrize("stored_hash", [None, "0" * 64])
def test_committed_null_result_cannot_be_receipted(monkeypatch, kind, stored_hash) -> None:
    _assert_payload_rejected(
        monkeypatch, _row(kind, result=None, business_result_hash=stored_hash),
    )


@pytest.mark.parametrize("result", [[], ["result"], "result", 0, False])
def test_committed_result_must_be_dict_even_with_matching_digest(monkeypatch, result) -> None:
    row = _row(
        "ticket", result=result, business_result_hash=sm3_hex(canonicalize(result)),
    )
    _assert_payload_rejected(monkeypatch, row)


@pytest.mark.parametrize("value", [
    0.0, float("nan"), float("inf"), 2**53, {1: "non-string-key"}, b"unsupported-bytes",
])
@pytest.mark.parametrize("stored_hash", [None, "0" * 64])
def test_committed_noncanonical_result_is_rejected(monkeypatch, value, stored_hash) -> None:
    _assert_payload_rejected(
        monkeypatch, _row("ticket", result={"value": value}, business_result_hash=stored_hash),
    )


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("failure", [
    "missing-effect", "empty-effect", "missing-result-id", "null-result-id",
    "empty-result-id", "both-empty", "different-result-id", "wrong-id-field", "numeric-result-id",
])
def test_committed_side_effect_requires_matching_nonempty_result_id(
    monkeypatch, kind, failure,
) -> None:
    original = _row(kind)
    effect = original[16]
    result = dict(original[15])
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
    _assert_payload_rejected(monkeypatch, _row(
        kind, result=result, business_effect_id=effect, business_result_hash=_digest(result),
    ))


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("field", ["business_action_id", "business_idempotency_key"])
def test_committed_side_effect_rejects_empty_action_or_key(monkeypatch, kind, field) -> None:
    original = _row(kind)
    row = _row(kind, business_result_hash=_digest(original[15]), **{field: ""})
    _assert_payload_rejected(monkeypatch, row)
    _assert_issue_rejected(monkeypatch, row)


@pytest.mark.parametrize("kind", ["ticket", "knowledge"])
@pytest.mark.parametrize("effect", ["EFFECT-UNEXPECTED", ""])
def test_committed_readonly_result_requires_null_effect(monkeypatch, kind, effect) -> None:
    _assert_payload_rejected(monkeypatch, _row(kind, business_effect_id=effect))


@pytest.mark.parametrize("kind", ["ticket", "knowledge"])
@pytest.mark.parametrize("field", ["business_action_id", "business_idempotency_key"])
@pytest.mark.parametrize("empty", [False, True])
def test_committed_readonly_row_requires_null_action_and_key(
    monkeypatch, kind, field, empty,
) -> None:
    value = "" if empty else "ACTION-OTHER" if field == "business_action_id" else "d" * 64
    _assert_payload_rejected(monkeypatch, _row(kind, **{field: value}))


@pytest.mark.parametrize("kind", list(TOOLS))
@pytest.mark.parametrize("missing_hash", [False, True])
def test_committed_valid_result_binds_hash_and_reports_only_committed_budget(
    monkeypatch, kind, missing_hash,
) -> None:
    original = _row(kind)
    expected_hash = _digest(dict(reversed(list(original[15].items()))))
    row = _row(kind, business_result_hash=None if missing_hash else expected_hash)
    case = _subject(monkeypatch, row, totals=(0, 9))

    payload = case.subject._build_payload(case.connection, row, CURRENT_TIME, EXISTING_RECEIPT)

    assert payload["business_result_hash"] == expected_hash
    assert payload["business_effect_id"] == row[16]
    assert payload["execution_id"] == row[0]
    assert payload["receipt_id"] == EXISTING_RECEIPT[0]
    assert payload["decision"] == "ALLOW"
    assert payload["reason_code"] == ReasonCode.ALLOWED.value
    assert payload["budget_reserved"] == 0
    assert payload["budget_committed"] == 9
    case.connect.assert_not_called()
    case.sign.assert_not_called()


@pytest.mark.parametrize("state", ["DENIED", "RELEASED"])
@pytest.mark.parametrize("committed", [1, 250])
def test_noncommitted_final_state_rejects_committed_budget(monkeypatch, state, committed) -> None:
    row = _noncommitted_row(state)
    _assert_payload_rejected(monkeypatch, row, totals=(0, committed))
    _assert_issue_rejected(monkeypatch, row, totals=(0, committed))


@pytest.mark.parametrize("state", ["DENIED", "RELEASED"])
@pytest.mark.parametrize(("field", "value"), [
    ("result", {}),
    ("result", []),
    ("result", False),
    ("result", {"refund_id": "REFUND-RESULT-BINDING"}),
    ("business_effect_id", ""),
    ("business_effect_id", "REFUND-RESULT-BINDING"),
    ("business_result_hash", ""),
    ("business_result_hash", "0" * 64),
])
def test_noncommitted_final_state_rejects_nonnull_result_evidence(
    monkeypatch, state, field, value,
) -> None:
    row = _noncommitted_row(state, **{field: value})
    _assert_payload_rejected(monkeypatch, row, totals=(0, 0))
    _assert_issue_rejected(monkeypatch, row, totals=(0, 0))


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
@pytest.mark.parametrize("reserved", [1, 250])
def test_receipt_final_state_with_unsettled_reservations_is_rejected(
    monkeypatch, state, reserved,
) -> None:
    row = _row() if state == "COMMITTED" else _noncommitted_row(state)
    _assert_payload_rejected(
        monkeypatch, row, totals=(reserved, 9 if state == "COMMITTED" else 0),
    )


@pytest.mark.parametrize("state", ["COMMITTED", "RELEASED", "DENIED"])
def test_budget_totals_query_separates_reserved_and_committed_and_scopes_execution(
    monkeypatch, state,
) -> None:
    row = _row() if state == "COMMITTED" else _noncommitted_row(state)
    case = _subject(monkeypatch, row, totals=(0, 9 if state == "COMMITTED" else 0))

    payload = case.subject._build_payload(case.connection, row, CURRENT_TIME, EXISTING_RECEIPT)

    totals = [(sql, params) for sql, params in case.connection.statements
              if "FROM execution_budget_reservations" in sql]
    assert len(totals) == 1
    sql, params = totals[0]
    assert "COALESCE(SUM(amount) FILTER (WHERE status = 'RESERVED'), 0)" in sql
    assert "COALESCE(SUM(amount) FILTER (WHERE status = 'COMMITTED'), 0)" in sql
    assert "status IN ('RESERVED', 'COMMITTED')" not in sql
    assert "WHERE execution_id = %s" in sql
    assert params == (row[0],)
    assert payload["budget_reserved"] == 0
    assert payload["budget_committed"] == (9 if state == "COMMITTED" else 0)
    if state != "COMMITTED":
        assert payload["business_effect_id"] is None
        assert payload["business_result_hash"] is None
        assert payload["decision"] == ("DENY" if state == "DENIED" else "ALLOW")


@pytest.mark.parametrize("failure", [
    "digest", "null-result", "nonobject-result", "missing-effect", "effect-id",
    "readonly-effect", "readonly-action", "readonly-key",
    "reserved-committed", "reserved-released", "reserved-denied",
])
def test_issue_rejects_invalid_binding_or_reservations_before_signing(monkeypatch, failure) -> None:
    changes = {}
    kind = "ticket" if failure.startswith("readonly-") or failure == "nonobject-result" else "refund"
    totals = (0, 9)
    if failure == "digest":
        changes["business_result_hash"] = "0" * 64
    elif failure == "null-result":
        changes["result"] = None
    elif failure == "nonobject-result":
        changes.update(result=[], business_result_hash=sm3_hex(canonicalize([])))
    elif failure == "missing-effect":
        changes["business_effect_id"] = None
    elif failure in {"effect-id", "readonly-effect"}:
        changes["business_effect_id"] = "EFFECT-OTHER"
    elif failure == "readonly-action":
        changes["business_action_id"] = "ACTION-OTHER"
    elif failure == "readonly-key":
        changes["business_idempotency_key"] = "d" * 64
    else:
        state = failure.removeprefix("reserved-").upper()
        changes["state"] = state
        totals = (1, 9 if state == "COMMITTED" else 0)
        if state != "COMMITTED":
            changes.update(result=None, business_effect_id=None)
        if state == "DENIED":
            changes["decision"] = "DENY"
            changes["reason_code"] = ReasonCode.BUSINESS_ACTION_INVALID.value
    row = _row(kind, **changes)
    _assert_issue_rejected(monkeypatch, row, totals=totals)
