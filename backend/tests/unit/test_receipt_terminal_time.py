"""Terminal-time regression sources, authored without execution or collection.

Rows, connections, clocks, key resolution, key reads, and signatures are fakes.
Schema validation is intercepted. These cases exercise receipt routing and SQL
arguments during a future authorized run, not durable PostgreSQL behavior or
cryptographic validity. No actor configuration or actual private key is used.
Decision and terminal instants are separate from creation and maintenance clocks.
"""

from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

import backend.receipt.service as receipt_module
from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.crypto.domains import EXECUTION_RECEIPT
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.receipt.service import ReceiptError, ReceiptService

DATABASE_URL = "mock-receipt-terminal-time-database"
CREATED_AT = 100
DECISION_AT = 120
TERMINAL_AT = 150
ENTRY_TIME = 200
SIGNING_TIME = 700
KEY_ID = "receipt-terminal-time-key"
PRIVATE_KEY_FIXTURE = "fixture-only-not-a-private-key"
EXISTING_RECEIPT = ("RECEIPT-TERMINAL-TIME", None, "PENDING")
FINAL_STATES = ("DENIED", "COMMITTED", "RELEASED")
# Keep the selected row order explicit, appending decision columns after terminal columns.
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


class RecordingConnection:
    def __init__(self, row: tuple[Any, ...], existing=None) -> None:
        self.row = row
        self.existing = existing
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
            assert "FOR UPDATE OF e" in sql
            return FakeCursor(self.row)
        if sql.startswith("SELECT ") and "FROM execution_receipts" in sql:
            return FakeCursor(self.existing)
        if sql.startswith("SELECT ") and "FROM execution_budget_reservations" in sql:
            return FakeCursor((0, 0))
        if sql.startswith((
            "UPDATE execution_records ", "INSERT INTO execution_receipts ",
            "UPDATE execution_receipts ", "INSERT INTO audit_outbox ",
        )):
            return FakeCursor()
        raise AssertionError(f"unexpected receipt SQL: {sql}")


@pytest.fixture(autouse=True)
def forbid_live_io(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("connect", "Path", "now_unix", "sign_payload"):
        monkeypatch.setattr(
            receipt_module, name,
            Mock(side_effect=AssertionError(f"unit source must fake {name}")),
        )
    monkeypatch.setattr(
        receipt_module.PostgresKeyRegistry, "resolve_for_signing_with_connection",
        Mock(side_effect=AssertionError("unit source must fake receipt key resolution")),
    )


def _row(state: str = "COMMITTED", **changes: Any) -> tuple[Any, ...]:
    fields = {
        "execution_id": "EXEC-TERMINAL-TIME", "request_id": "REQUEST-TERMINAL-TIME",
        "request_hash": "1" * 64, "credential_chain_hash": "2" * 64,
        "tenant_id": "TENANT-TERMINAL-TIME", "task_id": "TASK-TERMINAL-TIME",
        "tool_service": "ticket-service", "tool_name": "ticket.read", "tool_version": "v1",
        "parameter_hash": "3" * 64, "state": state,
        "decision": "DENY" if state == "DENIED" else "ALLOW",
        "reason_code": "TOOL_NOT_ALLOWED" if state == "DENIED" else "ALLOWED",
        "receipt_status": "PENDING", "business_action_id": None,
        "result": {} if state == "COMMITTED" else None,
        "business_effect_id": None, "business_result_hash": None,
        "created_at": CREATED_AT, "updated_at": TERMINAL_AT,
        "business_idempotency_key": None, "terminal_at": TERMINAL_AT,
        "terminal_state": state,
        "decision_at": DECISION_AT,
        "decision_value": "DENY" if state == "DENIED" else "ALLOW",
    }
    fields.update(changes)
    return tuple(fields[field] for field in ROW_FIELDS)


def _subject(monkeypatch: pytest.MonkeyPatch, row, *, existing=None) -> SimpleNamespace:
    connection = RecordingConnection(row, existing)
    connect = Mock(return_value=connection)
    monkeypatch.setattr(receipt_module, "connect", connect)
    schemas = Mock(spec=["validate"])
    subject = ReceiptService(
        DATABASE_URL, private_key_file="unused-terminal-time-key",
        key_id=KEY_ID, schemas=schemas,
    )
    failed = Mock()
    monkeypatch.setattr(subject, "_mark_failed", failed)
    return SimpleNamespace(
        subject=subject, connection=connection, connect=connect, schemas=schemas, failed=failed,
    )


def _signing_fakes(monkeypatch: pytest.MonkeyPatch, signed_at=SIGNING_TIME) -> SimpleNamespace:
    events: list[str] = []
    signed_payloads: list[dict[str, Any]] = []
    key = SimpleNamespace(
        key_id=KEY_ID, purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
        public_key_hex="fixture-only-not-a-public-key",
    )
    key_path = Mock(spec=["read_text"])
    key_path.read_text.return_value = f" {PRIVATE_KEY_FIXTURE}\n"
    path = Mock(return_value=key_path)

    def resolve(*_args, **_kwargs):
        events.append("resolve-key")
        return key

    def clock():
        events.append("signing-clock")
        return signed_at

    def sign(payload, **kwargs):
        events.append("sign")
        signed_payloads.append(deepcopy(payload))
        return {"signed_at": kwargs["signed_at"], "value": "fixture-only-signature"}

    resolver = Mock(side_effect=resolve)
    now = Mock(side_effect=clock)
    signer = Mock(side_effect=sign)
    monkeypatch.setattr(receipt_module, "Path", path)
    monkeypatch.setattr(
        receipt_module.PostgresKeyRegistry, "resolve_for_signing_with_connection", resolver,
    )
    monkeypatch.setattr(receipt_module, "now_unix", now)
    monkeypatch.setattr(receipt_module, "sign_payload", signer)
    return SimpleNamespace(
        events=events, key=key, key_path=key_path, path=path, resolver=resolver,
        now=now, signer=signer, signed_payloads=signed_payloads,
    )


def _assert_time_rejected(monkeypatch, row, *, timestamp=ENTRY_TIME) -> None:
    case = _subject(monkeypatch, row)
    sign = Mock(side_effect=AssertionError("untrusted execution times must fail before _sign"))
    monkeypatch.setattr(case.subject, "_sign", sign)

    with pytest.raises(ReceiptError) as built:
        case.subject._build_payload(case.connection, row, timestamp, EXISTING_RECEIPT)
    assert built.value.reason_code is ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert built.value.status_code == 409
    assert case.connection.statements == []
    case.connect.assert_not_called()
    case.failed.assert_not_called()

    with pytest.raises(ReceiptError) as issued:
        case.subject.issue(row[0], current_time=timestamp)
    assert issued.value.reason_code is ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert issued.value.status_code == 409
    assert case.connection.entries == case.connection.transactions == 1
    assert len(case.connection.statements) == 2
    assert all(sql.startswith("SELECT ") for sql, _params in case.connection.statements)
    case.connect.assert_called_once_with(DATABASE_URL)
    case.failed.assert_called_once_with(row[0], timestamp)
    case.schemas.validate.assert_not_called()
    sign.assert_not_called()


@pytest.mark.parametrize("state", FINAL_STATES)
@pytest.mark.parametrize(("updated_at", "receipt_status"), [
    (ENTRY_TIME, "PENDING"), (600, "FAILED_RETRYABLE"), (5_000, "PENDING"),
])
def test_terminal_times_are_stable_under_receipt_maintenance(
    monkeypatch, state, updated_at, receipt_status,
) -> None:
    original = _row(state)
    maintained = _row(state, updated_at=updated_at, receipt_status=receipt_status)
    case = _subject(monkeypatch, maintained)
    first = case.subject._build_payload(
        case.connection, original, ENTRY_TIME, EXISTING_RECEIPT,
    )
    later = case.subject._build_payload(
        case.connection, maintained, SIGNING_TIME, EXISTING_RECEIPT,
    )

    assert len(maintained) == 25 and maintained[21:23] == (TERMINAL_AT, state)
    assert maintained[23:] == (DECISION_AT, "DENY" if state == "DENIED" else "ALLOW")
    assert later == first | {"receipt_issued_at": SIGNING_TIME}
    assert later["started_at"] == CREATED_AT
    assert later["decision_at"] == DECISION_AT
    assert later["finished_at"] == TERMINAL_AT
    if state == "DENIED":
        assert later["decision"] == "DENY"
        assert later["receipt_type"] == "AUTHORIZATION_DENIAL"
        assert later["business_effect_finalized_at"] is None
        assert later["business_effect_id"] is later["business_result_hash"] is None
        assert later["budget_reserved"] == later["budget_committed"] == 0
    else:
        assert later["business_effect_finalized_at"] == TERMINAL_AT
    case.connect.assert_not_called()
    case.failed.assert_not_called()


@pytest.mark.parametrize("state", FINAL_STATES)
@pytest.mark.parametrize("column_count", [21, 22])
def test_old_short_rows_without_trusted_terminal_pair_are_not_signed(
    monkeypatch, state, column_count,
) -> None:
    _assert_time_rejected(monkeypatch, _row(state)[:column_count])


@pytest.mark.parametrize("state", FINAL_STATES)
@pytest.mark.parametrize("column_count", [23, 24])
def test_short_rows_without_trusted_decision_pair_are_not_signed(
    monkeypatch, state, column_count,
) -> None:
    _assert_time_rejected(monkeypatch, _row(state)[:column_count])


@pytest.mark.parametrize("state", FINAL_STATES)
@pytest.mark.parametrize("changes", [
    {"decision_at": None},
    {"decision_value": None},
    {"decision_at": None, "decision_value": None},
    {"decision_at": False},
    {"decision_at": True},
    {"decision_at": 120.0},
    {"decision_at": "120"},
    {"decision_at": []},
    {"decision_at": {}},
    {"decision_at": -1},
    {"decision_at": CREATED_AT - 1},
    {"decision_at": TERMINAL_AT + 1},
    {"decision_at": MAX_SAFE_INTEGER + 1},
    {"decision_value": False},
    {"decision_value": True},
    {"decision_value": 1},
    {"decision_value": ""},
    {"decision_value": []},
    {"decision_value": {}},
])
def test_final_rows_require_an_exact_complete_ordered_decision_pair(
    monkeypatch, state, changes,
) -> None:
    if type(changes.get("decision_at")) is bool:
        changes = {"created_at": 0, "terminal_at": 1, **changes}
    _assert_time_rejected(monkeypatch, _row(state, **changes))


@pytest.mark.parametrize("state", FINAL_STATES)
@pytest.mark.parametrize("field", ["decision", "decision_value"])
def test_decision_and_captured_value_must_match_receipt_final_state(
    monkeypatch, state, field,
) -> None:
    value = "ALLOW" if state == "DENIED" else "DENY"
    _assert_time_rejected(monkeypatch, _row(state, **{field: value}))


@pytest.mark.parametrize("state", FINAL_STATES)
def test_payload_binds_decision_after_creation_before_terminal(monkeypatch, state) -> None:
    row = _row(state, updated_at=5_000)
    case = _subject(monkeypatch, row)

    payload = case.subject._build_payload(case.connection, row, ENTRY_TIME, EXISTING_RECEIPT)

    assert payload["started_at"] == row[18] == CREATED_AT
    assert payload["decision_at"] == row[23] == DECISION_AT
    assert payload["finished_at"] == row[21] == TERMINAL_AT
    assert payload["decision"] == row[24] == ("DENY" if state == "DENIED" else "ALLOW")
    assert payload["started_at"] < payload["decision_at"] < payload["finished_at"]
    assert payload["finished_at"] <= payload["receipt_issued_at"] == ENTRY_TIME
    case.connect.assert_not_called()
    case.failed.assert_not_called()


@pytest.mark.parametrize("state", FINAL_STATES)
@pytest.mark.parametrize("missing", ["time", "state", "both", "mismatch"])
def test_final_rows_require_a_complete_matching_trusted_terminal_pair(
    monkeypatch, state, missing,
) -> None:
    changes = {}
    if missing in {"time", "both"}:
        changes["terminal_at"] = None
    if missing in {"state", "both"}:
        changes["terminal_state"] = None
    if missing == "mismatch":
        changes["terminal_state"] = "COMMITTED" if state == "DENIED" else "DENIED"
    _assert_time_rejected(monkeypatch, _row(state, **changes))


@pytest.mark.parametrize("changes", [
    {"created_at": 0, "decision_at": 0, "terminal_at": False},
    {"created_at": 0, "decision_at": 0, "terminal_at": True},
    {"terminal_at": 150.0},
    {"terminal_at": "150"},
    {"terminal_at": -1},
    {"created_at": TERMINAL_AT + 1},
    {"terminal_at": ENTRY_TIME + 1},
    {"terminal_at": MAX_SAFE_INTEGER + 1},
])
def test_trusted_terminal_time_must_be_an_exact_safe_ordered_integer(monkeypatch, changes) -> None:
    _assert_time_rejected(monkeypatch, _row(**changes))


@pytest.mark.parametrize("timestamp", [False, True, 200.0, "200", 149, MAX_SAFE_INTEGER + 1])
def test_initial_receipt_clock_must_be_exact_safe_and_not_before_terminal(
    monkeypatch, timestamp,
) -> None:
    row = _row(created_at=0, decision_at=0, terminal_at=0) if type(timestamp) is bool else _row()
    _assert_time_rejected(monkeypatch, row, timestamp=timestamp)


@pytest.mark.parametrize(("created_at", "decision_at", "terminal_at", "timestamp"), [
    (0, 0, 0, 0),
    (CREATED_AT, CREATED_AT, CREATED_AT, CREATED_AT),
    (CREATED_AT, DECISION_AT, TERMINAL_AT, TERMINAL_AT),
    (CREATED_AT, TERMINAL_AT, TERMINAL_AT, ENTRY_TIME),
    (MAX_SAFE_INTEGER - 2, MAX_SAFE_INTEGER - 1, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER),
])
def test_payload_time_order_allows_equal_and_safe_upper_boundaries(
    monkeypatch, created_at, decision_at, terminal_at, timestamp,
) -> None:
    row = _row(
        created_at=created_at, decision_at=decision_at,
        updated_at=terminal_at, terminal_at=terminal_at,
    )
    case = _subject(monkeypatch, row)
    payload = case.subject._build_payload(case.connection, row, timestamp, EXISTING_RECEIPT)
    assert payload["started_at"] == created_at
    assert payload["decision_at"] == decision_at
    assert payload["finished_at"] == payload["business_effect_finalized_at"] == terminal_at
    assert payload["receipt_issued_at"] == timestamp


@pytest.mark.parametrize("initial_time", [ENTRY_TIME, 5_000])
def test_sign_uses_service_clock_after_locked_key_resolution(monkeypatch, initial_time) -> None:
    row = _row(updated_at=600)
    case = _subject(monkeypatch, row)
    payload = case.subject._build_payload(case.connection, row, initial_time, EXISTING_RECEIPT)
    before = deepcopy(payload)
    fakes = _signing_fakes(monkeypatch)

    signed = case.subject._sign(payload, case.connection)

    assert fakes.events == ["resolve-key", "signing-clock", "sign"]
    fakes.path.assert_called_once_with("unused-terminal-time-key")
    fakes.key_path.read_text.assert_called_once_with(encoding="ascii")
    fakes.resolver.assert_called_once_with(
        case.connection, KEY_ID, expected_subject_id="receipt-service",
        expected_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING, lock=True,
    )
    fakes.now.assert_called_once_with()
    assert payload == before | {"receipt_issued_at": SIGNING_TIME}
    assert fakes.signed_payloads == [payload]
    assert signed["payload"] == payload
    assert signed["signature"]["signed_at"] == SIGNING_TIME
    fakes.signer.assert_called_once_with(
        payload, domain_separator=EXECUTION_RECEIPT, key_id=KEY_ID,
        key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
        private_key_hex=PRIVATE_KEY_FIXTURE, public_key_hex=fakes.key.public_key_hex,
        signed_at=SIGNING_TIME,
    )


@pytest.mark.parametrize(("signed_at", "terminal_at"), [
    (TERMINAL_AT - 1, TERMINAL_AT),
    (False, 0), (True, 0), (150.0, TERMINAL_AT), ("700", TERMINAL_AT),
    (-1, 0), (MAX_SAFE_INTEGER + 1, TERMINAL_AT),
])
def test_sign_rejects_an_untrusted_or_regressed_service_clock(
    monkeypatch, signed_at, terminal_at,
) -> None:
    row = _row(created_at=0, decision_at=0, terminal_at=terminal_at)
    case = _subject(monkeypatch, row)
    payload = case.subject._build_payload(case.connection, row, ENTRY_TIME, EXISTING_RECEIPT)
    before = deepcopy(payload)
    fakes = _signing_fakes(monkeypatch, signed_at)

    with pytest.raises(ReceiptError) as captured:
        case.subject._sign(payload, case.connection)
    assert captured.value.reason_code is ReasonCode.TOOL_EXECUTION_UNKNOWN
    assert captured.value.status_code == 409
    assert fakes.events == ["resolve-key", "signing-clock"]
    assert payload == before
    fakes.signer.assert_not_called()


@pytest.mark.parametrize("existing", [None, (EXISTING_RECEIPT[0], None, "FAILED_RETRYABLE")])
def test_late_issue_persists_actual_signing_time_in_receipt_execution_and_outbox(
    monkeypatch, existing,
) -> None:
    row = _row(updated_at=600, receipt_status="FAILED_RETRYABLE")
    case = _subject(monkeypatch, row, existing=existing)
    fakes = _signing_fakes(monkeypatch)

    signed = case.subject.issue(row[0], current_time=ENTRY_TIME)

    assert signed["payload"]["started_at"] == CREATED_AT
    assert signed["payload"]["decision_at"] == DECISION_AT
    assert signed["payload"]["finished_at"] == TERMINAL_AT
    assert signed["payload"]["business_effect_finalized_at"] == TERMINAL_AT
    assert signed["payload"]["receipt_issued_at"] == SIGNING_TIME
    assert signed["signature"]["signed_at"] == SIGNING_TIME
    fakes.now.assert_called_once_with()
    case.schemas.validate.assert_called_once_with("execution-receipt.schema.json", signed)
    receipt_writes = [(sql, params) for sql, params in case.connection.statements
                      if sql.startswith(("INSERT INTO execution_receipts ",
                                         "UPDATE execution_receipts "))]
    assert len(receipt_writes) == 1
    sql, params = receipt_writes[0]
    if existing is None:
        assert sql.startswith("INSERT INTO execution_receipts ")
        assert params[-2:] == (SIGNING_TIME, SIGNING_TIME)
        assert params[5].obj == signed
    else:
        assert sql.startswith("UPDATE execution_receipts ")
        assert params[-2:] == (SIGNING_TIME, row[0])
        assert params[3].obj == signed
        assert signed["payload"]["receipt_id"] == existing[0]
    signed_updates = [params for sql, params in case.connection.statements
                      if sql.startswith("UPDATE execution_records ")
                      and "receipt_status = 'SIGNED'" in sql]
    assert signed_updates == [(SIGNING_TIME, row[0])]
    outbox = [params for sql, params in case.connection.statements
              if sql.startswith("INSERT INTO audit_outbox ")]
    assert len(outbox) == 2
    assert [params[2] for params in outbox] == ["RECEIPT_SIGNED", "EXECUTION_COMMITTED"]
    assert all(params[-1] == SIGNING_TIME for params in outbox)
    assert fakes.signed_payloads == [signed["payload"]]
    case.failed.assert_not_called()


def test_issue_refreshes_initial_clock_after_execution_row_lock(monkeypatch) -> None:
    row = _row()
    case = _subject(monkeypatch, row)
    fakes = _signing_fakes(monkeypatch)
    times = iter((TERMINAL_AT - 1, ENTRY_TIME, SIGNING_TIME))

    def clock():
        value = next(times)
        if value == ENTRY_TIME:
            assert any("FROM execution_records e" in sql
                       for sql, _params in case.connection.statements)
        if value == SIGNING_TIME:
            assert "resolve-key" in fakes.events
        return value

    now = Mock(side_effect=clock)
    monkeypatch.setattr(receipt_module, "now_unix", now)

    signed = case.subject.issue(row[0])

    assert now.call_count == 3
    assert signed["payload"]["finished_at"] == TERMINAL_AT
    assert signed["payload"]["receipt_issued_at"] == SIGNING_TIME
    assert signed["signature"]["signed_at"] == SIGNING_TIME
    pending = [params for sql, params in case.connection.statements
               if sql.startswith("UPDATE execution_records ")
               and "receipt_status = 'PENDING'" in sql]
    assert pending == [(ENTRY_TIME, row[0])]
    case.failed.assert_not_called()


@pytest.mark.parametrize("state", FINAL_STATES)
@pytest.mark.parametrize("column_count", [21, 23, 24, 25])
def test_legacy_signed_receipt_returns_original_without_building_or_resigning(
    monkeypatch, state, column_count,
) -> None:
    row = _row(
        state, terminal_at=None, terminal_state=None, decision_at=None, decision_value=None,
        updated_at=600, receipt_status="FAILED_RETRYABLE",
    )[:column_count]
    legacy = {
        "payload": {
            "execution_id": row[0], "finished_at": 140, "receipt_issued_at": 180,
            "business_effect_finalized_at": None if state == "DENIED" else 140,
        },
        "signature": {"signed_at": 180, "value": "legacy-fixture-signature"},
    }
    before = deepcopy(legacy)
    case = _subject(monkeypatch, row, existing=(EXISTING_RECEIPT[0], legacy, "SIGNED"))
    build = Mock(side_effect=AssertionError("legacy SIGNED receipt must not be rebuilt"))
    sign = Mock(side_effect=AssertionError("legacy SIGNED receipt must not be resigned"))
    enqueue = Mock(side_effect=AssertionError("legacy SIGNED receipt must not add outbox events"))
    monkeypatch.setattr(case.subject, "_build_payload", build)
    monkeypatch.setattr(case.subject, "_sign", sign)
    monkeypatch.setattr(case.subject, "_enqueue_audit_events", enqueue)

    returned = case.subject.issue(row[0], current_time=SIGNING_TIME)

    assert returned == legacy == before
    assert returned["payload"]["receipt_issued_at"] == returned["signature"]["signed_at"] == 180
    assert len(case.connection.statements) == 3
    assert case.connection.statements[-1][1] == (SIGNING_TIME, row[0])
    assert "receipt_status = 'SIGNED'" in case.connection.statements[-1][0]
    build.assert_not_called()
    sign.assert_not_called()
    enqueue.assert_not_called()
    case.schemas.validate.assert_not_called()
    case.failed.assert_not_called()
