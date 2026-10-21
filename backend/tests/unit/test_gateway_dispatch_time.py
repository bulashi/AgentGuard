"""Dispatch-time regression sources, authored without execution or collection.

Execution, idempotency, key, and clock rows are synthetic. Connections record
SQL and transaction exit markers only; they do not implement PostgreSQL locks,
durability, rollback, concurrency, or budgets. Key lookup uses those fake rows.
Path reads, schema validation, signing, and tool transport are intercepted.
The signature has the model's SM2-shaped fields but is not an SM2 signature.
No actual private key, actor configuration, service, or database is used.
"""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest
from jsonschema import ValidationError

import backend.gateway.dispatch as dispatch_module
from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.crypto.domains import GATEWAY_EXECUTION_ENVELOPE
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.gateway.contracts import RequestEnvelopeModel, ValidatedToolCommandModel
from backend.gateway.dispatch import GatewayDispatchService, _ToolDispatchFailure
from backend.gateway.service import GatewayError
from backend.identity.key_registry import KeyRegistryError
from backend.tools.contracts import ToolExecutionResponse

DATABASE_URL = "mock-gateway-dispatch-time-database"
AUDIENCE = "GATEWAY-DISPATCH-TIME"
KEY_ID = "gateway-dispatch-time-key"
KEY_PATH = "unused-dispatch-time-key-not-read"
PRIVATE_KEY_FIXTURE = "fixture-only-not-a-private-key"
PUBLIC_KEY_FIXTURE = "fixture-only-not-a-public-key"
REQUEST_HASH = "1" * 64
PARAMETER_HASH = "3" * 64
IDEMPOTENCY_KEY = "c" * 64
ATTEMPT_ID = "ATTEMPT-DISPATCH-TIME-1"
ENTRY_TIME = 200
SIGNING_TIME = 700
TTL = 30
DEFAULT_ROW = object()
INVALID_TIMES = (None, True, False, "700", 700.0, -1, MAX_SAFE_INTEGER + 1)
EXECUTION_FIELDS = (
    "state", "decision", "created_at", "updated_at", "decision_at", "decision_value",
)
IDEMPOTENCY_FIELDS = ("business_idempotency_key", "parameter_hash", "status", "updated_at")
KEY_FIELDS = (
    "key_id", "subject_id", "subject_type", "purpose", "algorithm", "public_key_hex",
    "status", "material_state", "private_key_reference", "activated_at", "retired_at",
    "revoked_at", "compromised_at", "destroyed_at", "replaced_by", "created_at",
)
EXECUTION_SELECT = (
    "SELECT state, decision, created_at, updated_at, decision_at, decision_value::text "
    "FROM execution_records WHERE execution_id = %s FOR UPDATE"
)
IDEMPOTENCY_SELECT = (
    "SELECT business_idempotency_key, parameter_hash, status, updated_at "
    "FROM idempotency_records WHERE execution_id = %s FOR UPDATE"
)
KEY_SELECT = (
    "SELECT key_id, subject_id, subject_type, purpose, algorithm, public_key_hex, "
    "status, material_state, private_key_reference, activated_at, retired_at, "
    "revoked_at, compromised_at, destroyed_at, replaced_by, created_at "
    "FROM key_registry WHERE key_id = %s FOR UPDATE"
)
CLOCK_SELECT = "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
EXECUTION_UPDATE = (
    "UPDATE execution_records SET state = 'DISPATCHED', updated_at = %s "
    "WHERE execution_id = %s AND state = 'ADMITTED'"
)
IDEMPOTENCY_UPDATE = (
    "UPDATE idempotency_records SET status = 'DISPATCHED', updated_at = %s "
    "WHERE execution_id = %s"
)
SIGNING_RESOLVER = dispatch_module.PostgresKeyRegistry.resolve_for_signing_with_connection


class FakeCursor:
    def __init__(self, row=None) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class FakeTransaction:
    """Record the exception leaving the context, without simulating rollback."""

    def __init__(self, connection) -> None:
        self.connection = connection
        self.exit_error: BaseException | None = None

    def __enter__(self):
        self.connection.events.append("transaction-enter")
        return self

    def __exit__(self, _error_type, error, _traceback):
        self.exit_error = error
        marker = "transaction-commit-marker" if error is None else "transaction-rollback-marker"
        self.connection.events.append(marker)
        return False


class RecordingConnection:
    def __init__(
        self, command, row, idempotency, key, *, now, delays=None, clock_rows=None,
    ) -> None:
        self.command = command
        self.row = row
        self.idempotency = idempotency
        self.key = key
        self.now = now
        self.delays = {} if delays is None else dict(delays)
        self.clock_rows = None if clock_rows is None else iter(clock_rows)
        self.clock_samples: list[Any] = []
        self.events: list[str] = []
        self.statements: list[tuple[str, tuple[Any, ...] | None]] = []
        self.transactions: list[FakeTransaction] = []

    def __enter__(self):
        self.events.append("connection-enter")
        return self

    def __exit__(self, *_args):
        self.events.append("connection-exit")
        return False

    def transaction(self):
        transaction = FakeTransaction(self)
        self.transactions.append(transaction)
        return transaction

    def step(self, name: str) -> None:
        self.events.append(name)
        self.now += self.delays.get(name, 0)

    def execute(self, query: str, parameters: tuple[Any, ...] | None = None):
        sql = " ".join(query.split())
        self.statements.append((sql, parameters))
        if sql == EXECUTION_SELECT:
            assert parameters == (self.command.execution_id,)
            self.step("execution-lock")
            return FakeCursor(self.row)
        if sql == IDEMPOTENCY_SELECT:
            assert self.command.business_idempotency_key is not None
            assert parameters == (self.command.execution_id,)
            self.step("idempotency-lock")
            return FakeCursor(self.idempotency)
        if sql == KEY_SELECT:
            assert parameters == (KEY_ID,)
            self.step("key-lock")
            return FakeCursor(self.key)
        if sql == CLOCK_SELECT:
            assert parameters is None
            self.step("db-clock")
            row = (self.now,) if self.clock_rows is None else next(self.clock_rows)
            self.clock_samples.append(row)
            return FakeCursor(row)
        if sql in (EXECUTION_UPDATE, IDEMPOTENCY_UPDATE):
            assert parameters == (self.clock_samples[0][0], self.command.execution_id)
            if sql == IDEMPOTENCY_UPDATE:
                assert self.command.business_idempotency_key is not None
            self.step("update-execution" if sql == EXECUTION_UPDATE else "update-idempotency")
            return FakeCursor()
        raise AssertionError(f"unexpected dispatch-time SQL: {sql}")


@pytest.fixture(autouse=True)
def forbid_live_io(monkeypatch: pytest.MonkeyPatch) -> None:
    # These tests isolate envelope clocks; real chain/revocation locks are tested against PostgreSQL.
    monkeypatch.setattr(GatewayDispatchService, "_lock_dispatch_authorization", lambda *_args: ([], None))
    for name in ("connect", "Path", "sign_payload", "sm3_hex", "canonicalize", "new_id"):
        monkeypatch.setattr(
            dispatch_module, name,
            Mock(side_effect=AssertionError(f"unit source must fake {name}")),
        )
    monkeypatch.setattr(
        dispatch_module.PostgresKeyRegistry, "resolve_for_signing_with_connection",
        Mock(side_effect=AssertionError("unit source must supply synthetic signing key rows")),
    )
    monkeypatch.setattr(
        dispatch_module.httpx, "Client",
        Mock(side_effect=AssertionError("unit source must not open HTTP transport")),
    )
    monkeypatch.setattr(
        GatewayDispatchService, "_call_tool",
        Mock(side_effect=AssertionError("unit source must fake tool dispatch")),
    )


def _execution_row(**changes: Any) -> tuple[Any, ...]:
    fields = {
        "state": "ADMITTED", "decision": "ALLOW", "created_at": 100,
        "updated_at": 150, "decision_at": 120, "decision_value": "ALLOW",
    }
    fields.update(changes)
    return tuple(fields[field] for field in EXECUTION_FIELDS)


def _idempotency_row(**changes: Any) -> tuple[Any, ...]:
    fields = {
        "business_idempotency_key": IDEMPOTENCY_KEY, "parameter_hash": PARAMETER_HASH,
        "status": "ADMITTED", "updated_at": 180,
    }
    fields.update(changes)
    return tuple(fields[field] for field in IDEMPOTENCY_FIELDS)


def _key_row(**changes: Any) -> tuple[Any, ...]:
    fields = {
        "key_id": KEY_ID, "subject_id": AUDIENCE, "subject_type": "GATEWAY",
        "purpose": KeyPurpose.GATEWAY_EXECUTION_SIGNING.value, "algorithm": "SM2",
        "public_key_hex": PUBLIC_KEY_FIXTURE, "status": "ACTIVE", "material_state": "PRESENT",
        "private_key_reference": KEY_PATH, "activated_at": 0, "retired_at": None,
        "revoked_at": None, "compromised_at": None, "destroyed_at": None,
        "replaced_by": None, "created_at": 0,
    }
    fields.update(changes)
    return tuple(fields[field] for field in KEY_FIELDS)


def _command(*, readonly: bool = False) -> ValidatedToolCommandModel:
    return ValidatedToolCommandModel(
        schema_version="1.0", execution_id="EXEC-DISPATCH-TIME",
        tenant_id="TENANT-DISPATCH-TIME", task_id="TASK-DISPATCH-TIME",
        tool_service="ticket-service" if readonly else "refund-service",
        tool_name="ticket.read" if readonly else "refund.create", tool_version="v1",
        validated_parameters={"ticket_id": "TICKET-DISPATCH-TIME"},
        business_action_id=None if readonly else "ACTION-DISPATCH-TIME",
        business_idempotency_key=None if readonly else IDEMPOTENCY_KEY,
        parameter_hash=PARAMETER_HASH,
    )


def _new_subject(*, ttl: Any = TTL) -> GatewayDispatchService:
    return GatewayDispatchService(
        SimpleNamespace(database_url=DATABASE_URL, audience=AUDIENCE, schemas=Mock()),
        SimpleNamespace(admit_request=Mock()), tool_urls={}, gateway_key_id=KEY_ID,
        gateway_private_key_file=KEY_PATH, envelope_ttl_seconds=ttl,
    )


def _case(
    monkeypatch: pytest.MonkeyPatch, *, readonly=False, row=DEFAULT_ROW,
    idempotency=DEFAULT_ROW, key=DEFAULT_ROW, ttl=TTL, now=SIGNING_TIME,
    clock_rows=None, delays=None, schema_error=None,
) -> SimpleNamespace:
    command = _command(readonly=readonly)
    connection = RecordingConnection(
        command, _execution_row() if row is DEFAULT_ROW else row,
        _idempotency_row() if idempotency is DEFAULT_ROW else idempotency,
        _key_row() if key is DEFAULT_ROW else key,
        now=now, delays=delays, clock_rows=clock_rows,
    )
    connect = Mock(return_value=connection)
    monkeypatch.setattr(dispatch_module, "connect", connect)
    # The real registry's pure row checks run over this fake connection only.
    resolver = Mock(wraps=SIGNING_RESOLVER)
    monkeypatch.setattr(
        dispatch_module.PostgresKeyRegistry, "resolve_for_signing_with_connection", resolver,
    )

    def read_key(*, encoding):
        assert encoding == "ascii"
        connection.step("key-read")
        return f" {PRIVATE_KEY_FIXTURE}\n"

    key_path = Mock(spec=["read_text"])
    key_path.read_text.side_effect = read_key
    path = Mock(return_value=key_path)
    monkeypatch.setattr(dispatch_module, "Path", path)
    new_id = Mock(return_value=ATTEMPT_ID)
    monkeypatch.setattr(dispatch_module, "new_id", new_id)
    signed_payloads: list[dict[str, Any]] = []

    def sign(
        payload, *, domain_separator, key_id, key_purpose,
        private_key_hex, public_key_hex, signed_at,
    ):
        connection.step("sign")
        signed_payloads.append(deepcopy(payload))
        assert domain_separator == GATEWAY_EXECUTION_ENVELOPE
        assert key_id == KEY_ID and key_purpose is KeyPurpose.GATEWAY_EXECUTION_SIGNING
        assert private_key_hex == PRIVATE_KEY_FIXTURE
        assert public_key_hex == PUBLIC_KEY_FIXTURE
        return {
            "algorithm": "SM2", "key_id": key_id, "key_purpose": key_purpose.value,
            "encoding": "SM2_RS_HEX_128_LOWERCASE", "value": "a" * 128,
            "signed_at": signed_at,
        }

    signer = Mock(side_effect=sign)
    monkeypatch.setattr(dispatch_module, "sign_payload", signer)

    def validate(_name, _document):
        connection.step("schema-validate")
        if schema_error is not None:
            raise schema_error

    schemas = Mock(spec=["validate"])
    schemas.validate.side_effect = validate
    subject = _new_subject(ttl=ttl)
    subject.gateway.schemas = schemas
    tool = Mock(side_effect=AssertionError("direct marking must not call a tool"))
    monkeypatch.setattr(subject, "_call_tool", tool)
    return SimpleNamespace(
        subject=subject, command=command, connection=connection, connect=connect,
        resolver=resolver, path=path, key_path=key_path, new_id=new_id, signer=signer,
        signed_payloads=signed_payloads, schemas=schemas, tool=tool,
    )


def _wire_dispatch(monkeypatch, case) -> None:
    command = case.command
    case.body = {
        "execution_id": command.execution_id, "state": "ADMITTED", "decision": "ALLOW",
        "admission_outcome": "NEW_EXECUTION", "request_hash": REQUEST_HASH,
        "validated_command": command.model_dump(mode="json"),
    }
    case.request = RequestEnvelopeModel(
        schema_version="1.0", credential_chain=[{}], task_id=command.task_id,
        tool_service=command.tool_service, tool_name=command.tool_name, tool_version="v1",
        canonical_parameters=command.validated_parameters, request_id="REQUEST-DISPATCH-TIME",
        issued_at=ENTRY_TIME, holder_key_id="unused-holder-key", holder_proof={},
        business_action_id=command.business_action_id,
    )
    case.subject.admission.admit_request.return_value = SimpleNamespace(
        body=case.body, status_code=200,
    )
    case.load_command = Mock(return_value=command)
    case.request_hash = Mock(return_value=REQUEST_HASH)
    case.mark = Mock(wraps=case.subject._mark_dispatched)
    case.state = Mock(return_value="DISPATCHED")
    monkeypatch.setattr(case.subject, "_command_for_admitted_request", case.load_command)
    monkeypatch.setattr(case.subject, "_stored_request_hash", case.request_hash)
    monkeypatch.setattr(case.subject, "_mark_dispatched", case.mark)
    monkeypatch.setattr(case.subject, "_execution_state", case.state)

    def call_tool(envelope):
        case.connection.step("tool-call")
        return ToolExecutionResponse(
            execution_id=envelope.payload.execution_id,
            execution_attempt_id=envelope.payload.execution_attempt_id,
            outcome="SUCCESS", result={"unit_marker": "shape-only-tool-result"},
        )

    def settle(_command, *, body, tool_response):
        case.connection.step("settlement-call")
        return {"state": "COMMITTED", "unit_marker": "mocked-settlement"}

    case.tool = Mock(side_effect=call_tool)
    case.settle = Mock(side_effect=settle)
    case.unknown = Mock(return_value="UNKNOWN")
    monkeypatch.setattr(case.subject, "_call_tool", case.tool)
    monkeypatch.setattr(case.subject, "_settle_success", case.settle)
    monkeypatch.setattr(case.subject, "_mark_unknown", case.unknown)


def _writes(case):
    return [(sql, parameters) for sql, parameters in case.connection.statements
            if sql.startswith("UPDATE ")]


def _assert_resolver_call(case) -> None:
    case.resolver.assert_called_once_with(
        case.connection, KEY_ID, expected_subject_id=AUDIENCE,
        expected_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING, lock=True,
    )


def _assert_transaction_marker(case, error=None) -> None:
    case.connect.assert_called_once_with(DATABASE_URL)
    assert len(case.connection.transactions) == 1
    assert case.connection.transactions[0].exit_error is error
    marker = "transaction-commit-marker" if error is None else "transaction-rollback-marker"
    assert case.connection.events[-2:] == [marker, "connection-exit"]


def _reject(monkeypatch, case, reason_code, *, status_code=409) -> GatewayError:
    _wire_dispatch(monkeypatch, case)
    with pytest.raises(GatewayError) as caught:
        case.subject.dispatch(case.request, current_time=ENTRY_TIME)
    error = caught.value
    assert error.reason_code is reason_code and error.status_code == status_code
    case.mark.assert_called_once_with(case.command, request_hash=REQUEST_HASH)
    case.tool.assert_not_called()
    case.settle.assert_not_called()
    case.unknown.assert_not_called()
    case.state.assert_not_called()
    dispatch_module.httpx.Client.assert_not_called()
    _assert_transaction_marker(case, error)
    return error


def _assert_unsigned(case, *, key_locked=False, key_read=False, clock_count=0) -> None:
    if key_locked:
        _assert_resolver_call(case)
    else:
        case.resolver.assert_not_called()
    if key_read:
        case.path.assert_called_once_with(KEY_PATH)
        case.key_path.read_text.assert_called_once_with(encoding="ascii")
    else:
        case.path.assert_not_called()
        case.key_path.read_text.assert_not_called()
    assert len(case.connection.clock_samples) == clock_count
    case.new_id.assert_not_called()
    case.signer.assert_not_called()
    case.schemas.validate.assert_not_called()
    assert _writes(case) == []


def _assert_signed_shape(case, envelope, *, attempt_id=ATTEMPT_ID) -> None:
    issued_at = case.connection.clock_samples[0][0]
    expected_payload = {
        "schema_version": "1.0", "execution_id": case.command.execution_id,
        "execution_attempt_id": attempt_id, "request_hash": REQUEST_HASH,
        "tenant_id": case.command.tenant_id, "task_id": case.command.task_id,
        "tool_service": case.command.tool_service, "tool_name": case.command.tool_name,
        "tool_version": case.command.tool_version,
        "canonical_validated_parameters": case.command.validated_parameters,
        "business_action_id": case.command.business_action_id,
        "business_idempotency_key": case.command.business_idempotency_key,
        "parameter_hash": case.command.parameter_hash, "issued_at": issued_at,
        "expires_at": issued_at + case.subject.envelope_ttl_seconds, "gateway_key_id": KEY_ID,
    }
    assert envelope.payload.model_dump(mode="json") == expected_payload
    assert envelope.signature.signed_at == envelope.payload.issued_at == issued_at
    assert envelope.signature.model_dump(mode="json") == {
        "algorithm": "SM2", "key_id": KEY_ID,
        "key_purpose": KeyPurpose.GATEWAY_EXECUTION_SIGNING.value,
        "encoding": "SM2_RS_HEX_128_LOWERCASE", "value": "a" * 128,
        "signed_at": issued_at,
    }
    case.new_id.assert_called_once_with("ATTEMPT")
    case.signer.assert_called_once_with(
        expected_payload, domain_separator=GATEWAY_EXECUTION_ENVELOPE, key_id=KEY_ID,
        key_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
        private_key_hex=PRIVATE_KEY_FIXTURE, public_key_hex=PUBLIC_KEY_FIXTURE,
        signed_at=issued_at,
    )
    assert case.signed_payloads == [expected_payload]
    case.schemas.validate.assert_called_once_with(
        "gateway-execution-envelope.schema.json", envelope.model_dump(mode="json"),
    )
    _assert_resolver_call(case)
    case.path.assert_called_once_with(KEY_PATH)
    case.key_path.read_text.assert_called_once_with(encoding="ascii")


def test_signing_clock_starts_after_all_row_key_waits_and_key_read(monkeypatch) -> None:
    delays = {"execution-lock": 100, "idempotency-lock": 120, "key-lock": 80, "key-read": 200}
    case = _case(monkeypatch, now=ENTRY_TIME, delays=delays)

    envelope = case.subject._mark_dispatched(case.command, request_hash=REQUEST_HASH)

    assert case.connection.now == SIGNING_TIME == ENTRY_TIME + sum(delays.values())
    assert case.connection.clock_samples == [(SIGNING_TIME,), (SIGNING_TIME,)]
    assert case.connection.events == [
        "connection-enter", "transaction-enter", "execution-lock", "idempotency-lock",
        "key-lock", "key-read", "db-clock", "sign", "schema-validate",
        "update-execution", "update-idempotency", "db-clock",
        "transaction-commit-marker", "connection-exit",
    ]
    assert case.connection.statements == [
        (EXECUTION_SELECT, (case.command.execution_id,)),
        (IDEMPOTENCY_SELECT, (case.command.execution_id,)), (KEY_SELECT, (KEY_ID,)),
        (CLOCK_SELECT, None), (EXECUTION_UPDATE, (SIGNING_TIME, case.command.execution_id)),
        (IDEMPOTENCY_UPDATE, (SIGNING_TIME, case.command.execution_id)), (CLOCK_SELECT, None),
    ]
    _assert_signed_shape(case, envelope)
    _assert_transaction_marker(case)
    case.tool.assert_not_called()


def test_readonly_dispatch_never_selects_or_updates_idempotency(monkeypatch) -> None:
    case = _case(monkeypatch, readonly=True, idempotency=None)

    envelope = case.subject._mark_dispatched(case.command, request_hash=REQUEST_HASH)

    assert case.connection.statements == [
        (EXECUTION_SELECT, (case.command.execution_id,)), (KEY_SELECT, (KEY_ID,)),
        (CLOCK_SELECT, None), (EXECUTION_UPDATE, (SIGNING_TIME, case.command.execution_id)),
        (CLOCK_SELECT, None),
    ]
    assert "idempotency-lock" not in case.connection.events
    assert "update-idempotency" not in case.connection.events
    assert envelope.payload.business_action_id is None
    assert envelope.payload.business_idempotency_key is None
    _assert_signed_shape(case, envelope)
    _assert_transaction_marker(case)


@pytest.mark.parametrize(("issued_at", "ttl", "final_time"), [
    (0, 1, 0), (0, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER),
    (SIGNING_TIME, TTL, SIGNING_TIME), (SIGNING_TIME, TTL, SIGNING_TIME + TTL - 1),
    (SIGNING_TIME, TTL, SIGNING_TIME + TTL), (SIGNING_TIME, 1, SIGNING_TIME + 1),
    (MAX_SAFE_INTEGER - TTL, TTL, MAX_SAFE_INTEGER),
])
def test_exact_safe_integer_ttl_and_inclusive_final_clock_boundaries(
    monkeypatch, issued_at, ttl, final_time,
) -> None:
    case = _case(
        monkeypatch, row=_execution_row(created_at=0, decision_at=0, updated_at=0),
        idempotency=_idempotency_row(updated_at=0), ttl=ttl,
        clock_rows=((issued_at,), (final_time,)),
    )

    envelope = case.subject._mark_dispatched(case.command, request_hash=REQUEST_HASH)

    assert envelope.payload.expires_at - envelope.payload.issued_at == ttl
    assert issued_at <= final_time <= envelope.payload.expires_at <= MAX_SAFE_INTEGER
    _assert_signed_shape(case, envelope)
    assert _writes(case) == [
        (EXECUTION_UPDATE, (issued_at, case.command.execution_id)),
        (IDEMPOTENCY_UPDATE, (issued_at, case.command.execution_id)),
    ]
    _assert_transaction_marker(case)


def test_stored_execution_and_idempotency_times_equal_issued_at_are_accepted(monkeypatch) -> None:
    case = _case(
        monkeypatch, row=_execution_row(updated_at=SIGNING_TIME),
        idempotency=_idempotency_row(updated_at=SIGNING_TIME),
    )
    envelope = case.subject._mark_dispatched(case.command, request_hash=REQUEST_HASH)
    _assert_signed_shape(case, envelope)
    _assert_transaction_marker(case)


def test_each_independent_admitted_snapshot_binds_its_new_attempt_into_signed_payload(
    monkeypatch,
) -> None:
    envelopes = []
    for index in (1, 2):
        case = _case(monkeypatch)
        attempt_id = f"ATTEMPT-DISPATCH-TIME-{index}"
        case.new_id.return_value = attempt_id
        envelope = case.subject._mark_dispatched(case.command, request_hash=REQUEST_HASH)
        _assert_signed_shape(case, envelope, attempt_id=attempt_id)
        envelopes.append(envelope)
    # Independent fake rows are not evidence that a persisted execution can dispatch twice.
    assert envelopes[0].payload.execution_id == envelopes[1].payload.execution_id
    assert envelopes[0].payload.execution_attempt_id != envelopes[1].payload.execution_attempt_id


@pytest.mark.parametrize("state", [
    "RECEIVED", "DENIED", "DISPATCHED", "UNKNOWN", "RECONCILING", "COMMITTED",
    "RELEASED", "RECOVERY_FAILED_FINAL",
])
def test_nonadmitted_row_returns_none_before_key_read_or_crypto(monkeypatch, state) -> None:
    case = _case(monkeypatch, row=_execution_row(state=state, decision_at=None))
    assert case.subject._mark_dispatched(case.command, request_hash=REQUEST_HASH) is None
    assert case.connection.statements == [(EXECUTION_SELECT, (case.command.execution_id,))]
    _assert_unsigned(case)
    _assert_transaction_marker(case)
    case.tool.assert_not_called()


def test_missing_execution_row_is_rejected_before_key_access(monkeypatch) -> None:
    case = _case(monkeypatch, row=None)
    _reject(monkeypatch, case, ReasonCode.TOOL_EXECUTION_UNKNOWN, status_code=500)
    assert case.connection.statements == [(EXECUTION_SELECT, (case.command.execution_id,))]
    _assert_unsigned(case)


@pytest.mark.parametrize("changes", [
    {"decision_at": None, "decision_value": None}, {"decision": None},
    {"decision": "DENY"}, {"decision": "allow"}, {"decision": True},
    {"decision_value": None}, {"decision_value": "DENY"},
    {"decision_value": "ALLOW "}, {"decision_value": True},
    {"created_at": -1}, {"created_at": 121}, {"decision_at": 99},
    {"decision_at": 151}, {"updated_at": 119}, {"updated_at": MAX_SAFE_INTEGER + 1},
])
def test_missing_or_inconsistent_trusted_decision_pair_fails_before_signing(
    monkeypatch, changes,
) -> None:
    case = _case(monkeypatch, row=_execution_row(**changes))
    _reject(monkeypatch, case, ReasonCode.TOOL_EXECUTION_UNKNOWN)
    assert case.connection.statements == [(EXECUTION_SELECT, (case.command.execution_id,))]
    _assert_unsigned(case)


@pytest.mark.parametrize("field", ["created_at", "updated_at", "decision_at"])
@pytest.mark.parametrize("value", INVALID_TIMES)
def test_execution_times_require_nonboolean_nonnegative_safe_integers(
    monkeypatch, field, value,
) -> None:
    case = _case(monkeypatch, row=_execution_row(**{field: value}))
    _reject(monkeypatch, case, ReasonCode.TOOL_EXECUTION_UNKNOWN)
    _assert_unsigned(case)


@pytest.mark.parametrize("row", [
    None, _idempotency_row(business_idempotency_key="d" * 64),
    _idempotency_row(business_idempotency_key=None),
    _idempotency_row(parameter_hash="4" * 64), _idempotency_row(parameter_hash=None),
    _idempotency_row(status="DISPATCHED"), _idempotency_row(status=None),
])
def test_missing_or_mismatched_exact_idempotency_row_fails_before_key_access(
    monkeypatch, row,
) -> None:
    case = _case(monkeypatch, idempotency=row)
    _reject(monkeypatch, case, ReasonCode.IDEMPOTENCY_CONFLICT)
    assert case.connection.statements == [
        (EXECUTION_SELECT, (case.command.execution_id,)),
        (IDEMPOTENCY_SELECT, (case.command.execution_id,)),
    ]
    _assert_unsigned(case)


@pytest.mark.parametrize("value", INVALID_TIMES)
def test_idempotency_updated_at_requires_a_nonnegative_safe_integer(monkeypatch, value) -> None:
    case = _case(monkeypatch, idempotency=_idempotency_row(updated_at=value))
    _reject(monkeypatch, case, ReasonCode.IDEMPOTENCY_CONFLICT)
    _assert_unsigned(case)


@pytest.mark.parametrize("future_source", ["execution", "idempotency"])
def test_dispatch_clock_cannot_precede_existing_updated_at(monkeypatch, future_source) -> None:
    case = _case(
        monkeypatch,
        row=_execution_row(updated_at=SIGNING_TIME + 1 if future_source == "execution" else 150),
        idempotency=_idempotency_row(
            updated_at=SIGNING_TIME + 1 if future_source == "idempotency" else 180,
        ),
    )
    _reject(monkeypatch, case, ReasonCode.EXECUTION_ENVELOPE_EXPIRED)
    _assert_unsigned(case, key_locked=True, key_read=True, clock_count=1)


@pytest.mark.parametrize("issued_at", [MAX_SAFE_INTEGER - TTL + 1, MAX_SAFE_INTEGER])
def test_safe_clock_with_overflowing_expiry_is_rejected_before_signing(
    monkeypatch, issued_at,
) -> None:
    case = _case(monkeypatch, clock_rows=((issued_at,),))
    _reject(monkeypatch, case, ReasonCode.EXECUTION_ENVELOPE_EXPIRED)
    _assert_unsigned(case, key_locked=True, key_read=True, clock_count=1)


@pytest.mark.parametrize("row", [None, *((value,) for value in INVALID_TIMES)])
def test_dispatch_clock_rejects_missing_or_invalid_database_clock_rows(row) -> None:
    connection = Mock(spec=["execute"])
    connection.execute.return_value.fetchone.return_value = row
    with pytest.raises(GatewayError) as caught:
        GatewayDispatchService._dispatch_clock(connection)
    assert caught.value.reason_code is ReasonCode.EXECUTION_ENVELOPE_EXPIRED
    assert caught.value.status_code == 409
    connection.execute.assert_called_once_with(CLOCK_SELECT)
    connection.execute.return_value.fetchone.assert_called_once_with()


@pytest.mark.parametrize("timestamp", [0, SIGNING_TIME, MAX_SAFE_INTEGER])
def test_dispatch_clock_accepts_only_trusted_safe_integer_values(timestamp) -> None:
    connection = Mock(spec=["execute"])
    connection.execute.return_value.fetchone.return_value = (timestamp,)
    assert GatewayDispatchService._dispatch_clock(connection) == timestamp
    connection.execute.assert_called_once_with(CLOCK_SELECT)


@pytest.mark.parametrize("row", [None, *((value,) for value in INVALID_TIMES)])
def test_invalid_initial_clock_never_signs_or_dispatches_tool(monkeypatch, row) -> None:
    case = _case(monkeypatch, clock_rows=(row,))
    _reject(monkeypatch, case, ReasonCode.EXECUTION_ENVELOPE_EXPIRED)
    _assert_unsigned(case, key_locked=True, key_read=True, clock_count=1)


@pytest.mark.parametrize(("key", "reason"), [
    (None, ReasonCode.UNKNOWN_KEY),
    (_key_row(status="RETIRED"), ReasonCode.KEY_RETIRED_FOR_SIGNING),
    (_key_row(status="REVOKED"), ReasonCode.KEY_REVOKED),
    (_key_row(status="COMPROMISED"), ReasonCode.KEY_COMPROMISED),
    (_key_row(material_state="DESTROYED"), ReasonCode.UNKNOWN_KEY),
    (_key_row(subject_id="GATEWAY-OTHER"), ReasonCode.INVALID_SIGNATURE),
    (_key_row(purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING.value), ReasonCode.INVALID_SIGNATURE),
    (_key_row(algorithm="RSA"), ReasonCode.INVALID_SIGNATURE),
])
def test_rejected_synthetic_signing_key_prevents_key_read_clock_and_signing(
    monkeypatch, key, reason,
) -> None:
    case = _case(monkeypatch, key=key)
    error = _reject(monkeypatch, case, reason, status_code=403)
    assert isinstance(error.__cause__, KeyRegistryError)
    assert error.__cause__.reason_code is reason
    assert case.connection.statements[-1] == (KEY_SELECT, (KEY_ID,))
    _assert_unsigned(case, key_locked=True)


def test_schema_mock_failure_never_updates_state_or_calls_tool(monkeypatch) -> None:
    schema_error = ValidationError("synthetic frozen-schema rejection")
    case = _case(monkeypatch, schema_error=schema_error)
    error = _reject(monkeypatch, case, ReasonCode.REQUEST_SCHEMA_INVALID, status_code=500)
    assert error.__cause__ is schema_error
    case.signer.assert_called_once()
    case.schemas.validate.assert_called_once()
    assert case.schemas.validate.call_args.args[0] == "gateway-execution-envelope.schema.json"
    assert case.schemas.validate.call_args.args[1]["payload"] == case.signed_payloads[0]
    assert case.connection.clock_samples == [(SIGNING_TIME,)]
    assert _writes(case) == []


@pytest.mark.parametrize("readonly", [False, True])
@pytest.mark.parametrize("row", [
    None, *((value,) for value in INVALID_TIMES),
    (SIGNING_TIME - 1,), (SIGNING_TIME + TTL + 1,),
])
def test_invalid_regressed_or_expired_final_clock_records_fake_rollback_before_tool(
    monkeypatch, readonly, row,
) -> None:
    case = _case(monkeypatch, readonly=readonly, clock_rows=((SIGNING_TIME,), row))
    _reject(monkeypatch, case, ReasonCode.EXECUTION_ENVELOPE_EXPIRED)
    case.signer.assert_called_once()
    case.schemas.validate.assert_called_once()
    assert case.connection.clock_samples == [(SIGNING_TIME,), row]
    expected_writes = [(EXECUTION_UPDATE, (SIGNING_TIME, case.command.execution_id))]
    if not readonly:
        expected_writes.append((IDEMPOTENCY_UPDATE, (SIGNING_TIME, case.command.execution_id)))
    assert _writes(case) == expected_writes
    assert case.connection.events[-3:] == [
        "db-clock", "transaction-rollback-marker", "connection-exit",
    ]
    # The marker records propagation of GatewayError, not durable database rollback.


@pytest.mark.parametrize(("delay_stage", "readonly"), [
    ("sign", False), ("sign", True),
    ("update-execution", False), ("update-execution", True),
    ("update-idempotency", False),
])
def test_expiry_during_signing_or_state_updates_is_rejected_before_tool(
    monkeypatch, delay_stage, readonly,
) -> None:
    case = _case(monkeypatch, readonly=readonly, delays={delay_stage: TTL + 1})
    _reject(monkeypatch, case, ReasonCode.EXECUTION_ENVELOPE_EXPIRED)
    assert case.connection.clock_samples == [(SIGNING_TIME,), (SIGNING_TIME + TTL + 1,)]
    assert case.signed_payloads[0]["issued_at"] == SIGNING_TIME
    assert case.signed_payloads[0]["expires_at"] == SIGNING_TIME + TTL
    assert case.connection.events.index(delay_stage) < len(case.connection.events) - 3
    assert len(_writes(case)) == (1 if readonly else 2)
    case.signer.assert_called_once()


def test_dispatch_propagates_mark_error_without_tool_or_entry_clock_argument(monkeypatch) -> None:
    case = _case(monkeypatch)
    _wire_dispatch(monkeypatch, case)
    error = GatewayError(ReasonCode.EXECUTION_ENVELOPE_EXPIRED, "synthetic mark failure")
    case.mark.side_effect = error
    with pytest.raises(GatewayError) as caught:
        case.subject.dispatch(case.request, current_time=ENTRY_TIME)
    assert caught.value is error
    case.mark.assert_called_once_with(case.command, request_hash=REQUEST_HASH)
    case.tool.assert_not_called()
    case.settle.assert_not_called()
    case.unknown.assert_not_called()
    case.connect.assert_not_called()


def test_dispatch_none_mark_result_does_not_call_tool_or_read_key(monkeypatch) -> None:
    case = _case(monkeypatch, row=_execution_row(state="DISPATCHED", decision_at=None))
    _wire_dispatch(monkeypatch, case)
    result = case.subject.dispatch(case.request, current_time=ENTRY_TIME)
    assert result.status_code == 200 and result.body["state"] == "DISPATCHED"
    case.mark.assert_called_once_with(case.command, request_hash=REQUEST_HASH)
    case.state.assert_called_once_with(case.command.execution_id)
    case.tool.assert_not_called()
    case.settle.assert_not_called()
    case.unknown.assert_not_called()
    _assert_unsigned(case)
    _assert_transaction_marker(case)


def test_successful_dispatch_uses_post_wait_signed_shape_and_bound_attempt(monkeypatch) -> None:
    case = _case(monkeypatch, clock_rows=((SIGNING_TIME,), (SIGNING_TIME + TTL,)))
    _wire_dispatch(monkeypatch, case)
    result = case.subject.dispatch(case.request, current_time=ENTRY_TIME)
    assert result.status_code == 200
    assert result.body == {"state": "COMMITTED", "unit_marker": "mocked-settlement"}
    case.subject.admission.admit_request.assert_called_once_with(
        case.request, current_time=ENTRY_TIME,
    )
    case.load_command.assert_called_once_with(case.request, case.body)
    case.request_hash.assert_called_once_with(case.command.execution_id)
    case.mark.assert_called_once_with(case.command, request_hash=REQUEST_HASH)
    case.tool.assert_called_once()
    envelope = case.tool.call_args.args[0]
    _assert_signed_shape(case, envelope)
    assert envelope.payload.issued_at != ENTRY_TIME
    assert envelope.payload.execution_attempt_id == ATTEMPT_ID
    response = case.settle.call_args.kwargs["tool_response"]
    assert response.execution_id == envelope.payload.execution_id
    assert response.execution_attempt_id == envelope.payload.execution_attempt_id
    case.settle.assert_called_once_with(
        case.command, body=case.body, tool_response=response,
    )
    case.unknown.assert_not_called()
    assert case.connection.events[-4:] == [
        "transaction-commit-marker", "connection-exit", "tool-call", "settlement-call",
    ]


def _assert_posttool_failure_route(
    monkeypatch, *, observed_state, status_code, failure="settlement-gateway-error",
    unknown_error=False,
) -> None:
    case = _case(monkeypatch)
    _wire_dispatch(monkeypatch, case)
    case.unknown.return_value = observed_state
    case.state.return_value = observed_state
    if unknown_error:
        case.unknown.side_effect = GatewayError(
            ReasonCode.EXECUTION_ENVELOPE_EXPIRED, "synthetic UNKNOWN clock failure",
            status_code=409,
        )
    if failure == "tool-dispatch-failure":
        case.tool.side_effect = _ToolDispatchFailure("synthetic tool transport failure")
    elif failure == "settlement-tool-failure":
        case.settle.side_effect = _ToolDispatchFailure("synthetic result binding failure")
    else:
        assert failure == "settlement-gateway-error"
        case.settle.side_effect = GatewayError(
            ReasonCode.EXECUTION_ENVELOPE_EXPIRED, "synthetic settlement clock failure",
            status_code=409,
        )
    timeline = Mock()
    for name in ("tool", "settle", "unknown", "state"):
        timeline.attach_mock(getattr(case, name), name)

    result = case.subject.dispatch(case.request, current_time=ENTRY_TIME)

    assert result.status_code == status_code
    assert result.body["state"] == observed_state
    assert result.body["execution_id"] == case.command.execution_id
    assert result.body["decision"] == "ALLOW"
    assert result.body["request_hash"] == REQUEST_HASH
    assert result.body["validated_command"] == case.command.model_dump(mode="json")
    assert result.body["receipt"] is None
    assert result.body["reason_code"] == (
        ReasonCode.ALLOWED.value if observed_state == "COMMITTED"
        else ReasonCode.TOOL_EXECUTION_UNKNOWN.value
    )
    case.subject.admission.admit_request.assert_called_once_with(
        case.request, current_time=ENTRY_TIME,
    )
    case.mark.assert_called_once_with(case.command, request_hash=REQUEST_HASH)
    case.tool.assert_called_once()
    envelope = case.tool.call_args.args[0]
    _assert_signed_shape(case, envelope)
    expected_calls = [call.tool(envelope)]
    if failure == "tool-dispatch-failure":
        case.settle.assert_not_called()
    else:
        response = case.settle.call_args.kwargs["tool_response"]
        assert response.execution_attempt_id == envelope.payload.execution_attempt_id
        case.settle.assert_called_once_with(
            case.command, body=case.body, tool_response=response,
        )
        expected_calls.append(call.settle(case.command, body=case.body, tool_response=response))
    case.unknown.assert_called_once_with(case.command.execution_id)
    expected_calls.append(call.unknown(case.command.execution_id))
    if unknown_error:
        case.state.assert_called_once_with(case.command.execution_id)
        expected_calls.append(call.state(case.command.execution_id))
    else:
        case.state.assert_not_called()
    assert timeline.mock_calls == expected_calls
    # Only marking uses the synthetic SQL fixture; settlement and UNKNOWN are mocks.
    case.connect.assert_called_once_with(DATABASE_URL)
    assert len(case.connection.transactions) == 1
    assert case.connection.transactions[0].exit_error is None
    dispatch_module.httpx.Client.assert_not_called()


def test_dispatch_settlement_gateway_error_returns_observed_unknown_without_new_deny(
    monkeypatch,
) -> None:
    _assert_posttool_failure_route(monkeypatch, observed_state="UNKNOWN", status_code=502)


@pytest.mark.parametrize("observed_state", ["DISPATCHED", "UNKNOWN", "RELEASED"])
def test_dispatch_unknown_gateway_error_reads_actual_state_for_502_fallback(
    monkeypatch, observed_state,
) -> None:
    _assert_posttool_failure_route(
        monkeypatch, observed_state=observed_state, status_code=502, unknown_error=True,
    )


@pytest.mark.parametrize("unknown_error", [False, True])
@pytest.mark.parametrize("failure", [
    "settlement-gateway-error", "settlement-tool-failure", "tool-dispatch-failure",
])
def test_dispatch_posttool_error_preserves_observed_committed_state_with_200(
    monkeypatch, unknown_error, failure,
) -> None:
    _assert_posttool_failure_route(
        monkeypatch, observed_state="COMMITTED", status_code=200,
        failure=failure, unknown_error=unknown_error,
    )


@pytest.mark.parametrize("failure", ["settlement-tool-failure", "tool-dispatch-failure"])
def test_dispatch_tool_failure_returns_explicit_unknown_state_without_entry_clock(
    monkeypatch, failure,
) -> None:
    _assert_posttool_failure_route(
        monkeypatch, observed_state="UNKNOWN", status_code=502, failure=failure,
    )


@pytest.mark.parametrize("ttl", [True, False, 30.0, "30", None, -1, 0, MAX_SAFE_INTEGER + 1])
def test_constructor_rejects_nonpositive_or_nonsafe_integer_ttl(ttl) -> None:
    with pytest.raises(ValueError, match="envelope_ttl_seconds must be a positive safe integer"):
        _new_subject(ttl=ttl)
    dispatch_module.connect.assert_not_called()
    dispatch_module.Path.assert_not_called()
    dispatch_module.sign_payload.assert_not_called()
    dispatch_module.PostgresKeyRegistry.resolve_for_signing_with_connection.assert_not_called()


@pytest.mark.parametrize("ttl", [1, TTL, MAX_SAFE_INTEGER])
def test_constructor_accepts_positive_safe_integer_ttl_without_io(ttl) -> None:
    subject = _new_subject(ttl=ttl)
    assert type(subject.envelope_ttl_seconds) is int and subject.envelope_ttl_seconds == ttl
    dispatch_module.connect.assert_not_called()
    dispatch_module.Path.assert_not_called()
    dispatch_module.sign_payload.assert_not_called()
