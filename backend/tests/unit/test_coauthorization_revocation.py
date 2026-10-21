"""Revocation source cases, authored without execution or collection.

SQL results, Schema validation, clocks and connection/transaction exits are fakes.
Commit/rollback markers describe Python control flow, not PostgreSQL commit,
rollback, NOWAIT locks, triggers, root cascades or durable idempotency. No actual
keys, configuration, environment values, DB, HTTP or model calls are used.
"""

from __future__ import annotations

import json
import os
import runpy
import sys
from copy import deepcopy
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest
from jsonschema import ValidationError
from psycopg import OperationalError, errors

from backend.coauthorization import revocation
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from scripts import revoke_coauthorization as cli

DATABASE_URL = "unit-only-coauthorization-revocation-no-network"
DATABASE_ENV = "AGENTGUARD_DATABASE_URL"
TENANT_ID = "tenant-revocation-test"
KEY_ID = "approval-key-test"
POLICY_REVISION = "approval-policy-test-v1"
ROOT_ID = "root-coauthorized-test"
DATABASE_ACTOR = "synthetic-administrative-role"
KEY_CHANGE_AT = 1_800_000_120
EVENT_OBSERVED_AT = KEY_CHANGE_AT + 1
ACTIVATED_AT = KEY_CHANGE_AT - 100
EVENT_ID = 41

KEY_REVOKED = "APPROVAL_KEY_REVOKED"
KEY_COMPROMISED = "APPROVAL_KEY_COMPROMISED"
POLICY_REVOKED = "APPROVAL_POLICY_REVOKED"
ROOT_WITHDRAWN = "AUTHORIZATION_WITHDRAWN"
REQUEST_SCHEMA = "revocation-request.schema.json"
RESPONSE_SCHEMA = "revocation-response.schema.json"

SET_READ_COMMITTED = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
CLOCK_QUERY = "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
KEY_LOCK_QUERY = (
    "SELECT status, activated_at FROM coauthorization_keys "
    "WHERE tenant_id = %s AND key_id = %s FOR UPDATE NOWAIT"
)
POLICY_LOCK_QUERY = (
    "SELECT status FROM coauthorization_policies "
    "WHERE tenant_id = %s AND revision = %s FOR UPDATE NOWAIT"
)
KEY_REVOKE_UPDATE = (
    "UPDATE coauthorization_keys SET status = 'REVOKED', revoked_at = COALESCE(revoked_at, %s) "
    "WHERE tenant_id = %s AND key_id = %s"
)
KEY_COMPROMISE_UPDATE = (
    "UPDATE coauthorization_keys SET status = 'COMPROMISED', compromised_at = COALESCE(compromised_at, %s) "
    "WHERE tenant_id = %s AND key_id = %s"
)
POLICY_REVOKE_UPDATE = (
    "UPDATE coauthorization_policies SET status = 'REVOKED' WHERE tenant_id = %s AND revision = %s"
)
APPLY_QUERY = "SELECT apply_coauthorization_revocation(%s, %s, %s, %s)"
RECORDED_QUERY = (
    "SELECT event.revocation_event_id, event.tenant_id, event.source_kind, "
    "event.source_identifier, event.observed_at, event.observation_context, "
    "event.database_actor, COUNT(root.root_credential_id), "
    "COUNT(root.root_credential_id) FILTER (WHERE root.root_revocation_created) "
    "FROM coauthorization_revocation_events AS event "
    "LEFT JOIN coauthorization_revocation_roots AS root USING (revocation_event_id) "
    "WHERE event.revocation_event_id = %s "
    "GROUP BY event.revocation_event_id, event.tenant_id, event.source_kind, "
    "event.source_identifier, event.observed_at, event.observation_context, event.database_actor"
)


@dataclass(frozen=True)
class _Step:
    sql: str
    parameters: tuple = ()
    row: object = None
    failure: Exception | None = None


class _FakeTransaction:
    def __init__(self, connection) -> None:
        self.connection = connection

    def __enter__(self):
        connection = self.connection
        assert connection.connection_active and not connection.transaction_active
        connection.transaction_active = True
        connection.markers.append("transaction-begin-marker")
        connection.events.append(("transaction-begin-marker",))
        return self

    def __exit__(self, _error_type, error, _traceback):
        connection = self.connection
        connection.transaction_active = False
        exit_error = error if error is not None else connection.transaction_exit_failure
        marker = "transaction-commit-marker" if exit_error is None else "transaction-rollback-marker"
        connection.markers.append(marker)
        connection.events.append((marker, exit_error))
        if error is None and exit_error is not None:
            raise exit_error
        return False


class _SqlConnection:
    def __init__(self, steps, events, *, transaction_exit_failure=None) -> None:
        self.steps = list(steps)
        self.events = events
        self.statements = []
        self.markers = []
        self.connection_active = False
        self.transaction_active = False
        self.transaction_exit_failure = transaction_exit_failure
        self.exit_errors = []
        self.expected_audit_ids = []
        self.captured_audit_ids = []

    def __enter__(self):
        assert not self.connection_active
        self.connection_active = True
        self.events.append(("connection-enter-marker",))
        return self

    def __exit__(self, _error_type, error, _traceback):
        assert not self.transaction_active
        self.connection_active = False
        self.exit_errors.append(error)
        self.events.append(("connection-exit-marker", error))
        return False

    def transaction(self):
        return _FakeTransaction(self)

    def execute(self, query, parameters=()):
        assert self.connection_active and self.transaction_active, "SQL escaped the fake transaction"
        sql = " ".join(query.split())
        assert self.steps, f"unexpected revocation SQL: {sql}"
        step = self.steps.pop(0)
        # Only whitespace normalization is allowed; no prefixes or catch-all SQL.
        assert sql == step.sql, f"unexpected revocation SQL: {sql}"
        assert parameters == step.parameters
        self.statements.append((sql, parameters))
        self.events.append(("sql", sql, parameters))
        if step.failure is not None:
            raise step.failure
        if sql == APPLY_QUERY and step.row is not None and type(step.row[0]) is int and 1 <= step.row[0] <= MAX_SAFE_INTEGER:
            self.expected_audit_ids.append(step.row[0])
        return SimpleNamespace(fetchone=lambda: deepcopy(step.row))

    def assert_consumed(self) -> None:
        assert self.steps == [], "expected revocation SQL was not reached"
        assert not self.connection_active and not self.transaction_active
        assert self.captured_audit_ids == self.expected_audit_ids


@pytest.fixture(autouse=True)
def forbid_live_boundaries(monkeypatch):
    for module, name in (
        (revocation, "connect"), (revocation, "SchemaStore"), (revocation, "enqueue_revocation_audit"),
        (cli, "revoke_coauthorization_source"),
    ):
        monkeypatch.setattr(module, name, Mock(side_effect=AssertionError("unconfigured live boundary")))
    monkeypatch.setattr(cli, "os", SimpleNamespace(environ={}))


def _context(source_kind):
    return "EXPLICIT_WITHDRAWAL" if source_kind == ROOT_WITHDRAWN else "REGISTRY_STATUS_UPDATE"


def _response(
    source_kind=ROOT_WITHDRAWN, source_identifier=ROOT_ID, *, event_id=EVENT_ID,
    observed_at=EVENT_OBSERVED_AT, matched=1, created=1,
):
    return {
        "schema_version": "1.0", "revocation_event_id": event_id, "tenant_id": TENANT_ID,
        "source_kind": source_kind, "source_identifier": source_identifier,
        "observed_at": observed_at, "observation_context": _context(source_kind),
        "database_actor": DATABASE_ACTOR, "matched_root_count": matched,
        "created_root_revocation_count": created, "status": "RECORDED",
    }


def _row(response):
    return tuple(response[field] for field in (
        "revocation_event_id", "tenant_id", "source_kind", "source_identifier", "observed_at",
        "observation_context", "database_actor", "matched_root_count", "created_root_revocation_count",
    ))


def _tail(response, *, recorded_row=None):
    return [
        _Step(APPLY_QUERY, (
            response["source_kind"], TENANT_ID, response["source_identifier"],
            _context(response["source_kind"]),
        ), (response["revocation_event_id"],)),
        _Step(RECORDED_QUERY, (response["revocation_event_id"],),
              _row(response) if recorded_row is None else recorded_row),
    ]


def _case(
    monkeypatch, steps, *, source_kind=ROOT_WITHDRAWN, source_identifier=ROOT_ID,
    request_updates=None, schema_failures=None, transaction_exit_failure=None,
):
    events = []
    document = {"tenant_id": TENANT_ID, "source_kind": source_kind, "source_identifier": source_identifier}
    document.update(request_updates or {})
    connection = _SqlConnection(steps, events, transaction_exit_failure=transaction_exit_failure)
    schemas = Mock(spec=["validate"])

    def validate(schema_name, _document):
        events.append(("schema", schema_name, connection.connection_active, connection.transaction_active))
        if schema_name in (schema_failures or {}):
            raise schema_failures[schema_name]

    def schema_store(root):
        events.append(("schema-store", root))
        return schemas

    def connect(database_url):
        events.append(("connect", database_url))
        return connection

    def capture_revocation_audit(actual_connection, event_id):
        assert actual_connection is connection
        assert connection.connection_active and connection.transaction_active
        assert connection.statements[-1][0] == APPLY_QUERY
        assert type(event_id) is int and 1 <= event_id <= MAX_SAFE_INTEGER
        assert connection.expected_audit_ids[-1] == event_id
        connection.captured_audit_ids.append(event_id)
        events.append(("revocation-audit-capture", event_id, True, True))

    schemas.validate.side_effect = validate
    schema_factory = Mock(side_effect=schema_store)
    connector = Mock(side_effect=connect)
    monkeypatch.setattr(revocation, "SchemaStore", schema_factory)
    monkeypatch.setattr(revocation, "connect", connector)
    capture = Mock(side_effect=capture_revocation_audit)
    monkeypatch.setattr(revocation, "enqueue_revocation_audit", capture)
    return SimpleNamespace(
        document=document, connection=connection, events=events,
        schemas=schemas, schema_factory=schema_factory, connect=connector,
        audit_capture=capture,
    )


def _invoke(case):
    return revocation.revoke_coauthorization_source(DATABASE_URL, **case.document)


def _assert_recorded(case, response) -> None:
    case.connect.assert_called_once_with(DATABASE_URL)
    case.schema_factory.assert_called_once_with(revocation.EXTENSION_SCHEMA_ROOT)
    assert case.schemas.validate.call_args_list == [
        call(REQUEST_SCHEMA, case.document), call(RESPONSE_SCHEMA, response),
    ]
    assert case.events[:3] == [
        ("schema-store", revocation.EXTENSION_SCHEMA_ROOT),
        ("schema", REQUEST_SCHEMA, False, False), ("connect", DATABASE_URL),
    ]
    assert case.events[-3:] == [
        ("schema", RESPONSE_SCHEMA, True, True), ("transaction-commit-marker", None),
        ("connection-exit-marker", None),
    ]
    assert case.connection.markers == ["transaction-begin-marker", "transaction-commit-marker"]
    case.connection.assert_consumed()
    case.audit_capture.assert_called_once_with(case.connection, response["revocation_event_id"])


def _assert_rejected(case, reason_code):
    with pytest.raises(revocation.CoauthorizationRevocationError) as captured:
        _invoke(case)
    assert captured.value.reason_code == reason_code
    assert case.connection.markers == ["transaction-begin-marker", "transaction-rollback-marker"]
    assert case.connection.exit_errors == [captured.value]
    case.connection.assert_consumed()
    return captured.value


@pytest.mark.parametrize("source_kind,prior_status,update", [
    (KEY_REVOKED, "ACTIVE", KEY_REVOKE_UPDATE),
    (KEY_REVOKED, "RETIRED", KEY_REVOKE_UPDATE),
    (KEY_COMPROMISED, "ACTIVE", KEY_COMPROMISE_UPDATE),
    (KEY_COMPROMISED, "RETIRED", KEY_COMPROMISE_UPDATE),
    (KEY_COMPROMISED, "REVOKED", KEY_COMPROMISE_UPDATE),
])
def test_key_lifecycle_change_locks_nowait_then_samples_clock_and_preserves_old_timestamp(
    monkeypatch, source_kind, prior_status, update,
) -> None:
    expected = _response(source_kind, KEY_ID, matched=3, created=2)
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(KEY_LOCK_QUERY, (TENANT_ID, KEY_ID), (prior_status, ACTIVATED_AT)),
        _Step(CLOCK_QUERY, row=(KEY_CHANGE_AT,)),
        _Step(update, (KEY_CHANGE_AT, TENANT_ID, KEY_ID)),
        *_tail(expected),
    ], source_kind=source_kind, source_identifier=KEY_ID)

    assert _invoke(case) == expected

    _assert_recorded(case, expected)
    assert expected["observed_at"] != KEY_CHANGE_AT  # Return the event observation, not the key clock.


@pytest.mark.parametrize("prior_status", ["ACTIVE", "RETIRED"])
def test_policy_revocation_locks_nowait_before_status_update_and_records_counts(monkeypatch, prior_status) -> None:
    expected = _response(POLICY_REVOKED, POLICY_REVISION, matched=2, created=1)
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(POLICY_LOCK_QUERY, (TENANT_ID, POLICY_REVISION), (prior_status,)),
        _Step(POLICY_REVOKE_UPDATE, (TENANT_ID, POLICY_REVISION)),
        *_tail(expected),
    ], source_kind=POLICY_REVOKED, source_identifier=POLICY_REVISION)

    assert _invoke(case) == expected

    _assert_recorded(case, expected)
    assert CLOCK_QUERY not in [sql for sql, _ in case.connection.statements]


def test_single_root_withdrawal_uses_explicit_context_without_changing_key_or_policy(monkeypatch) -> None:
    expected = _response()
    case = _case(monkeypatch, [_Step(SET_READ_COMMITTED), *_tail(expected)])

    assert _invoke(case) == expected

    _assert_recorded(case, expected)
    assert case.connection.statements == [
        (SET_READ_COMMITTED, ()),
        (APPLY_QUERY, (ROOT_WITHDRAWN, TENANT_ID, ROOT_ID, "EXPLICIT_WITHDRAWAL")),
        (RECORDED_QUERY, (EVENT_ID,)),
    ]


@pytest.mark.parametrize("source_kind,identifier", [
    (KEY_REVOKED, KEY_ID), (KEY_COMPROMISED, KEY_ID),
    (POLICY_REVOKED, POLICY_REVISION), (ROOT_WITHDRAWN, ROOT_ID),
])
def test_same_target_retry_reuses_old_observation_and_does_not_rewrite_lifecycle(
    monkeypatch, source_kind, identifier,
) -> None:
    expected = _response(source_kind, identifier, matched=2, created=1)
    first, repeat = [_Step(SET_READ_COMMITTED)], [_Step(SET_READ_COMMITTED)]
    if source_kind in (KEY_REVOKED, KEY_COMPROMISED):
        status, update = ("REVOKED", KEY_REVOKE_UPDATE) if source_kind == KEY_REVOKED else (
            "COMPROMISED", KEY_COMPROMISE_UPDATE,
        )
        first.extend([
            _Step(KEY_LOCK_QUERY, (TENANT_ID, identifier), ("ACTIVE", ACTIVATED_AT)),
            _Step(CLOCK_QUERY, row=(KEY_CHANGE_AT,)),
            _Step(update, (KEY_CHANGE_AT, TENANT_ID, identifier)),
        ])
        repeat.append(_Step(KEY_LOCK_QUERY, (TENANT_ID, identifier), (status, ACTIVATED_AT)))
    elif source_kind == POLICY_REVOKED:
        first.extend([
            _Step(POLICY_LOCK_QUERY, (TENANT_ID, identifier), ("ACTIVE",)),
            _Step(POLICY_REVOKE_UPDATE, (TENANT_ID, identifier)),
        ])
        repeat.append(_Step(POLICY_LOCK_QUERY, (TENANT_ID, identifier), ("REVOKED",)))
    case = _case(monkeypatch, [*first, *_tail(expected), *repeat, *_tail(expected)],
                 source_kind=source_kind, source_identifier=identifier)

    initial = _invoke(case)
    repeated = _invoke(case)

    assert initial == repeated == expected
    assert repeated["observed_at"] == EVENT_OBSERVED_AT
    assert repeated["created_root_revocation_count"] == 1  # Historical count, not new writes on retry.
    assert case.schemas.validate.call_args_list == [
        call(REQUEST_SCHEMA, case.document), call(RESPONSE_SCHEMA, expected),
        call(REQUEST_SCHEMA, case.document), call(RESPONSE_SCHEMA, expected),
    ]
    assert case.connect.call_args_list == [call(DATABASE_URL), call(DATABASE_URL)]
    assert case.connection.statements[len(first) + 2:] == [
        (step.sql, step.parameters) for step in [*repeat, *_tail(expected)]
    ]
    assert case.connection.markers == [
        "transaction-begin-marker", "transaction-commit-marker",
        "transaction-begin-marker", "transaction-commit-marker",
    ]
    case.connection.assert_consumed()


def test_compromised_key_cannot_be_downgraded_to_revoked(monkeypatch) -> None:
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(KEY_LOCK_QUERY, (TENANT_ID, KEY_ID), ("COMPROMISED", ACTIVATED_AT)),
    ], source_kind=KEY_REVOKED, source_identifier=KEY_ID)

    _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)


@pytest.mark.parametrize("source_kind,identifier,query", [
    (KEY_REVOKED, KEY_ID, KEY_LOCK_QUERY), (KEY_COMPROMISED, KEY_ID, KEY_LOCK_QUERY),
    (POLICY_REVOKED, POLICY_REVISION, POLICY_LOCK_QUERY),
])
def test_missing_source_is_not_found_before_clock_update_or_event(monkeypatch, source_kind, identifier, query) -> None:
    case = _case(monkeypatch, [_Step(SET_READ_COMMITTED), _Step(query, (TENANT_ID, identifier))],
                 source_kind=source_kind, source_identifier=identifier)

    _assert_rejected(case, "COAUTH_REVOCATION_NOT_FOUND")

    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)


@pytest.mark.parametrize("source_kind,identifier,query,row", [
    (KEY_REVOKED, KEY_ID, KEY_LOCK_QUERY, ("UNKNOWN", ACTIVATED_AT)),
    (KEY_COMPROMISED, KEY_ID, KEY_LOCK_QUERY, (None, ACTIVATED_AT)),
    (POLICY_REVOKED, POLICY_REVISION, POLICY_LOCK_QUERY, ("COMPROMISED",)),
    (POLICY_REVOKED, POLICY_REVISION, POLICY_LOCK_QUERY, ("UNKNOWN",)),
])
def test_invalid_source_lifecycle_stops_before_any_update_or_event(
    monkeypatch, source_kind, identifier, query, row,
) -> None:
    case = _case(monkeypatch, [_Step(SET_READ_COMMITTED), _Step(query, (TENANT_ID, identifier), row)],
                 source_kind=source_kind, source_identifier=identifier)

    _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)


@pytest.mark.parametrize("updates", [
    {"tenant_id": ""}, {"tenant_id": "x" * 129},
    {"source_identifier": ""}, {"source_identifier": "invalid identifier"},
    {"source_kind": "UNKNOWN"},
])
def test_mock_schema_rejection_happens_before_connection(monkeypatch, updates) -> None:
    error = ValidationError("synthetic request schema rejection")
    case = _case(monkeypatch, [], request_updates=updates, schema_failures={REQUEST_SCHEMA: error})

    with pytest.raises(revocation.CoauthorizationRevocationError) as captured:
        _invoke(case)

    assert captured.value.reason_code == "COAUTH_REVOCATION_INVALID_REQUEST"
    assert captured.value.__cause__ is error
    case.connect.assert_not_called()
    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)
    assert case.connection.statements == case.connection.markers == []
    assert case.events == [
        ("schema-store", revocation.EXTENSION_SCHEMA_ROOT), ("schema", REQUEST_SCHEMA, False, False),
    ]


@pytest.mark.parametrize("source_kind", [KEY_REVOKED, KEY_COMPROMISED])
@pytest.mark.parametrize("clock_row", [
    None, (None,), (True,), (False,), (KEY_CHANGE_AT * 1.0,), (str(KEY_CHANGE_AT),),
    (float("nan"),), (float("inf"),), (-1,), (MAX_SAFE_INTEGER + 1,),
])
def test_unsafe_clock_rejects_key_transition_before_lifecycle_write_or_event(
    monkeypatch, source_kind, clock_row,
) -> None:
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(KEY_LOCK_QUERY, (TENANT_ID, KEY_ID), ("ACTIVE", ACTIVATED_AT)),
        _Step(CLOCK_QUERY, row=clock_row),
    ], source_kind=source_kind, source_identifier=KEY_ID)

    _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)


@pytest.mark.parametrize("source_kind,update", [
    (KEY_REVOKED, KEY_REVOKE_UPDATE), (KEY_COMPROMISED, KEY_COMPROMISE_UPDATE),
])
@pytest.mark.parametrize("clock,activated_at", [
    (0, 0), (KEY_CHANGE_AT, KEY_CHANGE_AT), (MAX_SAFE_INTEGER, 0), (MAX_SAFE_INTEGER, MAX_SAFE_INTEGER),
])
def test_safe_clock_and_activation_accept_inclusive_boundaries(monkeypatch, source_kind, update, clock, activated_at) -> None:
    expected = _response(source_kind, KEY_ID, observed_at=clock)
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(KEY_LOCK_QUERY, (TENANT_ID, KEY_ID), ("ACTIVE", activated_at)),
        _Step(CLOCK_QUERY, row=(clock,)), _Step(update, (clock, TENANT_ID, KEY_ID)),
        *_tail(expected),
    ], source_kind=source_kind, source_identifier=KEY_ID)

    assert _invoke(case) == expected

    _assert_recorded(case, expected)


@pytest.mark.parametrize("source_kind", [KEY_REVOKED, KEY_COMPROMISED])
@pytest.mark.parametrize("activated_at", [
    None, True, False, -1, KEY_CHANGE_AT * 1.0, str(KEY_CHANGE_AT), KEY_CHANGE_AT + 1, MAX_SAFE_INTEGER + 1,
])
def test_invalid_or_future_activation_stops_after_clock_before_lifecycle_write(
    monkeypatch, source_kind, activated_at,
) -> None:
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(KEY_LOCK_QUERY, (TENANT_ID, KEY_ID), ("ACTIVE", activated_at)),
        _Step(CLOCK_QUERY, row=(KEY_CHANGE_AT,)),
    ], source_kind=source_kind, source_identifier=KEY_ID)

    _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)


@pytest.mark.parametrize("event_row", [
    None, (None,), (True,), (False,), (0,), (-1,), (EVENT_ID * 1.0,), (str(EVENT_ID),),
    (float("nan"),), (float("inf"),), (MAX_SAFE_INTEGER + 1,),
])
def test_missing_or_unsafe_event_id_stops_before_response_read(monkeypatch, event_row) -> None:
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(APPLY_QUERY, (ROOT_WITHDRAWN, TENANT_ID, ROOT_ID, "EXPLICIT_WITHDRAWAL"), event_row),
    ])

    _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)


@pytest.mark.parametrize("event_id", [1, MAX_SAFE_INTEGER])
def test_event_id_accepts_positive_safe_integer_boundaries(monkeypatch, event_id) -> None:
    expected = _response(event_id=event_id)
    case = _case(monkeypatch, [_Step(SET_READ_COMMITTED), *_tail(expected)])

    assert _invoke(case) == expected

    _assert_recorded(case, expected)


@pytest.mark.parametrize("index", [0, 4, 7, 8])
@pytest.mark.parametrize("value", [
    None, True, False, -1, MAX_SAFE_INTEGER + 1, 1.0, "1", float("nan"), float("inf"),
])
def test_observation_numeric_fields_reject_noninteger_boolean_negative_or_unsafe_values(
    monkeypatch, index, value,
) -> None:
    expected = _response()
    row = list(_row(expected))
    row[index] = value
    case = _case(monkeypatch, [_Step(SET_READ_COMMITTED), *_tail(expected, recorded_row=tuple(row))])

    _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)


@pytest.mark.parametrize("mutation", ["missing", "event-id", "created-exceeds-matched"])
def test_missing_or_inconsistent_observation_cannot_be_reported_recorded(monkeypatch, mutation) -> None:
    expected = _response()
    row = list(_row(expected))
    if mutation == "event-id":
        row[0] = EVENT_ID + 1
    elif mutation == "created-exceeds-matched":
        row[7], row[8] = 0, 1
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED), _tail(expected)[0],
        _Step(RECORDED_QUERY, (EVENT_ID,), None if mutation == "missing" else tuple(row)),
    ])

    _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)


@pytest.mark.parametrize("matched,created", [(0, 0), (1, 0), (3, 2), (MAX_SAFE_INTEGER, 0), (MAX_SAFE_INTEGER, MAX_SAFE_INTEGER)])
def test_recorded_response_preserves_safe_historical_counts_and_exact_fields(monkeypatch, matched, created) -> None:
    expected = _response(POLICY_REVOKED, POLICY_REVISION, matched=matched, created=created)
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(POLICY_LOCK_QUERY, (TENANT_ID, POLICY_REVISION), ("REVOKED",)),
        *_tail(expected),
    ], source_kind=POLICY_REVOKED, source_identifier=POLICY_REVISION)

    result = _invoke(case)

    assert result == expected
    assert set(result) == {
        "schema_version", "revocation_event_id", "tenant_id", "source_kind", "source_identifier",
        "observed_at", "observation_context", "database_actor", "matched_root_count",
        "created_root_revocation_count", "status",
    }
    _assert_recorded(case, expected)


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "different-tenant"), ("source_kind", POLICY_REVOKED), ("source_identifier", "other-root"),
])
def test_response_target_binding_is_checked_even_when_mock_schema_accepts(monkeypatch, field, value) -> None:
    expected = _response()
    mismatched = {**expected, field: value}
    case = _case(monkeypatch, [_Step(SET_READ_COMMITTED), *_tail(expected, recorded_row=_row(mismatched))])

    _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    assert case.schemas.validate.call_args_list == [
        call(REQUEST_SCHEMA, case.document), call(RESPONSE_SCHEMA, mismatched),
    ]


def test_response_schema_rejection_is_invalid_state_and_aborts_return(monkeypatch) -> None:
    expected = _response()
    error = ValidationError("synthetic response schema rejection")
    case = _case(monkeypatch, [_Step(SET_READ_COMMITTED), *_tail(expected)],
                 schema_failures={RESPONSE_SCHEMA: error})

    captured = _assert_rejected(case, "COAUTH_REVOCATION_INVALID_STATE")

    assert captured.__cause__ is error
    assert case.schemas.validate.call_args_list == [
        call(REQUEST_SCHEMA, case.document), call(RESPONSE_SCHEMA, expected),
    ]


def _failure_plan(stage, error):
    is_policy = stage in ("policy-lock", "policy-update")
    source_kind, identifier = (POLICY_REVOKED, POLICY_REVISION) if is_policy else (KEY_REVOKED, KEY_ID)
    prefix = [
        _Step(SET_READ_COMMITTED),
        _Step(POLICY_LOCK_QUERY, (TENANT_ID, identifier), ("ACTIVE",)),
        _Step(POLICY_REVOKE_UPDATE, (TENANT_ID, identifier)),
    ] if is_policy else [
        _Step(SET_READ_COMMITTED),
        _Step(KEY_LOCK_QUERY, (TENANT_ID, identifier), ("ACTIVE", ACTIVATED_AT)),
        _Step(CLOCK_QUERY, row=(KEY_CHANGE_AT,)),
        _Step(KEY_REVOKE_UPDATE, (KEY_CHANGE_AT, TENANT_ID, identifier)),
    ]
    expected = _response(source_kind, identifier, matched=2, created=1)
    steps = [*prefix, *_tail(expected)]
    if stage != "transaction-exit":
        query = {
            "isolation": SET_READ_COMMITTED, "key-lock": KEY_LOCK_QUERY, "policy-lock": POLICY_LOCK_QUERY,
            "clock": CLOCK_QUERY, "key-update": KEY_REVOKE_UPDATE, "policy-update": POLICY_REVOKE_UPDATE,
            "apply": APPLY_QUERY, "response-read": RECORDED_QUERY,
        }[stage]
        index = next(index for index, step in enumerate(steps) if step.sql == query)
        selected = steps[index]
        steps = [*steps[:index], _Step(selected.sql, selected.parameters, failure=error)]
    return steps, source_kind, identifier, expected


@pytest.mark.parametrize("error_type", [errors.LockNotAvailable, errors.DeadlockDetected, errors.SerializationFailure])
@pytest.mark.parametrize("stage", [
    "isolation", "key-lock", "policy-lock", "clock", "key-update", "policy-update", "apply",
    "response-read", "transaction-exit",
])
def test_busy_errors_are_mapped_only_after_transaction_and_connection_exit(monkeypatch, error_type, stage) -> None:
    error = error_type("synthetic busy error")
    steps, source_kind, identifier, _expected = _failure_plan(stage, error)
    case = _case(monkeypatch, steps, source_kind=source_kind, source_identifier=identifier,
                 transaction_exit_failure=error if stage == "transaction-exit" else None)
    original = revocation.CoauthorizationRevocationError

    class ObservedError(original):
        def __init__(self, reason_code, message):
            case.events.append(("mapped-error", reason_code,
                                case.connection.connection_active, case.connection.transaction_active))
            super().__init__(reason_code, message)

    monkeypatch.setattr(revocation, "CoauthorizationRevocationError", ObservedError)

    with pytest.raises(ObservedError) as captured:
        _invoke(case)

    assert captured.value.reason_code == "COAUTH_REVOCATION_BUSY"
    assert captured.value.__cause__ is error
    assert case.events[-3:] == [
        ("transaction-rollback-marker", error), ("connection-exit-marker", error),
        ("mapped-error", "COAUTH_REVOCATION_BUSY", False, False),
    ]
    assert case.connection.exit_errors == [error]
    assert case.connection.markers == ["transaction-begin-marker", "transaction-rollback-marker"]
    case.connection.assert_consumed()


@pytest.mark.parametrize("error_type,reason_code", [
    (errors.InvalidParameterValue, "COAUTH_REVOCATION_INVALID_STATE"),
    (OperationalError, "COAUTH_REVOCATION_UNAVAILABLE"),
    (errors.UndefinedTable, "COAUTH_REVOCATION_UNAVAILABLE"),
    (errors.UndefinedFunction, "COAUTH_REVOCATION_UNAVAILABLE"),
])
def test_database_state_or_storage_errors_preserve_cause_after_fake_rollback(monkeypatch, error_type, reason_code) -> None:
    error = error_type("synthetic database boundary error")
    case = _case(monkeypatch, [
        _Step(SET_READ_COMMITTED),
        _Step(APPLY_QUERY, (ROOT_WITHDRAWN, TENANT_ID, ROOT_ID, "EXPLICIT_WITHDRAWAL"), failure=error),
    ])

    with pytest.raises(revocation.CoauthorizationRevocationError) as captured:
        _invoke(case)

    assert captured.value.reason_code == reason_code
    assert captured.value.__cause__ is error
    assert case.events[-2:] == [("transaction-rollback-marker", error), ("connection-exit-marker", error)]
    case.connection.assert_consumed()


def test_connection_failure_is_unavailable_without_entering_a_transaction(monkeypatch) -> None:
    case = _case(monkeypatch, [])
    error = OperationalError("synthetic connection failure")
    case.connect.side_effect = error

    with pytest.raises(revocation.CoauthorizationRevocationError) as captured:
        _invoke(case)

    assert captured.value.reason_code == "COAUTH_REVOCATION_UNAVAILABLE"
    assert captured.value.__cause__ is error
    case.schemas.validate.assert_called_once_with(REQUEST_SCHEMA, case.document)
    case.connect.assert_called_once_with(DATABASE_URL)
    assert case.connection.statements == case.connection.markers == []


def _cli_setup(monkeypatch, arguments, operation, *, environment=None):
    monkeypatch.setattr(sys, "argv", ["revoke_coauthorization.py", *arguments])
    monkeypatch.setattr(cli, "os", SimpleNamespace(environ={DATABASE_ENV: DATABASE_URL} if environment is None else environment))
    monkeypatch.setattr(cli, "revoke_coauthorization_source", operation)


def _cli_arguments(target="--withdraw-root-id", identifier=ROOT_ID):
    return ["--tenant-id", TENANT_ID, "--confirm-revocation", target, identifier]


@pytest.mark.parametrize("target,identifier,extra,source_kind", [
    ("--approval-key-id", KEY_ID, [], KEY_REVOKED),
    ("--approval-key-id", KEY_ID, ["--compromised"], KEY_COMPROMISED),
    ("--policy-revision", POLICY_REVISION, [], POLICY_REVOKED),
    ("--withdraw-root-id", ROOT_ID, [], ROOT_WITHDRAWN),
])
def test_cli_dispatches_confirmed_target_and_prints_only_returned_response(
    monkeypatch, capsys, target, identifier, extra, source_kind,
) -> None:
    expected = _response(source_kind, identifier)
    operation = Mock(return_value=expected)
    _cli_setup(monkeypatch, [*_cli_arguments(target, identifier), *extra], operation)

    assert cli.main() is None

    operation.assert_called_once_with(DATABASE_URL, tenant_id=TENANT_ID,
                                      source_kind=source_kind, source_identifier=identifier)
    captured = capsys.readouterr()
    assert captured.out == json.dumps(expected, ensure_ascii=True, sort_keys=True) + "\n"
    assert json.loads(captured.out) == expected
    assert captured.err == ""


@pytest.mark.parametrize("arguments", [
    ["--tenant-id", TENANT_ID, "--withdraw-root-id", ROOT_ID],
    ["--confirm-revocation", "--withdraw-root-id", ROOT_ID],
    ["--tenant-id", TENANT_ID, "--confirm-revocation"],
    ["--tenant-id", TENANT_ID, "--confirm-revocation", "--approval-key-id", KEY_ID, "--policy-revision", POLICY_REVISION],
    ["--tenant-id", TENANT_ID, "--confirm-revocation", "--approval-key-id", KEY_ID, "--withdraw-root-id", ROOT_ID],
    ["--tenant-id", TENANT_ID, "--confirm-revocation", "--policy-revision", POLICY_REVISION, "--withdraw-root-id", ROOT_ID],
    ["--tenant-id", TENANT_ID, "--confirm-revocation", "--policy-revision", POLICY_REVISION, "--compromised"],
    ["--tenant-id", TENANT_ID, "--confirm-revocation", "--withdraw-root-id", ROOT_ID, "--compromised"],
])
def test_cli_invalid_or_unconfirmed_arguments_stop_before_environment_or_operation(monkeypatch, capsys, arguments) -> None:
    environment = Mock(spec=["get"])
    environment.get.side_effect = AssertionError("invalid arguments must precede environment lookup")
    operation = Mock(side_effect=AssertionError("invalid arguments must not revoke"))
    _cli_setup(monkeypatch, arguments, operation, environment=environment)

    with pytest.raises(SystemExit) as captured:
        cli.main()

    assert captured.value.code == 2
    environment.get.assert_not_called()
    operation.assert_not_called()
    output = capsys.readouterr()
    assert output.out == "" and "RECORDED" not in output.err


@pytest.mark.parametrize("environment", [{}, {DATABASE_ENV: ""}])
def test_cli_missing_database_environment_stops_before_operation(monkeypatch, capsys, environment) -> None:
    operation = Mock(side_effect=AssertionError("missing environment must not revoke"))
    _cli_setup(monkeypatch, _cli_arguments(), operation, environment=environment)

    with pytest.raises(SystemExit) as captured:
        cli.main()

    assert captured.value.code == 2
    operation.assert_not_called()
    output = capsys.readouterr()
    assert output.out == ""
    assert "AGENTGUARD_DATABASE_URL must identify the intended administrative database role" in output.err
    assert "RECORDED" not in output.err


@pytest.mark.parametrize("error_type,reason_code", [
    (errors.LockNotAvailable, "COAUTH_REVOCATION_BUSY"),
    (errors.DeadlockDetected, "COAUTH_REVOCATION_BUSY"),
    (errors.SerializationFailure, "COAUTH_REVOCATION_BUSY"),
    (OperationalError, "COAUTH_REVOCATION_UNAVAILABLE"),
    (RuntimeError, None),
])
def test_cli_cannot_print_recorded_when_transaction_exit_fails_after_response_validation(
    monkeypatch, capsys, error_type, reason_code,
) -> None:
    expected = _response()
    error = error_type("synthetic transaction exit failure")
    case = _case(monkeypatch, [_Step(SET_READ_COMMITTED), *_tail(expected)], transaction_exit_failure=error)
    _cli_setup(monkeypatch, _cli_arguments(), revocation.revoke_coauthorization_source)
    expected_error = revocation.CoauthorizationRevocationError if reason_code else RuntimeError

    with pytest.raises(expected_error) as captured:
        cli.main()

    if reason_code:
        assert captured.value.reason_code == reason_code
        assert captured.value.__cause__ is error
    else:
        assert captured.value is error
    assert case.schemas.validate.call_args_list == [
        call(REQUEST_SCHEMA, case.document), call(RESPONSE_SCHEMA, expected),
    ]
    assert case.events[-2:] == [("transaction-rollback-marker", error), ("connection-exit-marker", error)]
    assert case.connection.markers == ["transaction-begin-marker", "transaction-rollback-marker"]
    case.connection.assert_consumed()
    output = capsys.readouterr()
    assert output.out == output.err == ""


@pytest.mark.parametrize("reason_code", [
    "COAUTH_REVOCATION_INVALID_REQUEST", "COAUTH_REVOCATION_NOT_FOUND", "COAUTH_REVOCATION_INVALID_STATE",
    "COAUTH_REVOCATION_BUSY", "COAUTH_REVOCATION_UNAVAILABLE",
])
def test_cli_operation_error_cannot_print_a_recorded_response(monkeypatch, capsys, reason_code) -> None:
    error = revocation.CoauthorizationRevocationError(reason_code, "synthetic rejected operation")
    operation = Mock(side_effect=error)
    _cli_setup(monkeypatch, _cli_arguments(), operation)

    with pytest.raises(revocation.CoauthorizationRevocationError) as captured:
        cli.main()

    assert captured.value is error
    operation.assert_called_once()
    output = capsys.readouterr()
    assert output.out == output.err == ""


@pytest.mark.parametrize("typed_error", [False, True])
def test_cli_script_guard_exits_without_recorded_and_sanitizes_unexpected_errors(monkeypatch, capsys, typed_error) -> None:
    error = revocation.CoauthorizationRevocationError("COAUTH_REVOCATION_BUSY", "synthetic busy") if typed_error else (
        RuntimeError("synthetic diagnostic marker must not be echoed")
    )
    operation = Mock(side_effect=error)
    monkeypatch.setattr(revocation, "revoke_coauthorization_source", operation)
    monkeypatch.setattr(sys, "argv", ["revoke_coauthorization.py", *_cli_arguments()])
    monkeypatch.setattr(os, "environ", {DATABASE_ENV: DATABASE_URL})

    # This source is only executed when the user runs the tests; all operation I/O is mocked.
    with pytest.raises(SystemExit) as captured:
        runpy.run_path(cli.__file__, run_name="__main__")

    if typed_error:
        assert captured.value.code == "COAUTH_REVOCATION_BUSY: synthetic busy"
    else:
        assert captured.value.code == (
            "COAUTH_REVOCATION_FAILED: no verified result; check migrations 0019/0020, target state and database permissions"
        )
    assert "RECORDED" not in captured.value.code
    assert "synthetic diagnostic marker" not in captured.value.code
    assert captured.value.__suppress_context__ is True
    operation.assert_called_once_with(DATABASE_URL, tenant_id=TENANT_ID,
                                      source_kind=ROOT_WITHDRAWN, source_identifier=ROOT_ID)
    output = capsys.readouterr()
    assert output.out == output.err == ""
