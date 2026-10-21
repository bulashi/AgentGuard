"""Recovery result-binding regression sources, authored without running or collecting.

All rows, response bodies, identifiers, hashes, and clocks below are synthetic.
Connections and HTTP clients are fakes; no settings, environment, or key files
are loaded. Transition mocks check routing and arguments, not durable budget
accounting, PostgreSQL locking, cryptography, or runtime acceptance.
"""

from __future__ import annotations

from copy import deepcopy
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock, call

import pytest
from pydantic import ValidationError

import backend.recovery.service as recovery_module
from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import InternalAuthenticator
from backend.crypto.canonical_json import canonicalize
from backend.recovery.service import RecoveryService
from backend.tools.contracts import ReconcileResponse

DATABASE_URL = "mock-recovery-binding-database"
TOOL_URL = "http://recovery-tool.invalid"
CURRENT_TIME = 1_000
MISSING = object()
BINDING_FIELDS = (
    "execution_id",
    "tenant_id",
    "task_id",
    "business_action_id",
    "business_idempotency_key",
    "parameter_hash",
)
EVIDENCE_FIELDS = ("parameter_hash", "result", "business_effect_id")
TOOL_IDENTITIES = {
    "refund": ("refund-service", "refund.create", "refund_id", "REFUND-BOUND"),
    "notification": (
        "notification-service", "notification.send_template", "notification_id", "NOTIFY-BOUND",
    ),
}
INVALID_RESPONSE_CASES = [
    *[
        pytest.param(
            "ALREADY_EXECUTED", field, replacement,
            id=f"executed-{field}-{label}",
        )
        for field in EVIDENCE_FIELDS
        for replacement, label in ((MISSING, "missing"), (None, "null"))
    ],
    *[
        pytest.param(status, field, value, id=f"{status}-{field}-present")
        for status in ("NOT_EXECUTED", "UNKNOWN")
        for field, value in (
            ("parameter_hash", "a" * 64),
            ("result", {}),
            ("business_effect_id", "EFFECT-UNCONFIRMED"),
        )
    ],
    *[
        pytest.param("ALREADY_EXECUTED", field, value, id=f"strict-{field}")
        for field, value in (
            ("schema_version", 1.0),
            ("execution_id", 123),
            ("status", 123),
            ("parameter_hash", 123),
            ("result", []),
            ("business_effect_id", 123),
            ("reason_code", 123),
        )
    ],
    pytest.param("ALREADY_EXECUTED", "unexpected", True, id="forbidden-extra"),
    pytest.param("ALREADY_EXECUTED", "status", "EXECUTED", id="invalid-status"),
    pytest.param("ALREADY_EXECUTED", "schema_version", "2.0", id="invalid-version"),
    pytest.param("ALREADY_EXECUTED", "execution_id", "bad id", id="invalid-execution-id"),
    pytest.param("ALREADY_EXECUTED", "parameter_hash", "A" * 64, id="invalid-hash"),
    pytest.param("ALREADY_EXECUTED", "business_effect_id", "bad id", id="invalid-effect-id"),
]


def _execution(kind: str) -> dict[str, Any]:
    tool_service, tool_name, _, _ = TOOL_IDENTITIES[kind]
    return {
        "execution_id": "EXEC-BOUND",
        "request_hash": "1" * 64,
        "credential_chain_hash": "2" * 64,
        "tenant_id": "TENANT-BOUND",
        "task_id": "TASK-BOUND",
        "tool_service": tool_service,
        "tool_name": tool_name,
        "tool_version": "v1",
        "parameter_hash": "a" * 64,
        "state": "RECONCILING",
        "decision": "ALLOW",
        "reason_code": ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
        "business_action_id": "ACTION-BOUND",
        "business_idempotency_key": "b" * 64,
        "result": None,
        "business_effect_id": None,
        "business_result_hash": None,
        "updated_at": CURRENT_TIME - 1,
    }


def _response_body(
    row: dict[str, Any], kind: str, status: str = "ALREADY_EXECUTED",
) -> dict[str, Any]:
    _, _, effect_field, effect_id = TOOL_IDENTITIES[kind]
    result = {field: row[field] for field in BINDING_FIELDS}
    result.update({effect_field: effect_id, "customer_id": "CUSTOMER-BOUND"})
    result["created_at"] = CURRENT_TIME - 10
    if kind == "refund":
        result.update({"ticket_id": "TICKET-BOUND", "amount_fen": 7000, "status": "COMMITTED"})
    else:
        result.update({
            "template_id": "REFUND_SUCCESS",
            "related_business_effect_id": "REFUND-RELATED",
            "status": "SENT",
        })
    body = {
        "schema_version": "1.0",
        "execution_id": row["execution_id"],
        "status": status,
        "parameter_hash": row["parameter_hash"],
        "result": result,
        "business_effect_id": effect_id,
        "reason_code": ReasonCode.ALLOWED.value,
    }
    if status in {"NOT_EXECUTED", "UNKNOWN"}:
        body.update(dict.fromkeys(EVIDENCE_FIELDS))
    if status == "UNKNOWN":
        body["reason_code"] = ReasonCode.TOOL_EXECUTION_UNKNOWN.value
    elif status == "IDEMPOTENCY_CONFLICT":
        body["reason_code"] = ReasonCode.IDEMPOTENCY_CONFLICT.value
    return body


@pytest.fixture(autouse=True)
def forbid_live_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recovery_module, "connect",
        Mock(side_effect=AssertionError("unit sources must not open a real database")),
    )
    monkeypatch.setattr(
        recovery_module.httpx, "Client",
        Mock(side_effect=AssertionError("unit sources must not make real HTTP requests")),
    )
    monkeypatch.setattr(
        recovery_module, "now_unix",
        Mock(side_effect=AssertionError("unit sources must supply the clock explicitly")),
    )


def _harness(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    *,
    recovery: tuple[int, int, int] = (1, 3, CURRENT_TIME + 300),
) -> SimpleNamespace:
    prepared = _execution(kind)
    locked = deepcopy(prepared)
    subject = RecoveryService(
        DATABASE_URL,
        internal_auth=InternalAuthenticator(
            service_id="recovery-worker", keys_json="{}", required=False,
        ),
        tool_urls={(prepared["tool_service"], prepared["tool_name"]): TOOL_URL},
    )
    connection = MagicMock(
        name="recovery-binding-connection",
        spec=["__enter__", "__exit__", "transaction", "execute"],
    )
    connection.__enter__.return_value = connection
    connection.__exit__.return_value = False
    connection.transaction.return_value.__exit__.return_value = False

    def execute(sql: str, params: tuple[Any, ...]) -> Mock:
        normalized = " ".join(sql.split())
        if normalized == (
            "SELECT recovery_attempt_count, max_recovery_attempts, recovery_deadline "
            "FROM execution_recovery_records WHERE execution_id = %s FOR UPDATE"
        ):
            assert params == (locked["execution_id"],)
            return Mock(fetchone=Mock(return_value=recovery))
        if normalized == (
            "UPDATE execution_records "
            "SET state = 'RECONCILING', reason_code = %s, updated_at = %s "
            "WHERE execution_id = %s AND state = 'RECONCILING'"
        ):
            assert params == (
                ReasonCode.TOOL_EXECUTION_UNKNOWN.value, CURRENT_TIME, locked["execution_id"],
            )
            return Mock(rowcount=1)
        if normalized == (
            "UPDATE execution_recovery_records SET last_error = %s, updated_at = %s "
            "WHERE execution_id = %s"
        ):
            assert params[1:] == (CURRENT_TIME, locked["execution_id"])
            return Mock(rowcount=1)
        raise AssertionError(f"unexpected SQL in bounded recovery fake: {normalized}")

    connection.execute.side_effect = execute
    connect = Mock(return_value=connection)
    load = Mock(return_value=locked)
    commit = Mock()
    release = Mock()
    mark_final = Mock()
    # This return value is a projection sentinel, not a fabricated persisted state.
    decision = Mock(return_value={"unit_projection": "recovery-binding"})
    monkeypatch.setattr(recovery_module, "connect", connect)
    monkeypatch.setattr(subject, "_load_execution", load)
    monkeypatch.setattr(subject, "_commit_execution", commit)
    monkeypatch.setattr(subject, "_release_execution", release)
    monkeypatch.setattr(subject, "_mark_final", mark_final)
    monkeypatch.setattr(subject, "_decision_from_row", decision)
    return SimpleNamespace(
        subject=subject, prepared=prepared, locked=locked, connection=connection,
        connect=connect, load=load, commit=commit, release=release,
        mark_final=mark_final, decision=decision,
    )


def _assert_reads(case: SimpleNamespace) -> None:
    case.connect.assert_called_once_with(DATABASE_URL)
    case.connection.transaction.assert_called_once_with()
    assert case.load.call_args_list == [
        call(case.connection, case.prepared["execution_id"], lock=True),
        call(case.connection, case.prepared["execution_id"], lock=False),
    ]
    case.decision.assert_called_once_with(case.connection, case.locked)


def _settle(case: SimpleNamespace, response: ReconcileResponse) -> None:
    result = case.subject._settle_reconciliation(
        case.prepared, response, current_time=CURRENT_TIME,
    )
    assert result is case.decision.return_value
    _assert_reads(case)


def _assert_conflict(case: SimpleNamespace) -> None:
    case.commit.assert_not_called()
    case.release.assert_not_called()
    case.mark_final.assert_called_once_with(
        case.connection, case.locked["execution_id"], current_time=CURRENT_TIME,
        reason=ReasonCode.IDEMPOTENCY_CONFLICT.value,
    )
    case.connection.execute.assert_not_called()


def _assert_unknown(case: SimpleNamespace, *, exhausted: bool = False) -> None:
    case.commit.assert_not_called()
    case.release.assert_not_called()
    if exhausted:
        case.mark_final.assert_called_once_with(
            case.connection, case.locked["execution_id"], current_time=CURRENT_TIME,
            reason="RECOVERY_LIMIT_REACHED",
        )
        assert case.connection.execute.call_count == 1
    else:
        case.mark_final.assert_not_called()
        assert case.connection.execute.call_count == 3
        assert case.connection.execute.call_args.args[1] == (
            ReasonCode.TOOL_EXECUTION_UNKNOWN.value, CURRENT_TIME, case.locked["execution_id"],
        )


def _fake_tool_response(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, Any],
) -> SimpleNamespace:
    response = Mock(status_code=200)
    response.json.return_value = deepcopy(body)
    client = MagicMock(spec=["__enter__", "__exit__", "post"])
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.post.return_value = response
    factory = Mock(return_value=client)
    monkeypatch.setattr(recovery_module.httpx, "Client", factory)
    return SimpleNamespace(factory=factory, client=client, response=response)


def _assert_only_reconcile_query(case: SimpleNamespace, transport: SimpleNamespace) -> None:
    transport.factory.assert_called_once_with(
        timeout=case.subject.request_timeout_seconds, trust_env=False,
    )
    transport.client.post.assert_called_once_with(
        f"{TOOL_URL}/internal/reconcile",
        headers={"X-AgentGuard-Internal": "recovery-worker", "Content-Type": "application/json"},
        content=canonicalize({"schema_version": "1.0"} | {
            field: case.prepared[field] for field in BINDING_FIELDS
        }),
    )
    transport.response.json.assert_called_once_with()


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("status", ["ALREADY_EXECUTED", "NOT_EXECUTED", "UNKNOWN"])
def test_response_dto_accepts_status_appropriate_evidence(kind: str, status: str) -> None:
    body = _response_body(_execution(kind), kind, status)

    response = ReconcileResponse.model_validate(body)

    assert response.model_dump(mode="python") == body
    if status == "ALREADY_EXECUTED":
        assert all(getattr(response, field) is not None for field in EVIDENCE_FIELDS)
    else:
        assert all(getattr(response, field) is None for field in EVIDENCE_FIELDS)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("status", ["NOT_EXECUTED", "UNKNOWN"])
def test_unconfirmed_dto_defaults_all_execution_evidence_to_null(kind: str, status: str) -> None:
    body = _response_body(_execution(kind), kind, status)
    for field in EVIDENCE_FIELDS:
        body.pop(field)

    response = ReconcileResponse.model_validate(body)

    assert all(getattr(response, field) is None for field in EVIDENCE_FIELDS)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize(("status", "field", "replacement"), INVALID_RESPONSE_CASES)
def test_invalid_dto_is_rejected_and_query_downgrades_without_releasing(
    monkeypatch: pytest.MonkeyPatch, kind: str, status: str, field: str, replacement: Any,
) -> None:
    case = _harness(monkeypatch, kind)
    body = _response_body(case.prepared, kind, status)
    if replacement is MISSING:
        body.pop(field)
    else:
        body[field] = replacement
    with pytest.raises(ValidationError):
        ReconcileResponse.model_validate(body)
    transport = _fake_tool_response(monkeypatch, body)

    response = case.subject._query_tool(case.prepared)

    _assert_only_reconcile_query(case, transport)
    assert response.status == "UNKNOWN"
    assert response.execution_id == case.prepared["execution_id"]
    assert response.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN.value
    assert all(getattr(response, name) is None for name in EVIDENCE_FIELDS)
    _settle(case, response)
    _assert_unknown(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
def test_complete_result_binding_commits_the_locked_execution(
    monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    case = _harness(monkeypatch, kind)
    response = ReconcileResponse.model_validate(_response_body(case.locked, kind))

    _settle(case, response)

    case.commit.assert_called_once_with(
        case.connection, case.locked, result=response.result,
        business_effect_id=response.business_effect_id, current_time=CURRENT_TIME,
    )
    assert case.commit.call_args.args[1] is case.locked
    assert case.commit.call_args.kwargs["result"] is response.result
    case.release.assert_not_called()
    case.mark_final.assert_not_called()
    case.connection.execute.assert_not_called()


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("field", BINDING_FIELDS)
@pytest.mark.parametrize("mutation", ["wrong", "missing", "null"])
def test_each_result_binding_field_failure_is_final_without_releasing(
    monkeypatch: pytest.MonkeyPatch, kind: str, field: str, mutation: str,
) -> None:
    case = _harness(monkeypatch, kind)
    body = _response_body(case.locked, kind)
    if mutation == "missing":
        body["result"].pop(field)
    else:
        body["result"][field] = None if mutation == "null" else (
            "f" * 64 if field in {"parameter_hash", "business_idempotency_key"}
            else f"{case.locked[field]}-OTHER"
        )

    _settle(case, ReconcileResponse.model_validate(body))

    _assert_conflict(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("missing_fields", [
    pytest.param(("business_action_id",), id="no-trusted-action"),
    pytest.param(("business_idempotency_key",), id="no-trusted-idempotency"),
    pytest.param(
        ("business_action_id", "business_idempotency_key"), id="no-trusted-action-or-key",
    ),
])
@pytest.mark.parametrize("result_evidence", ["missing", "null"])
def test_missing_locked_action_or_idempotency_is_final_without_releasing(
    monkeypatch: pytest.MonkeyPatch, kind: str,
    missing_fields: tuple[str, ...], result_evidence: str,
) -> None:
    case = _harness(monkeypatch, kind)
    for field in missing_fields:
        assert case.prepared[field] is not None
        case.locked[field] = None
    body = _response_body(case.locked, kind)
    for field in missing_fields:
        if result_evidence == "missing":
            body["result"].pop(field)
        assert body["result"].get(field) is None

    _settle(case, ReconcileResponse.model_validate(body))

    _assert_conflict(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("field", ["business_action_id", "business_idempotency_key"])
def test_empty_locked_action_or_idempotency_cannot_confirm_an_effect(
    monkeypatch: pytest.MonkeyPatch, kind: str, field: str,
) -> None:
    case = _harness(monkeypatch, kind)
    case.locked[field] = ""
    response = ReconcileResponse.model_validate(_response_body(case.locked, kind))

    _settle(case, response)

    _assert_conflict(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
def test_response_parameter_hash_mismatch_is_final_even_when_result_matches(
    monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    case = _harness(monkeypatch, kind)
    body = _response_body(case.locked, kind)
    body["parameter_hash"] = "f" * 64

    _settle(case, ReconcileResponse.model_validate(body))

    _assert_conflict(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("mutation", [
    "wrong-result-effect", "missing-result-effect", "null-result-effect",
    "wrong-response-effect", "other-kind-effect",
])
def test_effect_id_must_match_the_field_for_the_locked_tool_kind(
    monkeypatch: pytest.MonkeyPatch, kind: str, mutation: str,
) -> None:
    case = _harness(monkeypatch, kind)
    body = _response_body(case.locked, kind)
    effect_field = TOOL_IDENTITIES[kind][2]
    if mutation == "wrong-result-effect":
        body["result"][effect_field] = "EFFECT-OTHER"
    elif mutation == "missing-result-effect":
        body["result"].pop(effect_field)
    elif mutation == "null-result-effect":
        body["result"][effect_field] = None
    elif mutation == "wrong-response-effect":
        body["business_effect_id"] = "EFFECT-OTHER"
    else:
        body["result"].pop(effect_field)
        other_field = "notification_id" if kind == "refund" else "refund_id"
        body["result"][other_field] = body["business_effect_id"]

    _settle(case, ReconcileResponse.model_validate(body))

    _assert_conflict(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("field", BINDING_FIELDS[1:])
@pytest.mark.parametrize("matches_locked", [True, False], ids=["locked", "stale-prepared"])
def test_result_is_checked_against_fresh_locked_binding(
    monkeypatch: pytest.MonkeyPatch, kind: str, field: str, matches_locked: bool,
) -> None:
    case = _harness(monkeypatch, kind)
    case.locked[field] = (
        "f" * 64 if field in {"parameter_hash", "business_idempotency_key"}
        else f"{case.locked[field]}-LOCKED"
    )
    source = case.locked if matches_locked else case.prepared
    response = ReconcileResponse.model_validate(_response_body(source, kind))

    _settle(case, response)

    if matches_locked:
        case.commit.assert_called_once_with(
            case.connection, case.locked, result=response.result,
            business_effect_id=response.business_effect_id, current_time=CURRENT_TIME,
        )
        case.release.assert_not_called()
        case.mark_final.assert_not_called()
        case.connection.execute.assert_not_called()
    else:
        _assert_conflict(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("placement", ["field", "nested"])
@pytest.mark.parametrize("value", [0.0, 1.25])
def test_noncanonical_float_result_downgrades_to_unknown_before_binding(
    monkeypatch: pytest.MonkeyPatch, kind: str, placement: str, value: float,
) -> None:
    case = _harness(monkeypatch, kind)
    body = _response_body(case.locked, kind)
    if placement == "field":
        body["result"]["created_at"] = value
    else:
        body["result"]["metadata"] = {"values": [value]}
    response = ReconcileResponse.model_validate(body)

    _settle(case, response)

    _assert_unknown(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("status", [
    "ALREADY_EXECUTED", "NOT_EXECUTED", "IDEMPOTENCY_CONFLICT", "UNKNOWN",
])
@pytest.mark.parametrize("entry", ["query", "settlement"])
def test_wrong_response_execution_id_becomes_unknown_at_each_boundary(
    monkeypatch: pytest.MonkeyPatch, kind: str, status: str, entry: str,
) -> None:
    case = _harness(monkeypatch, kind)
    body = _response_body(case.locked, kind, status)
    body["execution_id"] = "EXEC-OTHER"
    if entry == "query":
        transport = _fake_tool_response(monkeypatch, body)
        response = case.subject._query_tool(case.prepared)
        _assert_only_reconcile_query(case, transport)
        assert response.execution_id == case.prepared["execution_id"]
        assert response.status == "UNKNOWN"
        assert all(getattr(response, field) is None for field in EVIDENCE_FIELDS)
    else:
        response = ReconcileResponse.model_validate(body)

    _settle(case, response)

    _assert_unknown(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("status", ["ALREADY_EXECUTED", "NOT_EXECUTED"])
@pytest.mark.parametrize("reason", [
    ReasonCode.IDEMPOTENCY_CONFLICT.value, ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
])
def test_success_status_with_nonallowed_reason_is_unknown_without_releasing(
    monkeypatch: pytest.MonkeyPatch, kind: str, status: str, reason: str,
) -> None:
    case = _harness(monkeypatch, kind)
    body = _response_body(case.locked, kind, status)
    body["reason_code"] = reason

    _settle(case, ReconcileResponse.model_validate(body))

    _assert_unknown(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("recovery", [
    (1, 3, CURRENT_TIME + 300),
    (3, 3, CURRENT_TIME - 1),
])
def test_genuine_not_executed_releases_only_the_locked_execution(
    monkeypatch: pytest.MonkeyPatch, kind: str, recovery: tuple[int, int, int],
) -> None:
    case = _harness(monkeypatch, kind, recovery=recovery)
    response = ReconcileResponse.model_validate(
        _response_body(case.locked, kind, "NOT_EXECUTED"),
    )

    _settle(case, response)

    case.release.assert_called_once_with(
        case.connection, case.locked, current_time=CURRENT_TIME,
        reason_code=ReasonCode.ALLOWED.value,
    )
    assert case.release.call_args.args[1] is case.locked
    case.commit.assert_not_called()
    case.mark_final.assert_not_called()
    case.connection.execute.assert_not_called()


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize(("recovery", "exhausted"), [
    pytest.param((1, 3, CURRENT_TIME + 1), False, id="within-limits"),
    pytest.param((1, 3, CURRENT_TIME), False, id="at-deadline"),
    pytest.param((3, 3, CURRENT_TIME + 1), True, id="at-attempt-limit"),
    pytest.param((4, 3, CURRENT_TIME + 1), True, id="past-attempt-limit"),
    pytest.param((1, 3, CURRENT_TIME - 1), True, id="past-deadline"),
])
def test_unknown_retains_reservations_or_routes_to_manual_review_at_limits(
    monkeypatch: pytest.MonkeyPatch, kind: str,
    recovery: tuple[int, int, int], exhausted: bool,
) -> None:
    case = _harness(monkeypatch, kind, recovery=recovery)
    response = ReconcileResponse.model_validate(_response_body(case.locked, kind, "UNKNOWN"))

    _settle(case, response)

    _assert_unknown(case, exhausted=exhausted)


@pytest.mark.parametrize("kind", ["refund", "notification"])
def test_explicit_idempotency_conflict_is_final_without_releasing(
    monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    case = _harness(monkeypatch, kind)
    response = ReconcileResponse.model_validate(
        _response_body(case.locked, kind, "IDEMPOTENCY_CONFLICT"),
    )

    _settle(case, response)

    _assert_conflict(case)


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("binding_matches", [True, False], ids=["bound", "conflict"])
def test_recover_once_only_queries_reconciliation_and_never_redispatches(
    monkeypatch: pytest.MonkeyPatch, kind: str, binding_matches: bool,
) -> None:
    case = _harness(monkeypatch, kind)
    body = _response_body(case.locked, kind)
    if not binding_matches:
        body["result"]["tenant_id"] = "TENANT-OTHER"
    transport = _fake_tool_response(monkeypatch, body)
    prepare = Mock(return_value=case.prepared)
    monkeypatch.setattr(case.subject, "_prepare_execution", prepare)
    monkeypatch.setattr(
        case.subject, "_execution_claim", lambda execution_id: nullcontext(execution_id),
    )

    recovered = case.subject.recover_once(
        execution_id=case.prepared["execution_id"], current_time=CURRENT_TIME,
    )

    assert recovered is not None
    assert recovered.body is case.decision.return_value
    prepare.assert_called_once_with(
        execution_id=case.prepared["execution_id"], current_time=CURRENT_TIME,
    )
    _assert_reads(case)
    _assert_only_reconcile_query(case, transport)
    if binding_matches:
        case.commit.assert_called_once_with(
            case.connection, case.locked, result=body["result"],
            business_effect_id=body["business_effect_id"], current_time=CURRENT_TIME,
        )
        case.release.assert_not_called()
        case.mark_final.assert_not_called()
        case.connection.execute.assert_not_called()
    else:
        _assert_conflict(case)
