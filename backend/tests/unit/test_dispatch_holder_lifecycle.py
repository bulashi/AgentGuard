"""Dispatch lifecycle checks use the real registry with synthetic key rows; no network or DB."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from backend.common.error_codes import ReasonCode
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.delegation.verifier import ChainVerificationError
from backend.revocation import dispatch_guard


def dispatch_case(monkeypatch, *, status="ACTIVE", material_state="PRESENT"):
    connection = Mock()
    sql_calls = []
    registry_row = (
        "leaf-holder-key", "leaf-agent", "AGENT", "AGENT_HOLDER_SIGNING", "SM2", "a" * 128,
        status, material_state, "fixture-only-key-reference", 0,
        150 if status == "RETIRED" else None,
        150 if status == "REVOKED" else None, 150 if status == "COMPROMISED" else None,
        150 if material_state == "DESTROYED" else None, None, 0,
    )

    def execute(sql, parameters=None):
        sql = " ".join(sql.split())
        sql_calls.append((sql, parameters))
        if "clock_timestamp()" in sql:
            row = (200,)
        elif "FROM key_registry" in sql:
            assert parameters == ("leaf-holder-key",)
            row = registry_row
        elif "FROM tasks" in sql:
            row = ("TENANT-unit", "AUTHORIZED", 300)
        else:
            raise AssertionError(f"unexpected dispatch failure SQL: {sql}")
        return SimpleNamespace(fetchone=lambda: row)

    connection.execute.side_effect = execute
    chain = [SimpleNamespace(
        credential_id="CRED-unit", signed_object={"fixture": "admitted-signed-object"},
        task_id="TASK-unit", tenant_id="TENANT-unit", holder_key_id="leaf-holder-key",
        holder_agent_id="leaf-agent",
    )]
    verifier = Mock()
    monkeypatch.setattr(dispatch_guard, "CredentialChainVerifier", Mock(return_value=verifier))
    execution = {
        "decision": "ALLOW", "decision_value": "ALLOW", "decision_at": 100,
        "updated_at": 100, "credential_chain_hash": sm3_hex(canonicalize([chain[0].signed_object])),
        "task_id": "TASK-unit", "tenant_id": "TENANT-unit",
    }
    return SimpleNamespace(
        connection=connection, chain=chain, execution=execution, schemas=Mock(),
        verifier=verifier, sql_calls=sql_calls,
    )


@pytest.mark.parametrize("status,material,reason", [
    ("REVOKED", "PRESENT", ReasonCode.KEY_REVOKED),
    ("COMPROMISED", "PRESENT", ReasonCode.KEY_COMPROMISED),
    ("RETIRED", "PRESENT", ReasonCode.KEY_RETIRED_FOR_SIGNING),
    ("ACTIVE", "DESTROYED", ReasonCode.UNKNOWN_KEY),
])
def test_dispatch_denies_leaf_proof_key_lifecycle_states(monkeypatch, status, material, reason):
    case = dispatch_case(monkeypatch, status=status, material_state=material)
    failure, timestamp = dispatch_guard.dispatch_failure(
        case.connection, case.chain, schemas=case.schemas, execution=case.execution,
    )
    assert (failure, timestamp) == (reason, 200)
    case.verifier.verify_chain_with_connection.assert_called_once_with(
        case.connection, "CRED-unit", current_time=200, lock=True,
    )
    key_queries = [sql for sql, _ in case.sql_calls if "FROM key_registry" in sql]
    assert len(key_queries) == 1 and key_queries[0].endswith("FOR UPDATE")
    assert not any("FROM tasks" in sql for sql, _ in case.sql_calls)


def test_active_leaf_key_continues_to_task_checks(monkeypatch):
    case = dispatch_case(monkeypatch)
    assert dispatch_guard.dispatch_failure(
        case.connection, case.chain, schemas=case.schemas, execution=case.execution,
    ) == (None, 200)
    assert any("FROM key_registry" in sql for sql, _ in case.sql_calls)
    assert any("FROM tasks" in sql for sql, _ in case.sql_calls)


def test_original_chain_verification_failure_is_preserved(monkeypatch):
    case = dispatch_case(monkeypatch)
    case.verifier.verify_chain_with_connection.side_effect = ChainVerificationError(
        ReasonCode.ANCESTOR_REVOKED, "fixture revoked ancestor",
    )
    assert dispatch_guard.dispatch_failure(
        case.connection, case.chain, schemas=case.schemas, execution=case.execution,
    ) == (ReasonCode.ANCESTOR_REVOKED, 200)
    assert not any("FROM key_registry" in sql for sql, _ in case.sql_calls)


def test_dispatch_locks_execution_before_action_and_idempotency(monkeypatch):
    events = []
    chain = [SimpleNamespace(
        credential_id="CRED-unit", issuer_key_id="root-key", holder_key_id="leaf-key",
        task_id="TASK-unit",
    )]
    monkeypatch.setattr(
        dispatch_guard.CredentialChainVerifier, "_load_chain",
        Mock(side_effect=lambda *_args, **_kwargs: events.append("credentials") or chain),
    )
    monkeypatch.setattr(
        dispatch_guard.PostgresKeyRegistry, "get_with_connection",
        Mock(side_effect=lambda _connection, key_id, **_kwargs: events.append(key_id)),
    )

    def execute(sql, parameters=None):
        sql = " ".join(sql.split())
        if "FROM execution_budget_reservations" in sql or "FROM credentials" in sql:
            return SimpleNamespace(fetchall=lambda: [("CRED-unit",)])
        assert sql.endswith("FOR UPDATE")
        if "FROM tasks" in sql:
            events.append("task")
            row = ("TASK-unit",)
        elif "FROM execution_records" in sql:
            events.append("execution")
            row = ("ACTION-unit",)
        elif "FROM business_actions" in sql:
            events.append("action")
            row = ("ACTION-unit",)
        elif "FROM idempotency_records" in sql:
            events.append("idempotency")
            row = ("EXEC-unit",)
        else:
            raise AssertionError(f"unexpected dispatch lock SQL: {sql}")
        return SimpleNamespace(fetchone=lambda: row)

    connection = SimpleNamespace(execute=execute)
    assert dispatch_guard.lock_dispatch_chain(connection, "EXEC-unit") == chain
    assert events == [
        "credentials", "leaf-key", "root-key", "task", "execution", "action", "idempotency",
    ]
