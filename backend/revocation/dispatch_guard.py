from __future__ import annotations

from typing import Any

from psycopg.types.json import Jsonb

from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.delegation.verifier import ChainVerificationError, CredentialChainVerifier
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.recovery.service import RecoveryService
from backend.revocation.audit import audit_schemas
from backend.state.database import connect


class DispatchGuardError(RuntimeError):
    pass


def database_time(connection) -> int:
    row = connection.execute(
        "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
    ).fetchone()
    if row is None or type(row[0]) is not int or not 0 <= row[0] <= MAX_SAFE_INTEGER:
        raise DispatchGuardError("trusted dispatch clock is unavailable")
    return row[0]


def lock_dispatch_chain(connection, execution_id: str, *, schemas: SchemaStore | None = None):
    # Credential locks precede execution/idempotency locks, as in atomic admission.
    ids = connection.execute(
        "SELECT DISTINCT credential_id FROM execution_budget_reservations WHERE execution_id = %s",
        (execution_id,),
    ).fetchall()
    if not ids:
        raise DispatchGuardError("execution has no recorded authorization budgets")
    credential_ids = {str(row[0]) for row in ids}
    leaves = connection.execute(
        """
        SELECT credential_id FROM credentials
        WHERE credential_id = ANY(%s)
          AND credential_id NOT IN (
              SELECT parent_credential_id FROM credentials
              WHERE credential_id = ANY(%s) AND parent_credential_id IS NOT NULL
          )
        """,
        (sorted(credential_ids), sorted(credential_ids)),
    ).fetchall()
    if len(leaves) != 1:
        raise DispatchGuardError("recorded dispatch chain is ambiguous")
    chain = CredentialChainVerifier._load_chain(connection, str(leaves[0][0]), lock=True)
    if {item.credential_id for item in chain} != credential_ids:
        raise DispatchGuardError("dispatch budgets do not cover the complete authorization chain")
    for key_id in sorted(
        {key for item in chain for key in (item.issuer_key_id, item.holder_key_id)}
    ):
        PostgresKeyRegistry.get_with_connection(connection, key_id, lock=True)
    connection.execute(
        "SELECT task_id FROM tasks WHERE task_id = %s FOR UPDATE",
        (chain[-1].task_id,),
    ).fetchone()
    action = connection.execute(
        "SELECT business_action_id FROM execution_records WHERE execution_id = %s FOR UPDATE",
        (execution_id,),
    ).fetchone()
    if action is not None and action[0] is not None:
        connection.execute(
            "SELECT business_action_id FROM business_actions WHERE business_action_id = %s FOR UPDATE",
            (action[0],),
        ).fetchone()
    connection.execute(
        "SELECT execution_id FROM idempotency_records WHERE execution_id = %s FOR UPDATE",
        (execution_id,),
    ).fetchone()
    return chain


def dispatch_failure(connection, chain, *, schemas: SchemaStore, execution: dict[str, Any]):
    timestamp = database_time(connection)
    if (
        execution["decision"] != "ALLOW"
        or execution["decision_value"] != "ALLOW"
        or type(execution["decision_at"]) is not int
        or type(execution["updated_at"]) is not int
        or not 0 <= execution["decision_at"] <= execution["updated_at"] <= timestamp
    ):
        raise DispatchGuardError("dispatch has no matching trusted admission decision time")
    signed_chain = [item.signed_object for item in chain]
    if sm3_hex(canonicalize(signed_chain)) != execution["credential_chain_hash"]:
        raise DispatchGuardError("recorded authorization chain digest changed")
    if any(
        item.task_id != execution["task_id"] or item.tenant_id != execution["tenant_id"]
        for item in chain
    ):
        raise DispatchGuardError("dispatch authorization chain belongs to another task")
    verifier = CredentialChainVerifier("", schemas)
    try:
        verifier.verify_chain_with_connection(
            connection,
            chain[-1].credential_id,
            current_time=timestamp,
            lock=True,
        )
        # Historical issuer signatures keep their retirement rules. The current
        # request's leaf Holder Proof still requires an ACTIVE, PRESENT key.
        PostgresKeyRegistry.resolve_for_signing_with_connection(
            connection,
            chain[-1].holder_key_id,
            expected_subject_id=chain[-1].holder_agent_id,
            expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            lock=True,
        )
    except (ChainVerificationError, KeyRegistryError) as error:
        return error.reason_code, timestamp
    task = connection.execute(
        "SELECT tenant_id, status, expires_at FROM tasks WHERE task_id = %s FOR SHARE",
        (execution["task_id"],),
    ).fetchone()
    if task is None or str(task[0]) != execution["tenant_id"] or str(task[1]) != "AUTHORIZED":
        return ReasonCode.CROSS_TASK, timestamp
    if timestamp > int(task[2]):
        return ReasonCode.CREDENTIAL_EXPIRED, timestamp
    return None, timestamp


def cancel_locked_execution(
    connection, execution: dict[str, Any], reason: ReasonCode, *, timestamp: int
):
    if execution["state"] != "ADMITTED":
        return None
    existing = connection.execute(
        "SELECT denial_execution_id FROM dispatch_cancellations WHERE execution_id = %s",
        (execution["execution_id"],),
    ).fetchone()
    if existing is not None:
        return denial_body(connection, str(existing[0]))
    budgets = connection.execute(
        """
        SELECT credential_id, quota_type, amount FROM execution_budget_reservations
        WHERE execution_id = %s AND status = 'RESERVED'
        ORDER BY credential_id, quota_type FOR UPDATE
        """,
        (execution["execution_id"],),
    ).fetchall()
    if not budgets:
        raise DispatchGuardError("admitted execution has no releasable reservation")
    if execution["business_idempotency_key"] is not None:
        idempotency = connection.execute(
            "SELECT business_idempotency_key, parameter_hash, status, updated_at "
            "FROM idempotency_records WHERE execution_id = %s FOR UPDATE",
            (execution["execution_id"],),
        ).fetchone()
        if (
            idempotency is None
            or tuple(idempotency[:3])
            != (
                execution["business_idempotency_key"],
                execution["parameter_hash"],
                "ADMITTED",
            )
            or type(idempotency[3]) is not int
            or not 0 <= idempotency[3] <= timestamp
        ):
            raise DispatchGuardError("pending cancellation and business idempotency state disagree")
    budget_times = connection.execute(
        "SELECT updated_at FROM credential_budget_state WHERE credential_id = ANY(%s) "
        "ORDER BY credential_id, quota_type FOR UPDATE",
        (sorted({str(item[0]) for item in budgets}),),
    ).fetchall()
    if any(type(item[0]) is not int or item[0] > timestamp for item in budget_times):
        raise DispatchGuardError("dispatch cancellation clock precedes budget state")
    request = connection.execute(
        "SELECT initial_request_id, request_hash, credential_chain_hash, created_at "
        "FROM execution_records WHERE execution_id = %s",
        (execution["execution_id"],),
    ).fetchone()
    if request is None or timestamp < int(request[3]):
        raise DispatchGuardError("dispatch cancellation has no matching request clock")
    RecoveryService._release_execution(
        connection, execution, current_time=timestamp, reason_code=reason.value
    )
    cancellation_id = new_id("CANCEL")
    denial_id = new_id("EXEC")
    connection.execute(
        """
        INSERT INTO execution_records (
            execution_id, initial_request_id, request_hash, credential_chain_hash,
            tenant_id, task_id, tool_service, tool_name, tool_version, parameter_hash,
            state, decision, reason_code, business_action_id, created_at, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                  'DENIED', 'DENY', %s, %s, %s, %s)
        """,
        (
            denial_id,
            new_id("DISPATCH-DENIAL"),
            request[1],
            request[2],
            execution["tenant_id"],
            execution["task_id"],
            execution["tool_service"],
            execution["tool_name"],
            execution["tool_version"],
            execution["parameter_hash"],
            reason.value,
            execution["business_action_id"],
            timestamp,
            timestamp,
        ),
    )
    revoked = connection.execute(
        """
        SELECT r.credential_id, r.revoked_at, r.revocation_reason, r.revoked_by
        FROM credential_revocations r JOIN execution_budget_reservations b USING (credential_id)
        WHERE b.execution_id = %s GROUP BY r.credential_id ORDER BY r.credential_id
        """,
        (execution["execution_id"],),
    ).fetchall()
    evidence = {
        "schema_version": "1.0",
        "record_type": "DISPATCH_CANCELLED_V1",
        "cancellation_id": cancellation_id,
        "execution_id": execution["execution_id"],
        "denial_execution_id": denial_id,
        "task_id": execution["task_id"],
        "request_id": str(request[0]),
        "request_hash": str(request[1]),
        "credential_chain_hash": str(request[2]),
        "admission_decision": "ALLOW",
        "dispatch_decision": "DENY",
        "reason_code": reason.value,
        "cancelled_at": timestamp,
        "released_budgets": [
            {"credential_id": str(item[0]), "quota_type": str(item[1]), "amount": int(item[2])}
            for item in budgets
        ],
        "revocations": [
            {
                "credential_id": str(item[0]),
                "revoked_at": int(item[1]),
                "reason": str(item[2]),
                "revoked_by": str(item[3]),
            }
            for item in revoked
        ],
    }
    audit_schemas().validate("dispatch-cancellation-evidence.schema.json", evidence)
    connection.execute(
        """
        INSERT INTO dispatch_cancellations (
            cancellation_id, execution_id, denial_execution_id, request_id, request_hash,
            credential_chain_hash, reason_code, evidence, cancelled_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            cancellation_id,
            execution["execution_id"],
            denial_id,
            request[0],
            request[1],
            request[2],
            reason.value,
            Jsonb(evidence),
            timestamp,
        ),
    )
    connection.execute(
        """
        INSERT INTO audit_outbox (
            outbox_event_id, execution_id, event_type, evidence_reference,
            payload_hash, payload, status, created_at
        ) VALUES (%s, %s, 'EXECUTION_RELEASED', %s, %s, %s, 'PENDING', %s)
        """,
        (
            "OUTBOX-DISPATCH-CANCEL-" + cancellation_id,
            execution["execution_id"],
            cancellation_id,
            sm3_hex(canonicalize(evidence)),
            Jsonb(evidence),
            timestamp,
        ),
    )
    return denial_body(connection, denial_id)


def denial_body(connection, denial_id: str):
    row = connection.execute(
        "SELECT execution_id, reason_code, request_hash, credential_chain_hash "
        "FROM execution_records WHERE execution_id = %s AND state = 'DENIED' AND decision = 'DENY'",
        (denial_id,),
    ).fetchone()
    if row is None:
        raise DispatchGuardError("dispatch cancellation has no matching denial execution")
    return {
        "execution_id": str(row[0]),
        "state": "DENIED",
        "decision": "DENY",
        "reason_code": str(row[1]),
        "request_hash": str(row[2]),
        "credential_chain_hash": str(row[3]),
        "admission_outcome": "DENIED",
        "validated_command": None,
        "receipt": None,
    }


def cancel_revoked_admissions(database_url: str, credential_id: str) -> list[str]:
    with connect(database_url) as connection:
        rows = connection.execute(
            """
            SELECT e.execution_id FROM execution_records e
            JOIN execution_budget_reservations b USING (execution_id)
            WHERE b.credential_id = %s AND e.state = 'ADMITTED'
            GROUP BY e.execution_id ORDER BY e.execution_id
            """,
            (credential_id,),
        ).fetchall()
    cancelled = []
    for item in rows:
        with connect(database_url) as connection, connection.transaction():
            chain = lock_dispatch_chain(connection, str(item[0]))
            execution = RecoveryService._load_execution(connection, str(item[0]), lock=True)
            if execution is None or execution["state"] != "ADMITTED":
                continue
            reason, timestamp = dispatch_failure(
                connection, chain, schemas=SchemaStore(), execution=execution
            )
            if reason is not None:
                body = cancel_locked_execution(connection, execution, reason, timestamp=timestamp)
                if body is not None:
                    cancelled.append(body["execution_id"])
    return cancelled
