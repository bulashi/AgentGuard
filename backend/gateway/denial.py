from __future__ import annotations

import json
from typing import Any

from psycopg.types.json import Jsonb

from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.gateway.contracts import RequestEnvelopeModel
from backend.gateway.service import GatewayError
from backend.state.database import connect


class DeniedExecutionRecorder:
    """Persist a parseable authorization failure as a terminal DENIED execution."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def record(
        self,
        request: RequestEnvelopeModel,
        error: GatewayError,
        *,
        current_time: int,
    ) -> dict[str, Any]:
        raw = request.model_dump(mode="json")
        request_hash = self._hash(raw)
        credential_chain_hash = self._hash(request.credential_chain)
        parameter_hash = self._hash(request.canonical_parameters)
        with connect(self.database_url) as connection, connection.transaction():
            existing = connection.execute(
                """
                SELECT execution_id, state, decision, reason_code,
                       request_hash, credential_chain_hash, task_id, tenant_id,
                       tool_service, tool_name, tool_version, business_action_id
                FROM execution_records
                WHERE initial_request_id = %s
                FOR UPDATE
                """,
                (request.request_id,),
            ).fetchone()
            if existing is not None:
                return self._record_replay_denial(
                    connection,
                    request=request,
                    error=error,
                    current_time=current_time,
                    existing=existing,
                    request_hash=request_hash,
                    credential_chain_hash=credential_chain_hash,
                    parameter_hash=parameter_hash,
                )

            task = connection.execute(
                "SELECT tenant_id FROM tasks WHERE task_id = %s",
                (request.task_id,),
            ).fetchone()
            if task is None:
                return self._fallback_body(
                    request,
                    request_hash=request_hash,
                    credential_chain_hash=credential_chain_hash,
                    reason_code=error.reason_code,
                )

            action_id = self._usable_action_id(connection, request)
            execution_id = new_id("EXEC")
            connection.execute(
                """
                INSERT INTO execution_records (
                    execution_id, initial_request_id, request_hash, credential_chain_hash,
                    tenant_id, task_id, tool_service, tool_name, tool_version, parameter_hash,
                    state, decision, reason_code, receipt_status, business_action_id,
                    created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        'DENIED', 'DENY', %s, 'NOT_REQUIRED', %s, %s, %s)
                """,
                (
                    execution_id,
                    request.request_id,
                    request_hash,
                    credential_chain_hash,
                    str(task[0]),
                    request.task_id,
                    request.tool_service,
                    request.tool_name,
                    request.tool_version,
                    parameter_hash,
                    error.reason_code.value,
                    action_id,
                    current_time,
                    current_time,
                ),
            )
            connection.execute(
                """
                INSERT INTO execution_requests (
                    request_id, execution_id, request_hash, issued_at, received_at,
                    admission_outcome
                )
                VALUES (%s, %s, %s, %s, %s, 'DENIED')
                """,
                (
                    request.request_id,
                    execution_id,
                    request_hash,
                    request.issued_at,
                    current_time,
                ),
            )
            connection.execute(
                """
                INSERT INTO replay_records (request_id, request_hash, first_seen_at)
                VALUES (%s, %s, %s)
                """,
                (request.request_id, request_hash, current_time),
            )
        return {
            "execution_id": execution_id,
            "state": "DENIED",
            "decision": "DENY",
            "reason_code": error.reason_code.value,
            "request_hash": request_hash,
            "credential_chain_hash": credential_chain_hash,
            "admission_outcome": "DENIED",
            "validated_command": None,
            "receipt": None,
        }

    @staticmethod
    def _record_replay_denial(
        connection,
        *,
        request: RequestEnvelopeModel,
        error: GatewayError,
        current_time: int,
        existing: tuple[Any, ...],
        request_hash: str,
        credential_chain_hash: str,
        parameter_hash: str,
    ) -> dict[str, Any]:
        original_execution_id = str(existing[0])
        denial_execution_id = new_id("EXEC")
        synthetic_request_id = new_id("REPLAY")
        attempt_id = new_id("DENIAL")
        connection.execute(
            """
            INSERT INTO execution_records (
                execution_id, initial_request_id, request_hash, credential_chain_hash,
                tenant_id, task_id, tool_service, tool_name, tool_version, parameter_hash,
                state, decision, reason_code, receipt_status, business_action_id,
                created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    'DENIED', 'DENY', %s, 'NOT_REQUIRED', %s, %s, %s)
            """,
            (
                denial_execution_id,
                synthetic_request_id,
                request_hash,
                credential_chain_hash,
                str(existing[7]),
                str(existing[6]),
                str(existing[8]),
                str(existing[9]),
                str(existing[10]),
                parameter_hash,
                error.reason_code.value,
                existing[11],
                current_time,
                current_time,
            ),
        )
        connection.execute(
            """
            INSERT INTO replay_denial_attempts (
                attempt_id, request_id, request_hash, original_execution_id,
                denial_execution_id, reason_code, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                attempt_id,
                request.request_id,
                request_hash,
                original_execution_id,
                denial_execution_id,
                error.reason_code.value,
                current_time,
            ),
        )
        event_payload = {
            "schema_version": "1.0",
            "event_type": "REPLAY_DENIAL_OBSERVED",
            "attempt_id": attempt_id,
            "request_id": request.request_id,
            "request_hash": request_hash,
            "original_execution_id": original_execution_id,
            "denial_execution_id": denial_execution_id,
            "reason_code": error.reason_code.value,
        }
        connection.execute(
            """
            INSERT INTO audit_outbox (
                outbox_event_id, execution_id, event_type, evidence_reference,
                payload_hash, payload, status, created_at
            )
            VALUES (%s, %s, 'REPLAY_DENIAL_OBSERVED', %s, %s, %s, 'PENDING', %s)
            """,
            (
                f"OUTBOX-{attempt_id}",
                denial_execution_id,
                attempt_id,
                sm3_hex(canonicalize(event_payload)),
                Jsonb(event_payload),
                current_time,
            ),
        )
        return {
            "execution_id": denial_execution_id,
            "state": "DENIED",
            "decision": "DENY",
            "reason_code": error.reason_code.value,
            "request_hash": request_hash,
            "credential_chain_hash": credential_chain_hash,
            "admission_outcome": "DENIED",
            "validated_command": None,
            "receipt": None,
        }

    @staticmethod
    def _body_from_row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "execution_id": str(row[0]),
            "state": str(row[1]),
            "decision": str(row[2] or "DENY"),
            "reason_code": str(row[3]),
            "request_hash": str(row[4]),
            "credential_chain_hash": str(row[5]),
            "admission_outcome": "DENIED",
            "validated_command": None,
            "receipt": None,
        }

    @staticmethod
    def _fallback_body(
        request: RequestEnvelopeModel,
        *,
        request_hash: str,
        credential_chain_hash: str,
        reason_code: ReasonCode,
    ) -> dict[str, Any]:
        return {
            "execution_id": "DENIED",
            "state": "DENIED",
            "decision": "DENY",
            "reason_code": reason_code.value,
            "request_hash": request_hash,
            "credential_chain_hash": credential_chain_hash,
            "admission_outcome": "DENIED",
            "validated_command": None,
            "receipt": None,
        }

    @staticmethod
    def _usable_action_id(connection, request: RequestEnvelopeModel) -> str | None:
        if request.business_action_id is None:
            return None
        row = connection.execute(
            """
            SELECT business_action_id FROM business_actions
            WHERE business_action_id = %s
            """,
            (request.business_action_id,),
        ).fetchone()
        return None if row is None else str(row[0])

    @staticmethod
    def _hash(value: Any) -> str:
        try:
            return sm3_hex(canonicalize(value))
        except (TypeError, ValueError):
            fallback = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            return sm3_hex(fallback)
