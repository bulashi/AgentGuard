from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import psycopg
from jsonschema import ValidationError

from backend.common.enums import AdmissionOutcome
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.gateway.contracts import RequestEnvelopeModel, ValidatedToolCommandModel
from backend.gateway.service import GatewayError, SecureGatewayService
from backend.state.database import connect


@dataclass(frozen=True)
class AdmissionResult:
    body: dict[str, Any]
    status_code: int = 200


class AdmissionService:
    """Linearize request replay, business idempotency, and budget reservation."""

    _QUOTA_TYPES = ("max_tool_calls", "refund_total_fen")

    def __init__(self, gateway: SecureGatewayService) -> None:
        self.gateway = gateway

    def admit_request(
        self, request: RequestEnvelopeModel, *, current_time: int
    ) -> AdmissionResult:
        raw_request = request.model_dump(mode="json")
        try:
            self.gateway.schemas.validate("request-envelope.schema.json", raw_request)
        except ValidationError as exc:
            raise GatewayError(
                ReasonCode.REQUEST_SCHEMA_INVALID,
                "request does not match the frozen RequestEnvelope schema",
                status_code=400,
            ) from exc

        if not (
            current_time - self.gateway.freshness_window_seconds
            <= request.issued_at
            <= current_time + self.gateway.allowed_clock_skew_seconds
        ):
            raise GatewayError(
                ReasonCode.REQUEST_STALE,
                "request issued_at is outside the trusted gateway freshness window",
            )

        request_hash = sm3_hex(canonicalize(raw_request))
        parameter_hash = sm3_hex(canonicalize(request.canonical_parameters))
        with connect(self.gateway.database_url) as connection, connection.transaction():
            chain, task = self._revalidate_context(
                connection, request, current_time=current_time, parameter_hash=parameter_hash,
            )

            existing_request = connection.execute(
                """
                SELECT execution_id, request_hash
                FROM execution_requests
                WHERE request_id = %s
                FOR UPDATE
                """,
                (request.request_id,),
            ).fetchone()
            if existing_request is not None:
                raise GatewayError(
                    ReasonCode.REPLAY_DETECTED,
                    "request_id has already been admitted or rejected",
                )

            credential_chain_hash = self.gateway._credential_chain_hash(chain)
            business_idempotency_key = self.gateway._business_idempotency_key(
                task.tenant_id,
                task.task_id,
                request.tool_service,
                request.tool_name,
                request.business_action_id,
            )

            if business_idempotency_key is not None:
                existing_idempotency = connection.execute(
                    """
                    SELECT parameter_hash, execution_id, status
                    FROM idempotency_records
                    WHERE business_idempotency_key = %s
                    FOR UPDATE
                    """,
                    (business_idempotency_key,),
                ).fetchone()
                if existing_idempotency is not None:
                    chain, task = self._revalidate_context(
                        connection, request, current_time=self._database_clock(connection),
                        parameter_hash=parameter_hash,
                    )
                    credential_chain_hash = self.gateway._credential_chain_hash(chain)
                    existing_parameter_hash = str(existing_idempotency[0])
                    existing_execution_id = str(existing_idempotency[1])
                    if existing_parameter_hash != parameter_hash:
                        self._existing_decision(
                            connection,
                            execution_id=existing_execution_id,
                            request_hash=request_hash,
                            credential_chain_hash=credential_chain_hash,
                            outcome=AdmissionOutcome.DENIED,
                            decision="DENY",
                            reason_code=ReasonCode.IDEMPOTENCY_CONFLICT,
                        )
                        self._recheck_decision_time(
                            request, chain, task, received_at=current_time,
                            decision_at=self._database_clock(connection),
                        )
                        # The endpoint records a separate DENIED execution and receipt.
                        # Never attach the original successful execution's ALLOW receipt.
                        raise GatewayError(
                            ReasonCode.IDEMPOTENCY_CONFLICT,
                            "business action was already observed with different parameters",
                            status_code=409,
                        )

                    outcome = (
                        AdmissionOutcome.IDEMPOTENT_RETURN
                        if str(existing_idempotency[2]) == "COMMITTED"
                        else AdmissionOutcome.EXISTING_EXECUTION
                    )
                    self._register_request(
                        connection,
                        request=request,
                        execution_id=existing_execution_id,
                        request_hash=request_hash,
                        current_time=current_time,
                        outcome=outcome,
                    )
                    body = self._existing_decision(
                        connection,
                        execution_id=existing_execution_id,
                        request_hash=request_hash,
                        credential_chain_hash=credential_chain_hash,
                        outcome=outcome,
                    )
                    self._recheck_decision_time(
                        request, chain, task, received_at=current_time,
                        decision_at=self._database_clock(connection),
                    )
                    return AdmissionResult(body=body)

            increments = self._budget_increments(request)
            credential_ids = [
                str(item["payload"]["credential_id"]) for item in chain
            ]
            reservation_rows = self._reserve_budgets(
                connection,
                credential_ids=credential_ids,
                increments=increments,
                current_time=current_time,
            )
            decision_time = self._database_clock(connection)
            chain, task = self._revalidate_context(
                connection, request, current_time=decision_time,
                parameter_hash=parameter_hash,
            )
            self._recheck_decision_time(
                request, chain, task,
                received_at=current_time, decision_at=decision_time,
            )
            credential_chain_hash = self.gateway._credential_chain_hash(chain)
            if reservation_rows is None:
                execution_id = new_id("EXEC")
                decision_at = self._insert_execution(
                    connection,
                    execution_id=execution_id,
                    request=request,
                    request_hash=request_hash,
                    credential_chain_hash=credential_chain_hash,
                    parameter_hash=parameter_hash,
                    task_id=task.task_id,
                    tenant_id=task.tenant_id,
                    state="DENIED",
                    decision="DENY",
                    reason_code=ReasonCode.BUDGET_EXCEEDED,
                    current_time=current_time,
                )
                self._recheck_decision_time(
                    request, chain, task,
                    received_at=current_time, decision_at=decision_at,
                )
                self._register_request(
                    connection,
                    request=request,
                    execution_id=execution_id,
                    request_hash=request_hash,
                    current_time=current_time,
                    outcome=AdmissionOutcome.DENIED,
                )
                return AdmissionResult(
                    body={
                        "execution_id": execution_id,
                        "state": "DENIED",
                        "decision": "DENY",
                        "reason_code": ReasonCode.BUDGET_EXCEEDED.value,
                        "request_hash": request_hash,
                        "credential_chain_hash": credential_chain_hash,
                        "admission_outcome": AdmissionOutcome.DENIED.value,
                        "validated_command": None,
                        "receipt": None,
                    },
                    status_code=403,
                )

            execution_id = new_id("EXEC")
            command = ValidatedToolCommandModel(
                schema_version="1.0",
                execution_id=execution_id,
                tenant_id=task.tenant_id,
                task_id=task.task_id,
                tool_service=request.tool_service,
                tool_name=request.tool_name,
                tool_version=request.tool_version,
                validated_parameters=request.canonical_parameters,
                business_action_id=request.business_action_id,
                business_idempotency_key=business_idempotency_key,
                parameter_hash=parameter_hash,
            )
            try:
                self.gateway.schemas.validate(
                    "validated-tool-command.schema.json",
                    command.model_dump(mode="json"),
                )
            except ValidationError as exc:
                raise GatewayError(
                    ReasonCode.REQUEST_SCHEMA_INVALID,
                    "validated command violates the frozen schema",
                ) from exc

            decision_at = self._insert_execution(
                connection,
                execution_id=execution_id,
                request=request,
                request_hash=request_hash,
                credential_chain_hash=credential_chain_hash,
                parameter_hash=parameter_hash,
                task_id=task.task_id,
                tenant_id=task.tenant_id,
                state="ADMITTED",
                decision="ALLOW",
                reason_code=ReasonCode.ALLOWED,
                current_time=current_time,
            )
            self._recheck_decision_time(
                request, chain, task,
                received_at=current_time, decision_at=decision_at,
            )
            self._insert_reservations(
                connection,
                execution_id=execution_id,
                reservation_rows=reservation_rows,
                current_time=current_time,
            )
            self._register_request(
                connection,
                request=request,
                execution_id=execution_id,
                request_hash=request_hash,
                current_time=current_time,
                outcome=AdmissionOutcome.NEW_EXECUTION,
            )
            if business_idempotency_key is not None:
                connection.execute(
                    """
                    INSERT INTO idempotency_records (
                        business_idempotency_key, business_action_id, parameter_hash,
                        execution_id, status, created_at, updated_at
                    )
                    VALUES (%s, %s, %s, %s, 'ADMITTED', %s, %s)
                    """,
                    (
                        business_idempotency_key,
                        request.business_action_id,
                        parameter_hash,
                        execution_id,
                        current_time,
                        current_time,
                    ),
                )

            return AdmissionResult(
                body={
                    "execution_id": execution_id,
                    "state": "ADMITTED",
                    "decision": "ALLOW",
                    "reason_code": ReasonCode.ALLOWED.value,
                    "request_hash": request_hash,
                    "credential_chain_hash": credential_chain_hash,
                    "admission_outcome": AdmissionOutcome.NEW_EXECUTION.value,
                    "validated_command": command.model_dump(mode="json"),
                    "receipt": None,
                }
            )

    @staticmethod
    def _database_clock(connection: psycopg.Connection) -> int:
        row = connection.execute(
            "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
        ).fetchone()
        if row is None or type(row[0]) is not int or not 0 <= row[0] <= MAX_SAFE_INTEGER:
            raise GatewayError(ReasonCode.REQUEST_STALE, "trusted database clock is unavailable")
        return row[0]

    def _revalidate_context(
        self,
        connection: psycopg.Connection,
        request: RequestEnvelopeModel,
        *,
        current_time: int,
        parameter_hash: str,
    ) -> tuple[list[dict[str, Any]], Any]:
        chain = self.gateway._verify_chain_and_binding(
            connection, request, current_time, lock=True
        )
        leaf_payload = chain[-1]["payload"]
        task = self.gateway._load_task(
            connection, request.task_id, current_time, lock=True
        )
        self.gateway._verify_holder_proof(
            connection, request, chain, leaf_payload,
            parameter_hash=parameter_hash,
            current_time=current_time, lock=True,
        )
        self.gateway._verify_request_identity(request, leaf_payload, task)
        capability = self.gateway._resolve_capability(leaf_payload, request)
        self.gateway._verify_parameters(connection, request, task, capability)
        business_key = self.gateway._business_idempotency_key(
            task.tenant_id, task.task_id, request.tool_service, request.tool_name,
            request.business_action_id,
        )
        if business_key is not None:
            existing = connection.execute(
                "SELECT execution_id FROM idempotency_records WHERE business_idempotency_key = %s",
                (business_key,),
            ).fetchone()
            if existing is not None:
                # Take this lock before action/idempotency locks and retry FK writes.
                # Tool execution also takes task -> execution -> business action.
                connection.execute(
                    "SELECT execution_id FROM execution_records WHERE execution_id = %s FOR SHARE",
                    (str(existing[0]),),
                ).fetchone()
        self.gateway._verify_business_action(connection, request, task, lock=True)
        return chain, task

    def _recheck_decision_time(
        self,
        request: RequestEnvelopeModel,
        chain: list[dict[str, Any]],
        task: Any,
        *,
        received_at: int,
        decision_at: int,
    ) -> None:
        # Entry-time checks cannot cover a wait for admission locks.
        if (
            type(decision_at) is not int
            or type(received_at) is not int
            or not 0 <= received_at <= decision_at <= MAX_SAFE_INTEGER
            or not decision_at - self.gateway.freshness_window_seconds <= request.issued_at <= decision_at
        ):
            raise GatewayError(ReasonCode.REQUEST_STALE, "request is stale at the admission decision")
        if decision_at > task.expires_at or any(
            not item["payload"]["not_before"] <= decision_at <= item["payload"]["expires_at"]
            for item in chain
        ):
            raise GatewayError(
                ReasonCode.CREDENTIAL_EXPIRED,
                "task or credential expired while admission waited for locks",
            )

    @staticmethod
    def _budget_increments(request: RequestEnvelopeModel) -> dict[str, int]:
        amount = 0
        if (request.tool_service, request.tool_name) == (
            "refund-service",
            "refund.create",
        ):
            amount = int(request.canonical_parameters["amount_fen"])
        return {"max_tool_calls": 1, "refund_total_fen": amount}

    @classmethod
    def _reserve_budgets(
        cls,
        connection: psycopg.Connection,
        *,
        credential_ids: list[str],
        increments: dict[str, int],
        current_time: int,
    ) -> list[tuple[str, str, int]] | None:
        ordered_ids = sorted(set(credential_ids))
        rows = connection.execute(
            """
            SELECT credential_id, quota_type, limit_value, reserved_value, committed_value
            FROM credential_budget_state
            WHERE credential_id = ANY(%s)
            ORDER BY credential_id, quota_type
            FOR UPDATE
            """,
            (ordered_ids,),
        ).fetchall()
        budgets = {
            (str(row[0]), str(row[1])): {
                "limit": int(row[2]),
                "reserved": int(row[3]),
                "committed": int(row[4]),
            }
            for row in rows
        }
        required = {
            (credential_id, quota_type)
            for credential_id in ordered_ids
            for quota_type in cls._QUOTA_TYPES
        }
        if not required <= budgets.keys():
            raise GatewayError(
                ReasonCode.BUDGET_EXCEEDED,
                "credential budget state is incomplete",
            )
        for credential_id in ordered_ids:
            for quota_type, increment in increments.items():
                budget = budgets[(credential_id, quota_type)]
                if budget["reserved"] + budget["committed"] + increment > budget["limit"]:
                    return None
        reservation_rows: list[tuple[str, str, int]] = []
        for credential_id in ordered_ids:
            for quota_type, increment in increments.items():
                if increment == 0:
                    continue
                reservation_rows.append((credential_id, quota_type, increment))
                connection.execute(
                    """
                    UPDATE credential_budget_state
                    SET reserved_value = reserved_value + %s,
                        version = version + 1,
                        updated_at = %s
                    WHERE credential_id = %s AND quota_type = %s
                    """,
                    (increment, current_time, credential_id, quota_type),
                )
        return reservation_rows

    @staticmethod
    def _insert_reservations(
        connection: psycopg.Connection,
        *,
        execution_id: str,
        reservation_rows: list[tuple[str, str, int]],
        current_time: int,
    ) -> None:
        for credential_id, quota_type, amount in reservation_rows:
            connection.execute(
                """
                INSERT INTO execution_budget_reservations (
                    execution_id, credential_id, quota_type, amount, status,
                    created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, 'RESERVED', %s, %s)
                """,
                (
                    execution_id,
                    credential_id,
                    quota_type,
                    amount,
                    current_time,
                    current_time,
                ),
            )

    @staticmethod
    def _insert_execution(
        connection: psycopg.Connection,
        *,
        execution_id: str,
        request: RequestEnvelopeModel,
        request_hash: str,
        credential_chain_hash: str,
        parameter_hash: str,
        task_id: str,
        tenant_id: str,
        state: str,
        decision: str,
        reason_code: ReasonCode,
        current_time: int,
    ) -> int:
        row = connection.execute(
            """
            INSERT INTO execution_records (
                execution_id, initial_request_id, request_hash, credential_chain_hash,
                tenant_id, task_id, tool_service, tool_name, tool_version, parameter_hash,
                state, decision, reason_code, receipt_status, business_action_id,
                created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, 'NOT_REQUIRED', %s, %s, %s)
            RETURNING decision_at
            """,
            (
                execution_id,
                request.request_id,
                request_hash,
                credential_chain_hash,
                tenant_id,
                task_id,
                request.tool_service,
                request.tool_name,
                request.tool_version,
                parameter_hash,
                state,
                decision,
                reason_code.value,
                request.business_action_id,
                current_time,
                current_time,
            ),
        ).fetchone()
        if row is None or type(row[0]) is not int or not current_time <= row[0] <= MAX_SAFE_INTEGER:
            raise GatewayError(ReasonCode.REQUEST_STALE, "execution has no trusted admission decision time")
        return row[0]

    @staticmethod
    def _register_request(
        connection: psycopg.Connection,
        *,
        request: RequestEnvelopeModel,
        execution_id: str,
        request_hash: str,
        current_time: int,
        outcome: AdmissionOutcome,
    ) -> None:
        connection.execute(
            """
            INSERT INTO execution_requests (
                request_id, execution_id, request_hash, issued_at, received_at,
                admission_outcome
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                request.request_id,
                execution_id,
                request_hash,
                request.issued_at,
                current_time,
                outcome.value,
            ),
        )
        connection.execute(
            """
            INSERT INTO replay_records (request_id, request_hash, first_seen_at)
            VALUES (%s, %s, %s)
            """,
            (request.request_id, request_hash, current_time),
        )

    @staticmethod
    def _existing_decision(
        connection: psycopg.Connection,
        *,
        execution_id: str,
        request_hash: str,
        credential_chain_hash: str,
        outcome: AdmissionOutcome,
        decision: str | None = None,
        reason_code: ReasonCode | None = None,
    ) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT state, decision, reason_code
            FROM execution_records WHERE execution_id = %s
            FOR SHARE
            """,
            (execution_id,),
        ).fetchone()
        if row is None:
            raise GatewayError(
                ReasonCode.IDEMPOTENCY_CONFLICT,
                "idempotency record references a missing execution",
                status_code=409,
            )
        return {
            "execution_id": execution_id,
            "state": str(row[0]),
            "decision": decision or str(row[1]),
            "reason_code": (reason_code or ReasonCode(str(row[2]))).value,
            "request_hash": request_hash,
            "credential_chain_hash": credential_chain_hash,
            "admission_outcome": outcome.value,
            "validated_command": None,
            "receipt": None,
        }
