from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from jsonschema import ValidationError
from psycopg.types.json import Jsonb

from backend.admission.service import AdmissionService
from backend.common.enums import AdmissionOutcome, KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import GATEWAY_EXECUTION_ENVELOPE
from backend.crypto.sm import sign_payload, sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.delegation.verifier import ChainVerificationError
from backend.gateway.contracts import RequestEnvelopeModel, ValidatedToolCommandModel
from backend.gateway.service import GatewayError, SecureGatewayService
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.recovery.service import RecoveryService
from backend.revocation.dispatch_guard import (
    DispatchGuardError,
    cancel_locked_execution,
    denial_body,
    dispatch_failure,
    lock_dispatch_chain,
)
from backend.state.database import connect
from backend.tools.contracts import GatewayExecutionEnvelopeModel, ToolExecutionResponse


@dataclass(frozen=True)
class DispatchResult:
    body: dict[str, Any]
    status_code: int = 200


class _ToolDispatchFailure(RuntimeError):
    pass


class GatewayDispatchService:
    """Dispatch an admitted command and settle its atomic budget reservation."""

    def __init__(
        self,
        gateway: SecureGatewayService,
        admission: AdmissionService,
        *,
        tool_urls: Mapping[tuple[str, str], str],
        gateway_key_id: str,
        gateway_private_key_file: str,
        envelope_ttl_seconds: int = 30,
        request_timeout_seconds: float = 15.0,
        recovery_max_attempts: int = 3,
        recovery_deadline_seconds: int = 300,
    ) -> None:
        if type(envelope_ttl_seconds) is not int or not 0 < envelope_ttl_seconds <= MAX_SAFE_INTEGER:
            raise ValueError("envelope_ttl_seconds must be a positive safe integer")
        if recovery_max_attempts <= 0:
            raise ValueError("recovery_max_attempts must be positive")
        if type(recovery_deadline_seconds) is not int or not 0 < recovery_deadline_seconds <= MAX_SAFE_INTEGER:
            raise ValueError("recovery_deadline_seconds must be a positive safe integer")
        self.gateway = gateway
        self.admission = admission
        self.tool_urls = dict(tool_urls)
        self.gateway_key_id = gateway_key_id
        self.gateway_private_key_file = gateway_private_key_file
        self.envelope_ttl_seconds = envelope_ttl_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.recovery_max_attempts = recovery_max_attempts
        self.recovery_deadline_seconds = recovery_deadline_seconds

    def dispatch(
        self, request: RequestEnvelopeModel, *, current_time: int
    ) -> DispatchResult:
        admission = self.admission.admit_request(request, current_time=current_time)
        if admission.status_code != 200:
            return DispatchResult(admission.body, admission.status_code)

        body = admission.body
        outcome = str(body.get("admission_outcome"))
        if outcome == AdmissionOutcome.IDEMPOTENT_RETURN.value:
            return DispatchResult(body)

        command = self._command_for_admitted_request(request, body)
        if command is None:
            return DispatchResult(body)

        envelope = self._mark_dispatched(
            command,
            request_hash=self._stored_request_hash(command.execution_id),
        )
        if isinstance(envelope, DispatchResult):
            return envelope
        if envelope is None:
            return DispatchResult(
                self._current_state_body(
                    body,
                    command,
                    state=self._execution_state(command.execution_id),
                )
            )

        try:
            tool_response = self._call_tool(envelope)
            committed = self._settle_success(
                command,
                body=body,
                tool_response=tool_response,
            )
        except (_ToolDispatchFailure, GatewayError):
            try:
                state = self._mark_unknown(command.execution_id)
            except GatewayError:
                # A post-tool observation failure is not a new authorization denial.
                state = self._execution_state(command.execution_id)
            if state == "COMMITTED":
                return DispatchResult(self._current_state_body(body, command, state=state))
            failed = self._unknown_body(body, command)
            failed["state"] = state
            return DispatchResult(
                failed,
                status_code=502,
            )

        return DispatchResult(committed)

    def _command_for_admitted_request(
        self,
        request: RequestEnvelopeModel,
        body: dict[str, Any],
    ) -> ValidatedToolCommandModel | None:
        command_data = body.get("validated_command")
        if command_data is not None:
            return ValidatedToolCommandModel.model_validate(command_data)
        if body.get("state") != "ADMITTED":
            return None

        execution_id = str(body["execution_id"])
        parameter_hash = sm3_hex(canonicalize(request.canonical_parameters))
        with connect(self.gateway.database_url) as connection:
            row = connection.execute(
                """
                SELECT execution_id, tenant_id, task_id, tool_service, tool_name,
                       tool_version, parameter_hash, business_action_id, state
                FROM execution_records
                WHERE execution_id = %s
                """,
                (execution_id,),
            ).fetchone()
            if row is None or str(row[8]) != "ADMITTED":
                return None
            if str(row[6]) != parameter_hash:
                raise GatewayError(
                    ReasonCode.IDEMPOTENCY_CONFLICT,
                    "stored execution parameters differ from the retry request",
                    status_code=409,
                )
            idempotency = connection.execute(
                """
                SELECT business_idempotency_key
                FROM idempotency_records
                WHERE execution_id = %s
                """,
                (execution_id,),
            ).fetchone()
        return ValidatedToolCommandModel(
            schema_version="1.0",
            execution_id=str(row[0]),
            tenant_id=str(row[1]),
            task_id=str(row[2]),
            tool_service=str(row[3]),
            tool_name=str(row[4]),
            tool_version=str(row[5]),
            validated_parameters=request.canonical_parameters,
            business_action_id=None if row[7] is None else str(row[7]),
            business_idempotency_key=(
                None if idempotency is None or idempotency[0] is None else str(idempotency[0])
            ),
            parameter_hash=str(row[6]),
        )

    def _mark_dispatched(
        self,
        command: ValidatedToolCommandModel,
        *,
        request_hash: str,
    ) -> GatewayExecutionEnvelopeModel | DispatchResult | None:
        with connect(self.gateway.database_url) as connection, connection.transaction():
            chain, execution = self._lock_dispatch_authorization(connection, command.execution_id)
            stopped = self._recheck_dispatch_authorization(connection, chain, execution)
            if stopped is not None:
                return stopped
            row = connection.execute(
                """
                SELECT state, decision, created_at, updated_at, decision_at, decision_value::text
                FROM execution_records
                WHERE execution_id = %s
                FOR UPDATE
                """,
                (command.execution_id,),
            ).fetchone()
            if row is None:
                raise GatewayError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "admitted execution does not exist",
                    status_code=500,
                )
            if str(row[0]) != "ADMITTED":
                return None
            if (
                str(row[1]) != "ALLOW" or row[5] != "ALLOW"
                or any(type(row[index]) is not int for index in (2, 3, 4))
                or not 0 <= row[2] <= row[4] <= row[3] <= MAX_SAFE_INTEGER
            ):
                raise GatewayError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "admitted execution has no matching trusted decision time",
                    status_code=409,
                )
            idempotency_updated_at = None
            if command.business_idempotency_key is not None:
                idempotency = connection.execute(
                    """
                    SELECT business_idempotency_key, parameter_hash, status, updated_at
                    FROM idempotency_records WHERE execution_id = %s FOR UPDATE
                    """,
                    (command.execution_id,),
                ).fetchone()
                if (
                    idempotency is None
                    or tuple(idempotency[:3]) != (
                        command.business_idempotency_key, command.parameter_hash, "ADMITTED",
                    )
                    or type(idempotency[3]) is not int
                    or not 0 <= idempotency[3] <= MAX_SAFE_INTEGER
                ):
                    raise GatewayError(
                        ReasonCode.IDEMPOTENCY_CONFLICT,
                        "admitted dispatch does not match its business idempotency record",
                        status_code=409,
                    )
                idempotency_updated_at = idempotency[3]
            try:
                key = PostgresKeyRegistry.resolve_for_signing_with_connection(
                    connection,
                    self.gateway_key_id,
                    expected_subject_id=self.gateway.audience,
                    expected_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
                    lock=True,
                )
            except KeyRegistryError as exc:
                raise GatewayError(exc.reason_code, str(exc)) from exc
            private_key = Path(self.gateway_private_key_file).read_text(encoding="ascii").strip()
            # Start the envelope lifetime after all dispatch row/key waits and key loading.
            issued_at = self._dispatch_clock(connection)
            if (
                issued_at < row[3]
                or (idempotency_updated_at is not None and issued_at < idempotency_updated_at)
                or issued_at > MAX_SAFE_INTEGER - self.envelope_ttl_seconds
            ):
                raise GatewayError(
                    ReasonCode.EXECUTION_ENVELOPE_EXPIRED,
                    "dispatch clock precedes stored state or envelope expiry overflows",
                    status_code=409,
                )
            expires_at = issued_at + self.envelope_ttl_seconds
            stopped = self._recheck_dispatch_authorization(connection, chain, execution)
            if stopped is not None:
                return stopped
            if chain:
                expires_at = min(expires_at, *(item.expires_at for item in chain))
            payload = {
                "schema_version": "1.0",
                "execution_id": command.execution_id,
                "execution_attempt_id": new_id("ATTEMPT"),
                "request_hash": request_hash,
                "tenant_id": command.tenant_id,
                "task_id": command.task_id,
                "tool_service": command.tool_service,
                "tool_name": command.tool_name,
                "tool_version": command.tool_version,
                "canonical_validated_parameters": command.validated_parameters,
                "business_action_id": command.business_action_id,
                "business_idempotency_key": command.business_idempotency_key,
                "parameter_hash": command.parameter_hash,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "gateway_key_id": self.gateway_key_id,
            }
            signature = sign_payload(
                payload,
                domain_separator=GATEWAY_EXECUTION_ENVELOPE,
                key_id=self.gateway_key_id,
                key_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
                private_key_hex=private_key,
                public_key_hex=key.public_key_hex,
                signed_at=issued_at,
            )
            envelope = GatewayExecutionEnvelopeModel(payload=payload, signature=signature)
            try:
                self.gateway.schemas.validate(
                    "gateway-execution-envelope.schema.json",
                    envelope.model_dump(mode="json"),
                )
            except ValidationError as exc:
                raise GatewayError(
                    ReasonCode.REQUEST_SCHEMA_INVALID,
                    "gateway execution envelope violates the frozen schema",
                    status_code=500,
                ) from exc
            connection.execute(
                """
                UPDATE execution_records
                SET state = 'DISPATCHED', updated_at = %s
                WHERE execution_id = %s AND state = 'ADMITTED'
                """,
                (issued_at, command.execution_id),
            )
            if command.business_idempotency_key is not None:
                connection.execute(
                    """
                    UPDATE idempotency_records
                    SET status = 'DISPATCHED', updated_at = %s
                    WHERE execution_id = %s
                    """,
                    (issued_at, command.execution_id),
                )
            if not issued_at <= self._dispatch_clock(connection) <= expires_at:
                raise GatewayError(
                    ReasonCode.EXECUTION_ENVELOPE_EXPIRED,
                    "execution envelope expired or clock regressed before dispatch commit",
                    status_code=409,
                )
        return envelope

    def _lock_dispatch_authorization(self, connection, execution_id: str):
        try:
            chain = lock_dispatch_chain(connection, execution_id)
            execution = RecoveryService._load_execution(connection, execution_id, lock=True)
            if execution is None:
                raise DispatchGuardError("admitted execution disappeared")
            return chain, execution
        except (DispatchGuardError, ChainVerificationError, KeyRegistryError) as error:
            raise GatewayError(ReasonCode.TOOL_EXECUTION_UNKNOWN, str(error), status_code=503) from error

    def _recheck_dispatch_authorization(self, connection, chain, execution):
        if execution is None:
            return None
        if execution["state"] != "ADMITTED":
            if execution["state"] == "RELEASED":
                cancelled = connection.execute(
                    "SELECT denial_execution_id FROM dispatch_cancellations WHERE execution_id = %s",
                    (execution["execution_id"],),
                ).fetchone()
                if cancelled is not None:
                    return DispatchResult(denial_body(connection, str(cancelled[0])), status_code=403)
            return None
        try:
            failure, observed_at = dispatch_failure(
                connection, chain, schemas=self.gateway.schemas, execution=execution,
            )
            if failure is not None:
                stopped = cancel_locked_execution(connection, execution, failure, timestamp=observed_at)
                return DispatchResult(stopped, status_code=403)
            return None
        except DispatchGuardError as error:
            raise GatewayError(ReasonCode.TOOL_EXECUTION_UNKNOWN, str(error), status_code=503) from error

    @staticmethod
    def _dispatch_clock(connection) -> int:
        row = connection.execute(
            "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
        ).fetchone()
        if row is None or type(row[0]) is not int or not 0 <= row[0] <= MAX_SAFE_INTEGER:
            raise GatewayError(
                ReasonCode.EXECUTION_ENVELOPE_EXPIRED,
                "trusted dispatch clock is unavailable",
                status_code=409,
            )
        return row[0]

    def _state_observation_time(self, connection, stored_times: list[int]) -> int:
        if any(type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER for value in stored_times):
            raise GatewayError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN, "stored execution clock is invalid", status_code=502,
            )
        try:
            observed_at = self._dispatch_clock(connection)
        except GatewayError as exc:
            raise GatewayError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN, "trusted execution clock is unavailable", status_code=502,
            ) from exc
        if any(observed_at < value for value in stored_times):
            raise GatewayError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN, "execution clock precedes stored state", status_code=502,
            )
        return observed_at

    def _call_tool(self, envelope: GatewayExecutionEnvelopeModel) -> ToolExecutionResponse:
        key = (envelope.payload.tool_service, envelope.payload.tool_name)
        base_url = self.tool_urls.get(key)
        if not base_url:
            raise _ToolDispatchFailure(f"no tool endpoint configured for {key}")
        try:
            with httpx.Client(timeout=self.request_timeout_seconds) as client:
                response = client.post(
                    f"{base_url.rstrip('/')}/internal/execute",
                    json=envelope.model_dump(mode="json"),
                )
        except httpx.HTTPError as exc:
            raise _ToolDispatchFailure("tool request failed") from exc
        if response.status_code != 200:
            raise _ToolDispatchFailure(
                f"tool rejected the execution envelope with HTTP {response.status_code}"
            )
        try:
            result = ToolExecutionResponse.model_validate(response.json())
        except Exception as exc:
            raise _ToolDispatchFailure("tool returned an invalid execution response") from exc
        if (
            result.execution_id != envelope.payload.execution_id
            or result.execution_attempt_id != envelope.payload.execution_attempt_id
            or result.outcome != "SUCCESS"
        ):
            raise _ToolDispatchFailure("tool response is not bound to the dispatched attempt")
        return result

    def _settle_success(
        self,
        command: ValidatedToolCommandModel,
        *,
        body: dict[str, Any],
        tool_response: ToolExecutionResponse,
    ) -> dict[str, Any]:
        result_value = tool_response.result
        if (
            tool_response.execution_id != command.execution_id
            or tool_response.outcome != "SUCCESS"
            or tool_response.reason_code != ReasonCode.ALLOWED.value
            or result_value is None
        ):
            raise _ToolDispatchFailure("tool success does not carry the matching result")
        try:
            result_hash = sm3_hex(canonicalize(result_value))
        except ValueError as exc:
            raise _ToolDispatchFailure("tool result violates the canonical JSON profile") from exc
        if (
            tool_response.business_result_hash is not None
            and tool_response.business_result_hash != result_hash
        ):
            raise _ToolDispatchFailure("tool result digest does not match the actual result")
        for field in (
            "execution_id", "tenant_id", "task_id", "business_action_id",
            "business_idempotency_key", "parameter_hash",
        ):
            if field in result_value and result_value[field] != getattr(command, field):
                raise _ToolDispatchFailure("tool result metadata belongs to another execution")
        effect_field = {
            ("refund-service", "refund.create"): "refund_id",
            ("notification-service", "notification.send_template"): "notification_id",
        }.get((command.tool_service, command.tool_name))
        if effect_field is not None:
            if (
                not command.business_action_id
                or not command.business_idempotency_key
                or not tool_response.business_effect_id
                or result_value.get(effect_field) != tool_response.business_effect_id
            ):
                raise _ToolDispatchFailure("tool result does not bind the business effect")
        elif (
            tool_response.business_effect_id is not None
            or command.business_action_id is not None
            or command.business_idempotency_key is not None
        ):
            raise _ToolDispatchFailure("read-only tool result cannot carry a business effect")
        with connect(self.gateway.database_url) as connection, connection.transaction():
            row = connection.execute(
                """
                SELECT state, business_action_id, updated_at
                FROM execution_records
                WHERE execution_id = %s
                FOR UPDATE
                """,
                (command.execution_id,),
            ).fetchone()
            if row is None:
                raise GatewayError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "execution disappeared before settlement",
                    status_code=500,
                )
            if str(row[0]) == "COMMITTED":
                return self._current_state_body(body, command, state="COMMITTED")
            if str(row[0]) != "DISPATCHED":
                raise GatewayError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "execution is not in DISPATCHED state at settlement",
                    status_code=502,
                )
            if row[1] != command.business_action_id:
                raise GatewayError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "stored execution action differs from the dispatched command",
                    status_code=502,
                )
            reservations = connection.execute(
                """
                SELECT credential_id, quota_type, amount, updated_at
                FROM execution_budget_reservations
                WHERE execution_id = %s AND status = 'RESERVED'
                ORDER BY credential_id, quota_type
                FOR UPDATE
                """,
                (command.execution_id,),
            ).fetchall()
            stored_times = [row[2], *(item[3] for item in reservations)]
            if reservations:
                budget_rows = connection.execute(
                    """
                    SELECT credential_id, quota_type, updated_at
                    FROM credential_budget_state WHERE credential_id = ANY(%s)
                    ORDER BY credential_id, quota_type FOR UPDATE
                    """,
                    (sorted({str(item[0]) for item in reservations}),),
                ).fetchall()
                budget_times = {(str(item[0]), str(item[1])): item[2] for item in budget_rows}
                required = {(str(item[0]), str(item[1])) for item in reservations}
                if not required <= budget_times.keys():
                    raise GatewayError(
                        ReasonCode.TOOL_EXECUTION_UNKNOWN,
                        "budget state disappeared before settlement",
                        status_code=502,
                    )
                stored_times.extend(budget_times[item] for item in required)
            if command.business_idempotency_key is not None:
                idempotency = connection.execute(
                    """
                    SELECT business_idempotency_key, parameter_hash, status, updated_at
                    FROM idempotency_records WHERE execution_id = %s FOR UPDATE
                    """,
                    (command.execution_id,),
                ).fetchone()
                if idempotency is None or tuple(idempotency[:3]) != (
                    command.business_idempotency_key, command.parameter_hash, "DISPATCHED",
                ):
                    raise GatewayError(
                        ReasonCode.IDEMPOTENCY_CONFLICT,
                        "settlement differs from the dispatched business idempotency record",
                        status_code=409,
                    )
                stored_times.append(idempotency[3])
            if command.business_action_id is not None:
                action = connection.execute(
                    "SELECT updated_at FROM business_actions WHERE business_action_id = %s FOR UPDATE",
                    (command.business_action_id,),
                ).fetchone()
                if action is None:
                    raise GatewayError(
                        ReasonCode.TOOL_EXECUTION_UNKNOWN, "business action disappeared before settlement", status_code=502,
                    )
                stored_times.append(action[0])
            current_time = self._state_observation_time(connection, stored_times)
            for credential_id, quota_type, amount, _reservation_updated_at in reservations:
                updated = connection.execute(
                    """
                    UPDATE credential_budget_state
                    SET reserved_value = reserved_value - %s,
                        committed_value = committed_value + %s,
                        version = version + 1,
                        updated_at = %s
                    WHERE credential_id = %s
                      AND quota_type = %s
                      AND reserved_value >= %s
                    RETURNING credential_id
                    """,
                    (
                        amount,
                        amount,
                        current_time,
                        str(credential_id),
                        str(quota_type),
                        amount,
                    ),
                ).fetchone()
                if updated is None:
                    raise GatewayError(
                        ReasonCode.TOOL_EXECUTION_UNKNOWN,
                        "budget reservation cannot be settled safely",
                        status_code=502,
                    )
                connection.execute(
                    """
                    UPDATE execution_budget_reservations
                    SET status = 'COMMITTED', updated_at = %s
                    WHERE execution_id = %s AND credential_id = %s AND quota_type = %s
                    """,
                    (current_time, command.execution_id, str(credential_id), str(quota_type)),
                )
            connection.execute(
                """
                UPDATE execution_records
                SET state = 'COMMITTED', result = %s, business_effect_id = %s,
                    business_result_hash = %s, updated_at = %s
                WHERE execution_id = %s AND state = 'DISPATCHED'
                """,
                (
                    None if result_value is None else Jsonb(result_value),
                    tool_response.business_effect_id,
                    result_hash,
                    current_time,
                    command.execution_id,
                ),
            )
            if command.business_idempotency_key is not None:
                connection.execute(
                    """
                    UPDATE idempotency_records
                    SET status = 'COMMITTED', result = %s, business_effect_id = %s,
                        updated_at = %s
                    WHERE execution_id = %s
                    """,
                    (
                        None if result_value is None else Jsonb(result_value),
                        tool_response.business_effect_id,
                        current_time,
                        command.execution_id,
                    ),
                )
            business_action_id = row[1]
            if business_action_id is not None:
                connection.execute(
                    """
                    UPDATE business_actions
                    SET status = 'COMMITTED', updated_at = %s
                    WHERE business_action_id = %s AND status IN ('ACTIVE', 'COMMITTED')
                    """,
                    (current_time, str(business_action_id)),
                )
        return self._current_state_body(body, command, state="COMMITTED")

    def _mark_unknown(self, execution_id: str) -> str:
        with connect(self.gateway.database_url) as connection, connection.transaction():
            execution = connection.execute(
                "SELECT state, updated_at FROM execution_records WHERE execution_id = %s FOR UPDATE",
                (execution_id,),
            ).fetchone()
            if execution is None:
                raise GatewayError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN, "execution disappeared before failure observation", status_code=500,
                )
            state = str(execution[0])
            if state != "DISPATCHED":
                return state
            stored_times = [execution[1]]
            idempotency = connection.execute(
                "SELECT status, updated_at FROM idempotency_records WHERE execution_id = %s FOR UPDATE",
                (execution_id,),
            ).fetchone()
            if idempotency is not None:
                if str(idempotency[0]) != "DISPATCHED":
                    raise GatewayError(
                        ReasonCode.IDEMPOTENCY_CONFLICT, "failed execution and business state disagree", status_code=409,
                    )
                stored_times.append(idempotency[1])
            recovery = connection.execute(
                "SELECT updated_at FROM execution_recovery_records WHERE execution_id = %s FOR UPDATE",
                (execution_id,),
            ).fetchone()
            if recovery is not None:
                stored_times.append(recovery[0])
            current_time = self._state_observation_time(connection, stored_times)
            if recovery is None and current_time > MAX_SAFE_INTEGER - self.recovery_deadline_seconds:
                raise GatewayError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN, "recovery deadline overflows the safe time range", status_code=502,
                )
            changed = connection.execute(
                """
                UPDATE execution_records
                SET state = 'UNKNOWN', reason_code = %s, updated_at = %s
                WHERE execution_id = %s AND state = 'DISPATCHED'
                """,
                (ReasonCode.TOOL_EXECUTION_UNKNOWN.value, current_time, execution_id),
            )
            if changed.rowcount and recovery is None:
                connection.execute(
                    """
                    INSERT INTO execution_recovery_records (
                        execution_id, recovery_attempt_count, max_recovery_attempts,
                        recovery_deadline, created_at, updated_at
                    )
                    VALUES (%s, 0, %s, %s, %s, %s)
                    ON CONFLICT (execution_id) DO NOTHING
                    """,
                    (
                        execution_id,
                        self.recovery_max_attempts,
                        current_time + self.recovery_deadline_seconds,
                        current_time,
                        current_time,
                    ),
                )
            connection.execute(
                """
                UPDATE idempotency_records
                SET status = 'UNKNOWN', updated_at = %s
                WHERE execution_id = %s AND status = 'DISPATCHED'
                """,
                (current_time, execution_id),
            )
            return "UNKNOWN"

    def _execution_state(self, execution_id: str) -> str:
        with connect(self.gateway.database_url) as connection:
            row = connection.execute(
                "SELECT state FROM execution_records WHERE execution_id = %s",
                (execution_id,),
            ).fetchone()
        if row is None:
            raise GatewayError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN,
                "execution state cannot be loaded",
                status_code=500,
            )
        return str(row[0])

    def _stored_request_hash(self, execution_id: str) -> str:
        with connect(self.gateway.database_url) as connection:
            row = connection.execute(
                "SELECT request_hash FROM execution_records WHERE execution_id = %s",
                (execution_id,),
            ).fetchone()
        if row is None:
            raise GatewayError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN,
                "execution request hash cannot be loaded",
                status_code=500,
            )
        return str(row[0])

    @staticmethod
    def _current_state_body(
        body: dict[str, Any],
        command: ValidatedToolCommandModel,
        *,
        state: str,
    ) -> dict[str, Any]:
        return {
            "execution_id": command.execution_id,
            "state": state,
            "decision": "ALLOW",
            "reason_code": ReasonCode.ALLOWED.value,
            "request_hash": body.get("request_hash"),
            "credential_chain_hash": body.get("credential_chain_hash"),
            "admission_outcome": body.get("admission_outcome"),
            "validated_command": command.model_dump(mode="json"),
            "receipt": None,
        }

    @staticmethod
    def _unknown_body(
        body: dict[str, Any], command: ValidatedToolCommandModel
    ) -> dict[str, Any]:
        return {
            "execution_id": command.execution_id,
            "state": "UNKNOWN",
            "decision": "ALLOW",
            "reason_code": ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
            "request_hash": body.get("request_hash"),
            "credential_chain_hash": body.get("credential_chain_hash"),
            "admission_outcome": body.get("admission_outcome"),
            "validated_command": command.model_dump(mode="json"),
            "receipt": None,
        }
