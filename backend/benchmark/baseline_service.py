from __future__ import annotations

from pathlib import Path
from time import perf_counter_ns
from typing import Any, cast

import httpx
from psycopg.types.json import Jsonb

from backend.benchmark.contracts import (
    BaselineMode,
    BaselineToolRequest,
    ConfigureRunRequest,
    RevokePrincipalRequest,
    SetupWorkloadRequest,
)
from backend.business_action.policy import TrustedTaskContext, notification_scope, refund_scope
from backend.common.enums import KeyPurpose
from backend.common.ids import new_id
from backend.common.time import now_unix
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import GATEWAY_EXECUTION_ENVELOPE
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex
from backend.state.database import connect

TOOL_ENDPOINTS = {
    "ticket-service": "benchmark_ticket_tool_url",
    "knowledge-service": "benchmark_knowledge_tool_url",
    "refund-service": "benchmark_refund_tool_url",
    "notification-service": "benchmark_notification_tool_url",
}

EXPECTED_TOOL_NAMES = {
    "ticket-service": "ticket.read",
    "knowledge-service": "knowledge.read_associated",
    "refund-service": "refund.create",
    "notification-service": "notification.send_template",
}

EXPECTED_PARAMETER_KEYS = {
    "ticket.read": {"ticket_id"},
    "knowledge.read_associated": {"ticket_id"},
    "refund.create": {"ticket_id", "customer_id", "amount_fen"},
    "notification.send_template": {
        "customer_id",
        "template_id",
        "related_business_effect_id",
    },
}


class BaselineError(RuntimeError):
    def __init__(self, reason_code: str, message: str, *, status_code: int = 403) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


def baseline_policy_decision(
    mode: BaselineMode,
    *,
    supplied_token_hash: str,
    principal: dict[str, Any],
    tenant_id: str,
    tool_service: str,
) -> str | None:
    if principal["status"] != "ACTIVE":
        return "CREDENTIAL_REVOKED"
    if supplied_token_hash != principal["token_hash"]:
        return "INVALID_CREDENTIAL"
    if mode == "shared_static_credential":
        return None
    if tenant_id != principal["tenant_scope"]:
        return "CROSS_TENANT"
    if tool_service not in principal["service_permissions"]:
        return "TOOL_NOT_ALLOWED"
    return None


def baseline_action_scope(
    request: BaselineToolRequest, *, task_ticket_id: str, task_customer_id: str
) -> tuple[str, dict[str, Any]]:
    parameters = request.canonical_parameters
    context = TrustedTaskContext(
        request.tenant_id,
        request.task_id,
        parameters.get("ticket_id", task_ticket_id),
        parameters.get("customer_id", task_customer_id),
    )
    if request.tool_name == "refund.create":
        return refund_scope(context, trusted_action_slot=request.trusted_action_slot)
    if request.tool_name == "notification.send_template":
        return notification_scope(
            context,
            template_id=parameters["template_id"],
            related_business_effect_id=parameters["related_business_effect_id"],
        )
    raise BaselineError("BUSINESS_ACTION_INVALID", "read-only tool has no business action")


class BaselineGatewayService:
    def __init__(self, settings: Settings) -> None:
        mode = settings.benchmark_mode
        if mode not in {"shared_static_credential", "conventional_rbac"}:
            raise ValueError(f"unsupported benchmark mode: {mode}")
        self.mode = cast(BaselineMode, mode)
        self.database_url = settings.database_url
        self.settings = settings
        private_path = Path(settings.gateway_private_key_file)
        self.private_key = private_path.read_text(encoding="ascii").strip()
        self.public_key = derive_public_key(self.private_key)
        self.gateway_key_id = settings.gateway_key_id

    def health(self) -> dict[str, str]:
        with connect(self.database_url) as connection:
            connection.execute("SELECT 1").fetchone()
        return {"status": "ok", "service": "benchmark-baseline", "mode": self.mode}

    def configure(self, request: ConfigureRunRequest) -> dict[str, Any]:
        token = self._configured_token()
        principal_id = (
            "shared-static-tool-credential"
            if self.mode == "shared_static_credential"
            else "agent-refund-rbac"
        )
        tenant_scope = None if self.mode == "shared_static_credential" else "tenant-A"
        permissions = sorted(TOOL_ENDPOINTS)
        current = now_unix()
        with connect(self.database_url) as connection, connection.transaction():
            inserted = connection.execute(
                """
                INSERT INTO benchmark_principals (
                    mode, run_id, principal_id, token_hash, agent_role,
                    tenant_scope, service_permissions, status, revoked_at, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'ACTIVE', NULL, %s)
                ON CONFLICT (mode, run_id) DO NOTHING
                RETURNING run_id
                """,
                (
                    self.mode,
                    request.run_id,
                    principal_id,
                    sm3_hex(token.encode("utf-8")),
                    "shared-agent" if self.mode == "shared_static_credential" else "refund-agent",
                    tenant_scope,
                    Jsonb(permissions),
                    current,
                ),
            ).fetchone()
            if inserted is None:
                raise BaselineError(
                    "BENCHMARK_RUN_EXISTS",
                    "a fresh benchmark principal is required; historical lifecycle is unchanged",
                    status_code=409,
                )
        return {
            "mode": self.mode,
            "run_id": request.run_id,
            "principal_id": principal_id,
            "tenant_scope": tenant_scope,
            "service_permissions": permissions,
            "status": "ACTIVE",
        }

    def setup_workload(self, request: SetupWorkloadRequest) -> dict[str, Any]:
        current = now_unix()
        with connect(self.database_url) as connection, connection.transaction():
            principal = connection.execute(
                "SELECT 1 FROM benchmark_principals WHERE mode=%s AND run_id=%s",
                (self.mode, request.run_id),
            ).fetchone()
            if principal is None:
                raise BaselineError(
                    "BENCHMARK_NOT_CONFIGURED", "benchmark run is not configured", status_code=409
                )
            connection.execute(
                """
                INSERT INTO tasks (
                    task_id, tenant_id, ticket_id, customer_id, refund_total_fen,
                    max_tool_calls, expires_at, status, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'AUTHORIZED', %s, %s)
                ON CONFLICT (task_id) DO NOTHING
                """,
                (
                    request.task_id,
                    request.tenant_id,
                    request.ticket_id,
                    request.customer_id,
                    request.refund_total_fen,
                    request.max_tool_calls,
                    current + request.expires_in_seconds,
                    current,
                    current,
                ),
            )
            connection.execute(
                """
                INSERT INTO benchmark_workloads (
                    mode, workload_id, run_id, task_id, intended_tenant_id,
                    intended_ticket_id, intended_customer_id, refund_total_fen,
                    max_tool_calls, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (mode, workload_id) DO NOTHING
                """,
                (
                    self.mode,
                    request.workload_id,
                    request.run_id,
                    request.task_id,
                    request.tenant_id,
                    request.ticket_id,
                    request.customer_id,
                    request.refund_total_fen,
                    request.max_tool_calls,
                    current,
                ),
            )
        return {
            "mode": self.mode,
            "run_id": request.run_id,
            "workload_id": request.workload_id,
            "task_id": request.task_id,
            "status": "READY",
        }

    def revoke(self, request: RevokePrincipalRequest) -> dict[str, Any]:
        current = now_unix()
        with connect(self.database_url) as connection, connection.transaction():
            row = connection.execute(
                """
                UPDATE benchmark_principals
                SET status='REVOKED', revoked_at=%s
                WHERE mode=%s AND run_id=%s
                RETURNING principal_id
                """,
                (current, self.mode, request.run_id),
            ).fetchone()
            if row is None:
                raise BaselineError(
                    "BENCHMARK_NOT_CONFIGURED",
                    "principal not found",
                    status_code=404,
                )
        return {
            "mode": self.mode,
            "run_id": request.run_id,
            "principal_id": str(row[0]),
            "status": "REVOKED",
            "revoked_at": current,
            "reason": request.reason,
        }

    def execute(self, request: BaselineToolRequest, *, bearer_token: str) -> dict[str, Any]:
        started_ns = perf_counter_ns()
        parameter_hash = sm3_hex(canonicalize(request.canonical_parameters))
        request_hash = sm3_hex(canonicalize(request.model_dump(mode="json")))
        persistence_ns = 0
        current = now_unix()

        self._validate_tool_shape(request)
        with connect(self.database_url) as connection, connection.transaction():
            lookup_started = perf_counter_ns()
            workload = connection.execute(
                """
                SELECT run_id FROM benchmark_workloads
                WHERE mode=%s AND workload_id=%s
                FOR SHARE
                """,
                (self.mode, request.workload_id),
            ).fetchone()
            if workload is None or str(workload[0]) != request.run_id:
                raise BaselineError(
                    "UNKNOWN_WORKLOAD",
                    "benchmark workload was not configured",
                    status_code=404,
                )
            principal_row = connection.execute(
                """
                SELECT token_hash, tenant_scope, service_permissions, status
                FROM benchmark_principals
                WHERE mode=%s AND run_id=%s
                FOR SHARE
                """,
                (self.mode, request.run_id),
            ).fetchone()
            if principal_row is None:
                raise BaselineError(
                    "BENCHMARK_NOT_CONFIGURED",
                    "principal not found",
                    status_code=404,
                )
            principal = {
                "token_hash": str(principal_row[0]),
                "tenant_scope": None if principal_row[1] is None else str(principal_row[1]),
                "service_permissions": list(principal_row[2]),
                "status": str(principal_row[3]),
            }
            reason = baseline_policy_decision(
                self.mode,
                supplied_token_hash=sm3_hex(bearer_token.encode("utf-8")),
                principal=principal,
                tenant_id=request.tenant_id,
                tool_service=request.tool_service,
            )
            if reason is not None:
                persistence_ns += perf_counter_ns() - lookup_started
                self._insert_request(
                    connection,
                    request=request,
                    request_hash=request_hash,
                    parameter_hash=parameter_hash,
                    decision="DENY",
                    reason_code=reason,
                    execution_id=None,
                    business_effect_id=None,
                    persistence_ns=persistence_ns,
                    current=current,
                )
                return self._decision(
                    request,
                    decision="DENY",
                    state="DENIED",
                    reason_code=reason,
                    persistence_ns=persistence_ns,
                    total_ns=perf_counter_ns() - started_ns,
                )

            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"{self.mode}|request|{request.request_id}",),
            )
            if (
                connection.execute(
                    "SELECT 1 FROM benchmark_requests WHERE mode=%s AND request_id=%s",
                    (self.mode, request.request_id),
                ).fetchone()
                is not None
            ):
                return self._decision(
                    request,
                    decision="DENY",
                    state="DENIED",
                    reason_code="REPLAY_DETECTED",
                    persistence_ns=perf_counter_ns() - lookup_started,
                    total_ns=perf_counter_ns() - started_ns,
                )

            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"{self.mode}|operation|{request.workload_id}|{request.operation_id}",),
            )
            existing = connection.execute(
                """
                SELECT parameter_hash, execution_id, state, result, business_effect_id
                FROM benchmark_operations
                WHERE mode=%s AND workload_id=%s AND operation_id=%s
                FOR UPDATE
                """,
                (self.mode, request.workload_id, request.operation_id),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != parameter_hash:
                    persistence_ns += perf_counter_ns() - lookup_started
                    self._insert_request(
                        connection,
                        request=request,
                        request_hash=request_hash,
                        parameter_hash=parameter_hash,
                        decision="DENY",
                        reason_code="IDEMPOTENCY_CONFLICT",
                        execution_id=str(existing[1]),
                        business_effect_id=None if existing[4] is None else str(existing[4]),
                        persistence_ns=persistence_ns,
                        current=current,
                    )
                    return self._decision(
                        request,
                        decision="DENY",
                        state="DENIED",
                        reason_code="IDEMPOTENCY_CONFLICT",
                        execution_id=str(existing[1]),
                        business_effect_id=None if existing[4] is None else str(existing[4]),
                        persistence_ns=persistence_ns,
                        total_ns=perf_counter_ns() - started_ns,
                    )
                if str(existing[2]) == "COMMITTED":
                    persistence_ns += perf_counter_ns() - lookup_started
                    self._insert_request(
                        connection,
                        request=request,
                        request_hash=request_hash,
                        parameter_hash=parameter_hash,
                        decision="ALLOW",
                        reason_code="IDEMPOTENT_RETURN",
                        execution_id=str(existing[1]),
                        business_effect_id=None if existing[4] is None else str(existing[4]),
                        persistence_ns=persistence_ns,
                        current=current,
                    )
                    return self._decision(
                        request,
                        decision="ALLOW",
                        state="COMMITTED",
                        reason_code="IDEMPOTENT_RETURN",
                        execution_id=str(existing[1]),
                        business_effect_id=None if existing[4] is None else str(existing[4]),
                        result=None if existing[3] is None else dict(existing[3]),
                        idempotent_return=True,
                        persistence_ns=persistence_ns,
                        total_ns=perf_counter_ns() - started_ns,
                    )
                persistence_ns += perf_counter_ns() - lookup_started
                self._insert_request(
                    connection,
                    request=request,
                    request_hash=request_hash,
                    parameter_hash=parameter_hash,
                    decision="DENY",
                    reason_code="OPERATION_IN_PROGRESS",
                    execution_id=str(existing[1]),
                    business_effect_id=None,
                    persistence_ns=persistence_ns,
                    current=current,
                )
                return self._decision(
                    request,
                    decision="DENY",
                    state="DENIED",
                    reason_code="OPERATION_IN_PROGRESS",
                    execution_id=str(existing[1]),
                    persistence_ns=persistence_ns,
                    total_ns=perf_counter_ns() - started_ns,
                )

            prepared = self._prepare_execution(
                connection,
                request=request,
                request_hash=request_hash,
                parameter_hash=parameter_hash,
                current=current,
            )
            persistence_ns += perf_counter_ns() - lookup_started

        dispatch_started = perf_counter_ns()
        try:
            tool_response = self._dispatch(prepared["envelope"], request.tool_service)
        except BaselineError as exc:
            self._release_failed_operation(
                request,
                prepared["execution_id"],
                request_hash=request_hash,
                parameter_hash=parameter_hash,
                reason_code=exc.reason_code,
                persistence_ns=persistence_ns,
            )
            raise
        dispatch_ns = perf_counter_ns() - dispatch_started

        settle_started = perf_counter_ns()
        with connect(self.database_url) as connection, connection.transaction():
            result = tool_response.get("result")
            effect_id = tool_response.get("business_effect_id")
            result_hash = tool_response.get("business_result_hash")
            connection.execute(
                """
                UPDATE execution_records
                SET state='COMMITTED', result=%s, business_effect_id=%s,
                    business_result_hash=%s, updated_at=%s
                WHERE execution_id=%s
                """,
                (
                    None if result is None else Jsonb(result),
                    effect_id,
                    result_hash,
                    now_unix(),
                    prepared["execution_id"],
                ),
            )
            if prepared["business_action_id"] is not None:
                connection.execute(
                    """
                    UPDATE business_actions
                    SET status='COMMITTED', updated_at=%s
                    WHERE business_action_id=%s
                    """,
                    (now_unix(), prepared["business_action_id"]),
                )
            connection.execute(
                """
                UPDATE benchmark_operations
                SET state='COMMITTED', result=%s, business_effect_id=%s, updated_at=%s
                WHERE mode=%s AND workload_id=%s AND operation_id=%s
                """,
                (
                    None if result is None else Jsonb(result),
                    effect_id,
                    now_unix(),
                    self.mode,
                    request.workload_id,
                    request.operation_id,
                ),
            )
            persistence_ns += perf_counter_ns() - settle_started
            self._insert_request(
                connection,
                request=request,
                request_hash=request_hash,
                parameter_hash=parameter_hash,
                decision="ALLOW",
                reason_code="ALLOWED",
                execution_id=prepared["execution_id"],
                business_effect_id=None if effect_id is None else str(effect_id),
                persistence_ns=persistence_ns,
                current=now_unix(),
            )
        return self._decision(
            request,
            decision="ALLOW",
            state="COMMITTED",
            reason_code="ALLOWED",
            execution_id=prepared["execution_id"],
            business_effect_id=None if effect_id is None else str(effect_id),
            result=None if result is None else cast(dict[str, Any], result),
            persistence_ns=persistence_ns,
            network_ns=dispatch_ns,
            total_ns=perf_counter_ns() - started_ns,
        )

    def _prepare_execution(
        self,
        connection: Any,
        *,
        request: BaselineToolRequest,
        request_hash: str,
        parameter_hash: str,
        current: int,
    ) -> dict[str, Any]:
        task = connection.execute(
            "SELECT ticket_id, customer_id FROM tasks WHERE task_id=%s",
            (request.task_id,),
        ).fetchone()
        if task is None:
            raise BaselineError("CROSS_TASK", "target task does not exist", status_code=404)
        execution_id = new_id("BASEEXEC")
        action_id: str | None = None
        idempotency_key: str | None = None
        if request.trusted_action_slot is not None:
            action_id = new_id("BASEACTION")
            action_scope_key, scope_payload = baseline_action_scope(
                request, task_ticket_id=str(task[0]), task_customer_id=str(task[1])
            )
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (action_scope_key,)
            )
            connection.execute(
                """
                INSERT INTO business_actions (
                    business_action_id, action_scope_key, trusted_action_slot,
                    tenant_id, task_id, tool_service, tool_name, status,
                    created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'ACTIVE', %s, %s)
                ON CONFLICT (action_scope_key) DO NOTHING
                """,
                (
                    action_id,
                    action_scope_key,
                    request.trusted_action_slot,
                    request.tenant_id,
                    request.task_id,
                    request.tool_service,
                    request.tool_name,
                    current,
                    current,
                ),
            )
            action_id = str(
                connection.execute(
                    "SELECT business_action_id FROM business_actions "
                    "WHERE action_scope_key=%s FOR SHARE",
                    (action_scope_key,),
                ).fetchone()[0]
            )
            idempotency_key = sm3_hex(
                canonicalize({**scope_payload, "business_action_id": action_id})
            )
        connection.execute(
            """
            INSERT INTO execution_records (
                execution_id, initial_request_id, request_hash, credential_chain_hash,
                tenant_id, task_id, tool_service, tool_name, tool_version,
                parameter_hash, state, decision, reason_code, receipt_status,
                business_action_id, created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'v1', %s,
                    'DISPATCHED', 'ALLOW', 'ALLOWED', 'NOT_REQUIRED', %s, %s, %s)
            """,
            (
                execution_id,
                request.request_id,
                request_hash,
                sm3_hex(f"{self.mode}|{request.run_id}".encode()),
                request.tenant_id,
                request.task_id,
                request.tool_service,
                request.tool_name,
                parameter_hash,
                action_id,
                current,
                current,
            ),
        )
        connection.execute(
            """
            INSERT INTO benchmark_operations (
                mode, workload_id, operation_id, parameter_hash, execution_id,
                state, created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, 'DISPATCHED', %s, %s)
            """,
            (
                self.mode,
                request.workload_id,
                request.operation_id,
                parameter_hash,
                execution_id,
                current,
                current,
            ),
        )
        issued_at = now_unix()
        payload = {
            "schema_version": "1.0",
            "execution_id": execution_id,
            "execution_attempt_id": new_id("BASEATTEMPT"),
            "request_hash": request_hash,
            "tenant_id": request.tenant_id,
            "task_id": request.task_id,
            "tool_service": request.tool_service,
            "tool_name": request.tool_name,
            "tool_version": "v1",
            "canonical_validated_parameters": request.canonical_parameters,
            "business_action_id": action_id,
            "business_idempotency_key": idempotency_key,
            "parameter_hash": parameter_hash,
            "issued_at": issued_at,
            "expires_at": issued_at + self.settings.envelope_ttl_seconds,
            "gateway_key_id": self.gateway_key_id,
        }
        return {
            "execution_id": execution_id,
            "business_action_id": action_id,
            "envelope": {
                "payload": payload,
                "signature": sign_payload(
                    payload,
                    domain_separator=GATEWAY_EXECUTION_ENVELOPE,
                    key_id=self.gateway_key_id,
                    key_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
                    private_key_hex=self.private_key,
                    public_key_hex=self.public_key,
                    signed_at=issued_at,
                ),
            },
        }

    def _dispatch(self, envelope: dict[str, Any], tool_service: str) -> dict[str, Any]:
        setting_name = TOOL_ENDPOINTS[tool_service]
        base_url = str(getattr(self.settings, setting_name))
        try:
            with httpx.Client(base_url=base_url, timeout=30, trust_env=False) as client:
                response = client.post("/internal/execute", json=envelope)
        except httpx.HTTPError as exc:
            raise BaselineError(
                "UPSTREAM_UNAVAILABLE",
                "benchmark tool unavailable",
                status_code=502,
            ) from exc
        if response.status_code != 200:
            try:
                body = response.json()
            except ValueError:
                body = {}
            detail = body.get("detail") if isinstance(body, dict) else None
            reason = detail.get("reason_code") if isinstance(detail, dict) else None
            raise BaselineError(
                str(reason or "TOOL_REJECTED"),
                response.text,
                status_code=response.status_code,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise BaselineError(
                "CONTROLLED_RESULT_INVALID",
                "benchmark tool returned non-object",
                status_code=502,
            )
        return body

    def _release_failed_operation(
        self,
        request: BaselineToolRequest,
        execution_id: str,
        *,
        request_hash: str,
        parameter_hash: str,
        reason_code: str,
        persistence_ns: int,
    ) -> None:
        with connect(self.database_url) as connection, connection.transaction():
            release_started = perf_counter_ns()
            current = now_unix()
            connection.execute(
                """
                UPDATE execution_records
                SET state='RELEASED', decision='DENY',
                    reason_code=%s, updated_at=%s
                WHERE execution_id=%s
                """,
                (reason_code, current, execution_id),
            )
            connection.execute(
                """
                UPDATE business_actions
                SET status='RELEASED', updated_at=%s
                WHERE business_action_id = (
                    SELECT business_action_id
                    FROM execution_records
                    WHERE execution_id=%s
                )
                  AND status='ACTIVE'
                """,
                (current, execution_id),
            )
            connection.execute(
                """
                UPDATE benchmark_operations SET state='RELEASED', updated_at=%s
                WHERE mode=%s AND workload_id=%s AND operation_id=%s
                """,
                (current, self.mode, request.workload_id, request.operation_id),
            )
            self._insert_request(
                connection,
                request=request,
                request_hash=request_hash,
                parameter_hash=parameter_hash,
                decision="DENY",
                reason_code=reason_code,
                execution_id=execution_id,
                business_effect_id=None,
                persistence_ns=persistence_ns + perf_counter_ns() - release_started,
                current=current,
            )

    def _insert_request(self, connection: Any, **kwargs: Any) -> None:
        request = cast(BaselineToolRequest, kwargs.pop("request"))
        connection.execute(
            """
            INSERT INTO benchmark_requests (
                mode, request_id, workload_id, operation_id, request_hash,
                parameter_hash, decision, reason_code, execution_id,
                business_effect_id, persistence_ns, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                self.mode,
                request.request_id,
                request.workload_id,
                request.operation_id,
                kwargs["request_hash"],
                kwargs["parameter_hash"],
                kwargs["decision"],
                kwargs["reason_code"],
                kwargs["execution_id"],
                kwargs["business_effect_id"],
                max(0, int(kwargs["persistence_ns"])),
                kwargs["current"],
            ),
        )

    def _validate_tool_shape(self, request: BaselineToolRequest) -> None:
        if EXPECTED_TOOL_NAMES[request.tool_service] != request.tool_name:
            raise BaselineError("TOOL_NOT_ALLOWED", "service and tool name do not match")
        expected = EXPECTED_PARAMETER_KEYS[request.tool_name]
        if set(request.canonical_parameters) != expected:
            raise BaselineError(
                "PARAMETER_CONSTRAINT_VIOLATION",
                "tool parameters do not match the shared tool contract",
            )
        if request.tool_name == "refund.create":
            amount = request.canonical_parameters.get("amount_fen")
            if type(amount) is not int or amount <= 0:
                raise BaselineError(
                    "PARAMETER_CONSTRAINT_VIOLATION",
                    "refund amount must be positive",
                )
        if (
            request.tool_name == "notification.send_template"
            and request.canonical_parameters.get("template_id") != "REFUND_SUCCESS"
        ):
            raise BaselineError("PARAMETER_CONSTRAINT_VIOLATION", "template is not supported")

    def _configured_token(self) -> str:
        return (
            self.settings.benchmark_static_token
            if self.mode == "shared_static_credential"
            else self.settings.benchmark_rbac_token
        )

    def _decision(
        self,
        request: BaselineToolRequest,
        *,
        decision: str,
        state: str,
        reason_code: str,
        persistence_ns: int,
        total_ns: int,
        network_ns: int = 0,
        execution_id: str | None = None,
        business_effect_id: str | None = None,
        result: dict[str, Any] | None = None,
        idempotent_return: bool = False,
    ) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "request_id": request.request_id,
            "operation_id": request.operation_id,
            "decision": decision,
            "state": state,
            "reason_code": reason_code,
            "execution_id": execution_id,
            "business_effect_id": business_effect_id,
            "result": result,
            "idempotent_return": idempotent_return,
            "timings": {
                "total_ms": round(total_ns / 1_000_000, 6),
                "network_ms": round(network_ns / 1_000_000, 6),
                "persistence_ms": round(persistence_ns / 1_000_000, 6),
            },
        }
