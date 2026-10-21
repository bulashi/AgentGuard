from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.admission.service import AdmissionResult, AdmissionService
from backend.agent_runtime.contracts import AgentRunRequest
from backend.audit.client import AuditClient
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.common.time import now_unix
from backend.config.settings import Settings, get_settings
from backend.crypto.sm import sm3_hex
from backend.crypto.strict_json import StrictJsonError, parse_strict_json
from backend.gateway.contracts import (
    GatewayDecisionModel,
    RequestEnvelopeModel,
    ResultRetrievalRequestModel,
    RetrievalResponseModel,
)
from backend.gateway.denial import DeniedExecutionRecorder
from backend.gateway.dispatch import DispatchResult, GatewayDispatchService
from backend.gateway.result_retrieval import ResultRetrievalService
from backend.gateway.runtime_authorization import ROLE_TOOLS, authorize_runtime
from backend.gateway.service import GatewayError, SecureGatewayService
from backend.receipt.client import ReceiptClient


def make_app(
    *,
    settings: Settings | None = None,
    service: SecureGatewayService | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Secure Gateway", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def resolved_service() -> SecureGatewayService:
        return service or SecureGatewayService(
            database_url=resolved.database_url,
            audience=resolved.gateway_audience,
            freshness_window_seconds=resolved.freshness_window_seconds,
            allowed_clock_skew_seconds=resolved.allowed_clock_skew_seconds,
        )

    @lru_cache(maxsize=1)
    def resolved_admission() -> AdmissionService:
        return AdmissionService(resolved_service())

    @lru_cache(maxsize=1)
    def runtime_auth() -> InternalAuthenticator:
        return InternalAuthenticator.from_settings(resolved, service_id="secure-gateway")

    async def require_runtime_auth(request: Request) -> str:
        return await runtime_auth().authenticate_request(request, allowed_callers=set(ROLE_TOOLS))

    @lru_cache(maxsize=1)
    def resolved_dispatch() -> GatewayDispatchService:
        return GatewayDispatchService(
            resolved_service(),
            resolved_admission(),
            tool_urls={
                ("ticket-service", "ticket.read"): resolved.ticket_tool_url,
                ("knowledge-service", "knowledge.read_associated"): resolved.knowledge_tool_url,
                ("refund-service", "refund.create"): resolved.refund_tool_url,
                (
                    "notification-service",
                    "notification.send_template",
                ): resolved.notification_tool_url,
            },
            gateway_key_id=resolved.gateway_key_id,
            gateway_private_key_file=resolved.gateway_private_key_file,
            envelope_ttl_seconds=resolved.envelope_ttl_seconds,
            request_timeout_seconds=resolved.tool_request_timeout_seconds,
            recovery_max_attempts=resolved.recovery_max_attempts,
            recovery_deadline_seconds=resolved.recovery_deadline_seconds,
        )

    @lru_cache(maxsize=1)
    def resolved_receipt_client() -> ReceiptClient:
        return ReceiptClient(
            resolved.receipt_service_url,
            timeout_seconds=resolved.receipt_request_timeout_seconds,
            internal_auth=InternalAuthenticator.from_settings(
                resolved, service_id="secure-gateway",
            ),
        )

    @lru_cache(maxsize=1)
    def resolved_denial_recorder() -> DeniedExecutionRecorder:
        return DeniedExecutionRecorder(resolved.database_url)

    @lru_cache(maxsize=1)
    def resolved_retrieval() -> ResultRetrievalService:
        return ResultRetrievalService(
            database_url=resolved.database_url,
            gateway=resolved_service(),
        )

    @lru_cache(maxsize=1)
    def resolved_audit_client() -> AuditClient:
        return AuditClient(
            resolved.audit_service_url,
            timeout_seconds=resolved.audit_request_timeout_seconds,
            internal_auth=InternalAuthenticator.from_settings(
                resolved, service_id="secure-gateway",
            ),
        )

    def denial_response(
        request_model: RequestEnvelopeModel,
        error: GatewayError,
        *,
        current_time: int,
    ) -> JSONResponse:
        body = resolved_denial_recorder().record(
            request_model,
            error,
            current_time=current_time,
        )
        body = attach_receipt(body, current_time=current_time)
        return JSONResponse(status_code=error.status_code, content=body)

    def _raw_rejection_event(
        request: Request,
        exc: RequestValidationError,
        raw: bytes,
        *,
        current_time: int,
    ) -> dict[str, Any]:
        parser_stage = "SCHEMA"
        reason_code = ReasonCode.REQUEST_SCHEMA_INVALID.value
        try:
            parse_strict_json(raw)
        except StrictJsonError as error:
            reason_code = error.reason_code.value
            parser_stage = {
                ReasonCode.INVALID_UTF8: "UTF8",
                ReasonCode.MALFORMED_JSON: "JSON",
                ReasonCode.DUPLICATE_FIELD: "DUPLICATE_KEY",
            }.get(error.reason_code, "SCHEMA")
        else:
            if any(item.get("type") == "extra_forbidden" for item in exc.errors()):
                reason_code = ReasonCode.UNKNOWN_FIELD.value
        return {
            "schema_version": "1.0",
            "event_id": new_id("EVENT-RAW"),
            "raw_request_hash": sm3_hex(raw),
            "parser_stage": parser_stage,
            "reason_code": reason_code,
            "source_context": {
                "transport": "HTTP",
                "source_label": request.url.path[:128] or "secure-gateway",
            },
            "received_at": current_time,
        }

    def attach_receipt(body: dict[str, Any], *, current_time: int) -> dict[str, Any]:
        execution_id = body.get("execution_id")
        state = body.get("state")
        if not isinstance(execution_id, str) or state not in {
            "DENIED",
            "COMMITTED",
            "RELEASED",
        }:
            return body
        receipt = resolved_receipt_client().issue(execution_id, current_time=current_time)
        if receipt is not None:
            body = dict(body)
            body["receipt"] = receipt
        return body

    @app.exception_handler(GatewayError)
    async def gateway_error_handler(request: Request, exc: GatewayError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "execution_id": "DENIED",
                "state": "DENIED",
                "decision": "DENY",
                "reason_code": exc.reason_code.value,
                "admission_outcome": None,
                "validated_command": None,
                "receipt": None,
                "message": str(exc),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        raw = await request.body()
        resolved_audit_client().enqueue_rejected(
            _raw_rejection_event(request, exc, raw, current_time=now_unix())
        )
        return JSONResponse(
            status_code=400,
            content={
                "status": "rejected_at_parse",
                "reason_code": ReasonCode.REQUEST_SCHEMA_INVALID.value,
            },
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "secure-gateway"}

    @app.post("/gateway/runtime/authorize")
    def runtime_authorization(
        request: AgentRunRequest, caller: str = Depends(require_runtime_auth),
    ) -> dict[str, Any]:
        return authorize_runtime(
            resolved_service(), request, caller=caller, current_time=now_unix(),
        )

    @app.post("/gateway/execute", response_model=GatewayDecisionModel)
    def execute(request: RequestEnvelopeModel) -> dict[str, Any] | JSONResponse:
        timestamp = now_unix()
        try:
            return resolved_service().validate_request(request, current_time=timestamp)
        except GatewayError as exc:
            return denial_response(request, exc, current_time=timestamp)

    @app.post("/gateway/admit", response_model=GatewayDecisionModel)
    def admit(request: RequestEnvelopeModel) -> dict[str, Any] | JSONResponse:
        timestamp = now_unix()
        try:
            result: AdmissionResult = resolved_admission().admit_request(
                request, current_time=timestamp
            )
        except GatewayError as exc:
            return denial_response(request, exc, current_time=timestamp)
        body = attach_receipt(result.body, current_time=timestamp)
        if result.status_code != 200:
            return JSONResponse(status_code=result.status_code, content=body)
        return body

    @app.post("/gateway/dispatch", response_model=GatewayDecisionModel)
    def dispatch(request: RequestEnvelopeModel) -> dict[str, Any] | JSONResponse:
        timestamp = now_unix()
        try:
            result: DispatchResult = resolved_dispatch().dispatch(
                request, current_time=timestamp
            )
        except GatewayError as exc:
            return denial_response(request, exc, current_time=timestamp)
        body = attach_receipt(result.body, current_time=timestamp)
        if result.status_code != 200:
            return JSONResponse(status_code=result.status_code, content=body)
        return body

    def retrieval_error_response(error: GatewayError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={"reason_code": error.reason_code.value, "message": str(error)},
        )

    @app.post(
        "/gateway/results/retrieve",
        response_model=RetrievalResponseModel,
    )
    def retrieve_result(
        request: ResultRetrievalRequestModel,
    ) -> dict[str, Any] | JSONResponse:
        try:
            return resolved_retrieval().retrieve(
                request,
                operation="result",
                current_time=now_unix(),
            )
        except GatewayError as exc:
            return retrieval_error_response(exc)

    @app.post("/gateway/receipts/retrieve", response_model=None)
    def retrieve_receipt(
        request: ResultRetrievalRequestModel,
    ) -> dict[str, Any] | JSONResponse:
        try:
            return resolved_retrieval().retrieve(
                request,
                operation="receipt",
                current_time=now_unix(),
            )
        except GatewayError as exc:
            return retrieval_error_response(exc)

    return app


app = make_app()
