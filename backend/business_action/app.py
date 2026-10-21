from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.business_action.contracts import (
    BusinessActionResponse,
    BusinessFactEvaluationResponse,
    CreateBusinessCaseRequest,
    CreateBusinessCaseResponse,
    EvaluateRefundFactsRequest,
    ResolveNotificationActionRequest,
    ResolveRefundActionRequest,
)
from backend.business_action.service import (
    BusinessActionError,
    BusinessActionRegistryService,
)
from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.common.time import now_unix
from backend.config.settings import Settings, get_settings


def make_app(
    *,
    settings: Settings | None = None,
    service: BusinessActionRegistryService | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Business Action Registry", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id="business-action-registry",
        )

    async def require_refund_auth(request: Request) -> str:
        return await auth().authenticate_request(
            request, allowed_callers={"agent-refund"}, allow_unsigned_in_test_mode=True,
        )

    async def require_notification_auth(request: Request) -> str:
        return await auth().authenticate_request(
            request, allowed_callers={"agent-case"}, allow_unsigned_in_test_mode=True,
        )

    async def require_business_case_auth(request: Request) -> str:
        return await auth().authenticate_request(request, allowed_callers={"ui-api"})

    async def require_evaluation_auth(request: Request) -> str:
        return await auth().authenticate_request(
            request, allowed_callers={"agent-refund", "agent-case"},
        )

    @lru_cache(maxsize=1)
    def resolved_service() -> BusinessActionRegistryService:
        return service or BusinessActionRegistryService(resolved.database_url)

    @app.exception_handler(BusinessActionError)
    async def business_action_error_handler(
        request: Request, exc: BusinessActionError
    ) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=exc.status_code,
            content={"reason_code": exc.reason_code.value, "message": str(exc)},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(
            status_code=400,
            content={
                "reason_code": ReasonCode.REQUEST_SCHEMA_INVALID.value,
                "message": "request does not match the trusted runtime schema",
            },
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "business-action-registry"}

    @app.post(
        "/business-cases", status_code=201, response_model=CreateBusinessCaseResponse,
        dependencies=[Depends(require_business_case_auth)],
    )
    def create_business_case(request: CreateBusinessCaseRequest) -> dict[str, object]:
        return resolved_service().create_business_case(request, current_time=now_unix())

    @app.post(
        "/business-actions/refund/evaluate", response_model=BusinessFactEvaluationResponse,
        dependencies=[Depends(require_evaluation_auth)],
    )
    def evaluate_refund_facts(request: EvaluateRefundFactsRequest) -> dict[str, object]:
        return resolved_service().evaluate_refund_facts(request, current_time=now_unix())

    @app.post(
        "/business-actions/refund/resolve", response_model=BusinessActionResponse,
        dependencies=[Depends(require_refund_auth)],
    )
    def resolve_refund(request: ResolveRefundActionRequest) -> dict[str, object]:
        return resolved_service().resolve_refund(request, current_time=now_unix())

    @app.post(
        "/business-actions/notification/resolve",
        response_model=BusinessActionResponse,
        dependencies=[Depends(require_notification_auth)],
    )
    def resolve_notification(
        request: ResolveNotificationActionRequest,
    ) -> dict[str, object]:
        return resolved_service().resolve_notification(request, current_time=now_unix())

    return app


app = make_app()
