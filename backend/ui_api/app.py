from __future__ import annotations

from functools import lru_cache

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from backend.agent_runtime.security_proof import SecurityProofRequest
from backend.audit.prefix_contracts import AuditPrefixRequest, AuditPrefixResponse
from backend.authorization.contracts import (
    IDENTIFIER_PATTERN,
    AuthorizeTaskRequest,
    CreateTaskRequest,
)
from backend.business_action.contracts import CreateBusinessCaseRequest, CreateBusinessCaseResponse
from backend.coauthorization.contracts import (
    MAX_BUNDLE_BYTES,
    ChallengeResponse,
    CoauthorizationBundle,
    CoauthorizationResponse,
    CoauthorizationTaskReview,
    CreateChallengeRequest,
)
from backend.common.strict_json_route import StrictJsonRoute
from backend.config.model_profiles import ModelConfigurationError
from backend.config.settings import Settings, get_settings
from backend.ui_api.contracts import (
    PromptInjectionDemoRequest,
    QueuedWorkflowResponse,
    RunTaskRequest,
    StartWorkflowRequest,
    WorkflowErrorResponse,
)
from backend.ui_api.model_api import ModelConfigurationGuard, model_configuration_router
from backend.ui_api.operator_session import (
    OperatorSessionGuard,
    OperatorSessionRequest,
    OperatorSessionResponse,
)
from backend.ui_api.revocation_contracts import UiRevocationResponse, UiRevokeCredentialRequest
from backend.ui_api.revocation_verification import (
    RevocationVerificationResponse,
    VerifyRevokedRequest,
)
from backend.ui_api.security_contracts import SecurityProofHistory, SecurityProofResponse
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore

WORKFLOW_ERROR_RESPONSES = {
    status: {"model": WorkflowErrorResponse} for status in (400, 403, 404, 409, 502, 503)
}
REVOCATION_ERROR_RESPONSES = {
    status: {"model": WorkflowErrorResponse} for status in (400, 401, 403, 404, 409, 502, 503)
}


def make_app(*, settings: Settings | None = None, service: UiService | None = None) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Workbench API", version="1.0.0")
    app.router.route_class = StrictJsonRoute
    app.add_middleware(ModelConfigurationGuard)
    app.add_middleware(
        OperatorSessionGuard,
        required=resolved.operator_auth_required,
        secret=resolved.operator_session_secret,
    )

    @lru_cache(maxsize=1)
    def resolved_service() -> UiService:
        return service or UiService(resolved, UiReadStore(resolved.ui_database_url))

    app.include_router(
        model_configuration_router(
            resolved,
            idle=lambda: not resolved_service().store.has_pending_workflows(),
        )
    )

    @app.exception_handler(ModelConfigurationError)
    async def model_error_handler(request: Request, exc: ModelConfigurationError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=exc.status_code,
            content={"reason_code": exc.reason_code, "message": str(exc)},
        )

    @app.exception_handler(UiApiError)
    async def ui_error_handler(request: Request, exc: UiApiError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=exc.status_code,
            content={"reason_code": exc.reason_code, "message": str(exc)},
        )

    @app.exception_handler(RequestValidationError)
    async def workflow_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        if (
            request.url.path.startswith("/api/model-configurations")
            or request.url.path == "/api/operator-session"
        ):
            return JSONResponse(
                status_code=422,
                content={
                    "reason_code": "REQUEST_SCHEMA_INVALID",
                    "message": "模型配置字段无效，请检查端点、模型与密钥格式",
                },
            )
        if request.method == "POST" and request.url.path == "/api/tasks":
            labels = {
                "tenant_id": "租户",
                "ticket_id": "工单",
                "customer_id": "客户",
                "refund_total_fen": "退款预算",
                "max_tool_calls": "工具调用预算",
                "expires_in_seconds": "有效期",
            }
            errors = {}
            for error in exc.errors():
                field = error["loc"][1] if len(error["loc"]) > 1 else None
                if field in labels:
                    if field in {"tenant_id", "customer_id"}:
                        errors[field] = (
                            f"{labels[field]}须为 1 至 128 字中文、字母或数字，"
                            "可含常用标识符号，不可含空白"
                        )
                    elif field == "ticket_id":
                        errors[field] = "工单编号须为 1 至 128 位字母或数字，可含 . _ : -"
                    else:
                        errors[field] = f"{labels[field]}须为有效范围内的整数"
            return JSONResponse(
                status_code=422,
                content={
                    "reason_code": "REQUEST_SCHEMA_INVALID",
                    "message": "请检查任务字段的格式和取值",
                    "field_errors": errors,
                },
            )
        if request.method == "POST" and request.url.path == "/api/business/cases":
            return JSONResponse(status_code=422, content={
                "reason_code": "REQUEST_SCHEMA_INVALID",
                "message": "请检查订单和支付记录：金额须大于零、最多两位小数；支付编号不可重复，已退金额不可超过该笔成功付款",
            })
        workflow_request = request.url.path == "/api/workflows" or (
            request.url.path.startswith("/api/tasks/") and request.url.path.endswith("/workflow")
        )
        revocation_request = request.url.path.startswith("/api/tasks/") and request.url.path.endswith(("/revoke", "/verify-revoked"))
        if revocation_request:
            return JSONResponse(status_code=400, content={
                "reason_code": "REQUEST_SCHEMA_INVALID",
                "message": "撤销请求须包含明确确认和有效原因",
            })
        if not workflow_request and not request.url.path.startswith(
            "/api/extensions/coauthorization/v1/"
        ):
            return await request_validation_exception_handler(request, exc)
        return JSONResponse(
            status_code=400,
            content={
                "reason_code": "REQUEST_SCHEMA_INVALID",
                "message": "协作请求不符合公开契约"
                if workflow_request
                else "共同授权请求不符合公开契约",
            },
        )

    @app.post("/api/operator-session", response_model=OperatorSessionResponse)
    def operator_session(request: OperatorSessionRequest) -> OperatorSessionResponse:
        del request
        # Native mode consumes this request in the outer guard, before route validation.
        raise HTTPException(status_code=503, detail="native operator session is not enabled")

    @app.get("/health")
    def health() -> dict[str, str]:
        subject = resolved_service()
        subject.store.probe_schema()
        subject.security_matrix()
        return {"status": "ok", "service": "ui-api"}

    @app.get("/api/overview")
    def overview() -> dict[str, object]:
        return resolved_service().overview()

    @app.get("/api/business/tickets")
    def business_tickets() -> dict[str, object]:
        return {"items": resolved_service().store.list_business_tickets()}

    @app.post("/api/business/cases", status_code=201, response_model=CreateBusinessCaseResponse)
    def create_business_case(request: CreateBusinessCaseRequest) -> dict[str, object]:
        return resolved_service().create_business_case(request)

    @app.get("/api/tasks")
    def tasks(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        search: str = Query(default="", max_length=200),
        status: str = Query(default="", max_length=40),
    ) -> dict[str, object]:
        rows = resolved_service().store.list_tasks(
            limit=limit + 1, offset=offset, search=search, status=status
        )
        return {"items": rows[:limit], "has_more": len(rows) > limit}

    @app.get("/api/tasks/{task_id}")
    def task(task_id: str) -> dict[str, object]:
        snapshot = resolved_service().store.task_snapshot(task_id)
        if snapshot is None:
            raise HTTPException(status_code=404, detail={"reason_code": "CROSS_TASK"})
        return snapshot

    @app.post("/api/tasks", status_code=201)
    def create_task(request: CreateTaskRequest) -> dict[str, object]:
        return resolved_service().create_task(request)

    @app.post(
        "/api/tasks/{task_id}/credentials/{credential_id}/revoke",
        response_model=UiRevocationResponse,
        responses=REVOCATION_ERROR_RESPONSES,
    )
    def revoke_credential(
        request: Request,
        body: UiRevokeCredentialRequest,
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
        credential_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
    ) -> dict[str, object]:
        from backend.ui_api.revocation import authenticated_operator, revoke_credential

        operator = authenticated_operator(request, resolved, operator_id=resolved.operator_subject_id)
        return revoke_credential(
            resolved_service(), task_id, credential_id, body,
            operator_id=operator, revocation_url=resolved.revocation_url,
        )

    @app.post(
        "/api/tasks/{task_id}/credentials/{credential_id}/verify-revoked",
        response_model=RevocationVerificationResponse,
        responses=REVOCATION_ERROR_RESPONSES,
    )
    def verify_revoked_credential(
        request: Request,
        body: VerifyRevokedRequest,
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
        credential_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
    ) -> dict[str, object]:
        from backend.ui_api.revocation import authenticated_operator
        from backend.ui_api.revocation_verification import verify_revoked

        del body
        authenticated_operator(request, resolved, operator_id=resolved.operator_subject_id)
        return verify_revoked(resolved_service(), task_id, credential_id)

    @app.post("/api/security/proofs", response_model=SecurityProofResponse)
    def security_proof(request: SecurityProofRequest) -> dict[str, object]:
        from backend.ui_api.security_proof import run_proof

        return run_proof(resolved_service(), request)

    @app.get("/api/security/proofs", response_model=SecurityProofHistory)
    def security_proof_history() -> dict[str, object]:
        from backend.ui_api.security_proof import reports

        return reports(resolved_service())

    @app.post(
        "/api/extensions/audit-prefix-binding/v1/tasks/{task_id}/verify-events",
        response_model=AuditPrefixResponse,
    )
    def audit_prefix(
        request: AuditPrefixRequest,
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
    ) -> dict[str, object]:
        return resolved_service().audit_prefix(task_id, request)

    @app.post("/api/tasks/{task_id}/authorize", status_code=201)
    def authorize_task(task_id: str, request: AuthorizeTaskRequest) -> dict[str, object]:
        return resolved_service().authorize_task(task_id, request)

    @app.post("/api/tasks/{task_id}/run")
    def run_task(task_id: str, request: RunTaskRequest) -> dict[str, object]:
        return resolved_service().run_task(task_id, prompt_text=request.prompt_text)

    @app.post(
        "/api/tasks/{task_id}/workflow",
        status_code=202,
        response_model=QueuedWorkflowResponse,
        responses=WORKFLOW_ERROR_RESPONSES,
    )
    def start_authorized_workflow(
        request: StartWorkflowRequest,
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
    ) -> dict[str, object]:
        return resolved_service().start_authorized_workflow(task_id, request)

    @app.post("/api/demos/normal")
    def normal_demo() -> dict[str, object]:
        return resolved_service().run_normal_demo()

    @app.get("/api/runtime-profiles")
    def runtime_profiles() -> dict[str, object]:
        return resolved_service().runtime_profiles()

    @app.get("/api/extensions/coauthorization/v1/status")
    def coauthorization_status() -> dict[str, object]:
        return resolved_service().coauthorization_status()

    @app.get(
        "/api/extensions/coauthorization/v1/tasks/{task_id}",
        response_model=CoauthorizationTaskReview,
    )
    def coauthorization_task(
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
        offset: int = Query(default=0, ge=0, le=1_000_000),
    ) -> dict[str, object]:
        return resolved_service().coauthorization_task(task_id, offset=offset)

    @app.post(
        "/api/extensions/coauthorization/v1/tasks/{task_id}/challenges",
        response_model=ChallengeResponse,
    )
    def create_coauthorization_challenge(
        request: CreateChallengeRequest,
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
    ) -> dict[str, object]:
        return resolved_service().create_coauthorization_challenge(task_id, request)

    @app.post(
        "/api/extensions/coauthorization/v1/tasks/{task_id}/authorize",
        response_model=CoauthorizationResponse,
    )
    async def authorize_coauthorization_task(
        request: Request,
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
    ) -> dict[str, object]:
        if (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            raise UiApiError("COAUTH_INVALID_BUNDLE", "须使用 application/json", status_code=400)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BUNDLE_BYTES:
                raise UiApiError(
                    "COAUTH_INVALID_BUNDLE", "审批签名包超过 32768 字节", status_code=400
                )
            body.extend(chunk)
        return await run_in_threadpool(
            resolved_service().authorize_coauthorization_task, task_id, bytes(body)
        )

    @app.post(
        "/api/workflows",
        status_code=202,
        response_model=QueuedWorkflowResponse,
        responses=WORKFLOW_ERROR_RESPONSES,
    )
    def start_workflow(request: StartWorkflowRequest) -> dict[str, object]:
        return resolved_service().start_workflow(request)

    @app.post("/api/demos/prompt-injection")
    def prompt_injection_demo(
        request: PromptInjectionDemoRequest,
    ) -> dict[str, object]:
        return resolved_service().run_prompt_injection_demo(request.prompt_text)

    @app.get("/api/security/matrix")
    def security_matrix() -> dict[str, object]:
        return resolved_service().security_matrix()

    @app.get("/api/benchmarks")
    def benchmarks() -> dict[str, object]:
        return resolved_service().benchmark_summary()

    def ui_openapi() -> dict:
        if app.openapi_schema is None:
            document = get_openapi(title=app.title, version=app.version, routes=app.routes)
            for path in ("/api/workflows", "/api/tasks/{task_id}/workflow"):
                document["paths"][path]["post"]["responses"].pop("422", None)
            for path in (
                "/api/tasks/{task_id}/credentials/{credential_id}/revoke",
                "/api/tasks/{task_id}/credentials/{credential_id}/verify-revoked",
            ):
                document["paths"][path]["post"]["responses"].pop("422", None)
            bundle = CoauthorizationBundle.model_json_schema(
                ref_template="#/components/schemas/UiCoauthV1{model}"
            )
            schemas = document.setdefault("components", {}).setdefault("schemas", {})
            schemas.update(
                {"UiCoauthV1" + name: value for name, value in bundle.pop("$defs", {}).items()}
            )
            schemas["UiCoauthV1Bundle"] = bundle
            document["paths"]["/api/extensions/coauthorization/v1/tasks/{task_id}/authorize"][
                "post"
            ]["requestBody"] = {
                "required": True,
                "description": (
                    "Raw strict JSON, maximum 32768 bytes; forwarded without re-serialization."
                ),
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/UiCoauthV1Bundle"}
                    }
                },
            }
            app.openapi_schema = document
        return app.openapi_schema

    app.openapi = ui_openapi

    return app


app = make_app()
