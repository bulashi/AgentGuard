from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import Depends, FastAPI, Path, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from psycopg import OperationalError, errors
from starlette.concurrency import run_in_threadpool

from backend.authorization.contracts import (
    IDENTIFIER_PATTERN,
    AuthorizeTaskRequest,
    CreateTaskRequest,
    TaskResponse,
)
from backend.authorization.service import AuthorizationError, RootAuthorizationService
from backend.coauthorization.contracts import (
    MAX_BUNDLE_BYTES,
    ChallengeResponse,
    CoauthorizationBundle,
    CoauthorizationResponse,
    CoauthorizationTaskReview,
    CreateChallengeRequest,
)
from backend.coauthorization.review import CoauthorizationReadService
from backend.coauthorization.service import CoauthorizationService
from backend.coauthorization.verifier import CoauthorizationError, CoauthorizationReason
from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.common.time import now_unix
from backend.config.settings import Settings, get_settings


def parse_trusted_confirmers(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in value.split(","):
        identifier, separator, source = item.strip().partition(":")
        if not separator or not identifier or source not in {"USER", "POLICY"}:
            raise ValueError("trusted confirmers must use confirmer_id:USER|POLICY")
        result[identifier] = source
    return result


def make_app(
    *,
    settings: Settings | None = None,
    service: RootAuthorizationService | None = None,
    coauthorization_service: CoauthorizationService | None = None,
    coauthorization_read_service: CoauthorizationReadService | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Authorization Authority", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id="authorization-authority",
        )

    async def require_control_auth(request: Request) -> str:
        return await auth().authenticate_request(
            request, allowed_callers={"ui-api"}, allow_unsigned_in_test_mode=True,
            max_body_bytes=MAX_BUNDLE_BYTES
            if request.url.path.startswith("/extensions/coauthorization/") else None,
        )

    @lru_cache(maxsize=1)
    def resolved_service() -> RootAuthorizationService:
        return service or RootAuthorizationService(
            database_url=resolved.database_url,
            private_key_root=resolved.authorization_private_key_root,
            authority_subject_id=resolved.authorization_subject_id,
            authority_key_id=resolved.authorization_key_id,
            trusted_confirmers=parse_trusted_confirmers(
                resolved.authorization_trusted_confirmers
            ),
            coauthorization_required=resolved.coauthorization_required,
        )

    @lru_cache(maxsize=1)
    def resolved_coauthorization_service() -> CoauthorizationService:
        if not resolved.coauthorization_required:
            raise CoauthorizationError(
                CoauthorizationReason.DISABLED, "coauthorization v1 is disabled",
            )
        return coauthorization_service or CoauthorizationService(
            root_service=resolved_service(),
            challenge_ttl_seconds=resolved.coauthorization_challenge_ttl_seconds,
        )

    @lru_cache(maxsize=1)
    def resolved_coauthorization_read_service() -> CoauthorizationReadService:
        return coauthorization_read_service or CoauthorizationReadService(resolved.database_url)

    @app.exception_handler(CoauthorizationError)
    async def coauthorization_error_handler(
        request: Request, exc: CoauthorizationError,
    ) -> JSONResponse:
        del request
        codes = {
            CoauthorizationReason.DISABLED: 404,
            CoauthorizationReason.INVALID_BUNDLE: 400,
            CoauthorizationReason.CHALLENGE_CONFLICT: 409,
            CoauthorizationReason.IDEMPOTENCY_CONFLICT: 409,
            CoauthorizationReason.TASK_NOT_AUTHORIZABLE: 409,
            CoauthorizationReason.REGISTRY_UNAVAILABLE: 503,
            CoauthorizationReason.STORED_EVIDENCE_INVALID: 503,
        }
        return JSONResponse(
            status_code=codes.get(exc.reason_code, 403),
            content={"reason_code": exc.reason_code.value, "message": str(exc)},
        )

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(
        request: Request, exc: AuthorizationError
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
                "message": "request does not match the frozen API schema",
            },
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "authorization-authority"}

    @app.post(
        "/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_control_auth)],
    )
    def create_task(request: CreateTaskRequest) -> dict[str, str]:
        return resolved_service().create_task(request, current_time=now_unix())

    @app.post(
        "/tasks/{task_id}/authorize", status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_control_auth)],
    )
    def authorize_task(task_id: str, request: AuthorizeTaskRequest) -> dict[str, Any]:
        if resolved.coauthorization_required:
            raise CoauthorizationError(
                CoauthorizationReason.REQUIRED, "independent approvals are required",
            )
        return resolved_service().authorize_task(task_id, request, current_time=now_unix())

    @app.get("/extensions/coauthorization/v1/status")
    def coauthorization_status() -> dict[str, Any]:
        return {
            "schema_version": "1.0", "enabled": resolved.coauthorization_required,
            "policy_source": "SERVER_REGISTERED_PUBLIC_KEYS", "signing": "EXTERNAL_APPROVERS_ONLY",
        }

    @app.get(
        "/extensions/coauthorization/v1/tasks/{task_id}", response_model=CoauthorizationTaskReview,
    )
    def coauthorization_task_history(
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
        offset: int = Query(default=0, ge=0, le=1_000_000),
    ) -> CoauthorizationTaskReview:
        try:
            return resolved_coauthorization_read_service().task_history(task_id, offset=offset)
        except (OperationalError, errors.UndefinedTable) as exc:
            raise CoauthorizationError(
                CoauthorizationReason.REGISTRY_UNAVAILABLE,
                "approval storage unavailable; check migration 0015",
            ) from exc

    @app.post(
        "/extensions/coauthorization/v1/tasks/{task_id}/challenges",
        response_model=ChallengeResponse, dependencies=[Depends(require_control_auth)],
    )
    def create_coauthorization_challenge(
        request: CreateChallengeRequest,
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
    ) -> ChallengeResponse:
        try:
            return resolved_coauthorization_service().create_challenge(task_id, request)
        except (OperationalError, errors.UndefinedTable) as exc:
            raise CoauthorizationError(
                CoauthorizationReason.REGISTRY_UNAVAILABLE,
                "approval storage unavailable; check migration 0015",
            ) from exc

    @app.post(
        "/extensions/coauthorization/v1/tasks/{task_id}/authorize",
        response_model=CoauthorizationResponse, dependencies=[Depends(require_control_auth)],
    )
    async def authorize_coauthorization(
        request: Request,
        task_id: str = Path(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN),
    ) -> CoauthorizationResponse:
        authority = resolved_coauthorization_service()
        if (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            raise CoauthorizationError(
                CoauthorizationReason.INVALID_BUNDLE, "application/json is required",
            )
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BUNDLE_BYTES:
                raise CoauthorizationError(
                    CoauthorizationReason.INVALID_BUNDLE, "approval bundle exceeds 32768 bytes",
                )
            body.extend(chunk)
        try:
            return await run_in_threadpool(authority.authorize_task, task_id, bytes(body))
        except (OperationalError, errors.UndefinedTable) as exc:
            raise CoauthorizationError(
                CoauthorizationReason.REGISTRY_UNAVAILABLE,
                "approval storage unavailable; check migration 0015",
            ) from exc

    def authority_openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            document = get_openapi(title=app.title, version=app.version, routes=app.routes)
            bundle_schema = CoauthorizationBundle.model_json_schema(
                ref_template="#/components/schemas/CoauthV1{model}"
            )
            schemas = document.setdefault("components", {}).setdefault("schemas", {})
            schemas.update({
                "CoauthV1" + name: value for name, value in bundle_schema.pop("$defs", {}).items()
            })
            schemas["CoauthV1Bundle"] = bundle_schema
            operation = document["paths"][
                "/extensions/coauthorization/v1/tasks/{task_id}/authorize"
            ]["post"]
            operation["requestBody"] = {
                "required": True,
                "description": (
                    "Raw strict JSON, maximum 32768 bytes; independent external signatures only."
                ),
                "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/CoauthV1Bundle"}},
                },
            }
            app.openapi_schema = document
        return app.openapi_schema

    app.openapi = authority_openapi
    return app


app = make_app()
