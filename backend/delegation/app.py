from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.common.time import now_unix
from backend.config.settings import Settings, get_settings
from backend.delegation.contracts import DelegateCredentialRequest
from backend.delegation.service import DelegationError, DelegationService


def make_app(
    *, settings: Settings | None = None, service: DelegationService | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Holder Delegation Service", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        role = resolved.delegation_agent_id.removeprefix("agent-")
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id=f"{role}-delegation-agent",
        )

    async def require_holder_auth(request: Request) -> str:
        return await auth().authenticate_request(
            request, allowed_callers={resolved.delegation_agent_id},
            allow_unsigned_in_test_mode=True,
        )

    @lru_cache(maxsize=1)
    def resolved_service() -> DelegationService:
        return service or DelegationService(
            database_url=resolved.database_url,
            agent_id=resolved.delegation_agent_id,
            agent_key_id=resolved.delegation_key_id,
            private_key_root=resolved.delegation_private_key_root,
        )

    @app.exception_handler(DelegationError)
    async def delegation_error_handler(
        request: Request, exc: DelegationError
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
        return {"status": "ok", "service": resolved.delegation_agent_id}

    @app.post(
        "/credentials/{credential_id}/delegate",
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_holder_auth)],
    )
    def delegate(
        credential_id: str, request: DelegateCredentialRequest
    ) -> dict[str, Any]:
        return resolved_service().delegate(
            credential_id, request, current_time=now_unix()
        )

    return app


app = make_app()
