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
from backend.revocation.contracts import RevocationResponse, RevokeCredentialRequest
from backend.revocation.service import RevocationError, RevocationService


def make_app(
    *, settings: Settings | None = None, service: RevocationService | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Revocation Authority", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id="revocation-authority",
        )

    async def require_control_auth(request: Request) -> str:
        allowed = {"revocation-controller", "ui-api"}
        if not auth().required:
            allowed.add("revocation-authority")
        return await auth().authenticate_request(request, allowed_callers=allowed)

    @lru_cache(maxsize=1)
    def resolved_service() -> RevocationService:
        return service or RevocationService(resolved.database_url)

    @app.exception_handler(RevocationError)
    async def revocation_error_handler(
        request: Request, exc: RevocationError
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
        return {"status": "ok", "service": "revocation-authority"}

    @app.post(
        "/credentials/{credential_id}/revoke",
        response_model=RevocationResponse,
        status_code=status.HTTP_200_OK,
        dependencies=[Depends(require_control_auth)],
    )
    def revoke(
        credential_id: str,
        request: RevokeCredentialRequest,
    ) -> dict[str, Any]:
        return resolved_service().revoke(
            credential_id,
            request,
            current_time=now_unix(),
        )

    return app


app = make_app()
