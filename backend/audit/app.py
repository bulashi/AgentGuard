from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, FastAPI, HTTPException, Request

from backend.audit.contracts import (
    AuditAppendRequest,
    AuditAppendResponse,
    AuditVerifyRequest,
    AuditVerifyResponse,
    RejectedAuditEventModel,
)
from backend.audit.prefix_contracts import AuditPrefixRequest, AuditPrefixResponse
from backend.audit.service import AuditError, AuditService
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.config.settings import Settings, get_settings


def make_app(
    *, settings: Settings | None = None, service: AuditService | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Audit Append Authority", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id="audit-append-authority",
        )

    async def require_append_auth(request: Request) -> str:
        allowed = {"audit-worker"}
        if not auth().required:
            allowed.update({"phase11-test", "phase12-test", "phase13-test"})
        return await auth().authenticate_request(request, allowed_callers=allowed)

    async def require_rejected_auth(request: Request) -> str:
        allowed = {"secure-gateway"}
        if not auth().required:
            allowed.update({"phase11-test", "phase12-test", "phase13-test"})
        return await auth().authenticate_request(request, allowed_callers=allowed)

    @lru_cache(maxsize=1)
    def resolved_service() -> AuditService:
        return service or AuditService(
            resolved.database_url,
            audit_database_url=resolved.audit_database_url,
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "audit-append-authority"}

    @app.post(
        "/internal/audit/append", response_model=AuditAppendResponse,
        dependencies=[Depends(require_append_auth)],
    )
    def append(
        request: AuditAppendRequest,
    ) -> AuditAppendResponse:
        try:
            result = resolved_service().append_pending(max_events=request.max_events)
            return AuditAppendResponse(**result)
        except AuditError as exc:
            raise HTTPException(
                status_code=500,
                detail={
                    "reason_code": "TOOL_EXECUTION_UNKNOWN",
                    "message": str(exc),
                },
            ) from exc

    @app.post("/internal/audit/rejected", dependencies=[Depends(require_rejected_auth)])
    def rejected(
        event: RejectedAuditEventModel,
    ) -> dict[str, str]:
        try:
            resolved_service().enqueue_rejected(event.model_dump(mode="json"))
        except AuditError as exc:
            raise HTTPException(
                status_code=400,
                detail={"reason_code": "REQUEST_SCHEMA_INVALID"},
            ) from exc
        return {"status": "accepted"}

    @app.post("/audit/verify", response_model=AuditVerifyResponse)
    def verify(request: AuditVerifyRequest) -> AuditVerifyResponse:
        try:
            return AuditVerifyResponse(**resolved_service().verify(
                from_sequence=request.from_sequence,
                include_independent_checkpoint=request.include_independent_checkpoint,
            ))
        except AuditError as exc:
            raise HTTPException(
                status_code=500,
                detail={"reason_code": "TOOL_EXECUTION_UNKNOWN"},
            ) from exc

    @app.post(
        "/extensions/audit-prefix-binding/v1/verify-events", response_model=AuditPrefixResponse,
    )
    def verify_events(request: AuditPrefixRequest) -> dict[str, object]:
        try:
            return resolved_service().verify_events(request)
        except (AuditError, ValueError) as exc:
            raise HTTPException(
                status_code=500,
                detail={
                    "reason_code": "TOOL_EXECUTION_UNKNOWN",
                    "message": "audit prefix verification unavailable",
                },
            ) from exc

    return app


app = make_app()
