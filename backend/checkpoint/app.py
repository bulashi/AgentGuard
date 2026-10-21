from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, FastAPI, HTTPException, Request

from backend.audit.contracts import CheckpointRunResponse
from backend.checkpoint.service import CheckpointError, CheckpointService
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.config.settings import Settings, get_settings
from backend.identity.key_registry import KeyRegistryError


def make_app(
    *, settings: Settings | None = None, service: CheckpointService | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Independent Checkpoint Service", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id="checkpoint-service",
        )

    async def require_worker_auth(request: Request) -> str:
        allowed = {"checkpoint-worker"}
        if not auth().required:
            allowed.update({"phase11-test", "phase12-test", "phase13-test"})
        return await auth().authenticate_request(request, allowed_callers=allowed)

    @lru_cache(maxsize=1)
    def resolved_service() -> CheckpointService:
        return service or CheckpointService(
            resolved.database_url,
            resolved.audit_database_url,
            private_key_file=resolved.audit_private_key_file,
            key_id=resolved.audit_key_id,
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "checkpoint-service"}

    @app.post(
        "/internal/checkpoint/run", response_model=CheckpointRunResponse,
        dependencies=[Depends(require_worker_auth)],
    )
    def run() -> CheckpointRunResponse:
        try:
            checkpoint = resolved_service().run_once()
        except (CheckpointError, KeyRegistryError, OSError, ValueError) as exc:
            raise HTTPException(
                status_code=500,
                detail={"reason_code": "TOOL_EXECUTION_UNKNOWN"},
            ) from exc
        if checkpoint is None:
            return CheckpointRunResponse(status="IDLE", checkpoint=None)
        return CheckpointRunResponse(status="CREATED", checkpoint=checkpoint)

    @app.get("/checkpoints/latest")
    def latest() -> dict[str, object]:
        checkpoint = resolved_service().latest()
        return {
            "status": "EMPTY" if checkpoint is None else "AVAILABLE",
            "checkpoint": checkpoint,
        }

    return app


app = make_app()
