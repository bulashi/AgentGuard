from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import Depends, FastAPI, HTTPException, Request

from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.common.time import now_unix
from backend.config.settings import Settings, get_settings
from backend.recovery.contracts import (
    RecoveryDecisionModel,
    RecoveryRunRequest,
    RecoveryRunResponse,
)
from backend.recovery.service import RecoveryService
from backend.recovery.worker import RecoveryWorker


def make_app(
    *, settings: Settings | None = None,
    internal_auth: InternalAuthenticator | None = None,
    recovery_service: RecoveryService | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    stop_event = asyncio.Event()
    worker_task: asyncio.Task[None] | None = None

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id="recovery-worker",
        )

    async def require_trigger_auth(request: Request) -> str:
        return await auth().authenticate_request(request, allowed_callers={"recovery-trigger"})

    @lru_cache(maxsize=1)
    def service() -> RecoveryService:
        return recovery_service or RecoveryService(
            resolved.database_url,
            internal_auth=auth(),
            tool_urls={
                ("refund-service", "refund.create"): resolved.refund_tool_url,
                (
                    "notification-service",
                    "notification.send_template",
                ): resolved.notification_tool_url,
            },
            max_attempts=resolved.recovery_max_attempts,
            deadline_seconds=resolved.recovery_deadline_seconds,
            stale_execution_seconds=resolved.recovery_dispatch_timeout_seconds,
            request_timeout_seconds=resolved.recovery_request_timeout_seconds,
            receipt_url=resolved.receipt_service_url,
            receipt_timeout_seconds=resolved.receipt_request_timeout_seconds,
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        nonlocal worker_task
        if resolved.recovery_autorun:
            worker_task = asyncio.create_task(
                RecoveryWorker(
                    service(), interval_seconds=resolved.recovery_interval_seconds
                ).run(stop_event)
            )
        yield
        stop_event.set()
        if worker_task is not None:
            worker_task.cancel()
            await asyncio.gather(worker_task, return_exceptions=True)

    app = FastAPI(title="AgentGuard Recovery Worker", version="1.0.0", lifespan=lifespan)
    app.router.route_class = StrictJsonRoute

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "recovery-worker"}

    @app.post("/internal/recovery/run", response_model=RecoveryRunResponse)
    def run(
        request: RecoveryRunRequest,
        _caller: str = Depends(require_trigger_auth),
    ) -> RecoveryRunResponse:
        if auth().required and request.current_time is not None:
            raise HTTPException(
                status_code=400,
                detail={"reason_code": ReasonCode.PARAMETER_CONSTRAINT_VIOLATION.value},
            )
        timestamp = request.current_time if request.current_time is not None else now_unix()
        if request.execution_id is not None:
            result = service().recover_once(
                execution_id=request.execution_id,
                current_time=timestamp,
            )
            results = [] if result is None else [result]
        else:
            results = service().scan_once(current_time=timestamp)
        decisions = [RecoveryDecisionModel.model_validate(item.body) for item in results]
        return RecoveryRunResponse(
            status="PROCESSED" if decisions else "IDLE",
            processed_count=len(decisions),
            decisions=decisions,
        )

    return app


app = make_app()
