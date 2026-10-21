from __future__ import annotations

from functools import lru_cache

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.benchmark.baseline_service import BaselineError, BaselineGatewayService
from backend.benchmark.contracts import (
    BaselineDecision,
    BaselineToolRequest,
    ConfigureRunRequest,
    RevokePrincipalRequest,
    SetupWorkloadRequest,
)
from backend.config.settings import Settings, get_settings


def make_app(
    *, settings: Settings | None = None, service: BaselineGatewayService | None = None
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Isolated Benchmark Baseline", version="1.0.0")

    @lru_cache(maxsize=1)
    def resolved_service() -> BaselineGatewayService:
        return service or BaselineGatewayService(resolved)

    def require_admin(value: str | None) -> None:
        if value != resolved.benchmark_admin_token:
            raise BaselineError("INVALID_CREDENTIAL", "benchmark admin boundary rejected caller")

    @app.exception_handler(BaselineError)
    async def baseline_error_handler(request: Request, exc: BaselineError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=exc.status_code,
            content={"reason_code": exc.reason_code, "message": str(exc)},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(
            status_code=400,
            content={
                "reason_code": "REQUEST_SCHEMA_INVALID",
                "message": "request does not match the benchmark contract",
            },
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return resolved_service().health()

    @app.post("/benchmark/configure")
    def configure(
        request: ConfigureRunRequest,
        x_benchmark_admin: str | None = Header(default=None, alias="X-Benchmark-Admin"),
    ) -> dict[str, object]:
        require_admin(x_benchmark_admin)
        return resolved_service().configure(request)

    @app.post("/benchmark/workloads", status_code=201)
    def setup_workload(
        request: SetupWorkloadRequest,
        x_benchmark_admin: str | None = Header(default=None, alias="X-Benchmark-Admin"),
    ) -> dict[str, object]:
        require_admin(x_benchmark_admin)
        return resolved_service().setup_workload(request)

    @app.post("/benchmark/principal/revoke")
    def revoke(
        request: RevokePrincipalRequest,
        x_benchmark_admin: str | None = Header(default=None, alias="X-Benchmark-Admin"),
    ) -> dict[str, object]:
        require_admin(x_benchmark_admin)
        return resolved_service().revoke(request)

    @app.post("/benchmark/execute", response_model=BaselineDecision)
    def execute(
        request: BaselineToolRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, object]:
        prefix = "Bearer "
        if not authorization or not authorization.startswith(prefix):
            raise BaselineError("INVALID_CREDENTIAL", "Bearer credential is required")
        return resolved_service().execute(request, bearer_token=authorization[len(prefix) :])

    return app


app = make_app()
