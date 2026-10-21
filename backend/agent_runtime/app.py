from __future__ import annotations

from functools import lru_cache

from fastapi import BackgroundTasks, Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.agent_runtime.contracts import AgentRunRequest, AgentRunResponse, AgentStep
from backend.agent_runtime.security_proof import (
    ProofCandidateRequest,
    ProofChainRequest,
    prepare_chain,
    signed_candidate,
)
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.agent_runtime.workflow_planner import runtime_profiles
from backend.agent_runtime.workflow_store import WorkflowStore, WorkflowStoreError
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.config.settings import Settings, get_settings


def make_app(
    *, settings: Settings | None = None, service: AgentRuntimeService | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Controlled Agent Runtime", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def resolved_service() -> AgentRuntimeService:
        return service or AgentRuntimeService(resolved)

    @lru_cache(maxsize=1)
    def proof_auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id=resolved.agent_id,
        )

    async def require_proof_auth(request: Request) -> str:
        callers = {"agent-coordinator"} if resolved.agent_role == "case" else {"ui-api"}
        return await proof_auth().authenticate_request(
            request, allowed_callers=callers, allow_unsigned_in_test_mode=True,
        )

    async def require_run_auth(request: Request) -> str:
        callers = {
            "coordinator": {"ui-api"},
            "knowledge": {"agent-coordinator"},
            "case": {"agent-coordinator"},
            "refund": {"agent-case", "ui-api"},
        }.get(resolved.agent_role, set())
        return await proof_auth().authenticate_request(
            request, allowed_callers=callers, allow_unsigned_in_test_mode=True,
        )

    @app.exception_handler(AgentRuntimeError)
    async def runtime_error_handler(request: Request, exc: AgentRuntimeError) -> JSONResponse:
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
                "message": "request does not match the controlled agent schema",
            },
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        runtime = resolved_service()
        return {
            "status": "ok",
            "service": resolved.agent_id,
            "planner": runtime.planner_name,
        }

    @app.post(
        "/agents/run", response_model=AgentRunResponse,
        dependencies=[Depends(require_run_auth)],
    )
    def run(request: AgentRunRequest) -> AgentRunResponse:
        return resolved_service().run(request)

    @app.post("/agents/security-proof/prepare", dependencies=[Depends(require_proof_auth)])
    def prepare_proof(request: ProofChainRequest) -> dict[str, object]:
        return prepare_chain(resolved_service(), request)

    @app.post("/agents/security-proof/request", dependencies=[Depends(require_proof_auth)])
    def proof_request(request: ProofCandidateRequest) -> dict[str, object]:
        return signed_candidate(resolved_service(), request)

    @app.get("/agents/runtime-profiles")
    def profiles() -> dict[str, object]:
        return runtime_profiles(resolved)

    @app.post(
        "/agents/workflows", status_code=202,
        dependencies=[Depends(require_run_auth)],
    )
    def start_workflow(request: AgentRunRequest, background: BackgroundTasks) -> dict[str, object]:
        started, internal = resolved_service().prepare_workflow(request)
        background.add_task(resolved_service().execute_workflow, internal)
        return started

    @app.post("/agents/workflows/{run_id}/observe")
    def observe(
        run_id: str, event: AgentStep, x_workflow_token: str = Header(default="")
    ) -> dict[str, bool]:
        if resolved.agent_role != "coordinator" or event.agent_id not in {
            "agent-coordinator",
            "agent-knowledge",
            "agent-case",
            "agent-refund",
        }:
            raise AgentRuntimeError(
                "REQUEST_SCHEMA_INVALID", "invalid observation recipient or role", status_code=400
            )
        try:
            WorkflowStore(resolved.workflow_database_url).append(run_id, x_workflow_token, event)
        except WorkflowStoreError as exc:
            raise AgentRuntimeError("OBSERVATION_REJECTED", str(exc), status_code=403) from exc
        return {"recorded": True}

    return app


app = make_app()
