from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, FastAPI, HTTPException, Request

from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.config.settings import Settings, get_settings
from backend.receipt.contracts import ReceiptIssueRequest, ReceiptIssueResponse
from backend.receipt.service import ReceiptError, ReceiptService


def make_app(
    *, settings: Settings | None = None, service: ReceiptService | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(title="AgentGuard Receipt Service", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(
            resolved, service_id="receipt-service",
        )

    async def require_issuer_auth(request: Request) -> str:
        allowed = {"secure-gateway", "recovery-worker"}
        if not auth().required:
            allowed.add("phase11-test")
        return await auth().authenticate_request(request, allowed_callers=allowed)

    async def require_reader_auth(request: Request) -> str:
        allowed = {"secure-gateway"}
        if not auth().required:
            allowed.add("phase11-test")
        return await auth().authenticate_request(request, allowed_callers=allowed)

    @lru_cache(maxsize=1)
    def resolved_service() -> ReceiptService:
        return service or ReceiptService(
            resolved.database_url,
            private_key_file=resolved.receipt_private_key_file,
            key_id=resolved.receipt_key_id,
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "receipt-service"}

    @app.post(
        "/internal/receipts/issue", response_model=ReceiptIssueResponse,
        dependencies=[Depends(require_issuer_auth)],
    )
    def issue(
        request: ReceiptIssueRequest,
    ) -> ReceiptIssueResponse:
        try:
            receipt = resolved_service().issue(request.execution_id)
        except ReceiptError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"reason_code": exc.reason_code.value, "message": str(exc)},
            ) from exc
        return ReceiptIssueResponse(receipt=receipt)

    @app.get(
        "/internal/receipts/{execution_id}", response_model=ReceiptIssueResponse,
        dependencies=[Depends(require_reader_auth)],
    )
    def get(
        execution_id: str,
    ) -> ReceiptIssueResponse:
        receipt = resolved_service().get(execution_id)
        if receipt is None:
            raise HTTPException(status_code=404, detail={"reason_code": "TOOL_EXECUTION_UNKNOWN"})
        return ReceiptIssueResponse(receipt=receipt)

    return app


app = make_app()
