from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from jsonschema import ValidationError

from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import InternalAuthenticator
from backend.common.schema import SchemaStore
from backend.common.strict_json_route import StrictJsonRoute
from backend.common.time import now_unix
from backend.config.settings import Settings, get_settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import GATEWAY_EXECUTION_ENVELOPE
from backend.crypto.sm import sm3_hex, verify_payload
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect
from backend.tools.contracts import (
    GatewayExecutionEnvelopeModel,
    ReconcileRequest,
    ReconcileResponse,
    ToolExecutionResponse,
)
from backend.tools.store import MemoryToolStore, PostgresToolStore, ToolExecutionError, ToolStore

TOOL_CONFIG: dict[str, tuple[str, str]] = {
    "ticket": ("ticket-service", "ticket.read"),
    "knowledge": ("knowledge-service", "knowledge.read_associated"),
    "refund": ("refund-service", "refund.create"),
    "notification": ("notification-service", "notification.send_template"),
}

TOOL_PARAMETER_KEYS: dict[str, set[str]] = {
    "ticket": {"ticket_id"},
    "knowledge": {"ticket_id"},
    "refund": {"ticket_id", "customer_id", "amount_fen"},
    "notification": {"customer_id", "template_id", "related_business_effect_id"},
}


def load_public_key(settings: Settings) -> str:
    if settings.gateway_public_key_hex:
        return settings.gateway_public_key_hex
    path = Path(settings.gateway_public_key_file)
    if not path.is_file():
        raise RuntimeError("gateway public key is not available")
    return path.read_text(encoding="ascii").strip()


def make_app(
    *, settings: Settings | None = None, store: ToolStore | None = None,
    internal_auth: InternalAuthenticator | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    kind = resolved.tool_kind
    if kind not in TOOL_CONFIG:
        raise RuntimeError(f"unsupported TOOL_KIND: {kind}")
    service, tool = TOOL_CONFIG[kind]
    if store is None:
        store = (
            MemoryToolStore()
            if resolved.storage == "memory"
            else PostgresToolStore(resolved.database_url)
        )
    schemas = SchemaStore()
    app = FastAPI(title=f"AgentGuard {kind} tool", version="1.0.0")
    app.router.route_class = StrictJsonRoute

    @lru_cache(maxsize=1)
    def auth() -> InternalAuthenticator:
        return internal_auth or InternalAuthenticator.from_settings(resolved, service_id=service)

    async def require_recovery_auth(request: Request) -> str:
        return await auth().authenticate_request(request, allowed_callers={"recovery-worker"})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "tool_service": service, "tool_name": tool}

    @app.post("/internal/execute", response_model=ToolExecutionResponse)
    def execute(envelope: GatewayExecutionEnvelopeModel) -> ToolExecutionResponse:
        payload = envelope.payload
        try:
            schemas.validate(
                "gateway-execution-envelope.schema.json",
                envelope.model_dump(mode="json"),
            )
        except ValidationError as exc:
            raise HTTPException(
                status_code=400,
                detail={"reason_code": ReasonCode.REQUEST_SCHEMA_INVALID.value},
            ) from exc
        if (
            payload.tool_service != service
            or payload.tool_name != tool
            or payload.tool_version != "v1"
        ):
            raise HTTPException(
                status_code=403, detail={"reason_code": ReasonCode.TOOL_NOT_ALLOWED.value}
            )
        current = now_unix()
        if (
            envelope.signature.signed_at != payload.issued_at
            or payload.expires_at <= payload.issued_at
            or payload.expires_at - payload.issued_at > resolved.envelope_ttl_seconds
            or current < payload.issued_at
            or current > payload.expires_at
        ):
            raise HTTPException(
                status_code=403, detail={"reason_code": ReasonCode.EXECUTION_ENVELOPE_EXPIRED.value}
            )
        if envelope.signature.key_id != payload.gateway_key_id:
            raise HTTPException(
                status_code=403, detail={"reason_code": ReasonCode.UNKNOWN_KEY.value}
            )
        try:
            public_key = load_public_key(resolved)
            if resolved.storage != "memory":
                try:
                    with connect(resolved.database_url) as connection:
                        trusted_key = PostgresKeyRegistry.resolve_for_signing_with_connection(
                            connection,
                            payload.gateway_key_id,
                            expected_subject_id=resolved.gateway_audience,
                            expected_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
                        )
                except KeyRegistryError as exc:
                    raise HTTPException(
                        status_code=403,
                        detail={"reason_code": exc.reason_code.value},
                    ) from exc
                if trusted_key.public_key_hex != public_key:
                    raise HTTPException(
                        status_code=403,
                        detail={"reason_code": ReasonCode.UNKNOWN_KEY.value},
                    )
            if not verify_payload(
                payload.model_dump(mode="json"),
                envelope.signature.model_dump(mode="json"),
                domain_separator=GATEWAY_EXECUTION_ENVELOPE,
                expected_key_id=payload.gateway_key_id,
                expected_key_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
                public_key_hex=public_key,
            ):
                raise HTTPException(
                    status_code=403, detail={"reason_code": ReasonCode.INVALID_SIGNATURE.value}
                )
            parameters = payload.canonical_validated_parameters
            if set(parameters) != TOOL_PARAMETER_KEYS[kind]:
                raise HTTPException(
                    status_code=403,
                    detail={"reason_code": ReasonCode.PARAMETER_CONSTRAINT_VIOLATION.value},
                )
            if kind == "refund" and (
                type(parameters["amount_fen"]) is not int or parameters["amount_fen"] <= 0
            ):
                raise HTTPException(
                    status_code=403,
                    detail={"reason_code": ReasonCode.PARAMETER_CONSTRAINT_VIOLATION.value},
                )
            if sm3_hex(canonicalize(parameters)) != payload.parameter_hash:
                raise HTTPException(
                    status_code=403,
                    detail={"reason_code": ReasonCode.PARAMETER_CONSTRAINT_VIOLATION.value},
                )
            result = store.execute(
                kind,
                payload,
                sm3_hex(canonicalize(envelope.model_dump(mode="json"))),
            )
        except ToolExecutionError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"reason_code": exc.reason_code.value, "message": str(exc)},
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail={"reason_code": ReasonCode.TOOL_EXECUTION_UNKNOWN.value},
            ) from exc
        result_value = result.get("result")
        effect_id = result.get("business_effect_id")
        result_hash = sm3_hex(canonicalize(result_value)) if result_value is not None else None
        return ToolExecutionResponse(
            execution_id=payload.execution_id,
            execution_attempt_id=payload.execution_attempt_id,
            outcome="SUCCESS",
            result=result_value,
            business_effect_id=effect_id,
            business_result_hash=result_hash,
        )

    @app.post("/internal/reconcile", response_model=ReconcileResponse)
    def reconcile(
        request: ReconcileRequest,
        _caller: str = Depends(require_recovery_auth),
    ) -> ReconcileResponse:
        if kind not in {"refund", "notification"}:
            raise HTTPException(
                status_code=403,
                detail={"reason_code": ReasonCode.TOOL_NOT_ALLOWED.value},
            )
        result = store.reconcile(kind, request)
        return ReconcileResponse(
            execution_id=request.execution_id,
            status=str(result["status"]),
            parameter_hash=result.get("parameter_hash"),
            result=result.get("result"),
            business_effect_id=result.get("business_effect_id"),
            reason_code={
                "IDEMPOTENCY_CONFLICT": ReasonCode.IDEMPOTENCY_CONFLICT.value,
                "UNKNOWN": ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
            }.get(str(result["status"]), ReasonCode.ALLOWED.value),
        )

    return app


app = make_app()
