from __future__ import annotations

from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

from backend.authorization.contracts import AuthorizeTaskRequest, CreateTaskRequest
from backend.authorization.credential import CredentialBuildError, build_signed_root_credential
from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.identity.key_lifecycle import FilePrivateKeyStore
from backend.identity.key_registry import KeyRecord, PostgresKeyRegistry
from backend.state.database import connect


class AuthorizationError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


def _require_active_key(
    record: KeyRecord,
    *,
    subject_id: str,
    subject_type: str,
    purpose: KeyPurpose,
) -> None:
    if record.subject_id != subject_id or record.subject_type != subject_type:
        raise AuthorizationError(
            ReasonCode.INVALID_SIGNATURE, "key subject binding mismatch", status_code=403
        )
    if record.purpose is not purpose or record.algorithm != "SM2":
        raise AuthorizationError(
            ReasonCode.INVALID_SIGNATURE, "key purpose binding mismatch", status_code=403
        )
    state_errors = {
        KeyState.RETIRED: ReasonCode.KEY_RETIRED_FOR_SIGNING,
        KeyState.REVOKED: ReasonCode.KEY_REVOKED,
        KeyState.COMPROMISED: ReasonCode.KEY_COMPROMISED,
    }
    if record.status in state_errors:
        raise AuthorizationError(state_errors[record.status], "key is not active", status_code=403)
    unavailable = (
        record.status is not KeyState.ACTIVE
        or record.material_state is not KeyMaterialState.PRESENT
    )
    if unavailable:
        raise AuthorizationError(
            ReasonCode.UNKNOWN_KEY, "active key material is unavailable", status_code=403
        )


class RootAuthorizationService:
    def __init__(
        self,
        *,
        database_url: str,
        private_key_root: str,
        authority_subject_id: str,
        authority_key_id: str,
        trusted_confirmers: dict[str, str],
        schema_store: SchemaStore | None = None,
        coauthorization_required: bool = False,
    ) -> None:
        self.database_url = database_url
        self.private_keys = FilePrivateKeyStore(Path(private_key_root))
        self.authority_subject_id = authority_subject_id
        self.authority_key_id = authority_key_id
        self.trusted_confirmers = trusted_confirmers
        self.schemas = schema_store or SchemaStore()
        self.coauthorization_required = coauthorization_required
        if not trusted_confirmers:
            raise ValueError("at least one trusted confirmer must be configured")
        if any(source not in {"USER", "POLICY"} for source in trusted_confirmers.values()):
            raise ValueError("trusted confirmer source must be USER or POLICY")

    def create_task(self, request: CreateTaskRequest, *, current_time: int) -> dict[str, str]:
        expires_at = current_time + request.expires_in_seconds
        if expires_at > 9_007_199_254_740_991:
            raise AuthorizationError(ReasonCode.REQUEST_SCHEMA_INVALID, "task expiry overflows")
        task_id = new_id("TASK")
        with connect(self.database_url) as connection, connection.transaction():
            trusted_resource = connection.execute(
                """
                SELECT 1 FROM tickets
                WHERE ticket_id = %s AND tenant_id = %s AND customer_id = %s
                """,
                (request.ticket_id, request.tenant_id, request.customer_id),
            ).fetchone()
            if trusted_resource is None:
                raise AuthorizationError(
                    ReasonCode.RESOURCE_NOT_ALLOWED,
                    "ticket is not bound to the requested tenant and customer",
                    status_code=403,
                )
            connection.execute(
                """
                INSERT INTO tasks (
                    task_id, tenant_id, ticket_id, customer_id, refund_total_fen,
                    max_tool_calls, expires_at, status, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'PENDING_AUTHORIZATION', %s, %s)
                """,
                (
                    task_id,
                    request.tenant_id,
                    request.ticket_id,
                    request.customer_id,
                    request.refund_total_fen,
                    request.max_tool_calls,
                    expires_at,
                    current_time,
                    current_time,
                ),
            )
        return {"task_id": task_id, "status": "PENDING_AUTHORIZATION"}

    def authorize_task(
        self,
        task_id: str,
        request: AuthorizeTaskRequest,
        *,
        current_time: int,
    ) -> dict[str, Any]:
        if self.coauthorization_required:
            raise AuthorizationError(
                ReasonCode.INVALID_SIGNATURE,
                "independent coauthorization is required; use the versioned approval endpoint",
                status_code=403,
            )
        source = self.trusted_confirmers.get(request.confirmer_id)
        if source is None:
            raise AuthorizationError(
                ReasonCode.INVALID_SIGNATURE,
                "confirmer is not trusted by the Authorization Authority",
                status_code=403,
            )
        request_hash = sm3_hex(canonicalize(request.model_dump(mode="json")))
        registry = PostgresKeyRegistry(self.database_url)
        with connect(self.database_url) as connection, connection.transaction():
            row = connection.execute(
                """
                SELECT task_id, tenant_id, ticket_id, customer_id, refund_total_fen,
                       max_tool_calls, expires_at, status
                FROM tasks WHERE task_id = %s FOR UPDATE
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                raise AuthorizationError(ReasonCode.CROSS_TASK, "task does not exist")
            task = {
                "task_id": str(row[0]),
                "tenant_id": str(row[1]),
                "ticket_id": str(row[2]),
                "customer_id": str(row[3]),
                "refund_total_fen": int(row[4]),
                "max_tool_calls": int(row[5]),
                "expires_at": int(row[6]),
                "status": str(row[7]),
            }
            if task["status"] == "AUTHORIZED":
                return self._existing_authorization(connection, task_id, request_hash)
            if task["status"] != "PENDING_AUTHORIZATION":
                raise AuthorizationError(
                    ReasonCode.CROSS_TASK, "task is not authorizable", status_code=403
                )
            if current_time > task["expires_at"]:
                raise AuthorizationError(
                    ReasonCode.CREDENTIAL_EXPIRED,
                    "task authorization expired",
                    status_code=403,
                )
            authority_key = registry.get_with_connection(
                connection, self.authority_key_id, lock=True
            )
            holder_key = registry.get_with_connection(connection, request.holder_key_id, lock=True)
            _require_active_key(
                authority_key,
                subject_id=self.authority_subject_id,
                subject_type="AUTHORITY",
                purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            )
            _require_active_key(
                holder_key,
                subject_id=request.holder_agent_id,
                subject_type="AGENT",
                purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            )
            holder = connection.execute(
                "SELECT 1 FROM agent_identities WHERE agent_id = %s",
                (request.holder_agent_id,),
            ).fetchone()
            if holder is None:
                raise AuthorizationError(
                    ReasonCode.WRONG_HOLDER, "holder agent is unknown", status_code=403
                )
            try:
                credential = build_signed_root_credential(
                    task=task,
                    request=request,
                    authority_subject_id=self.authority_subject_id,
                    authority_key=authority_key,
                    private_keys=self.private_keys,
                    current_time=current_time,
                    schemas=self.schemas,
                )
            except CredentialBuildError as exc:
                raise AuthorizationError(exc.reason_code, str(exc), status_code=403) from exc
            self._persist_authorization(
                connection,
                task=task,
                request=request,
                source=source,
                request_hash=request_hash,
                credential=credential,
                current_time=current_time,
            )
            return credential

    @staticmethod
    def _existing_authorization(
        connection: Any, task_id: str, request_hash: str
    ) -> dict[str, Any]:
        existing = connection.execute(
            """
            SELECT confirmation.request_hash, credential.signed_object
            FROM authorization_confirmations AS confirmation
            JOIN credentials AS credential
              ON credential.credential_id = confirmation.credential_id
            WHERE confirmation.task_id = %s
            """,
            (task_id,),
        ).fetchone()
        if existing is None or str(existing[0]) != request_hash:
            raise AuthorizationError(
                ReasonCode.IDEMPOTENCY_CONFLICT,
                "task was already authorized with different or missing evidence",
            )
        return dict(existing[1])

    def _persist_authorization(
        self,
        connection: Any,
        *,
        task: dict[str, Any],
        request: AuthorizeTaskRequest,
        source: str,
        request_hash: str,
        credential: dict[str, Any],
        current_time: int,
        write_base_confirmation: bool = True,
    ) -> None:
        payload = credential["payload"]
        credential_id = payload["credential_id"]
        connection.execute(
            """
            INSERT INTO credentials (
                credential_id, credential_type, parent_credential_id, parent_credential_hash,
                signed_object_hash, signed_object, issuer_subject_id, issuer_key_id,
                holder_agent_id, holder_key_id, tenant_id, task_id, verifier_audience,
                not_before, expires_at, delegation_depth, issued_at, created_at
            )
            VALUES (%s, 'ROOT', NULL, NULL, %s, %s, %s, %s, %s, %s, %s, %s,
                    'secure-tool-gateway', %s, %s, %s, %s, %s)
            """,
            (
                credential_id,
                signed_object_hash(credential),
                Jsonb(credential),
                self.authority_subject_id,
                self.authority_key_id,
                request.holder_agent_id,
                request.holder_key_id,
                task["tenant_id"],
                task["task_id"],
                payload["not_before"],
                payload["expires_at"],
                request.delegation_depth,
                payload["issued_at"],
                current_time,
            ),
        )
        if write_base_confirmation:
            connection.execute(
                """
                INSERT INTO authorization_confirmations (
                    confirmation_id, task_id, credential_id, confirmer_id, confirmation_source,
                    request_hash, holder_agent_id, holder_key_id, delegation_depth, confirmed_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    new_id("confirmation"),
                    task["task_id"],
                    credential_id,
                    request.confirmer_id,
                    source,
                    request_hash,
                    request.holder_agent_id,
                    request.holder_key_id,
                    request.delegation_depth,
                    current_time,
                ),
            )
        budget_rows = [
            (credential_id, "refund_total_fen", task["refund_total_fen"], current_time),
            (credential_id, "max_tool_calls", task["max_tool_calls"], current_time),
        ]
        for budget_row in budget_rows:
            connection.execute(
                """
                INSERT INTO credential_budget_state (
                    credential_id, quota_type, limit_value, reserved_value,
                    committed_value, version, updated_at
                )
                VALUES (%s, %s, %s, 0, 0, 0, %s)
                """,
                budget_row,
            )
        updated_task = connection.execute(
            """
            UPDATE tasks SET status = 'AUTHORIZED', updated_at = %s
            WHERE task_id = %s AND status = 'PENDING_AUTHORIZATION'
            """,
            (current_time, task["task_id"]),
        )
        if updated_task.rowcount != 1:
            raise AuthorizationError(
                ReasonCode.IDEMPOTENCY_CONFLICT, "task authorization state changed", status_code=409
            )
