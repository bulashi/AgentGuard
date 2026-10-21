from __future__ import annotations

from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.schema import SchemaStore
from backend.crypto.sm import signed_object_hash
from backend.delegation.attenuation import AttenuationError
from backend.delegation.contracts import DelegateCredentialRequest
from backend.delegation.credential import DelegationBuildError, build_signed_delegation_credential
from backend.delegation.verifier import ChainVerificationError, CredentialChainVerifier
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect


class DelegationError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str, *, status_code: int = 403) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


class DelegationService:
    def __init__(
        self,
        *,
        database_url: str,
        agent_id: str,
        agent_key_id: str,
        private_key_root: str,
        schema_store: SchemaStore | None = None,
    ) -> None:
        self.database_url = database_url
        self.agent_id = agent_id
        self.agent_key_id = agent_key_id
        self.private_key_root = Path(private_key_root)
        self.schemas = schema_store or SchemaStore()
        self.verifier = CredentialChainVerifier(database_url, self.schemas)

    def delegate(
        self,
        parent_credential_id: str,
        request: DelegateCredentialRequest,
        *,
        current_time: int,
    ) -> dict[str, Any]:
        registry = PostgresKeyRegistry(self.database_url)
        with connect(self.database_url) as connection, connection.transaction():
            try:
                chain = self.verifier.verify_chain_with_connection(
                    connection,
                    parent_credential_id,
                    current_time=current_time,
                    lock=True,
                )
            except ChainVerificationError as exc:
                raise DelegationError(exc.reason_code, str(exc)) from exc
            parent = chain[-1]
            parent_payload = parent["payload"]
            if parent_payload["holder"] != {
                "agent_id": self.agent_id,
                "key_id": self.agent_key_id,
            }:
                raise DelegationError(
                    ReasonCode.WRONG_HOLDER,
                    "this service does not hold the parent credential",
                )
            task = connection.execute(
                "SELECT status, expires_at FROM tasks WHERE task_id = %s FOR UPDATE",
                (parent_payload["task_id"],),
            ).fetchone()
            if task is None or str(task[0]) != "AUTHORIZED":
                raise DelegationError(ReasonCode.CROSS_TASK, "task is not authorized")
            if current_time > int(task[1]):
                raise DelegationError(
                    ReasonCode.CREDENTIAL_EXPIRED, "task expired before delegation"
                )
            if parent_payload["delegation_depth"] <= 0:
                raise DelegationError(
                    ReasonCode.DELEGATION_ESCALATION,
                    "parent credential has no remaining delegation depth",
                )
            if not request.not_before <= current_time <= request.expires_at:
                raise DelegationError(
                    ReasonCode.DELEGATION_ESCALATION,
                    "child validity interval must contain the issuance time",
                )
            try:
                issuer_key = registry.resolve_for_signing_with_connection(
                    connection,
                    self.agent_key_id,
                    expected_subject_id=self.agent_id,
                    expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
                    lock=True,
                )
                holder_key = registry.resolve_for_signing_with_connection(
                    connection,
                    request.holder_key_id,
                    expected_subject_id=request.holder_agent_id,
                    expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
                    lock=True,
                )
            except KeyRegistryError as exc:
                raise DelegationError(exc.reason_code, str(exc)) from exc
            if holder_key.subject_type != "AGENT" or issuer_key.subject_type != "AGENT":
                raise DelegationError(
                    ReasonCode.WRONG_HOLDER, "delegation keys must belong to agents"
                )
            holder_exists = connection.execute(
                "SELECT 1 FROM agent_identities WHERE agent_id = %s",
                (request.holder_agent_id,),
            ).fetchone()
            if holder_exists is None:
                raise DelegationError(ReasonCode.WRONG_HOLDER, "child holder is unknown")
            try:
                credential = build_signed_delegation_credential(
                    parent_credential=parent,
                    request=request,
                    issuer_agent_id=self.agent_id,
                    issuer_key=issuer_key,
                    private_key_root=self.private_key_root,
                    current_time=current_time,
                    schemas=self.schemas,
                )
            except (DelegationBuildError, AttenuationError) as exc:
                reason = getattr(exc, "reason_code", ReasonCode.DELEGATION_ESCALATION)
                raise DelegationError(reason, str(exc)) from exc
            self._persist(connection, credential, current_time=current_time)
            return credential

    @staticmethod
    def _persist(connection: Any, credential: dict[str, Any], *, current_time: int) -> None:
        payload = credential["payload"]
        connection.execute(
            """
            INSERT INTO credentials (
                credential_id, credential_type, parent_credential_id, parent_credential_hash,
                signed_object_hash, signed_object, issuer_subject_id, issuer_key_id,
                holder_agent_id, holder_key_id, tenant_id, task_id, verifier_audience,
                not_before, expires_at, delegation_depth, issued_at, created_at
            )
            VALUES (%s, 'DELEGATION', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    'secure-tool-gateway', %s, %s, %s, %s, %s)
            """,
            (
                payload["credential_id"],
                payload["parent_credential_id"],
                payload["parent_credential_hash"],
                signed_object_hash(credential),
                Jsonb(credential),
                payload["issuer"]["subject_id"],
                payload["issuer"]["key_id"],
                payload["holder"]["agent_id"],
                payload["holder"]["key_id"],
                payload["tenant_id"],
                payload["task_id"],
                payload["not_before"],
                payload["expires_at"],
                payload["delegation_depth"],
                payload["issued_at"],
                current_time,
            ),
        )
        for quota_type, limit_value in payload["quotas"].items():
            connection.execute(
                """
                INSERT INTO credential_budget_state (
                    credential_id, quota_type, limit_value, reserved_value,
                    committed_value, version, updated_at
                )
                VALUES (%s, %s, %s, 0, 0, 0, %s)
                """,
                (payload["credential_id"], quota_type, limit_value, current_time),
            )

