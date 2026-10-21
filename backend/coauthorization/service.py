from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Any

from jsonschema import ValidationError as SchemaValidationError
from psycopg import errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from referencing import Resource

from backend.authorization.contracts import AuthorizeTaskRequest
from backend.authorization.credential import CredentialBuildError, build_signed_root_credential
from backend.authorization.policy import build_root_capabilities
from backend.authorization.service import AuthorizationError, RootAuthorizationService, _require_active_key
from backend.coauthorization.audit import (
    COAUTHORIZATION_AUDIT_EVENT_TYPE, authorization_audit_outbox_id,
    make_authorization_audit_evidence,
)
from backend.coauthorization.contracts import (
    MAX_BUNDLE_BYTES, ApprovalPayload, ChallengeResponse, CoauthorizationBundle,
    CoauthorizationResponse, CreateChallengeRequest, RegisteredApprovalKey,
    TrustedApprovalPolicy, TrustedChallenge, TrustedTask,
)
from backend.coauthorization.public_keys import valid_public_point as _valid_public_point
from backend.coauthorization.verifier import (
    EXTENSION_SCHEMA_ROOT, CoauthorizationError, CoauthorizationReason,
    approval_payload_hash, build_approval_payload, capabilities_hash, verify_coauthorization,
)
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import CAPABILITY_CREDENTIAL
from backend.crypto.sm import signed_object_hash, sm3_hex, verify_payload
from backend.crypto.strict_json import MAX_SAFE_INTEGER, StrictJsonError, parse_strict_json
from backend.identity.key_registry import KeyRecord, KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect


def _one(connection: Any, query: str, parameters: tuple) -> dict[str, Any] | None:
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(query, parameters).fetchone()


class CoauthorizationService:
    """Opt-in v1 approvals, consumed in the same transaction as frozen root issuance."""

    def __init__(
        self, *, root_service: RootAuthorizationService,
        challenge_ttl_seconds: int = 300, clock: Callable[[], int] = now_unix,
    ) -> None:
        if type(challenge_ttl_seconds) is not int or not 1 <= challenge_ttl_seconds <= 3600:
            raise ValueError("challenge TTL must be an integer between 1 and 3600")
        self.root = root_service
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.clock = clock
        self.schemas = SchemaStore(EXTENSION_SCHEMA_ROOT)
        self.schemas.registry = self.schemas.registry.with_resources(
            (document["$id"], Resource.from_contents(document))
            for document in self.root.schemas.documents.values()
        )

    def require_enabled(self) -> None:
        if not self.root.coauthorization_required:
            raise CoauthorizationError(CoauthorizationReason.DISABLED, "coauthorization v1 is disabled")

    def _now(self) -> int:
        timestamp = self.clock()
        if type(timestamp) is not int or not 0 <= timestamp <= MAX_SAFE_INTEGER:
            raise CoauthorizationError(CoauthorizationReason.INVALID_TRUSTED_CONTEXT, "invalid server time")
        return timestamp

    @staticmethod
    def _task(connection: Any, task_id: str) -> dict[str, Any]:
        task = _one(connection, """
            SELECT task_id, tenant_id, ticket_id, customer_id, refund_total_fen,
                   max_tool_calls, created_at, expires_at, status
            FROM tasks WHERE task_id = %s FOR UPDATE
        """, (task_id,))
        if task is None:
            raise CoauthorizationError(CoauthorizationReason.TASK_NOT_AUTHORIZABLE, "task does not exist")
        return task

    @staticmethod
    def _policy(connection: Any, tenant_id: str) -> TrustedApprovalPolicy:
        row = _one(connection, """
            SELECT tenant_id, revision, enterprise_subject_id, enterprise_key_id,
                   finance_subject_id, finance_key_id, not_before, expires_at
            FROM coauthorization_policies WHERE tenant_id = %s AND status = 'ACTIVE'
            FOR SHARE
        """, (tenant_id,))
        if row is None:
            raise CoauthorizationError(
                CoauthorizationReason.POLICY_NOT_CONFIGURED, "no active approval policy is configured"
            )
        return TrustedApprovalPolicy.model_validate({
            "tenant_id": row["tenant_id"], "revision": row["revision"],
            "required_signers": {
                "enterprise_approver": {
                    "subject_id": row["enterprise_subject_id"], "key_id": row["enterprise_key_id"],
                },
                "finance_approver": {
                    "subject_id": row["finance_subject_id"], "key_id": row["finance_key_id"],
                },
            },
            "not_before": row["not_before"], "expires_at": row["expires_at"],
        })

    @staticmethod
    def _keys(connection: Any, policy: TrustedApprovalPolicy) -> dict[str, RegisteredApprovalKey]:
        signers = policy.required_signers
        ids = sorted([signers.enterprise_approver.key_id, signers.finance_approver.key_id])
        with connection.cursor(row_factory=dict_row) as cursor:
            rows = cursor.execute("""
                SELECT tenant_id, subject_id, principal_id, key_id, role, approval_purpose,
                       signing_purpose, algorithm, public_key_hex, status, activated_at,
                       expires_at, retired_at, revoked_at, compromised_at
                FROM coauthorization_keys WHERE key_id = ANY(%s) ORDER BY key_id FOR SHARE
            """, (ids,)).fetchall()
        records = {row["key_id"]: RegisteredApprovalKey.model_validate(row) for row in rows}
        for role in ("ENTERPRISE_APPROVER", "FINANCE_APPROVER"):
            signer = signers.for_role(role)
            record = records.get(signer.key_id)
            if record is None or (record.tenant_id, record.subject_id, record.role) != (
                policy.tenant_id, signer.subject_id, role
            ):
                raise CoauthorizationError(CoauthorizationReason.UNTRUSTED_KEY, "approval key binding mismatch")
            if not _valid_public_point(record.public_key_hex):
                raise CoauthorizationError(CoauthorizationReason.UNTRUSTED_KEY, "approval public key is not on the SM2 curve")
            # This registry is public-only and must not reuse an Authority/Agent key.
            reused = connection.execute("""
                SELECT 1 FROM key_registry WHERE key_id = %s OR public_key_hex = %s LIMIT 1
            """, (record.key_id, record.public_key_hex)).fetchone()
            if reused is not None:
                raise CoauthorizationError(CoauthorizationReason.UNTRUSTED_KEY, "approval key overlaps a runtime key")
        if records[ids[0]].principal_id == records[ids[1]].principal_id:
            raise CoauthorizationError(CoauthorizationReason.SAME_PRINCIPAL, "two roles resolve to one principal")
        if records[ids[0]].public_key_hex == records[ids[1]].public_key_hex:
            raise CoauthorizationError(CoauthorizationReason.SAME_KEY, "two roles resolve to one public key")
        return records

    def _runtime_keys(self, connection: Any, holder: CreateChallengeRequest) -> tuple[KeyRecord, KeyRecord]:
        ids = sorted({self.root.authority_key_id, holder.holder_key_id})
        connection.execute("""
            SELECT key_id FROM key_registry WHERE key_id = ANY(%s) ORDER BY key_id FOR UPDATE
        """, (ids,)).fetchall()
        try:
            authority = PostgresKeyRegistry.get_with_connection(connection, self.root.authority_key_id)
            holder_key = PostgresKeyRegistry.get_with_connection(connection, holder.holder_key_id)
        except KeyRegistryError as exc:
            raise AuthorizationError(exc.reason_code, "runtime key is unavailable", status_code=403) from exc
        _require_active_key(
            authority, subject_id=self.root.authority_subject_id, subject_type="AUTHORITY",
            purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        )
        _require_active_key(
            holder_key, subject_id=holder.holder_agent_id, subject_type="AGENT",
            purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        )
        if connection.execute("SELECT 1 FROM agent_identities WHERE agent_id = %s FOR SHARE",
                              (holder.holder_agent_id,)).fetchone() is None:
            raise CoauthorizationError(CoauthorizationReason.UNTRUSTED_KEY, "holder agent is unavailable")
        return authority, holder_key

    @staticmethod
    def _check_runtime_key_time(authority: KeyRecord, holder_key: KeyRecord, timestamp: int) -> None:
        if timestamp < max(authority.activated_at, holder_key.activated_at):
            raise CoauthorizationError(CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID, "runtime key is not yet valid")

    @staticmethod
    def _scope(connection: Any, task: dict[str, Any], holder: CreateChallengeRequest) -> TrustedTask:
        if connection.execute("""
            SELECT 1 FROM tickets WHERE ticket_id = %s AND tenant_id = %s AND customer_id = %s
            FOR SHARE
        """, (task["ticket_id"], task["tenant_id"], task["customer_id"])).fetchone() is None:
            raise CoauthorizationError(CoauthorizationReason.TASK_OR_POLICY_MISMATCH, "ticket binding changed")
        return TrustedTask.model_validate({
            "tenant_id": task["tenant_id"], "task_id": task["task_id"],
            "ticket_id": task["ticket_id"], "customer_id": task["customer_id"],
            "holder": {"agent_id": holder.holder_agent_id, "key_id": holder.holder_key_id},
            "capabilities": build_root_capabilities(
                ticket_id=task["ticket_id"], customer_id=task["customer_id"],
                refund_total_fen=task["refund_total_fen"],
            ),
            "quotas": {"refund_total_fen": task["refund_total_fen"], "max_tool_calls": task["max_tool_calls"]},
            "not_before": task["created_at"], "expires_at": task["expires_at"],
            "delegation_depth": holder.delegation_depth, "status": task["status"],
        })

    @staticmethod
    def _check_time(
        task: TrustedTask, policy: TrustedApprovalPolicy,
        keys: dict[str, RegisteredApprovalKey], now: int,
    ) -> None:
        if not task.not_before <= now < task.expires_at:
            raise CoauthorizationError(CoauthorizationReason.TASK_EXPIRED_OR_NOT_YET_VALID, "task is outside validity")
        if not policy.not_before <= now < policy.expires_at:
            raise CoauthorizationError(CoauthorizationReason.POLICY_EXPIRED_OR_NOT_YET_VALID, "policy is outside validity")
        for record in keys.values():
            if record.status != "ACTIVE" or any(value is not None for value in (
                record.retired_at, record.revoked_at, record.compromised_at
            )):
                raise CoauthorizationError(CoauthorizationReason.KEY_NOT_ACTIVE, "approval key is not active")
            if not record.activated_at <= now < record.expires_at:
                raise CoauthorizationError(CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID, "approval key is outside validity")

    def create_challenge(self, task_id: str, request: CreateChallengeRequest) -> ChallengeResponse:
        self.require_enabled()
        with connect(self.root.database_url) as connection, connection.transaction():
            task_row = self._task(connection, task_id)
            if task_row["status"] != "PENDING_AUTHORIZATION":
                raise CoauthorizationError(CoauthorizationReason.TASK_NOT_AUTHORIZABLE, "task is not pending")
            policy = self._policy(connection, task_row["tenant_id"])
            pending = _one(connection, """
                SELECT * FROM coauthorization_challenges WHERE task_id = %s AND status = 'PENDING'
                FOR UPDATE
            """, (task_id,))
            keys = self._keys(connection, policy)
            authority, holder_key = self._runtime_keys(connection, request)
            task = self._scope(connection, task_row, request)
            timestamp = self._now()
            self._check_runtime_key_time(authority, holder_key, timestamp)
            self._check_time(task, policy, keys, timestamp)
            if pending is not None:
                if timestamp < pending["issued_at"]:
                    raise CoauthorizationError(CoauthorizationReason.INVALID_TRUSTED_CONTEXT, "server clock moved backwards")
                if timestamp >= pending["expires_at"] or pending["policy_revision"] != policy.revision:
                    connection.execute("""
                        UPDATE coauthorization_challenges SET status = 'REVOKED', revoked_at = %s
                        WHERE challenge_id = %s AND status = 'PENDING'
                    """, (timestamp, pending["challenge_id"]))
                else:
                    expected = build_approval_payload(
                        task=task, policy=policy, challenge_id=pending["challenge_id"],
                        approval_not_before=pending["issued_at"], approval_expires_at=pending["expires_at"],
                    )
                    if expected.model_dump(mode="json") != pending["approval_payload"] or (
                        approval_payload_hash(expected) != pending["approval_payload_hash"]
                    ):
                        raise CoauthorizationError(
                            CoauthorizationReason.CHALLENGE_CONFLICT, "pending challenge binds another task scope or holder"
                        )
                    return self._challenge_response(task, expected)
            deadline = min(timestamp + self.challenge_ttl_seconds, task.expires_at,
                           policy.expires_at, *(key.expires_at for key in keys.values()))
            payload = build_approval_payload(
                task=task, policy=policy, challenge_id="COAUTH-" + secrets.token_hex(32),
                approval_not_before=timestamp, approval_expires_at=deadline,
            )
            self.schemas.validate("approval-payload.schema.json", payload.model_dump(mode="json"))
            digest = approval_payload_hash(payload)
            connection.execute("""
                INSERT INTO coauthorization_challenges (
                    challenge_id, tenant_id, task_id, policy_revision, approval_payload,
                    approval_payload_hash, issued_at, expires_at, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'PENDING')
            """, (payload.challenge_id, task.tenant_id, task.task_id, policy.revision,
                  Jsonb(payload.model_dump(mode="json")), digest, timestamp, deadline))
            return self._challenge_response(task, payload)

    def _challenge_response(self, task: TrustedTask, payload: ApprovalPayload) -> ChallengeResponse:
        response = ChallengeResponse(
            payload=payload, approval_payload_hash=approval_payload_hash(payload),
            task_capabilities=task.capabilities,
        )
        self.schemas.validate("challenge-response.schema.json", response.model_dump(mode="json"))
        return response

    def authorize_task(self, task_id: str, raw_bundle: bytes) -> CoauthorizationResponse:
        self.require_enabled()
        try:
            if not isinstance(raw_bundle, bytes) or len(raw_bundle) > MAX_BUNDLE_BYTES:
                raise ValueError("invalid bundle length")
            document = parse_strict_json(raw_bundle)
            self.schemas.validate("coauthorization-bundle.schema.json", document)
            bundle = CoauthorizationBundle.model_validate(document)
        except (ValueError, TypeError, RecursionError, SchemaValidationError, StrictJsonError) as exc:
            # No parser or schema internals, signatures, or submitted data enter the API error.
            raise CoauthorizationError(CoauthorizationReason.INVALID_BUNDLE, "invalid coauthorization bundle") from exc
        if bundle.payload.task_id != task_id:
            raise CoauthorizationError(CoauthorizationReason.TASK_OR_POLICY_MISMATCH, "path task differs from approval")
        bundle_document = bundle.model_dump(mode="json")
        bundle_hash = sm3_hex(canonicalize(bundle_document))
        with connect(self.root.database_url) as connection, connection.transaction():
            task_row = self._task(connection, task_id)
            policy = self._policy(connection, task_row["tenant_id"])
            challenge_row = _one(connection, """
                SELECT * FROM coauthorization_challenges WHERE challenge_id = %s AND task_id = %s
                FOR UPDATE
            """, (bundle.payload.challenge_id, task_id))
            if challenge_row is None:
                raise CoauthorizationError(CoauthorizationReason.CHALLENGE_MISMATCH, "challenge does not exist for this task")
            if challenge_row["status"] == "CONSUMED":
                # Existing delegation/admission locks credentials before tasks.
                # Do not wait for that credential while already holding the task.
                try:
                    locked = connection.execute("""
                        SELECT credential_id FROM credentials WHERE credential_id = %s FOR SHARE NOWAIT
                    """, (challenge_row["root_credential_id"],)).fetchone()
                except errors.LockNotAvailable as exc:
                    raise CoauthorizationError(
                        CoauthorizationReason.CHALLENGE_CONFLICT, "root is busy; retry the same approval bundle"
                    ) from exc
                if locked is None:
                    raise CoauthorizationError(CoauthorizationReason.ROOT_REVOKED_OR_INVALID, "root is unavailable")
            keys = self._keys(connection, policy)
            holder = CreateChallengeRequest(
                holder_agent_id=bundle.payload.holder.agent_id,
                holder_key_id=bundle.payload.holder.key_id,
                delegation_depth=bundle.payload.delegation_depth,
            )
            authority, holder_key = self._runtime_keys(connection, holder)
            task = self._scope(connection, task_row, holder)
            challenge = TrustedChallenge.model_validate({
                name: challenge_row[name] for name in (
                    "challenge_id", "tenant_id", "task_id", "policy_revision",
                    "approval_payload_hash", "issued_at", "expires_at", "status",
                )
            })
            timestamp = self._now()
            self._check_runtime_key_time(authority, holder_key, timestamp)
            reused = task.status == "AUTHORIZED" and challenge.status == "CONSUMED"
            if reused and challenge_row["bundle_hash"] != bundle_hash:
                raise CoauthorizationError(CoauthorizationReason.IDEMPOTENCY_CONFLICT, "challenge already consumed with other evidence")
            evidence = verify_coauthorization(
                raw_bundle, trusted_task=task, trusted_policy=policy, trusted_challenge=challenge,
                now=timestamp, registry=lambda **lookup: keys.get(lookup["key_id"]),
                allow_existing_authorization=reused,
            )
            if challenge_row["approval_payload"] != bundle.payload.model_dump(mode="json"):
                raise CoauthorizationError(CoauthorizationReason.CHALLENGE_MISMATCH, "stored challenge payload differs")
            if reused:
                credential = self._existing_root(connection, task, challenge_row, bundle_hash, authority)
                returned_at = self._now()
                self._check_time(task, policy, keys, returned_at)
                if returned_at < timestamp or returned_at >= challenge.expires_at:
                    raise CoauthorizationError(CoauthorizationReason.CHALLENGE_EXPIRED_OR_NOT_YET_VALID, "challenge expired during retrieval")
            else:
                request = AuthorizeTaskRequest(
                    confirmed=True, confirmer_id="coauthorization-v1",
                    holder_agent_id=holder.holder_agent_id, holder_key_id=holder.holder_key_id,
                    delegation_depth=holder.delegation_depth,
                )
                try:
                    credential = build_signed_root_credential(
                        task=task_row, request=request, authority_subject_id=self.root.authority_subject_id,
                        authority_key=authority, private_keys=self.root.private_keys,
                        current_time=timestamp, schemas=self.root.schemas,
                        credential_not_before=task.not_before,
                    )
                except CredentialBuildError as exc:
                    raise AuthorizationError(exc.reason_code, str(exc), status_code=403) from exc
                self._assert_root_scope(credential, task)
                consumed_at = self._now()
                self._check_time(task, policy, keys, consumed_at)
                if consumed_at < timestamp or not challenge.issued_at <= consumed_at < challenge.expires_at:
                    raise CoauthorizationError(CoauthorizationReason.CHALLENGE_EXPIRED_OR_NOT_YET_VALID, "challenge expired during signing")
                self.root._persist_authorization(
                    connection, task=task_row, request=request, source="POLICY",
                    request_hash=bundle_hash, credential=credential, current_time=consumed_at,
                    write_base_confirmation=False,
                )
                updated = connection.execute("""
                    UPDATE coauthorization_challenges
                    SET status = 'CONSUMED', bundle_hash = %s, signed_bundle = %s,
                        root_credential_id = %s, root_credential_hash = %s, consumed_at = %s
                    WHERE challenge_id = %s AND status = 'PENDING'
                """, (bundle_hash, Jsonb(bundle_document), credential["payload"]["credential_id"],
                      signed_object_hash(credential), consumed_at, challenge.challenge_id))
                if updated.rowcount != 1:
                    raise CoauthorizationError(CoauthorizationReason.CHALLENGE_CONFLICT, "challenge was not consumed")
                connection.execute("""
                    INSERT INTO coauthorization_authorizations (
                        task_id, challenge_id, root_credential_id, approval_payload_hash, bundle_hash,
                        enterprise_subject_id, enterprise_key_id, finance_subject_id, finance_key_id,
                        authorized_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    task.task_id, challenge.challenge_id, credential["payload"]["credential_id"],
                    evidence.approval_payload_hash, bundle_hash,
                    evidence.verified_subject_ids[0], evidence.verified_key_ids[0],
                    evidence.verified_subject_ids[1], evidence.verified_key_ids[1], consumed_at,
                ))
                try:
                    audit_evidence = make_authorization_audit_evidence(
                        signed_bundle=bundle_document, credential=credential,
                        authorized_at=consumed_at,
                    )
                except ValueError as exc:
                    raise CoauthorizationError(
                        CoauthorizationReason.INVALID_TRUSTED_CONTEXT,
                        "authorization audit evidence is inconsistent",
                    ) from exc
                connection.execute("""
                    INSERT INTO audit_outbox (
                        outbox_event_id, execution_id, event_type, evidence_reference,
                        payload_hash, payload, status, created_at
                    ) VALUES (%s, NULL, %s, %s, %s, %s, 'PENDING', %s)
                """, (
                    authorization_audit_outbox_id(credential["payload"]["credential_id"]),
                    COAUTHORIZATION_AUDIT_EVENT_TYPE, credential["payload"]["credential_id"],
                    sm3_hex(canonicalize(audit_evidence)), Jsonb(audit_evidence), consumed_at,
                ))
            response = CoauthorizationResponse(
                challenge_id=challenge.challenge_id, approval_payload_hash=evidence.approval_payload_hash,
                bundle_hash=bundle_hash, root_credential_id=credential["payload"]["credential_id"],
                root_credential_hash=signed_object_hash(credential), reused=reused, credential=credential,
            )
            self.schemas.validate("coauthorization-response.schema.json", response.model_dump(mode="json"))
            return response

    @staticmethod
    def _assert_root_scope(credential: dict[str, Any], task: TrustedTask) -> None:
        payload = credential["payload"]
        if any(payload.get(name) != expected for name, expected in (
            ("tenant_id", task.tenant_id), ("task_id", task.task_id),
            ("holder", task.holder.model_dump(mode="json")),
            ("quotas", task.quotas.model_dump(mode="json")), ("not_before", task.not_before),
            ("expires_at", task.expires_at), ("delegation_depth", task.delegation_depth),
        )) or sm3_hex(canonicalize({"capabilities": payload.get("capabilities")})) != capabilities_hash(task):
            raise CoauthorizationError(CoauthorizationReason.ROOT_REVOKED_OR_INVALID, "root scope differs from approvals")

    def _existing_root(
        self, connection: Any, task: TrustedTask, challenge: dict[str, Any],
        bundle_hash: str, authority: KeyRecord,
    ) -> dict[str, Any]:
        row = _one(connection, """
            SELECT credential.credential_id, credential.task_id, credential.tenant_id,
                   credential.signed_object, credential.signed_object_hash,
                   approval.bundle_hash, approval.task_id AS authorization_task_id,
                   approval.challenge_id, approval.approval_payload_hash
            FROM credentials AS credential
            JOIN coauthorization_authorizations AS approval
                ON approval.root_credential_id = credential.credential_id
            WHERE credential.credential_id = %s AND credential.credential_type = 'ROOT'
            FOR SHARE OF credential, approval
        """, (challenge["root_credential_id"],))
        if row is None or row["bundle_hash"] != bundle_hash or (
            row["task_id"], row["tenant_id"]
        ) != (task.task_id, task.tenant_id) or (
            row["authorization_task_id"], row["challenge_id"], row["approval_payload_hash"]
        ) != (task.task_id, challenge["challenge_id"], challenge["approval_payload_hash"]):
            raise CoauthorizationError(CoauthorizationReason.ROOT_REVOKED_OR_INVALID, "root evidence binding is invalid")
        if connection.execute("SELECT 1 FROM credential_revocations WHERE credential_id = %s",
                              (row["credential_id"],)).fetchone() is not None:
            raise CoauthorizationError(CoauthorizationReason.ROOT_REVOKED_OR_INVALID, "root is revoked")
        credential = dict(row["signed_object"])
        try:
            self.root.schemas.validate("capability-credential.schema.json", credential)
        except SchemaValidationError as exc:
            raise CoauthorizationError(CoauthorizationReason.ROOT_REVOKED_OR_INVALID, "stored root schema is invalid") from exc
        digest = signed_object_hash(credential)
        if digest != row["signed_object_hash"] or digest != challenge["root_credential_hash"] or (
            sm3_hex(canonicalize(challenge["signed_bundle"])) != bundle_hash
        ):
            raise CoauthorizationError(CoauthorizationReason.ROOT_REVOKED_OR_INVALID, "stored evidence hash is invalid")
        self._assert_root_scope(credential, task)
        if credential["payload"]["issuer"] != {
            "subject_id": self.root.authority_subject_id, "key_id": authority.key_id,
        } or not verify_payload(
            credential["payload"], credential["signature"], domain_separator=CAPABILITY_CREDENTIAL,
            expected_key_id=authority.key_id, expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            public_key_hex=authority.public_key_hex,
        ):
            raise CoauthorizationError(CoauthorizationReason.ROOT_REVOKED_OR_INVALID, "root signature is invalid")
        return credential
