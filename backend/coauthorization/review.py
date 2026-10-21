from __future__ import annotations

from collections.abc import Callable
from typing import Any

from jsonschema import ValidationError as SchemaValidationError
from psycopg.rows import dict_row

from backend.authorization.policy import build_root_capabilities
from backend.coauthorization.contracts import (
    ApprovalPayload, CoauthorizationHistoryEntry, CoauthorizationTaskReview,
)
from backend.coauthorization.verifier import (
    EXTENSION_SCHEMA_ROOT, CoauthorizationError, CoauthorizationReason, approval_payload_hash,
)
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.state.database import connect


class CoauthorizationReadService:
    """Read one consistent history snapshot without signing or consuming challenges."""

    def __init__(self, database_url: str, *, clock: Callable[[], int] = now_unix) -> None:
        self.database_url = database_url
        self.clock = clock
        self.schemas = SchemaStore(EXTENSION_SCHEMA_ROOT)
        self.root_schemas = SchemaStore()

    def task_history(self, task_id: str, *, offset: int = 0) -> CoauthorizationTaskReview:
        if type(offset) is not int or not 0 <= offset <= 1_000_000:
            raise CoauthorizationError(CoauthorizationReason.INVALID_TRUSTED_CONTEXT, "invalid history offset")
        with connect(self.database_url) as connection, connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            with connection.cursor(row_factory=dict_row) as cursor:
                task = cursor.execute("""
                    SELECT task_id, tenant_id, ticket_id, customer_id, status::text AS status
                    FROM tasks WHERE task_id = %s
                """, (task_id,)).fetchone()
                if task is None:
                    raise CoauthorizationError(CoauthorizationReason.TASK_NOT_AUTHORIZABLE, "task does not exist")
                rows = cursor.execute("""
                    SELECT challenge.*,
                           approval.task_id AS associated_task_id,
                           approval.root_credential_id AS associated_root_id,
                           approval.approval_payload_hash AS associated_payload_hash,
                           approval.bundle_hash AS associated_bundle_hash,
                           approval.enterprise_subject_id, approval.enterprise_key_id,
                           approval.finance_subject_id, approval.finance_key_id,
                           approval.authorized_at,
                           root.credential_id AS stored_root_id, root.task_id AS stored_root_task_id,
                           root.tenant_id AS stored_root_tenant_id,
                           root.credential_type::text AS stored_root_type,
                           root.signed_object AS stored_root_object, root.signed_object_hash AS stored_root_hash
                    FROM coauthorization_challenges AS challenge
                    LEFT JOIN coauthorization_authorizations AS approval
                        ON approval.challenge_id = challenge.challenge_id
                    LEFT JOIN credentials AS root ON root.credential_id = challenge.root_credential_id
                    WHERE challenge.task_id = %s AND challenge.tenant_id = %s
                    ORDER BY challenge.issued_at DESC, challenge.challenge_id DESC
                    LIMIT 21 OFFSET %s
                """, (task_id, task["tenant_id"], offset)).fetchall()
            observed_at = self.clock()
            if type(observed_at) is not int or not 0 <= observed_at <= MAX_SAFE_INTEGER:
                raise CoauthorizationError(CoauthorizationReason.INVALID_TRUSTED_CONTEXT, "invalid server time")
            try:
                response = CoauthorizationTaskReview(
                    task_id=task_id, task_status=task["status"], observed_at=observed_at,
                    offset=offset, has_more=len(rows) > 20,
                    items=[self._entry(task, row, observed_at) for row in rows[:20]],
                )
                self.schemas.validate("task-review-response.schema.json", response.model_dump(mode="json"))
                return response
            except (ValueError, TypeError, KeyError, RecursionError, SchemaValidationError) as exc:
                raise CoauthorizationError(
                    CoauthorizationReason.STORED_EVIDENCE_INVALID, "stored approval evidence is inconsistent"
                ) from exc

    def _entry(self, task: dict[str, Any], row: dict[str, Any], observed_at: int) -> CoauthorizationHistoryEntry:
        payload = ApprovalPayload.model_validate(row["approval_payload"])
        if (row["task_id"], row["tenant_id"], row["policy_revision"]) != (
            payload.task_id, payload.tenant_id, payload.policy_revision
        ) or (payload.task_id, payload.tenant_id, payload.ticket_id, payload.customer_id) != (
            task["task_id"], task["tenant_id"], task["ticket_id"], task["customer_id"]
        ) or approval_payload_hash(payload) != row["approval_payload_hash"]:
            raise ValueError("stored challenge binding is inconsistent")
        # V1 has a fixed four-tool root policy. Never present reconstructed scope
        # unless it hashes to the original signed approval payload.
        capabilities = build_root_capabilities(
            ticket_id=payload.ticket_id, customer_id=payload.customer_id,
            refund_total_fen=payload.quotas.refund_total_fen,
        )
        if sm3_hex(canonicalize({"capabilities": capabilities})) != payload.capabilities_hash:
            raise ValueError("stored capability scope cannot be reconstructed exactly")
        if row["status"] == "CONSUMED":
            if sm3_hex(canonicalize(row["signed_bundle"])) != row["bundle_hash"]:
                raise ValueError("stored bundle hash is inconsistent")
            required = payload.required_signers
            if (
                row["associated_task_id"], row["associated_root_id"],
                row["associated_payload_hash"], row["associated_bundle_hash"],
                row["enterprise_subject_id"], row["enterprise_key_id"],
                row["finance_subject_id"], row["finance_key_id"], row["authorized_at"],
            ) != (
                payload.task_id, row["root_credential_id"], row["approval_payload_hash"], row["bundle_hash"],
                required.enterprise_approver.subject_id, required.enterprise_approver.key_id,
                required.finance_approver.subject_id, required.finance_approver.key_id, row["consumed_at"],
            ):
                raise ValueError("stored root association is inconsistent")
            credential = row["stored_root_object"]
            self.root_schemas.validate("capability-credential.schema.json", credential)
            root_payload = credential["payload"]
            root_signature = credential["signature"]
            digest = signed_object_hash(credential)
            if (
                (row["stored_root_id"], row["stored_root_task_id"], row["stored_root_tenant_id"], row["stored_root_type"]) !=
                (row["root_credential_id"], payload.task_id, payload.tenant_id, "ROOT")
                or digest != row["stored_root_hash"] or digest != row["root_credential_hash"]
                or root_payload["credential_id"] != row["root_credential_id"]
                or root_signature["key_id"] != root_payload["issuer"]["key_id"]
                or root_signature["key_purpose"] != "AUTHORIZATION_ROOT_SIGNING"
                or root_signature["signed_at"] != root_payload["issued_at"]
                or any(root_payload.get(name) != value for name, value in (
                    ("task_id", payload.task_id), ("tenant_id", payload.tenant_id),
                    ("holder", payload.holder.model_dump(mode="json")),
                    ("quotas", payload.quotas.model_dump(mode="json")),
                    ("not_before", payload.not_before), ("expires_at", payload.expires_at),
                    ("delegation_depth", payload.delegation_depth),
                ))
                or sm3_hex(canonicalize({"capabilities": root_payload["capabilities"]})) != payload.capabilities_hash
            ):
                raise ValueError("stored root object differs from approval evidence")
        elif row["associated_task_id"] is not None:
            raise ValueError("unconsumed challenge has a root association")
        entry = CoauthorizationHistoryEntry.model_validate({
            "challenge_id": row["challenge_id"], "challenge_status": row["status"],
            "window_state": "NOT_YET_VALID" if observed_at < row["issued_at"] else
                "EXPIRED" if observed_at >= row["expires_at"] else "OPEN",
            "issued_at": row["issued_at"], "expires_at": row["expires_at"],
            "consumed_at": row["consumed_at"], "revoked_at": row["revoked_at"],
            "payload": payload.model_dump(mode="json"),
            "approval_payload_hash": row["approval_payload_hash"], "task_capabilities": capabilities,
            "bundle_hash": row["bundle_hash"], "signed_bundle": row["signed_bundle"],
            "root_credential_id": row["root_credential_id"], "root_credential_hash": row["root_credential_hash"],
        })
        self.schemas.validate("history-entry.schema.json", entry.model_dump(mode="json"))
        return entry
