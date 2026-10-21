from __future__ import annotations

import time
from functools import cached_property
from typing import Any

from backend.agent_runtime.workflow_store import safe_observation
from backend.coauthorization.audit import (
    COAUTHORIZATION_AUDIT_EVENT_TYPE,
    COAUTHORIZATION_AUDIT_SCHEMA_VERSION,
    validate_authorization_audit_evidence,
)
from backend.coauthorization.revocation_audit import (
    REVOCATION_AUDIT_EVENT_TYPE,
    REVOCATION_AUDIT_SCHEMA_VERSION,
    validate_revocation_audit_outbox,
)
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import (
    CAPABILITY_CREDENTIAL,
    DELEGATION_CREDENTIAL,
    EXECUTION_RECEIPT,
    HOLDER_PROOF,
)
from backend.crypto.sm import sm3_hex, verify_payload
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.revocation.audit import (
    AUDIT_EVENT_TYPE as CREDENTIAL_REVOCATION_EVENT_TYPE,
)
from backend.revocation.audit import (
    AUDIT_SCHEMA_VERSION as CREDENTIAL_REVOCATION_SCHEMA_VERSION,
)
from backend.revocation.audit import (
    validate_revocation_audit_outbox as validate_credential_revocation_outbox,
)
from backend.state.database import connect
from backend.tools.notification_templates import notification_catalog
from backend.ui_api.evidence_binding import (
    credential_source_verification,
    receipt_source_verification,
)


class UiReadStore:
    """SELECT-only browser projection store backed by a restricted DB role."""

    def __init__(self, database_url: str) -> None:
        if not database_url:
            raise ValueError("UI read store requires AGENTGUARD_UI_DATABASE_URL")
        self.database_url = database_url

    @cached_property
    def schemas(self) -> SchemaStore:
        return SchemaStore()

    def probe_schema(self) -> None:
        """Fail health checks when the read projection drifts from migrations."""
        with connect(self.database_url) as connection:
            connection.execute(
                """
                SELECT c.credential_id, r.revocation_reason, a.schema_version
                FROM credentials c
                LEFT JOIN credential_revocations r USING (credential_id)
                LEFT JOIN agent_workflow_runs w ON w.task_id = c.task_id
                LEFT JOIN agent_workflow_events e ON e.run_id = w.run_id
                LEFT JOIN audit_events a ON FALSE
                LEFT JOIN dispatch_cancellations dc ON FALSE
                LIMIT 0
                """
            )

    def has_pending_workflows(self) -> bool:
        with connect(self.database_url) as connection:
            return bool(
                connection.execute(
                    "SELECT EXISTS (SELECT 1 FROM agent_workflow_runs "
                    "WHERE state IN ('QUEUED', 'RUNNING') "
                    "AND deadline_at_ms >= extract(epoch from clock_timestamp()) * 1000)"
                ).fetchone()[0]
            )

    def list_business_tickets(self) -> list[dict[str, Any]]:
        with connect(self.database_url) as connection:
            return self._business_tickets(connection)

    def verify_security_request(self, envelope: dict[str, Any]) -> bool:
        """Independently check public proof material; this grants no execution permit."""
        from jsonschema import ValidationError

        try:
            self.schemas.validate("request-envelope.schema.json", envelope)
            chain = envelope["credential_chain"]
            holder = chain[-1]["payload"]["holder"]
            expected = {
                "schema_version": "1.0",
                "credential_chain_hash": sm3_hex(canonicalize(chain)),
                "task_id": envelope["task_id"],
                "tool_service": envelope["tool_service"],
                "tool_name": envelope["tool_name"],
                "tool_version": envelope["tool_version"],
                "canonical_parameter_hash": sm3_hex(canonicalize(envelope["canonical_parameters"])),
                "request_id": envelope["request_id"],
                "issued_at": envelope["issued_at"],
                "business_action_id": envelope["business_action_id"],
            }
            proof = envelope["holder_proof"]
            if (
                proof["payload"] != expected or envelope["holder_key_id"] != holder["key_id"]
                or proof["signature"]["key_id"] != holder["key_id"]
                or proof["signature"]["signed_at"] != envelope["issued_at"]
            ):
                return False
            with connect(self.database_url) as connection:
                return self._verify_signed(
                    connection, proof, domain=HOLDER_PROOF,
                    expected_subject_id=holder["agent_id"],
                    purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
                    trusted_registered_at=int(time.time()),
                )
        except (ValidationError, KeyError, TypeError, ValueError):
            return False

    def business_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        with connect(self.database_url) as connection:
            rows = self._business_tickets(connection, ticket_id)
            return rows[0] if rows else None

    @staticmethod
    def _business_tickets(connection: Any, ticket_id: str = "") -> list[dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT t.ticket_id, t.tenant_id, t.customer_id, t.title, t.status,
                   t.cloud_shareable, e.verification_status, p.verification_status,
                   e.original_transaction_id, e.refund_reason_code,
                   e.refundable_amount_fen, e.evidence_reference,
                   GREATEST(0, p.refundable_amount_fen - COALESCE((
                       SELECT SUM(r.amount_fen) FROM refunds r WHERE r.tenant_id = t.tenant_id
                       AND r.original_transaction_id = e.original_transaction_id), 0)),
                   EXISTS (SELECT 1 FROM refunds r WHERE r.tenant_id = t.tenant_id
                       AND ((r.ticket_id = t.ticket_id AND r.original_transaction_id IS NULL)
                           OR (r.original_transaction_id = e.original_transaction_id
                               AND r.refund_reason_code = e.refund_reason_code
                               AND r.trusted_action_slot = 'primary-refund'))),
                   EXISTS (SELECT 1 FROM tasks a JOIN agent_workflow_runs w USING (task_id)
                       WHERE a.ticket_id = t.ticket_id AND a.tenant_id = t.tenant_id
                       AND w.state IN ('QUEUED', 'RUNNING')
                       AND w.deadline_at_ms >= extract(epoch from clock_timestamp()) * 1000)
            FROM tickets t
            LEFT JOIN refund_eligibility e ON e.ticket_id = t.ticket_id
                AND e.trusted_action_slot = 'primary-refund'
            LEFT JOIN business_payment_verifications p ON p.tenant_id = e.tenant_id
                AND p.original_transaction_id = e.original_transaction_id
                AND p.customer_id = e.customer_id
            WHERE t.status = 'OPEN' AND (%s = '' OR t.ticket_id = %s)
            ORDER BY t.created_at DESC, t.ticket_id DESC LIMIT 100
            """,
            (ticket_id, ticket_id),
        ).fetchall()
        fields = (
            "ticket_id",
            "tenant_id",
            "customer_id",
            "title",
            "status",
            "cloud_shareable",
            "verification_status",
            "payment_verification_status",
            "original_transaction_id",
            "refund_reason_code",
            "refundable_amount_fen",
            "evidence_reference",
            "transaction_remaining_fen",
            "already_processed",
            "in_progress",
        )
        result = []
        for row in rows:
            item = dict(zip(fields, row, strict=True))
            item["verification_status"] = item["verification_status"] or "UNKNOWN"
            item["payment_verification_status"] = item["payment_verification_status"] or "UNKNOWN"
            item["refundable_amount_fen"] = int(item["refundable_amount_fen"] or 0)
            item["transaction_remaining_fen"] = int(item["transaction_remaining_fen"] or 0)
            item["can_refund"] = (
                item["verification_status"] == item["payment_verification_status"] == "VERIFIED"
                and not item["already_processed"]
                and not item["in_progress"]
                and min(item["refundable_amount_fen"], item["transaction_remaining_fen"]) > 0
            )
            projection = UiReadStore._facts_projection(connection, item["ticket_id"])
            if projection is not None:
                item.update(projection)
                item["can_refund"] = (
                    item["verification_status"] == "VERIFIED" and not item["already_processed"]
                    and not item["in_progress"] and item["refundable_amount_fen"] > 0
                )
            result.append(item)
        return result

    @staticmethod
    def _facts_projection(
        connection: Any, ticket_id: str, task_id: str | None = None,
    ) -> dict[str, Any] | None:
        from backend.business_action.facts import load_business_case_facts

        case = load_business_case_facts(connection, ticket_id)
        if case is None:
            return None
        row = connection.execute(
            "SELECT result FROM business_fact_evaluations WHERE ticket_id = %s "
            "AND (%s::text IS NULL OR task_id = %s) ORDER BY created_at DESC, task_id DESC LIMIT 1",
            (ticket_id, task_id, task_id),
        ).fetchone()
        evaluation = row[0] if row is not None else None
        return {
            "source": "facts", "business_facts": case["facts"], "facts_hash": case["facts_hash"],
            "business_verification": evaluation, "refund_verifications": [],
            "verification_status": evaluation["status"] if evaluation else "UNKNOWN",
            "payment_verification_status": evaluation["status"] if evaluation else "UNKNOWN",
            "verification_reason": evaluation["reason"] if evaluation else None,
            "original_transaction_id": (
                evaluation["original_transaction_id"] if evaluation else None
            ),
            "refundable_amount_fen": evaluation["refundable_amount_fen"] if evaluation else 0,
            "evidence_reference": f"facts:{case['facts_hash']}",
        }

    def list_tasks(
        self, *, limit: int = 20, offset: int = 0, search: str = "", status: str = ""
    ) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 101))
        bounded_offset = max(0, min(offset, 1_000_000))
        pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        with connect(self.database_url) as connection:
            rows = connection.execute(
                """
                SELECT t.task_id, t.tenant_id, t.ticket_id, t.customer_id,
                       t.refund_total_fen, t.max_tool_calls, t.expires_at,
                       t.status, t.created_at, t.updated_at,
                       (SELECT count(*) FROM credentials c WHERE c.task_id = t.task_id),
                       (SELECT count(*) FROM execution_records e WHERE e.task_id = t.task_id),
                       w.state, w.runtime_mode, w.model, w.deadline_at_ms, w.reason_code,
                       CASE WHEN EXISTS (SELECT 1 FROM business_case_facts f
                                         WHERE f.ticket_id = t.ticket_id)
                        THEN (SELECT f.result->>'status' FROM business_fact_evaluations f
                              WHERE f.task_id = t.task_id)
                        ELSE (SELECT e.verification_status FROM refund_eligibility e
                        WHERE e.ticket_id = t.ticket_id
                          AND e.trusted_action_slot = 'primary-refund' LIMIT 1) END,
                       CASE WHEN EXISTS (SELECT 1 FROM business_case_facts f
                                         WHERE f.ticket_id = t.ticket_id)
                        THEN (SELECT f.result->>'status' FROM business_fact_evaluations f
                              WHERE f.task_id = t.task_id)
                        ELSE (SELECT p.verification_status FROM refund_eligibility e
                        JOIN business_payment_verifications p ON p.tenant_id = e.tenant_id
                          AND p.original_transaction_id = e.original_transaction_id
                        WHERE e.ticket_id = t.ticket_id
                          AND e.trusted_action_slot = 'primary-refund' LIMIT 1) END,
                       (SELECT count(*) FROM refunds r
                        WHERE r.task_id = t.task_id AND r.status = 'COMMITTED'),
                       (SELECT count(*) FROM notifications n WHERE n.task_id = t.task_id)
                FROM tasks t
                LEFT JOIN agent_workflow_runs w USING (task_id)
                WHERE (%s = '' OR t.task_id ILIKE %s OR t.ticket_id ILIKE %s
                       OR t.customer_id ILIKE %s)
                  AND (%s = '' OR t.status::text = %s)
                ORDER BY t.created_at DESC, t.task_id DESC
                LIMIT %s OFFSET %s
                """,
                (search, pattern, pattern, pattern, status, status, bounded, bounded_offset),
            ).fetchall()
        return [
            {
                "task_id": str(row[0]),
                "tenant_id": str(row[1]),
                "ticket_id": str(row[2]),
                "customer_id": str(row[3]),
                "refund_total_fen": int(row[4]),
                "max_tool_calls": int(row[5]),
                "expires_at": int(row[6]),
                "status": str(row[7]),
                "created_at": int(row[8]),
                "updated_at": int(row[9]),
                "credential_count": int(row[10]),
                "execution_count": int(row[11]),
                "workflow_state": (
                    "INTERRUPTED"
                    if row[12] in {"QUEUED", "RUNNING"} and int(row[15]) < int(time.time() * 1000)
                    else row[12]
                ),
                "runtime_mode": row[13],
                "model": row[14],
                "workflow_reason_code": row[16],
                "business_verification_status": row[17],
                "business_payment_verification_status": row[18],
                "refund_count": int(row[19]),
                "notification_count": int(row[20]),
            }
            for row in rows
        ]

    def overview(self) -> dict[str, Any]:
        with connect(self.database_url) as connection:
            task_counts = connection.execute(
                "SELECT status::text, count(*) FROM tasks GROUP BY status ORDER BY status"
            ).fetchall()
            execution_counts = connection.execute(
                """
                SELECT COALESCE(decision::text, 'PENDING'), state::text, count(*)
                FROM execution_records
                GROUP BY decision, state
                ORDER BY decision, state
                """
            ).fetchall()
            effects = connection.execute(
                "SELECT (SELECT count(*) FROM refunds), (SELECT count(*) FROM notifications)"
            ).fetchone()
            pending = connection.execute(
                "SELECT count(*) FROM audit_outbox WHERE status = 'PENDING'"
            ).fetchone()
            head = connection.execute(
                """
                SELECT latest_event_sequence, latest_event_hash, updated_at
                FROM audit_chain_head WHERE singleton = TRUE
                """
            ).fetchone()
        return {
            "tasks": {str(row[0]): int(row[1]) for row in task_counts},
            "executions": [
                {"decision": str(row[0]), "state": str(row[1]), "count": int(row[2])}
                for row in execution_counts
            ],
            "business_effects": {
                "refunds": int(effects[0]) if effects else 0,
                "notifications": int(effects[1]) if effects else 0,
            },
            "audit": {
                "pending_outbox": int(pending[0]) if pending else 0,
                "latest_event_sequence": int(head[0]) if head else 0,
                "latest_event_hash": str(head[1]) if head else "0" * 64,
                "updated_at": int(head[2]) if head else 0,
            },
        }

    def root_credential(self, task_id: str) -> dict[str, Any] | None:
        with connect(self.database_url) as connection:
            row = connection.execute(
                """
                SELECT signed_object
                FROM credentials
                WHERE task_id = %s AND credential_type = 'ROOT'
                """,
                (task_id,),
            ).fetchone()
        return None if row is None else dict(row[0])

    def task_snapshot(self, task_id: str) -> dict[str, Any] | None:
        with connect(self.database_url) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            task = connection.execute(
                """
                SELECT task_id, tenant_id, ticket_id, customer_id, refund_total_fen,
                       max_tool_calls, expires_at, status::text, created_at, updated_at
                FROM tasks WHERE task_id = %s
                """,
                (task_id,),
            ).fetchone()
            if task is None:
                return None
            credentials = connection.execute(
                """
                SELECT c.credential_id, c.credential_type::text, c.parent_credential_id,
                       c.parent_credential_hash, c.signed_object_hash, c.signed_object,
                       c.issuer_subject_id, c.issuer_key_id, c.holder_agent_id,
                       c.holder_key_id, c.not_before, c.expires_at,
                       c.delegation_depth, c.issued_at, r.revoked_at,
                       r.revocation_reason,
                       c.created_at, c.tenant_id, c.task_id, c.verifier_audience, r.revoked_by
                FROM credentials c
                LEFT JOIN credential_revocations r USING (credential_id)
                WHERE c.task_id = %s
                ORDER BY c.issued_at, c.credential_id
                """,
                (task_id,),
            ).fetchall()
            budgets = connection.execute(
                """
                SELECT b.credential_id, b.quota_type, b.limit_value,
                       b.reserved_value, b.committed_value, b.version
                FROM credential_budget_state b
                JOIN credentials c USING (credential_id)
                WHERE c.task_id = %s
                ORDER BY b.credential_id, b.quota_type
                """,
                (task_id,),
            ).fetchall()
            executions = connection.execute(
                """
                SELECT execution_id, request_hash, credential_chain_hash,
                       tool_service, tool_name, tool_version, parameter_hash,
                       state::text, decision::text, reason_code, receipt_status::text,
                       business_action_id, business_effect_id, business_result_hash,
                       created_at, updated_at
                FROM execution_records
                WHERE task_id = %s
                ORDER BY created_at, execution_id
                """,
                (task_id,),
            ).fetchall()
            cancellations = connection.execute(
                """
                SELECT dc.cancellation_id, dc.execution_id, dc.denial_execution_id,
                       dc.request_id, dc.request_hash, dc.credential_chain_hash,
                       dc.reason_code, dc.cancelled_at, dc.evidence
                FROM dispatch_cancellations dc
                JOIN execution_records e USING (execution_id)
                WHERE e.task_id = %s ORDER BY dc.cancelled_at, dc.cancellation_id
                """,
                (task_id,),
            ).fetchall()
            receipts = connection.execute(
                """
                SELECT r.receipt_id, r.execution_id, r.receipt_type::text,
                       r.decision::text, r.reason_code, r.signed_receipt,
                       r.receipt_hash, r.receipt_status::text, r.created_at,
                       e.tenant_id, e.task_id, e.request_hash, e.credential_chain_hash,
                       e.tool_service, e.tool_name, e.tool_version, e.parameter_hash,
                       e.state::text, e.decision::text, e.reason_code,
                       e.business_action_id, e.business_effect_id,
                       e.business_result_hash, e.result, e.created_at,
                       e.terminal_at, e.terminal_state::text,
                       e.decision_at, e.decision_value::text
                FROM execution_receipts r
                JOIN execution_records e USING (execution_id)
                WHERE e.task_id = %s
                ORDER BY r.created_at, r.receipt_id
                """,
                (task_id,),
            ).fetchall()
            refunds = connection.execute(
                """
                SELECT refund_id, execution_id, amount_fen, status, created_at
                FROM refunds WHERE task_id = %s ORDER BY created_at
                """,
                (task_id,),
            ).fetchall()
            notifications = connection.execute(
                """
                SELECT notification_id, execution_id, template_id,
                       related_business_effect_id, status, created_at,
                       customer_id, template_version, content
                FROM notifications WHERE task_id = %s ORDER BY created_at
                """,
                (task_id,),
            ).fetchall()
            audit_events = connection.execute(
                """
                SELECT a.event_sequence, a.event_id, a.execution_id, a.event_type,
                       a.event_timestamp, a.payload_hash, a.evidence_reference,
                       a.previous_event_hash, a.event_hash, a.schema_version,
                       outbox.payload, outbox.outbox_event_id, outbox.execution_id,
                       outbox.event_type, outbox.evidence_reference, outbox.payload_hash,
                       outbox.created_at, outbox.status
                FROM audit_events a
                LEFT JOIN execution_records e ON e.execution_id = a.execution_id
                LEFT JOIN audit_outbox outbox USING (outbox_event_id)
                WHERE e.task_id = %s OR (
                    a.event_type = 'COAUTH_ROOT_AUTHORIZED' AND EXISTS (
                        SELECT 1 FROM credentials root
                        WHERE root.credential_id = a.evidence_reference
                          AND root.credential_type = 'ROOT' AND root.task_id = %s
                    )
                ) OR (
                    a.event_type = 'CREDENTIAL_REVOKED'
                    AND outbox.payload ->> 'task_id' = %s
                ) OR (
                    a.event_type = 'COAUTH_REVOCATION_APPLIED'
                    AND outbox.payload ->> 'tenant_id' = %s AND EXISTS (
                        SELECT 1 FROM jsonb_array_elements(
                            CASE WHEN jsonb_typeof(outbox.payload -> 'roots') = 'array'
                                 THEN outbox.payload -> 'roots' ELSE '[]'::jsonb END
                        ) AS affected(root)
                        WHERE affected.root ->> 'task_id' = %s
                    )
                )
                ORDER BY a.event_sequence
                """,
                (task_id, task_id, task_id, task[1], task_id),
            ).fetchall()
            credential_projection = [
                self._credential_projection(connection, row) for row in credentials
            ]
            receipt_projection = [self._receipt_projection(connection, row) for row in receipts]
            business_context = self._business_context(connection, task)
            workflow_runs = self._workflow_runs(connection, task_id)

        budget_by_credential: dict[str, list[dict[str, Any]]] = {}
        for row in budgets:
            budget_by_credential.setdefault(str(row[0]), []).append(
                {
                    "quota_type": str(row[1]),
                    "limit": int(row[2]),
                    "reserved": int(row[3]),
                    "committed": int(row[4]),
                    "remaining": int(row[2]) - int(row[3]) - int(row[4]),
                    "version": int(row[5]),
                }
            )
        for item in credential_projection:
            item["budgets"] = budget_by_credential.get(str(item["credential_id"]), [])

        body = self._snapshot_body(
            task=task,
            credentials=credential_projection,
            executions=executions,
            receipts=receipt_projection,
            refunds=refunds,
            notifications=notifications,
            audit_events=audit_events,
        )
        body["business_context"] = business_context
        ticket = business_context["ticket"] or {}
        verification_status = ticket.get("verification_status")
        payment_verification_status = ticket.get("payment_verification_status")
        if ticket.get("source") == "facts":
            evaluation = ticket.get("business_verification")
            verification_status = evaluation["status"] if evaluation is not None else None
            payment_verification_status = verification_status
        body["task"].update(
            business_verification_status=verification_status,
            business_payment_verification_status=payment_verification_status,
            refund_count=sum(
                refund["status"] == "COMMITTED" for refund in body["business_effects"]["refunds"]
            ),
            notification_count=len(body["business_effects"]["notifications"]),
        )
        body["dispatch_cancellations"] = [
            {
                "cancellation_id": str(row[0]), "execution_id": str(row[1]),
                "denial_execution_id": str(row[2]), "request_id": str(row[3]),
                "request_hash": str(row[4]), "credential_chain_hash": str(row[5]),
                "reason_code": str(row[6]), "cancelled_at": int(row[7]),
                "evidence": row[8],
            }
            for row in cancellations
        ]
        body["workflow_runs"] = workflow_runs
        if workflow_runs:
            body["task"]["workflow_state"] = workflow_runs[0]["state"]
            body["task"]["workflow_reason_code"] = workflow_runs[0]["reason_code"]
            body["task"]["runtime_mode"] = workflow_runs[0]["runtime_mode"]
            body["task"]["model"] = workflow_runs[0]["model"]
        return body

    @staticmethod
    def _business_context(connection: Any, task: Any) -> dict[str, Any]:
        ticket = connection.execute(
            """SELECT t.ticket_id, t.customer_id, t.title, t.description, t.status,
                      t.cloud_shareable, e.verification_status, p.verification_status,
                      e.original_transaction_id, e.refund_reason_code,
                      e.refundable_amount_fen, e.evidence_reference, e.verified_at,
                      p.refundable_amount_fen
               FROM tickets t LEFT JOIN refund_eligibility e ON e.ticket_id = t.ticket_id
                   AND e.trusted_action_slot = 'primary-refund'
               LEFT JOIN business_payment_verifications p ON p.tenant_id = e.tenant_id
                   AND p.original_transaction_id = e.original_transaction_id
                   AND p.customer_id = e.customer_id
               WHERE t.ticket_id = %s AND t.tenant_id = %s AND t.customer_id = %s""",
            (task[2], task[1], task[3]),
        ).fetchone()
        documents = connection.execute(
            """SELECT d.document_id, d.title, d.sensitivity
               FROM knowledge_documents d JOIN ticket_document_relations r USING (document_id)
               WHERE r.ticket_id = %s AND d.tenant_id = %s ORDER BY d.document_id""",
            (task[2], task[1]),
        ).fetchall()
        public_ticket = (
            None
            if ticket is None
            else dict(
                zip(
                    (
                        "ticket_id",
                        "customer_id",
                        "title",
                        "description",
                        "status",
                        "cloud_shareable",
                        "verification_status",
                        "payment_verification_status",
                        "original_transaction_id",
                        "refund_reason_code",
                        "refundable_amount_fen",
                        "evidence_reference",
                        "verified_at",
                        "transaction_refundable_amount_fen",
                    ),
                    ticket,
                    strict=True,
                )
            )
        )
        if public_ticket is not None:
            public_ticket["refund_verifications"] = (
                []
                if ticket[6] is None
                else [
                    {
                        "trusted_action_slot": "primary-refund",
                        **{
                            key: public_ticket[key]
                            for key in (
                                "verification_status",
                                "payment_verification_status",
                                "original_transaction_id",
                                "refund_reason_code",
                                "refundable_amount_fen",
                                "evidence_reference",
                                "verified_at",
                                "transaction_refundable_amount_fen",
                            )
                        },
                    }
                ]
            )
            projection = UiReadStore._facts_projection(connection, str(task[2]), str(task[0]))
            if projection is not None:
                public_ticket.update(projection)
        return {
            "ticket": public_ticket,
            "documents": [
                dict(zip(("document_id", "title", "sensitivity"), row, strict=True))
                for row in documents
            ],
            "notification_templates": notification_catalog(),
        }

    @staticmethod
    def _workflow_runs(connection: Any, task_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            """SELECT run_id, runtime_mode, scenario, model, state, reason_code,
                      created_at_ms, updated_at_ms, deadline_at_ms, finished_at_ms
               FROM agent_workflow_runs WHERE task_id = %s ORDER BY created_at_ms DESC""",
            (task_id,),
        ).fetchall()
        result = []
        for row in rows:
            events = connection.execute(
                """SELECT sequence, agent_id, action, status, timestamp_ms, recorded_at_ms, details
                   FROM agent_workflow_events WHERE run_id = %s ORDER BY sequence""",
                (row[0],),
            ).fetchall()
            state = str(row[4])
            if state in {"QUEUED", "RUNNING"} and int(row[8]) < int(time.time() * 1000):
                state = "INTERRUPTED"
            result.append(
                {
                    "run_id": row[0],
                    "runtime_mode": row[1],
                    "scenario": row[2],
                    "model": row[3],
                    "state": state,
                    "reason_code": row[5],
                    "created_at_ms": row[6],
                    "updated_at_ms": row[7],
                    "deadline_at_ms": row[8],
                    "finished_at_ms": row[9],
                    "observation_kind": "operational_not_signed_audit",
                    "events": [
                        dict(
                            zip(
                                (
                                    "sequence",
                                    "agent_id",
                                    "action",
                                    "status",
                                    "timestamp_ms",
                                    "recorded_at_ms",
                                    "details",
                                ),
                                (*event[:6], safe_observation(event[6])),
                                strict=True,
                            )
                        )
                        for event in events
                    ],
                }
            )
        return result

    def _credential_projection(self, connection: Any, row: Any) -> dict[str, Any]:
        original = row[5]
        signed = original if isinstance(original, dict) else {}
        payload = signed.get("payload")
        signature = signed.get("signature")
        payload = payload if isinstance(payload, dict) else {}
        signature = signature if isinstance(signature, dict) else {}
        credential_type = str(row[1])
        purpose = (
            KeyPurpose.AUTHORIZATION_ROOT_SIGNING
            if credential_type == "ROOT"
            else KeyPurpose.AGENT_HOLDER_SIGNING
        )
        domain = CAPABILITY_CREDENTIAL if credential_type == "ROOT" else DELEGATION_CREDENTIAL
        capabilities = payload.get("capabilities")
        capabilities = capabilities if isinstance(capabilities, list) else []
        source_verification = credential_source_verification(
            original,
            {
                "credential_id": row[0],
                "credential_type": row[1],
                "parent_credential_id": row[2],
                "parent_credential_hash": row[3],
                "signed_object_hash": row[4],
                "issuer_subject_id": row[6],
                "issuer_key_id": row[7],
                "holder_agent_id": row[8],
                "holder_key_id": row[9],
                "not_before": row[10],
                "expires_at": row[11],
                "delegation_depth": row[12],
                "issued_at": row[13],
                "tenant_id": row[17],
                "task_id": row[18],
                "verifier_audience": row[19],
            },
            self.schemas,
        )
        return {
            "credential_id": str(row[0]),
            "credential_type": credential_type,
            "parent_credential_id": None if row[2] is None else str(row[2]),
            "parent_credential_hash": None if row[3] is None else str(row[3]),
            "signed_object_hash": str(row[4]),
            "stored_hash_valid": source_verification["stored_hash_valid"],
            "source_verification": source_verification,
            "issuer_subject_id": str(row[6]),
            "issuer_key_id": str(row[7]),
            "holder_agent_id": str(row[8]),
            "holder_key_id": str(row[9]),
            "not_before": int(row[10]),
            "expires_at": int(row[11]),
            "delegation_depth": int(row[12]),
            "issued_at": int(row[13]),
            "revoked_at": None if row[14] is None else int(row[14]),
            "revocation_reason": None if row[15] is None else str(row[15]),
            "revoked_by": None if len(row) <= 20 or row[20] is None else str(row[20]),
            "capabilities": [
                {
                    "tool": item.get("tool"),
                    "service": item.get("service"),
                    "version": item.get("version"),
                    "resources": {
                        key: value
                        for key, value in (
                            item["resources"] if isinstance(item.get("resources"), dict) else {}
                        ).items()
                        if key in {"ticket_ids", "customer_ids", "document_ids"}
                        and isinstance(value, list)
                        and all(isinstance(identifier, str) for identifier in value)
                    },
                    "constraints": {
                        key: value
                        for key, value in (
                            item["constraints"] if isinstance(item.get("constraints"), dict) else {}
                        ).items()
                        if (
                            key == "single_max_fen"
                            and type(value) is int
                            and 0 <= value <= 9_007_199_254_740_991
                        )
                        or (
                            key == "template_ids"
                            and isinstance(value, list)
                            and all(isinstance(identifier, str) for identifier in value)
                        )
                    },
                }
                for item in capabilities
                if isinstance(item, dict)
            ],
            "signature": {
                "algorithm": signature.get("algorithm"),
                "key_id": signature.get("key_id"),
                "fingerprint_sm3": self._signature_fingerprint(signature),
                "valid": self._verify_signed(
                    connection,
                    signed,
                    domain=domain,
                    expected_subject_id=str(row[6]),
                    purpose=purpose,
                    trusted_registered_at=int(row[16]),
                ),
            },
        }

    def _receipt_projection(self, connection: Any, row: Any) -> dict[str, Any]:
        original = row[5]
        signed = original if isinstance(original, dict) else {}
        signature = signed.get("signature")
        signature = signature if isinstance(signature, dict) else {}
        source_verification = receipt_source_verification(
            original,
            {
                "receipt_id": row[0],
                "execution_id": row[1],
                "receipt_type": row[2],
                "decision": row[3],
                "reason_code": row[4],
                "receipt_hash": row[6],
                "receipt_status": row[7],
            },
            {
                "execution_id": row[1],
                "tenant_id": row[9],
                "task_id": row[10],
                "request_hash": row[11],
                "credential_chain_hash": row[12],
                "tool_service": row[13],
                "tool_name": row[14],
                "tool_version": row[15],
                "parameter_hash": row[16],
                "state": row[17],
                "decision": row[18],
                "reason_code": row[19],
                "business_action_id": row[20],
                "business_effect_id": row[21],
                "business_result_hash": row[22],
                "result": row[23],
                "created_at": row[24],
                "terminal_at": row[25],
                "terminal_state": row[26],
                "decision_at": row[27],
                "decision_value": row[28],
            },
            self.schemas,
        )
        return {
            "receipt_id": str(row[0]),
            "execution_id": str(row[1]),
            "receipt_type": str(row[2]),
            "decision": str(row[3]),
            "reason_code": str(row[4]),
            "receipt_hash": str(row[6]),
            "receipt_status": str(row[7]),
            "created_at": int(row[8]),
            "source_verification": source_verification,
            "signature": {
                "algorithm": signature.get("algorithm"),
                "key_id": signature.get("key_id"),
                "fingerprint_sm3": self._signature_fingerprint(signature),
                "valid": self._verify_signed(
                    connection,
                    signed,
                    domain=EXECUTION_RECEIPT,
                    expected_subject_id="receipt-service",
                    purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
                    trusted_registered_at=int(row[8]),
                ),
            },
        }

    @staticmethod
    def _verify_signed(
        connection: Any,
        signed: dict[str, Any],
        *,
        domain: str,
        expected_subject_id: str,
        purpose: KeyPurpose,
        trusted_registered_at: int,
    ) -> bool:
        payload = signed.get("payload")
        signature = signed.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            return False
        key_id = signature.get("key_id")
        signed_at = signature.get("signed_at")
        if not isinstance(key_id, str) or not isinstance(signed_at, int):
            return False
        try:
            key = PostgresKeyRegistry.resolve_for_verification_with_connection(
                connection,
                key_id,
                expected_subject_id=expected_subject_id,
                expected_purpose=purpose,
                signed_at=signed_at,
                trusted_registered_at=trusted_registered_at,
            )
            return verify_payload(
                payload,
                signature,
                domain_separator=domain,
                expected_key_id=key.key_id,
                expected_key_purpose=key.purpose,
                public_key_hex=key.public_key_hex,
            )
        except (KeyRegistryError, KeyError, TypeError, ValueError):
            return False

    @staticmethod
    def _signature_fingerprint(signature: dict[str, Any]) -> str | None:
        value = signature.get("value")
        if not isinstance(value, str):
            return None
        try:
            return sm3_hex(value.encode("ascii"))[:24]
        except UnicodeEncodeError:
            return None

    @staticmethod
    def _snapshot_body(
        *,
        task: Any,
        credentials: list[dict[str, Any]],
        executions: list[Any],
        receipts: list[dict[str, Any]],
        refunds: list[Any],
        notifications: list[Any],
        audit_events: list[Any],
    ) -> dict[str, Any]:
        return {
            "task": {
                "task_id": str(task[0]),
                "tenant_id": str(task[1]),
                "ticket_id": str(task[2]),
                "customer_id": str(task[3]),
                "refund_total_fen": int(task[4]),
                "max_tool_calls": int(task[5]),
                "expires_at": int(task[6]),
                "status": str(task[7]),
                "created_at": int(task[8]),
                "updated_at": int(task[9]),
            },
            "credentials": credentials,
            "executions": [
                {
                    "execution_id": str(row[0]),
                    "request_hash": str(row[1]),
                    "credential_chain_hash": str(row[2]),
                    "tool_service": str(row[3]),
                    "tool_name": str(row[4]),
                    "tool_version": str(row[5]),
                    "parameter_hash": str(row[6]),
                    "state": str(row[7]),
                    "decision": None if row[8] is None else str(row[8]),
                    "reason_code": None if row[9] is None else str(row[9]),
                    "receipt_status": str(row[10]),
                    "business_action_id": None if row[11] is None else str(row[11]),
                    "business_effect_id": None if row[12] is None else str(row[12]),
                    "business_result_hash": None if row[13] is None else str(row[13]),
                    "created_at": int(row[14]),
                    "updated_at": int(row[15]),
                }
                for row in executions
            ],
            "receipts": receipts,
            "business_effects": {
                "refunds": [
                    {
                        "refund_id": str(row[0]),
                        "execution_id": str(row[1]),
                        "amount_fen": int(row[2]),
                        "status": str(row[3]),
                        "created_at": int(row[4]),
                    }
                    for row in refunds
                ],
                "notifications": [
                    {
                        "notification_id": str(row[0]),
                        "execution_id": str(row[1]),
                        "template_id": str(row[2]),
                        "related_business_effect_id": str(row[3]),
                        "status": str(row[4]),
                        "created_at": int(row[5]),
                        "customer_id": str(row[6]) if len(row) > 6 else None,
                        "template_version": row[7] if len(row) > 7 else None,
                        "content": row[8] if len(row) > 8 else None,
                    }
                    for row in notifications
                ],
            },
            "audit_events": [UiReadStore._audit_projection(row) for row in audit_events],
        }

    @staticmethod
    def _audit_projection(row: Any) -> dict[str, Any]:
        binding_valid: bool | None = None
        evidence = None
        revocation_evidence = None
        credential_revocation_evidence = None
        if row[3] == COAUTHORIZATION_AUDIT_EVENT_TYPE:
            binding_valid = False
            try:
                validate_authorization_audit_evidence(row[10])
                if (
                    row[9] == COAUTHORIZATION_AUDIT_SCHEMA_VERSION
                    and row[2] is None
                    and row[6] == row[10]["root_credential_id"]
                    and row[5] == sm3_hex(canonicalize(row[10]))
                    and int(row[4]) >= row[10]["authorized_at"]
                ):
                    binding_valid = True
                    evidence = row[10]
            except (TypeError, ValueError):
                pass
        elif row[3] == REVOCATION_AUDIT_EVENT_TYPE:
            binding_valid = False
            try:
                if len(row) < 18:
                    raise ValueError("revocation projection metadata is missing")
                validate_revocation_audit_outbox(
                    outbox_id=row[11],
                    execution_id=row[12],
                    event_type=row[13],
                    evidence_reference=row[14],
                    payload_hash=row[15],
                    payload=row[10],
                    created_at=row[16],
                )
                if (
                    row[9] == REVOCATION_AUDIT_SCHEMA_VERSION
                    and row[2] is None
                    and row[12] is None
                    and row[13] == row[3]
                    and row[14] == row[6]
                    and row[15] == row[5]
                    and row[17] == "APPENDED"
                    and type(row[4]) is int
                    and row[4] >= row[10]["captured_at"]
                ):
                    binding_valid = True
                    revocation_evidence = row[10]
            except (TypeError, ValueError):
                pass
        elif row[3] == CREDENTIAL_REVOCATION_EVENT_TYPE:
            binding_valid = False
            try:
                if len(row) < 18:
                    raise ValueError("credential revocation metadata is missing")
                validate_credential_revocation_outbox(
                    outbox_id=row[11], execution_id=row[12], event_type=row[13],
                    evidence_reference=row[14], payload_hash=row[15],
                    payload=row[10], created_at=row[16],
                )
                if (
                    row[9] == CREDENTIAL_REVOCATION_SCHEMA_VERSION
                    and row[2] is None and row[13] == row[3]
                    and row[14] == row[6] and row[15] == row[5]
                    and row[17] == "APPENDED" and type(row[4]) is int
                    and row[4] >= row[10]["revoked_at"]
                ):
                    binding_valid = True
                    credential_revocation_evidence = row[10]
            except (TypeError, ValueError):
                pass
        result = {
            "event_sequence": int(row[0]),
            "event_id": str(row[1]),
            "execution_id": None if row[2] is None else str(row[2]),
            "event_type": str(row[3]),
            "timestamp": int(row[4]),
            "payload_hash": str(row[5]),
            "evidence_reference": str(row[6]),
            "previous_event_hash": str(row[7]),
            "event_hash": str(row[8]),
            "schema_version": str(row[9]),
            "coauthorization_evidence": evidence,
            "revocation_evidence": revocation_evidence,
            "evidence_binding_valid": binding_valid,
        }
        if row[3] == CREDENTIAL_REVOCATION_EVENT_TYPE:
            result["credential_revocation_evidence"] = credential_revocation_evidence
        return result
