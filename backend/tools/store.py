from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Protocol

from backend.business_action.eligibility import (
    BusinessEligibilityReason,
    EligibilityError,
    check_unprocessed_business,
    load_verified_refund_business,
    payment_refunded_amount,
    validate_refund_business,
)
from backend.business_action.policy import (
    NOTIFICATION_SERVICE,
    NOTIFICATION_TOOL,
    REFUND_SUCCESS_NOTIFICATION_SLOT,
    TrustedTaskContext,
    notification_scope,
    refund_scope,
)
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.time import now_unix
from backend.state.database import connect
from backend.tools.contracts import EnvelopePayload, ReconcileRequest
from backend.tools.notification_templates import REFUND_SUCCESS, render_refund_success


class ToolExecutionError(RuntimeError):
    def __init__(
        self,
        reason_code: ReasonCode | BusinessEligibilityReason,
        message: str,
        *,
        status_code: int = 409,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


class ToolStore(Protocol):
    def execute(
        self, kind: str, payload: EnvelopePayload, envelope_hash: str
    ) -> dict[str, Any]: ...

    def reconcile(self, kind: str, request: ReconcileRequest) -> dict[str, Any]: ...


@dataclass
class MemoryToolStore:
    attempts: set[str] = field(default_factory=set)
    tickets: dict[str, dict[str, Any]] = field(default_factory=dict)
    documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    ticket_documents: dict[str, list[str]] = field(default_factory=dict)
    refunds: dict[str, dict[str, Any]] = field(default_factory=dict)
    notifications: dict[str, dict[str, Any]] = field(default_factory=dict)
    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
    business_actions: dict[str, dict[str, Any]] = field(default_factory=dict)
    payment_verifications: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    refund_eligibility: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    _lock: Any = field(default_factory=RLock, repr=False, compare=False)

    def execute(self, kind: str, payload: EnvelopePayload, envelope_hash: str) -> dict[str, Any]:
        with self._lock:
            return self._execute(kind, payload, envelope_hash)

    def _execute(self, kind: str, payload: EnvelopePayload, envelope_hash: str) -> dict[str, Any]:
        del envelope_hash
        if payload.execution_attempt_id in self.attempts:
            raise ToolExecutionError(
                ReasonCode.EXECUTION_ENVELOPE_REPLAY, "execution attempt replay"
            )
        self.attempts.add(payload.execution_attempt_id)
        params = payload.canonical_validated_parameters
        if kind == "ticket":
            ticket = self.tickets.get(params["ticket_id"])
            if ticket is None:
                raise ToolExecutionError(
                    ReasonCode.RESOURCE_NOT_ALLOWED, "ticket not found", status_code=404
                )
            result = dict(ticket)
            result.setdefault("cloud_shareable", False)
            result["refund_verifications"] = [
                dict(row)
                for (ticket_id, _), row in self.refund_eligibility.items()
                if ticket_id == params["ticket_id"]
            ]
            return {"result": result, "business_effect_id": None}
        if kind == "knowledge":
            ticket_id = params["ticket_id"]
            result = [
                self.documents[doc_id]
                for doc_id in self.ticket_documents.get(ticket_id, [])
                if doc_id in self.documents
            ]
            return {
                "result": {"ticket_id": ticket_id, "documents": result},
                "business_effect_id": None,
            }
        if kind == "refund":
            return self._refund(payload, params)
        if kind == "notification":
            return self._notification(payload, params)
        raise ToolExecutionError(
            ReasonCode.TOOL_NOT_ALLOWED, f"unknown tool kind: {kind}", status_code=404
        )

    def reconcile(self, kind: str, request: ReconcileRequest) -> dict[str, Any]:
        if kind == "refund":
            existing = self.refunds.get(request.business_idempotency_key)
        elif kind == "notification":
            existing = self.notifications.get(request.business_idempotency_key)
        else:
            return {
                "status": "NOT_EXECUTED",
                "parameter_hash": None,
                "result": None,
                "business_effect_id": None,
            }
        if existing is None:
            return {
                "status": "NOT_EXECUTED",
                "parameter_hash": None,
                "result": None,
                "business_effect_id": None,
            }
        if tuple(
            str(existing.get(field))
            for field in ("execution_id", "tenant_id", "task_id", "business_action_id")
        ) != (
            request.execution_id,
            request.tenant_id,
            request.task_id,
            request.business_action_id,
        ):
            return {
                "status": "IDEMPOTENCY_CONFLICT",
                "parameter_hash": None,
                "result": None,
                "business_effect_id": None,
            }
        effect_id = existing.get("refund_id") or existing.get("notification_id")
        if existing["parameter_hash"] != request.parameter_hash:
            return {
                "status": "IDEMPOTENCY_CONFLICT",
                "parameter_hash": existing["parameter_hash"],
                "result": existing,
                "business_effect_id": effect_id,
            }
        return {
            "status": "ALREADY_EXECUTED",
            "parameter_hash": existing["parameter_hash"],
            "result": existing,
            "business_effect_id": effect_id,
        }

    def _refund(self, payload: EnvelopePayload, params: dict[str, Any]) -> dict[str, Any]:
        key = payload.business_idempotency_key
        if key is None or payload.business_action_id is None:
            raise ToolExecutionError(
                ReasonCode.BUSINESS_ACTION_INVALID, "refund requires business action"
            )
        parameter_hash = payload.parameter_hash
        existing = self.refunds.get(key)
        if existing is not None:
            if existing["parameter_hash"] != parameter_hash or not _matches_effect_identity(
                existing, payload
            ):
                raise ToolExecutionError(
                    ReasonCode.IDEMPOTENCY_CONFLICT, "refund parameter conflict"
                )
            return {"result": existing, "business_effect_id": existing["refund_id"]}
        context = _refund_task_context(self.tasks.get(payload.task_id), payload, params)
        slot = _refund_action_slot(self.business_actions.get(payload.business_action_id), context)
        eligibility = self.refund_eligibility.get((context.ticket_id, slot))
        payment = (
            self.payment_verifications.get(
                (
                    context.tenant_id,
                    str(eligibility.get("original_transaction_id")),
                )
            )
            if eligibility
            else None
        )
        try:
            business = validate_refund_business(
                context,
                ticket=self.tickets.get(context.ticket_id),
                eligibility=eligibility,
                payment=payment,
                trusted_action_slot=slot,
                amount_fen=params["amount_fen"],
            )
            for row in self.refunds.values():
                if row.get("refund_business_key") == business.business_key or (
                    row.get("tenant_id") == context.tenant_id
                    and row.get("ticket_id") == context.ticket_id
                    and row.get("original_transaction_id") is None
                ):
                    raise EligibilityError(
                        BusinessEligibilityReason.BUSINESS_ALREADY_PROCESSED,
                        "this refund business has already been processed; "
                        "no new effect was created",
                    )
            refunded = sum(
                row["amount_fen"]
                for row in self.refunds.values()
                if row.get("tenant_id") == context.tenant_id
                and row.get("original_transaction_id") == business.original_transaction_id
            )
            if refunded + params["amount_fen"] > business.transaction_amount_fen:
                raise EligibilityError(
                    BusinessEligibilityReason.BUSINESS_AMOUNT_EXCEEDED,
                    "refund exceeds the original transaction's remaining refundable amount",
                )
        except EligibilityError as exc:
            raise ToolExecutionError(exc.reason_code, str(exc)) from exc
        refund_id = new_id("REFUND")
        row = {
            "refund_id": refund_id,
            "execution_id": payload.execution_id,
            "business_action_id": payload.business_action_id,
            "business_idempotency_key": key,
            "parameter_hash": parameter_hash,
            "tenant_id": payload.tenant_id,
            "task_id": payload.task_id,
            "ticket_id": params["ticket_id"],
            "customer_id": params["customer_id"],
            "amount_fen": params["amount_fen"],
            "status": "COMMITTED",
            "created_at": now_unix(),
            "original_transaction_id": business.original_transaction_id,
            "refund_reason_code": business.refund_reason_code,
            "trusted_action_slot": business.trusted_action_slot,
            "refund_business_key": business.business_key,
        }
        self.refunds[key] = row
        return {"result": row, "business_effect_id": refund_id}

    def _notification(self, payload: EnvelopePayload, params: dict[str, Any]) -> dict[str, Any]:
        key = payload.business_idempotency_key
        if key is None or payload.business_action_id is None:
            raise ToolExecutionError(
                ReasonCode.BUSINESS_ACTION_INVALID, "notification requires business action"
            )
        if params["template_id"] != "REFUND_SUCCESS":
            raise ToolExecutionError(
                ReasonCode.PARAMETER_CONSTRAINT_VIOLATION,
                "notification template is not allowed",
                status_code=403,
            )
        context = _notification_task_context(self.tasks.get(payload.task_id), payload, params)
        _verify_notification_action(
            self.business_actions.get(payload.business_action_id), context, params
        )
        existing = self.notifications.get(key)
        if existing is not None:
            if existing["parameter_hash"] != payload.parameter_hash or not _matches_effect_identity(
                existing, payload
            ):
                raise ToolExecutionError(
                    ReasonCode.IDEMPOTENCY_CONFLICT, "notification parameter conflict"
                )
            return {"result": existing, "business_effect_id": existing["notification_id"]}
        refund = next(
            (
                row
                for row in self.refunds.values()
                if row["refund_id"] == params["related_business_effect_id"]
            ),
            {},
        )
        try:
            if refund.get("ticket_id") != context.ticket_id:
                raise ValueError("notification refund is bound to a different task ticket")
            content = render_refund_success(
                refund,
                tenant_id=payload.tenant_id,
                task_id=payload.task_id,
                customer_id=params["customer_id"],
            )
        except ValueError as exc:
            raise ToolExecutionError(ReasonCode.BUSINESS_ACTION_INVALID, str(exc)) from exc
        notification_id = new_id("NOTIFY")
        row = {
            "notification_id": notification_id,
            "execution_id": payload.execution_id,
            "business_action_id": payload.business_action_id,
            "business_idempotency_key": key,
            "parameter_hash": payload.parameter_hash,
            "tenant_id": payload.tenant_id,
            "task_id": payload.task_id,
            "customer_id": params["customer_id"],
            "template_id": params["template_id"],
            "template_version": REFUND_SUCCESS["version"],
            "content": content,
            "related_business_effect_id": params["related_business_effect_id"],
            "status": "SENT",
            "created_at": now_unix(),
        }
        self.notifications[key] = row
        return {"result": row, "business_effect_id": notification_id}


class PostgresToolStore:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def execute(self, kind: str, payload: EnvelopePayload, envelope_hash: str) -> dict[str, Any]:
        params = payload.canonical_validated_parameters
        with connect(self.database_url) as connection:
            with connection.transaction():
                if kind in {"refund", "notification"}:
                    # Admission and dispatch take the task lock before the execution lock.
                    connection.execute(
                        "SELECT task_id FROM tasks WHERE task_id = %s FOR SHARE",
                        (payload.task_id,),
                    ).fetchone()
                # Recovery and the first side effect serialize on the same execution row.
                execution = connection.execute(
                    """
                    SELECT state, decision, request_hash, tenant_id, task_id,
                           tool_service, tool_name, tool_version, parameter_hash,
                           business_action_id
                    FROM execution_records WHERE execution_id = %s FOR UPDATE
                    """,
                    (payload.execution_id,),
                ).fetchone()
                if (
                    connection.execute(
                        "SELECT 1 FROM tool_execution_attempts WHERE execution_attempt_id = %s",
                        (payload.execution_attempt_id,),
                    ).fetchone()
                    is not None
                ):
                    raise ToolExecutionError(
                        ReasonCode.EXECUTION_ENVELOPE_REPLAY, "execution attempt replay"
                    )
                if execution is None or (
                    str(execution[0]) != "DISPATCHED"
                    or str(execution[1]) != "ALLOW"
                    or tuple(execution[2:])
                    != (
                        payload.request_hash,
                        payload.tenant_id,
                        payload.task_id,
                        payload.tool_service,
                        payload.tool_name,
                        payload.tool_version,
                        payload.parameter_hash,
                        payload.business_action_id,
                    )
                ):
                    raise ToolExecutionError(
                        ReasonCode.TOOL_NOT_ALLOWED,
                        "execution is not an active matching dispatch",
                    )
                if now_unix() > payload.expires_at:
                    raise ToolExecutionError(
                        ReasonCode.EXECUTION_ENVELOPE_EXPIRED,
                        "execution envelope expired before the tool transaction",
                    )
                try:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO tool_execution_attempts
                                (
                                    execution_attempt_id,
                                    execution_id,
                                    envelope_hash,
                                    received_at,
                                    status
                                )
                            VALUES (%s, %s, %s, %s, 'RECEIVED')
                            ON CONFLICT (execution_attempt_id) DO NOTHING
                            RETURNING execution_attempt_id
                            """,
                            (
                                payload.execution_attempt_id,
                                payload.execution_id,
                                envelope_hash,
                                now_unix(),
                            ),
                        )
                        accepted_attempt = cursor.fetchone()
                    if accepted_attempt is None:
                        raise ToolExecutionError(
                            ReasonCode.EXECUTION_ENVELOPE_REPLAY,
                            "execution attempt replay",
                        )
                except ToolExecutionError:
                    raise
                if kind == "ticket":
                    result = self._ticket(connection, params)
                elif kind == "knowledge":
                    result = self._knowledge(connection, params)
                elif kind == "refund":
                    result = self._refund(connection, payload, params)
                elif kind == "notification":
                    result = self._notification(connection, payload, params)
                else:
                    raise ToolExecutionError(
                        ReasonCode.TOOL_NOT_ALLOWED, f"unknown tool kind: {kind}", status_code=404
                    )
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE tool_execution_attempts
                        SET status = 'COMPLETED', tool_outcome = %s
                        WHERE execution_attempt_id = %s
                        """,
                        ("SUCCESS", payload.execution_attempt_id),
                    )
                return result

    def reconcile(self, kind: str, request: ReconcileRequest) -> dict[str, Any]:
        if kind not in {"refund", "notification"}:
            return {
                "status": "NOT_EXECUTED",
                "parameter_hash": None,
                "result": None,
                "business_effect_id": None,
            }
        with connect(self.database_url) as connection:
            if kind == "refund":
                fields = [
                    "refund_id",
                    "execution_id",
                    "business_action_id",
                    "business_idempotency_key",
                    "parameter_hash",
                    "tenant_id",
                    "task_id",
                    "ticket_id",
                    "customer_id",
                    "amount_fen",
                    "status",
                    "created_at",
                ]
                table = "refunds"
            else:
                fields = [
                    "notification_id",
                    "execution_id",
                    "business_action_id",
                    "business_idempotency_key",
                    "parameter_hash",
                    "tenant_id",
                    "task_id",
                    "customer_id",
                    "template_id",
                    "related_business_effect_id",
                    "status",
                    "created_at",
                    "template_version",
                    "content",
                ]
                table = "notifications"
            row = connection.execute(
                f"""
                SELECT {", ".join(fields)}
                FROM {table}
                WHERE business_idempotency_key = %s
                FOR SHARE
                """,
                (request.business_idempotency_key,),
            ).fetchone()
            if row is not None:
                existing = dict(zip(fields, row, strict=True))
                if tuple(
                    str(existing[field])
                    for field in ("execution_id", "tenant_id", "task_id", "business_action_id")
                ) != (
                    request.execution_id,
                    request.tenant_id,
                    request.task_id,
                    request.business_action_id,
                ):
                    return {
                        "status": "IDEMPOTENCY_CONFLICT",
                        "parameter_hash": None,
                        "result": None,
                        "business_effect_id": None,
                    }
                effect_id = str(
                    existing["refund_id"] if kind == "refund" else existing["notification_id"]
                )
                if str(existing["parameter_hash"]) != request.parameter_hash:
                    return {
                        "status": "IDEMPOTENCY_CONFLICT",
                        "parameter_hash": str(existing["parameter_hash"]),
                        "result": existing,
                        "business_effect_id": effect_id,
                    }
                return {
                    "status": "ALREADY_EXECUTED",
                    "parameter_hash": str(existing["parameter_hash"]),
                    "result": existing,
                    "business_effect_id": effect_id,
                }
            attempt = connection.execute(
                """
                SELECT status, tool_outcome
                FROM tool_execution_attempts
                WHERE execution_id = %s
                ORDER BY received_at DESC
                LIMIT 1
                """,
                (request.execution_id,),
            ).fetchone()
            if attempt is not None and str(attempt[0]) != "REJECTED":
                return {
                    "status": "UNKNOWN",
                    "parameter_hash": None,
                    "result": None,
                    "business_effect_id": None,
                }
            return {
                "status": "NOT_EXECUTED",
                "parameter_hash": None,
                "result": None,
                "business_effect_id": None,
            }

    def _ticket(self, connection, params: dict[str, Any]) -> dict[str, Any]:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    ticket_id,
                    tenant_id,
                    customer_id,
                    title,
                    description,
                    status,
                    created_at,
                    updated_at,
                    cloud_shareable
                FROM tickets
                WHERE ticket_id = %s
                """,
                (params["ticket_id"],),
            )
            row = cursor.fetchone()
        if row is None:
            raise ToolExecutionError(
                ReasonCode.RESOURCE_NOT_ALLOWED, "ticket not found", status_code=404
            )
        fields = [
            "ticket_id",
            "tenant_id",
            "customer_id",
            "title",
            "description",
            "status",
            "created_at",
            "updated_at",
            "cloud_shareable",
        ]
        result = dict(zip(fields, row, strict=True))
        from backend.business_action.facts import load_business_case_facts

        facts = load_business_case_facts(connection, params["ticket_id"])
        if facts is not None:
            # The planner receives source transactions, never the independent verdict.
            result.update(business_facts=facts["facts"], facts_hash=facts["facts_hash"], source="facts")
            return {"result": result, "business_effect_id": None}
        verification_fields = (
            "trusted_action_slot",
            "verification_status",
            "original_transaction_id",
            "refund_reason_code",
            "refundable_amount_fen",
            "evidence_reference",
            "verified_at",
            "payment_verification_status",
            "transaction_refundable_amount_fen",
        )
        records = connection.execute(
            "SELECT e.trusted_action_slot, e.verification_status, e.original_transaction_id, "
            "e.refund_reason_code, e.refundable_amount_fen, e.evidence_reference, e.verified_at, "
            "p.verification_status, p.refundable_amount_fen FROM refund_eligibility e "
            "LEFT JOIN business_payment_verifications p ON p.tenant_id = e.tenant_id "
            "AND p.original_transaction_id = e.original_transaction_id "
            "WHERE e.ticket_id = %s ORDER BY e.trusted_action_slot",
            (params["ticket_id"],),
        ).fetchall()
        result["refund_verifications"] = [
            dict(zip(verification_fields, record, strict=True)) for record in records
        ]
        return {"result": result, "business_effect_id": None}

    def _knowledge(self, connection, params: dict[str, Any]) -> dict[str, Any]:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT d.document_id, d.tenant_id, d.title, d.content, d.sensitivity, d.created_at
                FROM knowledge_documents d
                JOIN ticket_document_relations r ON r.document_id = d.document_id
                WHERE r.ticket_id = %s
                ORDER BY d.document_id
                """,
                (params["ticket_id"],),
            )
            rows = cursor.fetchall()
        fields = ["document_id", "tenant_id", "title", "content", "sensitivity", "created_at"]
        return {
            "result": {
                "ticket_id": params["ticket_id"],
                "documents": [dict(zip(fields, row, strict=False)) for row in rows],
            },
            "business_effect_id": None,
        }

    def _refund(
        self, connection, payload: EnvelopePayload, params: dict[str, Any]
    ) -> dict[str, Any]:
        if payload.business_idempotency_key is None or payload.business_action_id is None:
            raise ToolExecutionError(
                ReasonCode.BUSINESS_ACTION_INVALID, "refund requires business action"
            )
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (payload.business_idempotency_key,),
            )
            cursor.execute(
                """
                SELECT
                    refund_id,
                    execution_id,
                    business_action_id,
                    business_idempotency_key,
                    parameter_hash,
                    tenant_id,
                    task_id,
                    ticket_id,
                    customer_id,
                    amount_fen,
                    status,
                    created_at
                FROM refunds
                WHERE business_idempotency_key = %s
                FOR UPDATE
                """,
                (payload.business_idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                fields = [
                    "refund_id",
                    "execution_id",
                    "business_action_id",
                    "business_idempotency_key",
                    "parameter_hash",
                    "tenant_id",
                    "task_id",
                    "ticket_id",
                    "customer_id",
                    "amount_fen",
                    "status",
                    "created_at",
                ]
                stored = dict(zip(fields, existing, strict=True))
                if existing[4] != payload.parameter_hash or not _matches_effect_identity(
                    stored, payload
                ):
                    raise ToolExecutionError(
                        ReasonCode.IDEMPOTENCY_CONFLICT, "refund parameter or identity conflict"
                    )
                return {
                    "result": stored,
                    "business_effect_id": existing[0],
                }
            task_fields = (
                "tenant_id",
                "task_id",
                "ticket_id",
                "customer_id",
                "status",
                "expires_at",
            )
            task_row = connection.execute(
                "SELECT " + ", ".join(task_fields) + " FROM tasks WHERE task_id = %s FOR SHARE",
                (payload.task_id,),
            ).fetchone()
            task = dict(zip(task_fields, task_row, strict=True)) if task_row else None
            context = _refund_task_context(task, payload, params)
            action_fields = (
                "tenant_id",
                "task_id",
                "tool_service",
                "tool_name",
                "trusted_action_slot",
                "action_scope_key",
                "status",
            )
            action_row = connection.execute(
                "SELECT " + ", ".join(action_fields) + " FROM business_actions "
                "WHERE business_action_id = %s FOR SHARE",
                (payload.business_action_id,),
            ).fetchone()
            action = dict(zip(action_fields, action_row, strict=True)) if action_row else None
            slot = _refund_action_slot(action, context)
            try:
                business = load_verified_refund_business(
                    connection,
                    context,
                    trusted_action_slot=slot,
                    amount_fen=params["amount_fen"],
                    for_execution=True,
                )
                check_unprocessed_business(connection, context, business)
                refunded = payment_refunded_amount(connection, context, business)
                if refunded + params["amount_fen"] > business.transaction_amount_fen:
                    raise EligibilityError(
                        BusinessEligibilityReason.BUSINESS_AMOUNT_EXCEEDED,
                        "refund exceeds the original transaction's remaining refundable amount",
                    )
            except EligibilityError as exc:
                raise ToolExecutionError(exc.reason_code, str(exc)) from exc
            refund_id = new_id("REFUND")
            created_at = now_unix()
            cursor.execute(
                """
                INSERT INTO refunds (
                    refund_id,
                    execution_id,
                    business_action_id,
                    business_idempotency_key,
                    parameter_hash,
                    tenant_id,
                    task_id,
                    ticket_id,
                    customer_id,
                    amount_fen,
                    status,
                    created_at,
                    original_transaction_id,
                    refund_reason_code,
                    trusted_action_slot,
                    refund_business_key
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'COMMITTED', %s, %s, %s, %s, %s)
                """,
                (
                    refund_id,
                    payload.execution_id,
                    payload.business_action_id,
                    payload.business_idempotency_key,
                    payload.parameter_hash,
                    payload.tenant_id,
                    payload.task_id,
                    params["ticket_id"],
                    params["customer_id"],
                    params["amount_fen"],
                    created_at,
                    business.original_transaction_id,
                    business.refund_reason_code,
                    business.trusted_action_slot,
                    business.business_key,
                ),
            )
            return {
                "result": {
                    "refund_id": refund_id,
                    "execution_id": payload.execution_id,
                    "business_action_id": payload.business_action_id,
                    "business_idempotency_key": payload.business_idempotency_key,
                    "parameter_hash": payload.parameter_hash,
                    "tenant_id": payload.tenant_id,
                    "task_id": payload.task_id,
                    "ticket_id": params["ticket_id"],
                    "customer_id": params["customer_id"],
                    "amount_fen": params["amount_fen"],
                    "status": "COMMITTED",
                    "created_at": created_at,
                },
                "business_effect_id": refund_id,
            }

    def _notification(
        self, connection, payload: EnvelopePayload, params: dict[str, Any]
    ) -> dict[str, Any]:
        if payload.business_idempotency_key is None or payload.business_action_id is None:
            raise ToolExecutionError(
                ReasonCode.BUSINESS_ACTION_INVALID, "notification requires business action"
            )
        if params["template_id"] != "REFUND_SUCCESS":
            raise ToolExecutionError(
                ReasonCode.PARAMETER_CONSTRAINT_VIOLATION,
                "notification template is not allowed",
                status_code=403,
            )
        with connection.cursor() as cursor:
            task_fields = (
                "tenant_id", "task_id", "ticket_id", "customer_id", "status", "expires_at"
            )
            task_row = connection.execute(
                "SELECT " + ", ".join(task_fields) + " FROM tasks WHERE task_id = %s FOR SHARE",
                (payload.task_id,),
            ).fetchone()
            task = dict(zip(task_fields, task_row, strict=True)) if task_row else None
            context = _notification_task_context(task, payload, params)
            action_fields = (
                "tenant_id", "task_id", "tool_service", "tool_name", "trusted_action_slot",
                "action_scope_key", "status",
            )
            action_row = connection.execute(
                "SELECT " + ", ".join(action_fields) + " FROM business_actions "
                "WHERE business_action_id = %s FOR SHARE",
                (payload.business_action_id,),
            ).fetchone()
            action = dict(zip(action_fields, action_row, strict=True)) if action_row else None
            _verify_notification_action(action, context, params)
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (payload.business_idempotency_key,),
            )
            cursor.execute(
                """
                SELECT
                    notification_id,
                    execution_id,
                    business_action_id,
                    business_idempotency_key,
                    parameter_hash,
                    tenant_id,
                    task_id,
                    customer_id,
                    template_id,
                    related_business_effect_id,
                    status,
                    created_at,
                    template_version,
                    content
                FROM notifications
                WHERE business_idempotency_key = %s
                FOR UPDATE
                """,
                (payload.business_idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                fields = [
                    "notification_id",
                    "execution_id",
                    "business_action_id",
                    "business_idempotency_key",
                    "parameter_hash",
                    "tenant_id",
                    "task_id",
                    "customer_id",
                    "template_id",
                    "related_business_effect_id",
                    "status",
                    "created_at",
                    "template_version",
                    "content",
                ]
                stored = dict(zip(fields, existing, strict=True))
                if existing[4] != payload.parameter_hash or not _matches_effect_identity(
                    stored, payload
                ):
                    raise ToolExecutionError(
                        ReasonCode.IDEMPOTENCY_CONFLICT,
                        "notification parameter or identity conflict",
                    )
                return {
                    "result": stored,
                    "business_effect_id": existing[0],
                }
            cursor.execute(
                "SELECT refund_id, tenant_id, task_id, ticket_id, customer_id, amount_fen, status "
                "FROM refunds WHERE refund_id = %s FOR SHARE",
                (params["related_business_effect_id"],),
            )
            refund_row = cursor.fetchone()
            refund_fields = (
                "refund_id",
                "tenant_id",
                "task_id",
                "ticket_id",
                "customer_id",
                "amount_fen",
                "status",
            )
            refund = {} if refund_row is None else dict(zip(refund_fields, refund_row, strict=True))
            try:
                if refund.get("ticket_id") != context.ticket_id:
                    raise ValueError("notification refund is bound to a different task ticket")
                content = render_refund_success(
                    refund,
                    tenant_id=payload.tenant_id,
                    task_id=payload.task_id,
                    customer_id=params["customer_id"],
                )
            except ValueError as exc:
                raise ToolExecutionError(ReasonCode.BUSINESS_ACTION_INVALID, str(exc)) from exc
            notification_id = new_id("NOTIFY")
            created_at = now_unix()
            cursor.execute(
                """
                INSERT INTO notifications (
                    notification_id,
                    execution_id,
                    business_action_id,
                    business_idempotency_key,
                    parameter_hash,
                    tenant_id,
                    task_id,
                    customer_id,
                    template_id,
                    related_business_effect_id,
                    status,
                    created_at,
                    template_version,
                    content
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'SENT', %s, %s, %s)
                """,
                (
                    notification_id,
                    payload.execution_id,
                    payload.business_action_id,
                    payload.business_idempotency_key,
                    payload.parameter_hash,
                    payload.tenant_id,
                    payload.task_id,
                    params["customer_id"],
                    params["template_id"],
                    params["related_business_effect_id"],
                    created_at,
                    REFUND_SUCCESS["version"],
                    content,
                ),
            )
            return {
                "result": {
                    "notification_id": notification_id,
                    "execution_id": payload.execution_id,
                    "business_action_id": payload.business_action_id,
                    "business_idempotency_key": payload.business_idempotency_key,
                    "parameter_hash": payload.parameter_hash,
                    "tenant_id": payload.tenant_id,
                    "task_id": payload.task_id,
                    "customer_id": params["customer_id"],
                    "template_id": params["template_id"],
                    "template_version": REFUND_SUCCESS["version"],
                    "content": content,
                    "related_business_effect_id": params["related_business_effect_id"],
                    "status": "SENT",
                    "created_at": created_at,
                },
                "business_effect_id": notification_id,
            }


def _matches_effect_identity(existing: dict[str, Any], payload: EnvelopePayload) -> bool:
    return tuple(
        existing.get(field)
        for field in (
            "execution_id",
            "tenant_id",
            "task_id",
            "business_action_id",
        )
    ) == (
        payload.execution_id,
        payload.tenant_id,
        payload.task_id,
        payload.business_action_id,
    )


def _notification_task_context(
    task: dict[str, Any] | None, payload: EnvelopePayload, params: dict[str, Any]
) -> TrustedTaskContext:
    if task is None or (
        task.get("tenant_id") != payload.tenant_id
        or task.get("task_id") != payload.task_id
        or task.get("customer_id") != params.get("customer_id")
        or not isinstance(task.get("ticket_id"), str)
        or not task["ticket_id"]
        or task.get("status") != "AUTHORIZED"
    ):
        raise ToolExecutionError(
            ReasonCode.BUSINESS_ACTION_INVALID,
            "notification does not match the independently authorized task",
        )
    if type(task.get("expires_at")) is not int or now_unix() > task["expires_at"]:
        raise ToolExecutionError(ReasonCode.CREDENTIAL_EXPIRED, "notification task is expired")
    return TrustedTaskContext(
        payload.tenant_id, payload.task_id, task["ticket_id"], params["customer_id"]
    )


def _verify_notification_action(
    action: dict[str, Any] | None, context: TrustedTaskContext, params: dict[str, Any]
) -> None:
    if action is None or (
        action.get("tenant_id") != context.tenant_id
        or action.get("task_id") != context.task_id
        or action.get("tool_service") != NOTIFICATION_SERVICE
        or action.get("tool_name") != NOTIFICATION_TOOL
        or action.get("status") not in {"ACTIVE", "COMMITTED"}
    ):
        raise ToolExecutionError(
            ReasonCode.BUSINESS_ACTION_INVALID, "notification action identity is invalid"
        )
    scope_key, _ = notification_scope(
        context,
        template_id=params["template_id"],
        related_business_effect_id=params["related_business_effect_id"],
    )
    if (
        action.get("trusted_action_slot") != REFUND_SUCCESS_NOTIFICATION_SLOT
        or action.get("action_scope_key") != scope_key
    ):
        raise ToolExecutionError(
            ReasonCode.BUSINESS_ACTION_CONFLICT,
            "notification action scope differs from the actual refund or template",
        )


def _refund_task_context(
    task: dict[str, Any] | None,
    payload: EnvelopePayload,
    params: dict[str, Any],
) -> TrustedTaskContext:
    amount = params.get("amount_fen")
    if type(amount) is not int or not 0 < amount <= 9_007_199_254_740_991:
        raise ToolExecutionError(
            ReasonCode.PARAMETER_CONSTRAINT_VIOLATION,
            "refund amount must be positive integer fen",
        )
    if task is None or (
        task.get("tenant_id") != payload.tenant_id
        or task.get("task_id") != payload.task_id
        or task.get("ticket_id") != params.get("ticket_id")
        or task.get("customer_id") != params.get("customer_id")
        or task.get("status") != "AUTHORIZED"
    ):
        raise ToolExecutionError(
            ReasonCode.BUSINESS_ACTION_INVALID,
            "refund request does not match the independently authorized task",
        )
    if type(task.get("expires_at")) is not int or now_unix() > task["expires_at"]:
        raise ToolExecutionError(ReasonCode.CREDENTIAL_EXPIRED, "refund task is expired")
    return TrustedTaskContext(
        tenant_id=payload.tenant_id,
        task_id=payload.task_id,
        ticket_id=params["ticket_id"],
        customer_id=params["customer_id"],
    )


def _refund_action_slot(action: dict[str, Any] | None, context: TrustedTaskContext) -> str:
    if action is None or (
        action.get("tenant_id") != context.tenant_id
        or action.get("task_id") != context.task_id
        or action.get("tool_service") != "refund-service"
        or action.get("tool_name") != "refund.create"
        or action.get("status") not in {"ACTIVE", "COMMITTED"}
    ):
        raise ToolExecutionError(
            ReasonCode.BUSINESS_ACTION_INVALID,
            "refund action identity is invalid",
        )
    slot = str(action.get("trusted_action_slot"))
    scope_key, _ = refund_scope(context, trusted_action_slot=slot)
    if action.get("action_scope_key") != scope_key:
        raise ToolExecutionError(
            ReasonCode.BUSINESS_ACTION_CONFLICT,
            "refund action scope is inconsistent",
        )
    return slot
