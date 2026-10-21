from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import ValidationError
from psycopg.types.json import Jsonb

from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import BUSINESS_IDEMPOTENCY, EXECUTION_RECEIPT
from backend.crypto.sm import sign_payload, sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect


class ReceiptError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str, *, status_code: int = 500) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


class ReceiptService:
    """Issue one durable, schema-valid signed receipt per execution."""

    def __init__(
        self,
        database_url: str,
        *,
        private_key_file: str,
        key_id: str = "receipt-key-01",
        schemas: SchemaStore | None = None,
    ) -> None:
        self.database_url = database_url
        self.private_key_file = private_key_file
        self.key_id = key_id
        self.schemas = schemas or SchemaStore()

    def issue(self, execution_id: str, *, current_time: int | None = None) -> dict[str, Any]:
        timestamp = now_unix() if current_time is None else current_time
        try:
            with connect(self.database_url) as connection, connection.transaction():
                row = connection.execute(
                    """
                    SELECT e.execution_id,
                           COALESCE(dc.request_id, rda.request_id, e.initial_request_id),
                           e.request_hash,
                           e.credential_chain_hash, e.tenant_id, e.task_id,
                           e.tool_service, e.tool_name, e.tool_version, e.parameter_hash,
                           e.state, e.decision, e.reason_code, e.receipt_status,
                           e.business_action_id, e.result, e.business_effect_id,
                           e.business_result_hash, e.created_at, e.updated_at,
                           i.business_idempotency_key, e.terminal_at, e.terminal_state::text,
                           e.decision_at, e.decision_value::text
                    FROM execution_records e
                    LEFT JOIN replay_denial_attempts rda
                      ON rda.denial_execution_id = e.execution_id
                    LEFT JOIN dispatch_cancellations dc
                      ON dc.denial_execution_id = e.execution_id
                    LEFT JOIN idempotency_records i ON i.execution_id = e.execution_id
                    WHERE e.execution_id = %s
                    FOR UPDATE OF e
                    """,
                    (execution_id,),
                ).fetchone()
                if row is None:
                    raise ReceiptError(
                        ReasonCode.TOOL_EXECUTION_UNKNOWN,
                        "execution does not exist",
                        status_code=404,
                    )
                if current_time is None:
                    timestamp = now_unix()

                existing = connection.execute(
                    """
                    SELECT receipt_id, signed_receipt, receipt_status
                    FROM execution_receipts
                    WHERE execution_id = %s
                    FOR UPDATE
                    """,
                    (execution_id,),
                ).fetchone()
                if existing is not None and str(existing[2]) == "SIGNED":
                    connection.execute(
                        """
                        UPDATE execution_records
                        SET receipt_status = 'SIGNED', updated_at = GREATEST(updated_at, %s)
                        WHERE execution_id = %s
                        """,
                        (timestamp, execution_id),
                    )
                    return dict(existing[1])

                payload = self._build_payload(connection, row, timestamp, existing)
                connection.execute(
                    """
                    UPDATE execution_records
                    SET receipt_status = 'PENDING', updated_at = GREATEST(updated_at, %s)
                    WHERE execution_id = %s
                    """,
                    (timestamp, execution_id),
                )
                signed = self._sign(payload, connection)
                timestamp = int(payload["receipt_issued_at"])
                try:
                    self.schemas.validate(
                        "execution-receipt.schema.json", signed
                    )
                except ValidationError as exc:
                    raise ReceiptError(
                        ReasonCode.REQUEST_SCHEMA_INVALID,
                        "signed execution receipt violates the frozen schema",
                    ) from exc
                receipt_hash = sm3_hex(canonicalize(signed))
                receipt_id = str(payload["receipt_id"])
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO execution_receipts (
                            receipt_id, execution_id, receipt_type, decision, reason_code,
                            signed_receipt, receipt_hash, receipt_status, created_at, updated_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, 'SIGNED', %s, %s)
                        """,
                        (
                            receipt_id,
                            execution_id,
                            payload["receipt_type"],
                            payload["decision"],
                            payload["reason_code"],
                            Jsonb(signed),
                            receipt_hash,
                            timestamp,
                            timestamp,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE execution_receipts
                        SET receipt_type = %s, decision = %s, reason_code = %s,
                            signed_receipt = %s, receipt_hash = %s,
                            receipt_status = 'SIGNED', updated_at = %s
                        WHERE execution_id = %s
                        """,
                        (
                            payload["receipt_type"],
                            payload["decision"],
                            payload["reason_code"],
                            Jsonb(signed),
                            receipt_hash,
                            timestamp,
                            execution_id,
                        ),
                    )
                connection.execute(
                    """
                    UPDATE execution_records
                    SET receipt_status = 'SIGNED', updated_at = GREATEST(updated_at, %s)
                    WHERE execution_id = %s
                    """,
                    (timestamp, execution_id),
                )
                self._enqueue_audit_events(
                    connection,
                    execution_id=execution_id,
                    receipt_id=receipt_id,
                    receipt_hash=receipt_hash,
                    payload=payload,
                    execution_state=str(row[10]),
                    timestamp=timestamp,
                )
                return signed
        except ReceiptError:
            self._mark_failed(execution_id, timestamp)
            raise
        except (KeyRegistryError, OSError, ValueError) as exc:
            self._mark_failed(execution_id, timestamp)
            reason = (
                exc.reason_code
                if isinstance(exc, KeyRegistryError)
                else ReasonCode.UNKNOWN_KEY
            )
            raise ReceiptError(reason, "receipt signing failed") from exc
        except Exception as exc:
            self._mark_failed(execution_id, timestamp)
            raise ReceiptError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN, "receipt issuance failed"
            ) from exc

    def get(self, execution_id: str) -> dict[str, Any] | None:
        with connect(self.database_url) as connection:
            row = connection.execute(
                """
                SELECT signed_receipt FROM execution_receipts
                WHERE execution_id = %s AND receipt_status = 'SIGNED'
                """,
                (execution_id,),
            ).fetchone()
        return None if row is None else dict(row[0])

    def _build_payload(
        self,
        connection,
        row: tuple[Any, ...],
        timestamp: int,
        existing: tuple[Any, ...] | None,
    ) -> dict[str, Any]:
        state = str(row[10])
        if state not in {"DENIED", "COMMITTED", "RELEASED"}:
            raise ReceiptError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN,
                f"execution state {state} is not receipt-final",
                status_code=409,
            )
        terminal_at = row[21] if len(row) > 21 else None
        terminal_state = row[22] if len(row) > 22 else None
        decision_at = row[23] if len(row) > 23 else None
        decision_value = row[24] if len(row) > 24 else None
        decision = "DENY" if state == "DENIED" else "ALLOW"
        if (
            type(terminal_at) is not int
            or type(decision_at) is not int
            or type(row[18]) is not int
            or type(timestamp) is not int
            or not 0 <= row[18] <= decision_at <= terminal_at <= timestamp <= MAX_SAFE_INTEGER
            or terminal_state != state
            or decision_value != decision
            or str(row[11]) != decision
        ):
            raise ReceiptError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN,
                "execution has no matching trusted decision/terminal time or receipt clock precedes it",
                status_code=409,
            )
        reason_code = str(row[12]) if decision == "DENY" else ReasonCode.ALLOWED.value
        receipt_type = "AUTHORIZATION_DENIAL" if decision == "DENY" else "EXECUTION_RESULT"
        business_action_id = None if row[14] is None else str(row[14])
        business_key = None if row[20] is None else str(row[20])
        if business_key is None and business_action_id is not None:
            business_key = sm3_hex(
                self._business_idempotency_message(
                    tenant_id=str(row[4]),
                    task_id=str(row[5]),
                    tool_service=str(row[6]),
                    tool_name=str(row[7]),
                    business_action_id=business_action_id,
                )
            )
        totals = connection.execute(
            """
            SELECT
                COALESCE(SUM(amount) FILTER (WHERE status = 'RESERVED'), 0),
                COALESCE(SUM(amount) FILTER (WHERE status = 'COMMITTED'), 0)
            FROM execution_budget_reservations
            WHERE execution_id = %s
            """,
            (str(row[0]),),
        ).fetchone()
        budget_reserved = int(totals[0])
        budget_committed = int(totals[1])
        if budget_reserved != 0:
            raise ReceiptError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN,
                "receipt-final execution still has unsettled budget reservations",
                status_code=409,
            )
        if state != "COMMITTED" and (
            budget_committed != 0 or any(row[index] is not None for index in (15, 16, 17))
        ):
            raise ReceiptError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN,
                "noncommitted execution carries committed budget or result evidence",
                status_code=409,
            )
        result = row[15] if decision == "ALLOW" and state == "COMMITTED" else None
        result_hash = None
        if state == "COMMITTED":
            if not isinstance(result, dict):
                raise ReceiptError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "committed execution has no business result evidence",
                    status_code=409,
                )
            try:
                result_hash = sm3_hex(canonicalize(result))
            except ValueError as exc:
                raise ReceiptError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "business result violates the canonical JSON profile",
                    status_code=409,
                ) from exc
            if row[17] is not None and row[17] != result_hash:
                raise ReceiptError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "stored business result digest does not match the actual result",
                    status_code=409,
                )
        effect_id = (
            str(row[16])
            if decision == "ALLOW" and state == "COMMITTED" and row[16] is not None
            else None
        )
        if state == "COMMITTED":
            effect_field = {
                ("refund-service", "refund.create"): "refund_id",
                ("notification-service", "notification.send_template"): "notification_id",
            }.get((str(row[6]), str(row[7])))
            if effect_field is not None:
                if (
                    not business_action_id
                    or not business_key
                    or not effect_id
                    or result.get(effect_field) != effect_id
                ):
                    raise ReceiptError(
                        ReasonCode.TOOL_EXECUTION_UNKNOWN,
                        "committed result does not bind the business effect",
                        status_code=409,
                    )
            elif (
                effect_id is not None
                or business_action_id is not None
                or business_key is not None
            ):
                raise ReceiptError(
                    ReasonCode.TOOL_EXECUTION_UNKNOWN,
                    "read-only execution cannot carry a business effect",
                    status_code=409,
                )
        finalized_at = terminal_at if state in {"COMMITTED", "RELEASED"} else None
        receipt_id = str(existing[0]) if existing is not None else new_id("RECEIPT")
        return {
            "schema_version": "1.0",
            "receipt_id": receipt_id,
            "receipt_type": receipt_type,
            "execution_id": str(row[0]),
            "request_id": str(row[1]),
            "request_hash": str(row[2]),
            "credential_chain_hash": str(row[3]),
            "tenant_id": str(row[4]),
            "task_id": str(row[5]),
            "tool_service": str(row[6]),
            "tool_name": str(row[7]),
            "tool_version": str(row[8]),
            "parameter_hash": str(row[9]),
            "decision": decision,
            "reason_code": reason_code,
            "business_action_id": business_action_id,
            "business_idempotency_key": business_key,
            "business_effect_id": effect_id,
            "business_result_hash": result_hash,
            "budget_reserved": budget_reserved,
            "budget_committed": budget_committed,
            "started_at": int(row[18]),
            "finished_at": terminal_at,
            "decision_at": decision_at,
            "business_effect_finalized_at": finalized_at,
            "receipt_issued_at": timestamp,
            "receipt_signing_key_id": self.key_id,
        }

    def _sign(self, payload: dict[str, Any], connection) -> dict[str, Any]:
        private_key = Path(self.private_key_file).read_text(encoding="ascii").strip()
        key = PostgresKeyRegistry.resolve_for_signing_with_connection(
            connection,
            self.key_id,
            expected_subject_id="receipt-service",
            expected_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
            lock=True,
        )
        signed_at = now_unix()
        if (
            type(signed_at) is not int
            or not int(payload["finished_at"]) <= signed_at <= MAX_SAFE_INTEGER
        ):
            raise ReceiptError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN,
                "receipt signing clock precedes the trusted execution terminal time",
                status_code=409,
            )
        payload["receipt_issued_at"] = signed_at
        signature = sign_payload(
            payload,
            domain_separator=EXECUTION_RECEIPT,
            key_id=key.key_id,
            key_purpose=key.purpose,
            private_key_hex=private_key,
            public_key_hex=key.public_key_hex,
            signed_at=signed_at,
        )
        return {"payload": payload, "signature": signature}

    @staticmethod
    def _business_idempotency_message(
        *, tenant_id: str, task_id: str, tool_service: str, tool_name: str, business_action_id: str
    ) -> bytes:
        from backend.crypto.sm import domain_message

        return domain_message(
            BUSINESS_IDEMPOTENCY,
            {
                "tenant_id": tenant_id,
                "task_id": task_id,
                "tool_service": tool_service,
                "tool_name": tool_name,
                "business_action_id": business_action_id,
            },
        )

    @staticmethod
    def _enqueue_audit_events(
        connection,
        *,
        execution_id: str,
        receipt_id: str,
        receipt_hash: str,
        payload: dict[str, Any],
        execution_state: str,
        timestamp: int,
    ) -> None:
        outcome_type = {
            "DENIED": "AUTHORIZATION_DENIED",
            "COMMITTED": "EXECUTION_COMMITTED",
            "RELEASED": "EXECUTION_RELEASED",
        }[execution_state]
        records = (
            (f"OUTBOX-{receipt_id}-RECEIPT", "RECEIPT_SIGNED", receipt_id),
            (f"OUTBOX-{receipt_id}-OUTCOME", outcome_type, receipt_id),
        )
        for outbox_id, event_type, evidence_reference in records:
            event_payload = {
                "schema_version": "1.0",
                "event_type": event_type,
                "execution_id": execution_id,
                "receipt_id": receipt_id,
                "receipt_hash": receipt_hash,
                "decision": payload["decision"],
            }
            connection.execute(
                """
                INSERT INTO audit_outbox (
                    outbox_event_id, execution_id, event_type, evidence_reference,
                    payload_hash, payload, status, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, 'PENDING', %s)
                ON CONFLICT (outbox_event_id) DO NOTHING
                """,
                (
                    outbox_id,
                    execution_id,
                    event_type,
                    evidence_reference,
                    sm3_hex(canonicalize(event_payload)),
                    Jsonb(event_payload),
                    timestamp,
                ),
            )

    def _mark_failed(self, execution_id: str, timestamp: int) -> None:
        try:
            with connect(self.database_url) as connection, connection.transaction():
                connection.execute(
                    """
                    UPDATE execution_records
                    SET receipt_status = 'FAILED_RETRYABLE', updated_at = GREATEST(updated_at, %s)
                    WHERE execution_id = %s AND receipt_status <> 'SIGNED'
                    """,
                    (timestamp, execution_id),
                )
        except Exception:
            pass
