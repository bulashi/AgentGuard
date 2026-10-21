from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, ClassVar

import httpx
from psycopg.types.json import Jsonb

from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.internal_auth import InternalAuthenticator, InternalAuthError
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.state.database import connect
from backend.tools.contracts import ReconcileRequest, ReconcileResponse


@dataclass(frozen=True)
class RecoveryResult:
    body: dict[str, Any]
    status_code: int = 200


class RecoveryService:
    """Recover an existing execution without creating authorization or dispatching again."""

    _SIDE_EFFECT_TO_KIND: ClassVar[dict[tuple[str, str], str]] = {
        ("refund-service", "refund.create"): "refund",
        ("notification-service", "notification.send_template"): "notification",
    }

    def __init__(
        self,
        database_url: str,
        *,
        internal_auth: InternalAuthenticator,
        tool_urls: Mapping[tuple[str, str], str],
        max_attempts: int = 3,
        deadline_seconds: int = 300,
        stale_execution_seconds: int = 30,
        request_timeout_seconds: float = 10.0,
        receipt_url: str = "",
        receipt_timeout_seconds: float = 10.0,
    ) -> None:
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        if stale_execution_seconds <= 0:
            raise ValueError("stale_execution_seconds must be positive")
        self.database_url = database_url
        self.internal_auth = internal_auth
        self.tool_urls = dict(tool_urls)
        self.max_attempts = max_attempts
        self.deadline_seconds = deadline_seconds
        self.stale_execution_seconds = stale_execution_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.receipt_url = receipt_url.rstrip("/")
        self.receipt_timeout_seconds = receipt_timeout_seconds

    def recover_once(
        self, *, execution_id: str | None = None, current_time: int | None = None
    ) -> RecoveryResult | None:
        # Row locks end before the tool query. Keep one session-level claim across
        # that query so concurrent scans cannot spend this execution's attempts.
        with self._execution_claim(execution_id) as claimed_id:
            if claimed_id is None:
                return None
            return self._recover_claimed(claimed_id, current_time=current_time)

    @contextmanager
    def _execution_claim(self, execution_id: str | None) -> Iterator[str | None]:
        with connect(self.database_url) as connection:
            if execution_id is None:
                candidate = self._load_execution(connection, None, lock=False)
                if candidate is None:
                    yield None
                    return
                execution_id = str(candidate["execution_id"])
            key_bytes = bytes.fromhex(sm3_hex(
                ("AGENTGUARD|RECOVERY_CLAIM|V1|" + execution_id).encode("utf-8")
            ))[:8]
            lock_key = int.from_bytes(key_bytes, "big", signed=True)
            acquired = connection.execute(
                "SELECT pg_try_advisory_lock(%s)", (lock_key,),
            ).fetchone()
            connection.commit()
            if acquired is None or acquired[0] is not True:
                yield None
                return
            try:
                yield execution_id
            finally:
                # PostgreSQL also releases this lock if the owning session exits.
                if not connection.closed:
                    connection.execute("SELECT pg_advisory_unlock(%s)", (lock_key,))

    def _recover_claimed(
        self, execution_id: str, *, current_time: int | None = None,
    ) -> RecoveryResult | None:
        timestamp = now_unix() if current_time is None else current_time
        prepared = self._prepare_execution(execution_id=execution_id, current_time=timestamp)
        if prepared is None:
            return None
        action = prepared.get("action")
        if action == "RELEASE_ADMITTED":
            decision = self._load_decision(prepared["execution_id"])
            return RecoveryResult(self._with_receipt(decision, timestamp))
        if action in {"FINAL", "RECEIPT_ONLY"}:
            decision = self._load_decision(prepared["execution_id"])
            return RecoveryResult(self._with_receipt(decision, timestamp))

        reconcile = self._query_tool(prepared)
        decision = self._settle_reconciliation(
            prepared,
            reconcile,
            current_time=timestamp,
        )
        return RecoveryResult(self._with_receipt(decision, timestamp))

    def _with_receipt(self, body: dict[str, Any], current_time: int) -> dict[str, Any]:
        del current_time
        if not self.receipt_url or body.get("state") not in {"DENIED", "COMMITTED", "RELEASED"}:
            return body
        try:
            request_body = canonicalize({"execution_id": body["execution_id"]})
            headers = self.internal_auth.request_headers(
                recipient="receipt-service", method="POST", path="/internal/receipts/issue",
                body=request_body,
            )
            with httpx.Client(timeout=self.receipt_timeout_seconds, trust_env=False) as client:
                response = client.post(
                    f"{self.receipt_url}/internal/receipts/issue",
                    headers=headers,
                    content=request_body,
                )
            if response.status_code == 200:
                value = response.json()
                if isinstance(value, dict) and isinstance(value.get("receipt"), dict):
                    body = dict(body)
                    body["receipt"] = value["receipt"]
        except (httpx.HTTPError, ValueError, InternalAuthError):
            pass
        return body

    def scan_once(self, *, current_time: int | None = None) -> list[RecoveryResult]:
        timestamp = now_unix() if current_time is None else current_time
        with connect(self.database_url) as connection:
            rows = connection.execute(
                """
                SELECT e.execution_id
                FROM execution_records e
                LEFT JOIN execution_recovery_records r ON r.execution_id = e.execution_id
                WHERE (
                    e.state IN ('UNKNOWN', 'RECONCILING')
                    OR (e.state = 'ADMITTED' AND e.updated_at <= %s)
                    OR (e.state = 'DISPATCHED' AND e.updated_at <= %s)
                    OR (
                        %s AND e.state IN ('DENIED', 'COMMITTED', 'RELEASED')
                        AND e.receipt_status IN ('NOT_REQUIRED', 'PENDING', 'FAILED_RETRYABLE')
                        AND e.terminal_at IS NOT NULL AND e.terminal_state = e.state
                        AND e.decision_at IS NOT NULL AND e.decision_value = e.decision
                    )
                )
                AND (r.manual_review_required IS NULL OR r.manual_review_required = FALSE)
                ORDER BY CASE WHEN e.state IN ('DENIED', 'COMMITTED', 'RELEASED')
                              THEN 1 ELSE 0 END,
                         e.updated_at, e.execution_id
                LIMIT 100
                """,
                (
                    timestamp - self.stale_execution_seconds,
                    timestamp - self.stale_execution_seconds,
                    bool(self.receipt_url),
                ),
            ).fetchall()
        results: list[RecoveryResult] = []
        for row in rows:
            recovered = self.recover_once(execution_id=str(row[0]), current_time=timestamp)
            if recovered is not None:
                results.append(recovered)
        return results

    def _prepare_execution(
        self, *, execution_id: str | None, current_time: int
    ) -> dict[str, Any] | None:
        with connect(self.database_url) as connection, connection.transaction():
            row = self._load_execution(connection, execution_id, lock=True)
            if row is None:
                return None
            state = str(row["state"])
            if state in {"DENIED", "COMMITTED", "RELEASED", "RECOVERY_FAILED_FINAL"}:
                if (
                    self.receipt_url
                    and state != "RECOVERY_FAILED_FINAL"
                    and row.get("receipt_status") in {"NOT_REQUIRED", "PENDING", "FAILED_RETRYABLE"}
                    and row.get("terminal_at") is not None
                    and row.get("terminal_state") == state
                    and row.get("decision_at") is not None
                    and row.get("decision_value") == row.get("decision")
                ):
                    return {"action": "RECEIPT_ONLY", "execution_id": row["execution_id"]}
                return None

            recovery = connection.execute(
                """
                SELECT recovery_attempt_count, max_recovery_attempts, recovery_deadline,
                       manual_review_required
                FROM execution_recovery_records
                WHERE execution_id = %s
                FOR UPDATE
                """,
                (row["execution_id"],),
            ).fetchone()
            if recovery is None:
                deadline = current_time + self.deadline_seconds
                connection.execute(
                    """
                    INSERT INTO execution_recovery_records (
                        execution_id, recovery_attempt_count, max_recovery_attempts,
                        recovery_deadline, created_at, updated_at
                    )
                    VALUES (%s, 0, %s, %s, %s, %s)
                    """,
                    (
                        row["execution_id"],
                        self.max_attempts,
                        deadline,
                        current_time,
                        current_time,
                    ),
                )
                recovery = (0, self.max_attempts, deadline, False)

            attempt_count, max_attempts, deadline, manual_review = (
                int(recovery[0]),
                int(recovery[1]),
                int(recovery[2]),
                bool(recovery[3]),
            )
            if manual_review:
                return {"action": "FINAL", "execution_id": row["execution_id"]}

            if state == "ADMITTED" and int(row["updated_at"]) <= (
                current_time - self.stale_execution_seconds
            ):
                self._release_execution(
                    connection,
                    row,
                    current_time=current_time,
                    reason_code=ReasonCode.ALLOWED.value,
                )
                return {"action": "RELEASE_ADMITTED", "execution_id": row["execution_id"]}

            if state == "DISPATCHED" and int(row["updated_at"]) <= (
                current_time - self.stale_execution_seconds
            ):
                connection.execute(
                    """
                    UPDATE execution_records
                    SET state = 'UNKNOWN', updated_at = %s, reason_code = %s
                    WHERE execution_id = %s AND state = 'DISPATCHED'
                    """,
                    (current_time, ReasonCode.TOOL_EXECUTION_UNKNOWN.value, row["execution_id"]),
                )
                connection.execute(
                    """
                    UPDATE idempotency_records
                    SET status = 'UNKNOWN', updated_at = %s
                    WHERE execution_id = %s AND status = 'DISPATCHED'
                    """,
                    (current_time, row["execution_id"]),
                )
                state = "UNKNOWN"

            if state not in {"UNKNOWN", "RECONCILING"}:
                return None
            if attempt_count >= max_attempts or current_time > deadline:
                self._mark_final(
                    connection,
                    row["execution_id"],
                    current_time=current_time,
                    reason="RECOVERY_LIMIT_REACHED",
                )
                return {"action": "FINAL", "execution_id": row["execution_id"]}

            next_attempt = attempt_count + 1
            connection.execute(
                """
                UPDATE execution_recovery_records
                SET recovery_attempt_count = %s, last_attempt_at = %s,
                    last_error = NULL, updated_at = %s
                WHERE execution_id = %s
                """,
                (next_attempt, current_time, current_time, row["execution_id"]),
            )
            connection.execute(
                """
                UPDATE execution_records
                SET state = 'RECONCILING', reason_code = %s, updated_at = %s
                WHERE execution_id = %s AND state IN ('UNKNOWN', 'RECONCILING')
                """,
                (ReasonCode.TOOL_EXECUTION_UNKNOWN.value, current_time, row["execution_id"]),
            )
            if row["business_idempotency_key"] is not None:
                connection.execute(
                    """
                    UPDATE idempotency_records
                    SET status = 'RECONCILING', updated_at = %s
                    WHERE execution_id = %s AND status IN ('UNKNOWN', 'RECONCILING')
                    """,
                    (current_time, row["execution_id"]),
                )
            row["recovery_attempt_count"] = next_attempt
            row["max_recovery_attempts"] = max_attempts
            row["recovery_deadline"] = deadline
            return row

    @staticmethod
    def _load_execution(
        connection, execution_id: str | None, *, lock: bool
    ) -> dict[str, Any] | None:
        query = """
            SELECT e.execution_id, e.request_hash, e.credential_chain_hash, e.tenant_id,
                   e.task_id, e.tool_service, e.tool_name, e.tool_version, e.parameter_hash,
                   e.state, e.decision, e.reason_code, e.business_action_id, e.result,
                   e.business_effect_id, e.business_result_hash, e.updated_at,
                   i.business_idempotency_key, e.receipt_status::text,
                   e.terminal_at, e.terminal_state::text,
                   e.decision_at, e.decision_value::text
            FROM execution_records e
            LEFT JOIN idempotency_records i ON i.execution_id = e.execution_id
        """
        if execution_id is None:
            query += " WHERE e.state IN ('UNKNOWN', 'RECONCILING') ORDER BY e.updated_at LIMIT 1"
            params: tuple[Any, ...] = ()
        else:
            query += " WHERE e.execution_id = %s"
            params = (execution_id,)
        if lock:
            query += " FOR UPDATE OF e"
        row = connection.execute(query, params).fetchone()
        if row is None:
            return None
        fields = [
            "execution_id",
            "request_hash",
            "credential_chain_hash",
            "tenant_id",
            "task_id",
            "tool_service",
            "tool_name",
            "tool_version",
            "parameter_hash",
            "state",
            "decision",
            "reason_code",
            "business_action_id",
            "result",
            "business_effect_id",
            "business_result_hash",
            "updated_at",
            "business_idempotency_key",
            "receipt_status",
            "terminal_at",
            "terminal_state",
            "decision_at",
            "decision_value",
        ]
        return dict(zip(fields, row, strict=True))

    def _query_tool(self, row: dict[str, Any]) -> ReconcileResponse:
        kind = self._SIDE_EFFECT_TO_KIND.get((str(row["tool_service"]), str(row["tool_name"])))
        base_url = self.tool_urls.get((str(row["tool_service"]), str(row["tool_name"])))
        if kind is None or base_url is None or row["business_idempotency_key"] is None:
            return ReconcileResponse(
                execution_id=str(row["execution_id"]),
                status="UNKNOWN",
                reason_code=ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
            )
        request = ReconcileRequest(
            schema_version="1.0",
            execution_id=str(row["execution_id"]),
            tenant_id=str(row["tenant_id"]),
            task_id=str(row["task_id"]),
            business_action_id=str(row["business_action_id"]),
            business_idempotency_key=str(row["business_idempotency_key"]),
            parameter_hash=str(row["parameter_hash"]),
        )
        try:
            request_body = canonicalize(request.model_dump(mode="json"))
            headers = self.internal_auth.request_headers(
                recipient=str(row["tool_service"]), method="POST", path="/internal/reconcile",
                body=request_body,
            )
            with httpx.Client(timeout=self.request_timeout_seconds, trust_env=False) as client:
                response = client.post(
                    f"{base_url.rstrip('/')}/internal/reconcile",
                    headers=headers,
                    content=request_body,
                )
            if response.status_code != 200:
                raise RuntimeError(f"reconcile returned HTTP {response.status_code}")
            parsed = ReconcileResponse.model_validate(response.json())
            if parsed.execution_id != str(row["execution_id"]):
                raise RuntimeError("reconcile response is bound to another execution")
            return parsed
        except Exception:
            return ReconcileResponse(
                execution_id=str(row["execution_id"]),
                status="UNKNOWN",
                reason_code=ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
            )

    def _settle_reconciliation(
        self,
        row: dict[str, Any],
        reconcile: ReconcileResponse,
        *,
        current_time: int,
    ) -> dict[str, Any]:
        if reconcile.execution_id != str(row["execution_id"]) or (
            reconcile.status in {"ALREADY_EXECUTED", "NOT_EXECUTED"}
            and reconcile.reason_code != ReasonCode.ALLOWED.value
        ):
            reconcile = ReconcileResponse(
                execution_id=str(row["execution_id"]),
                status="UNKNOWN",
                reason_code=ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
            )
        if reconcile.status == "ALREADY_EXECUTED":
            try:
                canonicalize(reconcile.result)
            except ValueError:
                reconcile = ReconcileResponse(
                    execution_id=str(row["execution_id"]),
                    status="UNKNOWN",
                    reason_code=ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
                )
        with connect(self.database_url) as connection, connection.transaction():
            locked = self._load_execution(connection, str(row["execution_id"]), lock=True)
            if locked is None:
                raise RuntimeError("execution disappeared during recovery")
            if str(locked["state"]) in {"COMMITTED", "RELEASED", "RECOVERY_FAILED_FINAL"}:
                return self._decision_from_row(connection, locked)
            if reconcile.status == "ALREADY_EXECUTED":
                kind = self._SIDE_EFFECT_TO_KIND.get(
                    (str(locked["tool_service"]), str(locked["tool_name"]))
                )
                effect_field = {"refund": "refund_id", "notification": "notification_id"}.get(
                    kind
                )
                expected_binding = {
                    "execution_id": str(locked["execution_id"]),
                    "tenant_id": str(locked["tenant_id"]),
                    "task_id": str(locked["task_id"]),
                    "business_action_id": locked["business_action_id"],
                    "business_idempotency_key": locked["business_idempotency_key"],
                    "parameter_hash": str(locked["parameter_hash"]),
                }
                if (
                    reconcile.parameter_hash != str(locked["parameter_hash"])
                    or not locked["business_action_id"]
                    or not locked["business_idempotency_key"]
                    or not reconcile.business_effect_id
                    or reconcile.result is None
                    or effect_field is None
                    or reconcile.result.get(effect_field) != reconcile.business_effect_id
                    or any(
                        reconcile.result.get(field) != expected
                        for field, expected in expected_binding.items()
                    )
                ):
                    self._mark_final(
                        connection,
                        str(locked["execution_id"]),
                        current_time=current_time,
                        reason=ReasonCode.IDEMPOTENCY_CONFLICT.value,
                    )
                else:
                    self._commit_execution(
                        connection,
                        locked,
                        result=reconcile.result,
                        business_effect_id=reconcile.business_effect_id,
                        current_time=current_time,
                    )
            elif reconcile.status == "NOT_EXECUTED":
                self._release_execution(
                    connection,
                    locked,
                    current_time=current_time,
                    reason_code=ReasonCode.ALLOWED.value,
                )
            elif reconcile.status == "IDEMPOTENCY_CONFLICT":
                self._mark_final(
                    connection,
                    str(locked["execution_id"]),
                    current_time=current_time,
                    reason=ReasonCode.IDEMPOTENCY_CONFLICT.value,
                )
            else:
                recovery = connection.execute(
                    """
                    SELECT recovery_attempt_count, max_recovery_attempts, recovery_deadline
                    FROM execution_recovery_records WHERE execution_id = %s FOR UPDATE
                    """,
                    (locked["execution_id"],),
                ).fetchone()
                assert recovery is not None
                if int(recovery[0]) >= int(recovery[1]) or current_time > int(recovery[2]):
                    self._mark_final(
                        connection,
                        str(locked["execution_id"]),
                        current_time=current_time,
                        reason="RECOVERY_LIMIT_REACHED",
                    )
                else:
                    connection.execute(
                        """
                        UPDATE execution_records
                        SET state = 'RECONCILING', reason_code = %s, updated_at = %s
                        WHERE execution_id = %s AND state = 'RECONCILING'
                        """,
                        (
                            ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
                            current_time,
                            locked["execution_id"],
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE execution_recovery_records
                        SET last_error = %s, updated_at = %s
                        WHERE execution_id = %s
                        """,
                        (reconcile.reason_code, current_time, locked["execution_id"]),
                    )
            final = self._load_execution(connection, str(row["execution_id"]), lock=False)
            assert final is not None
            return self._decision_from_row(connection, final)

    @staticmethod
    def _commit_execution(
        connection,
        row: dict[str, Any],
        *,
        result: dict[str, Any] | None,
        business_effect_id: str | None,
        current_time: int,
    ) -> None:
        result_hash = sm3_hex(canonicalize(result)) if result is not None else None
        reservations = connection.execute(
            """
            SELECT credential_id, quota_type, amount
            FROM execution_budget_reservations
            WHERE execution_id = %s AND status = 'RESERVED'
            ORDER BY credential_id, quota_type FOR UPDATE
            """,
            (row["execution_id"],),
        ).fetchall()
        for credential_id, quota_type, amount in reservations:
            updated = connection.execute(
                """
                UPDATE credential_budget_state
                SET reserved_value = reserved_value - %s,
                    committed_value = committed_value + %s,
                    version = version + 1, updated_at = %s
                WHERE credential_id = %s AND quota_type = %s AND reserved_value >= %s
                RETURNING credential_id
                """,
                (amount, amount, current_time, credential_id, quota_type, amount),
            ).fetchone()
            if updated is None:
                raise RuntimeError("budget reservation cannot be committed safely")
            connection.execute(
                """
                UPDATE execution_budget_reservations
                SET status = 'COMMITTED', updated_at = %s
                WHERE execution_id = %s AND credential_id = %s AND quota_type = %s
                """,
                (current_time, row["execution_id"], credential_id, quota_type),
            )
        connection.execute(
            """
            UPDATE execution_records
            SET state = 'COMMITTED', result = %s, business_effect_id = %s,
                business_result_hash = %s, reason_code = %s, updated_at = %s
            WHERE execution_id = %s AND state IN ('UNKNOWN', 'RECONCILING')
            """,
            (
                None if result is None else Jsonb(result),
                business_effect_id,
                result_hash,
                ReasonCode.ALLOWED.value,
                current_time,
                row["execution_id"],
            ),
        )
        if row["business_idempotency_key"] is not None:
            connection.execute(
                """
                UPDATE idempotency_records
                SET status = 'COMMITTED', result = %s, business_effect_id = %s, updated_at = %s
                WHERE execution_id = %s
                """,
                (
                    None if result is None else Jsonb(result),
                    business_effect_id,
                    current_time,
                    row["execution_id"],
                ),
            )
        if row["business_action_id"] is not None:
            connection.execute(
                """
                UPDATE business_actions SET status = 'COMMITTED', updated_at = %s
                WHERE business_action_id = %s AND status = 'ACTIVE'
                """,
                (current_time, row["business_action_id"]),
            )
        connection.execute(
            """
            UPDATE execution_recovery_records
            SET last_error = NULL, manual_review_required = FALSE, updated_at = %s
            WHERE execution_id = %s
            """,
            (current_time, row["execution_id"]),
        )

    @staticmethod
    def _release_execution(
        connection,
        row: dict[str, Any],
        *,
        current_time: int,
        reason_code: str,
    ) -> None:
        reservations = connection.execute(
            """
            SELECT credential_id, quota_type, amount
            FROM execution_budget_reservations
            WHERE execution_id = %s AND status = 'RESERVED'
            ORDER BY credential_id, quota_type FOR UPDATE
            """,
            (row["execution_id"],),
        ).fetchall()
        for credential_id, quota_type, amount in reservations:
            updated = connection.execute(
                """
                UPDATE credential_budget_state
                SET reserved_value = reserved_value - %s, version = version + 1, updated_at = %s
                WHERE credential_id = %s AND quota_type = %s AND reserved_value >= %s
                RETURNING credential_id
                """,
                (amount, current_time, credential_id, quota_type, amount),
            ).fetchone()
            if updated is None:
                raise RuntimeError("budget reservation cannot be released safely")
            connection.execute(
                """
                UPDATE execution_budget_reservations
                SET status = 'RELEASED', updated_at = %s
                WHERE execution_id = %s AND credential_id = %s AND quota_type = %s
                """,
                (current_time, row["execution_id"], credential_id, quota_type),
            )
        connection.execute(
            """
            UPDATE execution_records
            SET state = 'RELEASED', reason_code = %s, updated_at = %s
            WHERE execution_id = %s AND state IN ('ADMITTED', 'UNKNOWN', 'RECONCILING')
            """,
            (reason_code, current_time, row["execution_id"]),
        )
        if row["business_idempotency_key"] is not None:
            connection.execute(
                """
                UPDATE idempotency_records SET status = 'RELEASED', updated_at = %s
                WHERE execution_id = %s AND status IN ('ADMITTED', 'UNKNOWN', 'RECONCILING')
                """,
                (current_time, row["execution_id"]),
            )
        if row["business_action_id"] is not None:
            connection.execute(
                """
                UPDATE business_actions SET status = 'RELEASED', updated_at = %s
                WHERE business_action_id = %s AND status = 'ACTIVE'
                """,
                (current_time, row["business_action_id"]),
            )
        connection.execute(
            """
            UPDATE execution_recovery_records
            SET last_error = NULL, manual_review_required = FALSE, updated_at = %s
            WHERE execution_id = %s
            """,
            (current_time, row["execution_id"]),
        )

    def _mark_final(self, connection, execution_id: str, *, current_time: int, reason: str) -> None:
        changed = connection.execute(
            """
            UPDATE execution_records
            SET state = 'RECOVERY_FAILED_FINAL', reason_code = %s, updated_at = %s
            WHERE execution_id = %s AND state IN ('UNKNOWN', 'RECONCILING', 'DISPATCHED')
            """,
            (
                ReasonCode.IDEMPOTENCY_CONFLICT.value
                if reason == ReasonCode.IDEMPOTENCY_CONFLICT.value
                else ReasonCode.TOOL_EXECUTION_UNKNOWN.value,
                current_time,
                execution_id,
            ),
        )
        connection.execute(
            """
            UPDATE idempotency_records SET status = 'RECONCILING', updated_at = %s
            WHERE execution_id = %s AND status IN ('UNKNOWN', 'RECONCILING', 'DISPATCHED')
            """,
            (current_time, execution_id),
        )
        connection.execute(
            """
            UPDATE execution_recovery_records
            SET manual_review_required = TRUE, final_failure_reason = %s,
                last_error = %s, updated_at = %s
            WHERE execution_id = %s
            """,
            (reason, reason, current_time, execution_id),
        )
        if changed.rowcount:
            payload = {
                "schema_version": "1.0",
                "priority": "HIGH",
                "event": "MANUAL_REVIEW_REQUIRED",
                "execution_id": execution_id,
                "final_failure_reason": reason,
            }
            payload_hash = sm3_hex(canonicalize(payload))
            connection.execute(
                """
                INSERT INTO audit_outbox (
                    outbox_event_id, execution_id, event_type, evidence_reference,
                    payload_hash, payload, status, created_at
                )
                VALUES (%s, %s, 'RECOVERY_FAILED_FINAL', %s, %s, %s, 'PENDING', %s)
                """,
                (
                    new_id("OUTBOX"),
                    execution_id,
                    f"MANUAL_REVIEW:{execution_id}",
                    payload_hash,
                    Jsonb(payload),
                    current_time,
                ),
            )

    def _load_decision(self, execution_id: str) -> dict[str, Any]:
        with connect(self.database_url) as connection:
            row = self._load_execution(connection, execution_id, lock=False)
            if row is None:
                raise RuntimeError("execution does not exist")
            return self._decision_from_row(connection, row)

    @staticmethod
    def _decision_from_row(connection, row: dict[str, Any]) -> dict[str, Any]:
        recovery = connection.execute(
            """
            SELECT recovery_attempt_count, max_recovery_attempts, recovery_deadline,
                   manual_review_required
            FROM execution_recovery_records WHERE execution_id = %s
            """,
            (row["execution_id"],),
        ).fetchone()
        if recovery is None:
            recovery = (0, 1, 0, False)
        return {
            "execution_id": str(row["execution_id"]),
            "state": str(row["state"]),
            "decision": str(row["decision"] or "ALLOW"),
            "reason_code": str(row["reason_code"] or ReasonCode.ALLOWED.value),
            "request_hash": str(row["request_hash"]),
            "credential_chain_hash": str(row["credential_chain_hash"]),
            "admission_outcome": "EXISTING_EXECUTION",
            "recovery_attempt_count": int(recovery[0]),
            "max_recovery_attempts": int(recovery[1]),
            "recovery_deadline": int(recovery[2]),
            "manual_review_required": bool(recovery[3]),
            "result": row["result"],
            "business_effect_id": row["business_effect_id"],
            "receipt": None,
        }
