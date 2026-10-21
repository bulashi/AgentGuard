from __future__ import annotations

import re
from typing import Any

from psycopg.errors import UniqueViolation

from backend.business_action.contracts import (
    CreateBusinessCaseRequest,
    EvaluateRefundFactsRequest,
    ResolveNotificationActionRequest,
    ResolveRefundActionRequest,
)
from backend.business_action.eligibility import (
    BusinessEligibilityReason,
    EligibilityError,
    check_unprocessed_business,
    load_verified_refund_business,
)
from backend.business_action.facts import (
    BusinessFactsError,
    create_business_case,
    evaluate_case_for_task,
)
from backend.business_action.policy import (
    APPROVED_REFUND_SLOTS,
    NOTIFICATION_SERVICE,
    NOTIFICATION_TOOL,
    PRIMARY_REFUND_SLOT,
    REFUND_SERVICE,
    REFUND_SUCCESS_NOTIFICATION_SLOT,
    REFUND_TOOL,
    TrustedTaskContext,
    notification_scope,
    refund_scope,
)
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.state.database import connect

IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class BusinessActionError(RuntimeError):
    def __init__(
        self,
        reason_code: ReasonCode | BusinessEligibilityReason,
        message: str,
        *,
        status_code: int = 403,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


class BusinessActionRegistryService:
    def __init__(self, database_url: str, schema_store: SchemaStore | None = None) -> None:
        self.database_url = database_url
        self.schemas = schema_store or SchemaStore()

    def create_business_case(
        self, request: CreateBusinessCaseRequest, *, current_time: int,
    ) -> dict[str, Any]:
        try:
            with connect(self.database_url) as connection, connection.transaction():
                return create_business_case(connection, request, current_time=current_time)
        except (UniqueViolation, BusinessFactsError) as exc:
            raise BusinessActionError(
                ReasonCode.BUSINESS_ACTION_CONFLICT,
                "工单编号, 订单或支付编号已被使用; 同一租户不能换工单重复提交同一交易.",
                status_code=409,
            ) from exc

    def evaluate_refund_facts(
        self, request: EvaluateRefundFactsRequest, *, current_time: int,
    ) -> dict[str, Any]:
        with connect(self.database_url) as connection, connection.transaction():
            context = self._load_task(connection, request.task_id, current_time=current_time)
            try:
                result = evaluate_case_for_task(connection, context, current_time=current_time)
            except BusinessFactsError as exc:
                raise BusinessActionError(
                    BusinessEligibilityReason.BUSINESS_ELIGIBILITY_INVALID,
                    str(exc), status_code=409,
                ) from exc
            if result is None:
                raise BusinessActionError(
                    BusinessEligibilityReason.BUSINESS_ELIGIBILITY_INVALID,
                    "该工单使用已有核验记录, 不属于原始事实核验模式.", status_code=409,
                )
            # REJECTED/PENDING are saved outcomes, not exceptions that roll back the evidence.
            return result

    def resolve_refund(
        self, request: ResolveRefundActionRequest, *, current_time: int
    ) -> dict[str, Any]:
        return self.resolve_refund_for_trusted_slot(
            request.task_id,
            trusted_action_slot=PRIMARY_REFUND_SLOT,
            current_time=current_time,
        )

    def resolve_refund_for_trusted_slot(
        self,
        task_id: str,
        *,
        trusted_action_slot: str,
        current_time: int,
    ) -> dict[str, Any]:
        if not IDENTIFIER_RE.fullmatch(trusted_action_slot):
            raise BusinessActionError(
                ReasonCode.BUSINESS_ACTION_INVALID,
                "trusted action slot is not a valid server-controlled identifier",
            )
        if trusted_action_slot not in APPROVED_REFUND_SLOTS:
            raise BusinessActionError(
                ReasonCode.BUSINESS_ACTION_INVALID,
                "trusted action slot is not approved by the fixed refund policy",
            )
        # Commit the first fact evaluation before action resolution can reject the request.
        # Legacy fixtures have no raw facts and retain the existing verification path.
        with connect(self.database_url) as connection, connection.transaction():
            context = self._load_task(connection, task_id, current_time=current_time)
            try:
                evaluate_case_for_task(connection, context, current_time=current_time)
            except BusinessFactsError as exc:
                raise BusinessActionError(
                    BusinessEligibilityReason.BUSINESS_ELIGIBILITY_INVALID,
                    str(exc), status_code=409,
                ) from exc
        with connect(self.database_url) as connection, connection.transaction():
            context = self._load_task(connection, task_id, current_time=current_time)
            try:
                business = load_verified_refund_business(
                    connection,
                    context,
                    trusted_action_slot=trusted_action_slot,
                )
                check_unprocessed_business(connection, context, business, allow_same_task=True)
            except EligibilityError as exc:
                raise BusinessActionError(exc.reason_code, str(exc), status_code=409) from exc
            scope_key, _ = refund_scope(context, trusted_action_slot=trusted_action_slot)
            return self._resolve(
                connection,
                context=context,
                action_scope_key=scope_key,
                trusted_action_slot=trusted_action_slot,
                tool_service=REFUND_SERVICE,
                tool_name=REFUND_TOOL,
                current_time=current_time,
            )

    def resolve_notification(
        self, request: ResolveNotificationActionRequest, *, current_time: int
    ) -> dict[str, Any]:
        with connect(self.database_url) as connection, connection.transaction():
            context = self._load_task(connection, request.task_id, current_time=current_time)
            refund = connection.execute(
                """
                SELECT tenant_id, task_id, ticket_id, customer_id, status
                FROM refunds WHERE refund_id = %s FOR SHARE
                """,
                (request.related_business_effect_id,),
            ).fetchone()
            if refund is None or tuple(str(value) for value in refund) != (
                context.tenant_id,
                context.task_id,
                context.ticket_id,
                context.customer_id,
                "COMMITTED",
            ):
                raise BusinessActionError(
                    ReasonCode.BUSINESS_ACTION_INVALID,
                    "notification requires the task's matching committed refund",
                )
            scope_key, _ = notification_scope(
                context,
                template_id=request.template_id,
                related_business_effect_id=request.related_business_effect_id,
            )
            return self._resolve(
                connection,
                context=context,
                action_scope_key=scope_key,
                trusted_action_slot=REFUND_SUCCESS_NOTIFICATION_SLOT,
                tool_service=NOTIFICATION_SERVICE,
                tool_name=NOTIFICATION_TOOL,
                current_time=current_time,
            )

    @staticmethod
    def _load_task(connection: Any, task_id: str, *, current_time: int) -> TrustedTaskContext:
        row = connection.execute(
            """
            SELECT tenant_id, task_id, ticket_id, customer_id, status, expires_at
            FROM tasks WHERE task_id = %s FOR SHARE
            """,
            (task_id,),
        ).fetchone()
        if row is None:
            raise BusinessActionError(ReasonCode.BUSINESS_ACTION_INVALID, "task does not exist")
        if str(row[4]) != "AUTHORIZED":
            raise BusinessActionError(ReasonCode.BUSINESS_ACTION_INVALID, "task is not authorized")
        if current_time > int(row[5]):
            raise BusinessActionError(
                ReasonCode.CREDENTIAL_EXPIRED, "task expired before action resolution"
            )
        return TrustedTaskContext(
            tenant_id=str(row[0]),
            task_id=str(row[1]),
            ticket_id=str(row[2]),
            customer_id=str(row[3]),
        )

    def _resolve(
        self,
        connection: Any,
        *,
        context: TrustedTaskContext,
        action_scope_key: str,
        trusted_action_slot: str,
        tool_service: str,
        tool_name: str,
        current_time: int,
    ) -> dict[str, Any]:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (action_scope_key,),
        )
        existing = connection.execute(
            """
            SELECT business_action_id, action_scope_key, tenant_id, task_id,
                   tool_service, tool_name, trusted_action_slot, created_at, status
            FROM business_actions WHERE action_scope_key = %s FOR SHARE
            """,
            (action_scope_key,),
        ).fetchone()
        expected = {
            "action_scope_key": action_scope_key,
            "tenant_id": context.tenant_id,
            "task_id": context.task_id,
            "tool_service": tool_service,
            "tool_name": tool_name,
            "trusted_action_slot": trusted_action_slot,
        }
        if existing is not None:
            action = self._row_to_action(existing)
            if any(action[key] != value for key, value in expected.items()):
                raise BusinessActionError(
                    ReasonCode.BUSINESS_ACTION_CONFLICT,
                    "stored business action conflicts with the trusted scope",
                    status_code=409,
                )
            self.schemas.validate("business-action.schema.json", action)
            return action

        action = {
            "schema_version": "1.0",
            "business_action_id": new_id("ACTION"),
            **expected,
            "created_at": current_time,
            "status": "ACTIVE",
        }
        self.schemas.validate("business-action.schema.json", action)
        connection.execute(
            """
            INSERT INTO business_actions (
                business_action_id, action_scope_key, trusted_action_slot,
                tenant_id, task_id, tool_service, tool_name, status,
                created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'ACTIVE', %s, %s)
            """,
            (
                action["business_action_id"],
                action_scope_key,
                trusted_action_slot,
                context.tenant_id,
                context.task_id,
                tool_service,
                tool_name,
                current_time,
                current_time,
            ),
        )
        return action

    @staticmethod
    def _row_to_action(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "business_action_id": str(row[0]),
            "action_scope_key": str(row[1]),
            "tenant_id": str(row[2]),
            "task_id": str(row[3]),
            "tool_service": str(row[4]),
            "tool_name": str(row[5]),
            "trusted_action_slot": str(row[6]),
            "created_at": int(row[7]),
            "status": str(row[8]),
        }
