from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import backend.business_action.service as registry_module
from backend.business_action.contracts import ResolveNotificationActionRequest
from backend.business_action.policy import (
    REFUND_SUCCESS_NOTIFICATION_SLOT,
    TrustedTaskContext,
    notification_scope,
)
from backend.business_action.service import BusinessActionError, BusinessActionRegistryService
from backend.common.error_codes import ReasonCode
from backend.common.time import now_unix
from backend.gateway.service import GatewayError, SecureGatewayService
from backend.tests.business_fixtures import memory_refund_store
from backend.tests.unit.test_tools import client, signed_envelope

CONTEXT = TrustedTaskContext("tenant-A", "TASK-001", "T10086", "C9527")
REFUND = {
    "refund_id": "REFUND-001",
    "tenant_id": CONTEXT.tenant_id,
    "task_id": CONTEXT.task_id,
    "ticket_id": CONTEXT.ticket_id,
    "customer_id": CONTEXT.customer_id,
    "amount_fen": 7000,
    "status": "COMMITTED",
}
PARAMETERS = {
    "customer_id": CONTEXT.customer_id,
    "template_id": "REFUND_SUCCESS",
    "related_business_effect_id": REFUND["refund_id"],
}


def _action(refund_id="REFUND-001"):
    scope, _ = notification_scope(
        CONTEXT, template_id="REFUND_SUCCESS", related_business_effect_id=refund_id
    )
    return {
        "tenant_id": CONTEXT.tenant_id,
        "task_id": CONTEXT.task_id,
        "tool_service": "notification-service",
        "tool_name": "notification.send_template",
        "trusted_action_slot": REFUND_SUCCESS_NOTIFICATION_SLOT,
        "action_scope_key": scope,
        "status": "ACTIVE",
    }


class NotificationRows:
    """Small read-only DB double; mutation behavior is covered by PostgreSQL tests."""

    def __init__(self, *, refund=None, action=None):
        self.refund = refund
        self.action = action
        self.statements = []

    def execute(self, query, parameters=()):
        sql = " ".join(query.split())
        self.statements.append((sql, parameters))
        if "FROM tasks" in sql:
            row = (
                CONTEXT.tenant_id,
                CONTEXT.task_id,
                CONTEXT.ticket_id,
                CONTEXT.customer_id,
                "AUTHORIZED",
                now_unix() + 60,
            )
        elif "FROM refunds" in sql:
            fields = ("tenant_id", "task_id", "ticket_id", "customer_id", "status")
            row = None if self.refund is None else tuple(self.refund[field] for field in fields)
        elif "SELECT action_scope_key, trusted_action_slot" in sql:
            row = (
                None
                if self.action is None
                else (self.action["action_scope_key"], self.action["trusted_action_slot"])
            )
        elif "FROM business_actions" in sql:
            fields = ("tenant_id", "task_id", "tool_service", "tool_name", "status")
            row = None if self.action is None else tuple(self.action[field] for field in fields)
        else:
            raise AssertionError(f"unexpected notification SQL: {sql}")
        return SimpleNamespace(fetchone=lambda: row)

    @contextmanager
    def transaction(self):
        yield self


@pytest.mark.parametrize(
    "change",
    [
        None,
        {"tenant_id": "tenant-B"},
        {"task_id": "TASK-other"},
        {"ticket_id": "T-other"},
        {"customer_id": "C-other"},
        {"status": "UNKNOWN"},
    ],
)
def test_registry_rejects_unbound_refund_before_creating_action(monkeypatch, change):
    refund = None if change is None else {**REFUND, **change}
    rows = NotificationRows(refund=refund)

    @contextmanager
    def database(_url):
        yield rows

    monkeypatch.setattr(registry_module, "connect", database)
    service = BusinessActionRegistryService("unit-only-notification")
    resolve = Mock()
    monkeypatch.setattr(service, "_resolve", resolve)
    with pytest.raises(BusinessActionError) as captured:
        service.resolve_notification(
            ResolveNotificationActionRequest(
                task_id=CONTEXT.task_id,
                template_id="REFUND_SUCCESS",
                related_business_effect_id=REFUND["refund_id"],
            ),
            current_time=now_unix(),
        )
    assert captured.value.reason_code is ReasonCode.BUSINESS_ACTION_INVALID
    resolve.assert_not_called()


def test_gateway_rejects_action_scope_for_a_different_actual_refund():
    rows = NotificationRows(refund=REFUND, action=_action("REFUND-other"))
    request = SimpleNamespace(
        tool_service="notification-service",
        tool_name="notification.send_template",
        business_action_id="ACTION-NOTIFY",
        canonical_parameters=PARAMETERS,
    )
    with pytest.raises(GatewayError) as captured:
        SecureGatewayService._verify_business_action(rows, request, CONTEXT, lock=True)
    assert captured.value.reason_code is ReasonCode.BUSINESS_ACTION_CONFLICT
    assert not any("FROM refunds" in sql for sql, _ in rows.statements)


@pytest.mark.parametrize(
    "change",
    [
        None,
        {"tenant_id": "tenant-B"},
        {"task_id": "TASK-other"},
        {"ticket_id": "T-other"},
        {"customer_id": "C-other"},
        {"status": "UNKNOWN"},
    ],
)
def test_gateway_requires_matching_committed_refund(change):
    refund = None if change is None else {**REFUND, **change}
    rows = NotificationRows(refund=refund, action=_action())
    request = SimpleNamespace(
        tool_service="notification-service",
        tool_name="notification.send_template",
        business_action_id="ACTION-NOTIFY",
        canonical_parameters=PARAMETERS,
    )
    with pytest.raises(GatewayError) as captured:
        SecureGatewayService._verify_business_action(rows, request, CONTEXT, lock=True)
    assert captured.value.reason_code is ReasonCode.BUSINESS_ACTION_INVALID


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"tenant_id": "tenant-B"}, "BUSINESS_ACTION_INVALID"),
        ({"task_id": "TASK-other"}, "BUSINESS_ACTION_INVALID"),
        ({"tool_service": "refund-service"}, "BUSINESS_ACTION_INVALID"),
        ({"tool_name": "refund.create"}, "BUSINESS_ACTION_INVALID"),
        ({"status": "RELEASED"}, "BUSINESS_ACTION_INVALID"),
        ({"trusted_action_slot": "untrusted"}, "BUSINESS_ACTION_CONFLICT"),
        (
            {"action_scope_key": _action("REFUND-other")["action_scope_key"]},
            "BUSINESS_ACTION_CONFLICT",
        ),
    ],
)
def test_signed_tool_envelope_cannot_use_unbound_notification_action(change, reason):
    store = memory_refund_store()
    store.refunds["b" * 64] = deepcopy(REFUND)
    store.business_actions["ACTION-NOTIFY"] = {**_action(), **change}
    response = client("notification", store).post(
        "/internal/execute",
        json=signed_envelope(
            kind="notification",
            attempt="ATTEMPT-SCOPE",
            parameters=PARAMETERS,
            business_action_id="ACTION-NOTIFY",
            idempotency_key="e" * 64,
        ),
    )
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == reason
    assert not store.notifications


def test_distinct_committed_refunds_keep_separate_notifications_and_retry_is_idempotent():
    store = memory_refund_store()
    api = client("notification", store)
    notices = []
    for number in (1, 2):
        refund_id = f"REFUND-00{number}"
        action_id = f"ACTION-NOTIFY-{number}"
        store.refunds[str(number) * 64] = {**REFUND, "refund_id": refund_id}
        store.business_actions[action_id] = _action(refund_id)
        parameters = {**PARAMETERS, "related_business_effect_id": refund_id}
        first = signed_envelope(
            kind="notification",
            attempt=f"ATTEMPT-NOTIFY-{number}",
            parameters=parameters,
            business_action_id=action_id,
            idempotency_key=str(number + 2) * 64,
        )
        response = api.post("/internal/execute", json=first)
        assert response.status_code == 200, response.text
        notices.append(response.json()["business_effect_id"])
        retry = api.post(
            "/internal/execute",
            json=signed_envelope(
                kind="notification",
                attempt=f"ATTEMPT-RETRY-{number}",
                parameters=parameters,
                business_action_id=action_id,
                idempotency_key=str(number + 2) * 64,
                execution_id=first["payload"]["execution_id"],
            ),
        )
        assert retry.status_code == 200, retry.text
        assert retry.json()["business_effect_id"] == notices[-1]
    assert len(set(notices)) == len(store.notifications) == 2
