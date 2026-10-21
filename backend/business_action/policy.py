from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import NOTIFICATION_ACTION_SCOPE, REFUND_ACTION_SCOPE
from backend.crypto.sm import sm3_hex

REFUND_SERVICE = "refund-service"
REFUND_TOOL = "refund.create"
NOTIFICATION_SERVICE = "notification-service"
NOTIFICATION_TOOL = "notification.send_template"
PRIMARY_REFUND_SLOT = "primary-refund"
APPROVED_SECOND_REFUND_SLOT = "approved-second-refund"
APPROVED_REFUND_SLOTS = frozenset(
    {PRIMARY_REFUND_SLOT, APPROVED_SECOND_REFUND_SLOT}
)
REFUND_SUCCESS_NOTIFICATION_SLOT = "refund-success-notification"


@dataclass(frozen=True)
class TrustedTaskContext:
    tenant_id: str
    task_id: str
    ticket_id: str
    customer_id: str


def _scope_hash(domain: str, payload: dict[str, Any]) -> str:
    return sm3_hex(domain.encode("utf-8") + b"\x00" + canonicalize(payload))


def refund_scope(
    context: TrustedTaskContext,
    *,
    trusted_action_slot: str = PRIMARY_REFUND_SLOT,
) -> tuple[str, dict[str, Any]]:
    payload = {
        "tenant_id": context.tenant_id,
        "task_id": context.task_id,
        "action_type": "refund",
        "ticket_id": context.ticket_id,
        "customer_id": context.customer_id,
        "trusted_action_slot": trusted_action_slot,
    }
    return _scope_hash(REFUND_ACTION_SCOPE, payload), payload


def notification_scope(
    context: TrustedTaskContext,
    *,
    template_id: str,
    related_business_effect_id: str,
) -> tuple[str, dict[str, Any]]:
    payload = {
        "tenant_id": context.tenant_id,
        "task_id": context.task_id,
        "action_type": "notification",
        "template_id": template_id,
        "related_business_effect_id": related_business_effect_id,
    }
    return _scope_hash(NOTIFICATION_ACTION_SCOPE, payload), payload
