from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.business_action.contracts import (
    ResolveNotificationActionRequest,
    ResolveRefundActionRequest,
)
from backend.business_action.policy import (
    APPROVED_SECOND_REFUND_SLOT,
    TrustedTaskContext,
    notification_scope,
    refund_scope,
)
from backend.business_action.service import (
    BusinessActionError,
    BusinessActionRegistryService,
)
from backend.common.error_codes import ReasonCode

CONTEXT = TrustedTaskContext(
    tenant_id="tenant-A",
    task_id="TASK-001",
    ticket_id="T10086",
    customer_id="C9527",
)


def test_refund_scope_is_domain_separated_and_slot_sensitive() -> None:
    first, payload = refund_scope(CONTEXT)
    second, second_payload = refund_scope(
        CONTEXT, trusted_action_slot=APPROVED_SECOND_REFUND_SLOT
    )
    assert payload == {
        "tenant_id": "tenant-A",
        "task_id": "TASK-001",
        "action_type": "refund",
        "ticket_id": "T10086",
        "customer_id": "C9527",
        "trusted_action_slot": "primary-refund",
    }
    assert first == "ca105abf1a0b306d42ea537c928a363663f22b63597b23b64d55b82b1516cd5c"
    assert second_payload["trusted_action_slot"] == "approved-second-refund"
    assert first != second


def test_notification_scope_matches_frozen_fields() -> None:
    value, payload = notification_scope(
        CONTEXT,
        template_id="REFUND_SUCCESS",
        related_business_effect_id="REFUND-001",
    )
    assert payload == {
        "tenant_id": "tenant-A",
        "task_id": "TASK-001",
        "action_type": "notification",
        "template_id": "REFUND_SUCCESS",
        "related_business_effect_id": "REFUND-001",
    }
    assert value == "7639be225c7decd66ab414126803220944ff14025e1a15f3455be2e800b8d510"


@pytest.mark.parametrize(
    "field,value",
    [
        ("business_action_id", "ACTION-attacker"),
        ("action_scope_key", "a" * 64),
        ("trusted_action_slot", "attacker-slot"),
        ("tenant_id", "tenant-B"),
        ("tool_name", "refund.create"),
    ],
)
def test_public_refund_request_forbids_identity_overrides(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        ResolveRefundActionRequest.model_validate({"task_id": "TASK-001", field: value})


def test_notification_request_accepts_only_fixed_template() -> None:
    with pytest.raises(ValidationError):
        ResolveNotificationActionRequest.model_validate(
            {
                "task_id": "TASK-001",
                "template_id": "ARBITRARY_TEMPLATE",
                "related_business_effect_id": "REFUND-001",
            }
        )


def test_refund_registry_rejects_unapproved_trusted_slot_before_database_access() -> None:
    service = BusinessActionRegistryService("postgresql+psycopg://unused")

    with pytest.raises(BusinessActionError) as exc_info:
        service.resolve_refund_for_trusted_slot(
            "TASK-001",
            trusted_action_slot="refund-3",
            current_time=1,
        )

    assert exc_info.value.reason_code is ReasonCode.BUSINESS_ACTION_INVALID
    assert "fixed refund policy" in str(exc_info.value)
