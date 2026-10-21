from __future__ import annotations

from backend.gateway.service import SecureGatewayService


def test_business_idempotency_key_is_stable_and_action_bound() -> None:
    first = SecureGatewayService._business_idempotency_key(
        "tenant-A", "TASK-1", "refund-service", "refund.create", "ACTION-1"
    )
    retry = SecureGatewayService._business_idempotency_key(
        "tenant-A", "TASK-1", "refund-service", "refund.create", "ACTION-1"
    )
    second_action = SecureGatewayService._business_idempotency_key(
        "tenant-A", "TASK-1", "refund-service", "refund.create", "ACTION-2"
    )

    assert first == retry
    assert first != second_action
    assert first == "0890541f36a467380fe0d008057aa7f15a93936cb495a1a4022344d597e8b824"


def test_read_only_business_idempotency_key_is_null() -> None:
    assert (
        SecureGatewayService._business_idempotency_key(
            "tenant-A", "TASK-1", "ticket-service", "ticket.read", None
        )
        is None
    )
