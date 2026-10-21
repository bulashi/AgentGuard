from __future__ import annotations

from typing import Any

from backend.business_action.policy import (
    APPROVED_SECOND_REFUND_SLOT,
    PRIMARY_REFUND_SLOT,
    TrustedTaskContext,
    refund_scope,
)
from backend.common.time import now_unix
from backend.state.database import connect
from backend.tools.demo_materials import POLICY_CONTENT, TICKET_DESCRIPTION
from backend.tools.store import MemoryToolStore
from scripts.seed_demo import seed_fresh_business_case

POSTGRES_BUSINESS_TEST_CASE: dict[str, str | int] | None = None


def business_test_case() -> dict[str, str | int]:
    if POSTGRES_BUSINESS_TEST_CASE is None:
        raise AssertionError("a fresh independently verified business fixture is required")
    return POSTGRES_BUSINESS_TEST_CASE


def verified_postgres_case(
    database_url: str,
    *,
    tenant_id: str = "tenant-A",
    customer_id: str = "C9527",
) -> dict[str, str | int]:
    """Declare payment and two explicit slots without weakening protocol or budget checks."""
    case = seed_fresh_business_case(
        database_url,
        tenant_id=tenant_id,
        customer_id=customer_id,
        refundable_amount_fen=50_000,
    )
    with connect(database_url) as connection, connection.transaction():
        connection.execute(
            "INSERT INTO refund_eligibility (ticket_id, trusted_action_slot, tenant_id, "
            "customer_id, verification_status, original_transaction_id, refund_reason_code, "
            "refundable_amount_fen, evidence_reference, verified_at, created_at, updated_at) "
            "SELECT ticket_id, %s, tenant_id, customer_id, verification_status, "
            "original_transaction_id, refund_reason_code, refundable_amount_fen, %s, "
            "verified_at, created_at, updated_at FROM refund_eligibility "
            "WHERE ticket_id = %s AND trusted_action_slot = %s",
            (
                APPROVED_SECOND_REFUND_SLOT,
                f"fixture://protocol-fairness/{case['ticket_id']}/explicit-second-approval",
                case["ticket_id"],
                PRIMARY_REFUND_SLOT,
            ),
        )
    return case


def add_memory_refund_task(
    store: MemoryToolStore,
    *,
    task_id: str = "TASK-001",
    action_id: str = "ACTION-REFUND-1",
    tenant_id: str = "tenant-A",
    ticket_id: str = "T10086",
    customer_id: str = "C9527",
    trusted_action_slot: str = PRIMARY_REFUND_SLOT,
) -> None:
    context = TrustedTaskContext(tenant_id, task_id, ticket_id, customer_id)
    scope_key, _ = refund_scope(context, trusted_action_slot=trusted_action_slot)
    store.tasks[task_id] = {
        "tenant_id": tenant_id,
        "task_id": task_id,
        "ticket_id": ticket_id,
        "customer_id": customer_id,
        "status": "AUTHORIZED",
        "expires_at": now_unix() + 1800,
    }
    store.business_actions[action_id] = {
        "tenant_id": tenant_id,
        "task_id": task_id,
        "tool_service": "refund-service",
        "tool_name": "refund.create",
        "trusted_action_slot": trusted_action_slot,
        "action_scope_key": scope_key,
        "status": "ACTIVE",
    }


def memory_refund_store(
    *,
    task_id: str = "TASK-001",
    action_id: str = "ACTION-REFUND-1",
    amount_fen: int = 50_000,
    verification_status: str = "VERIFIED",
) -> MemoryToolStore:
    current = now_unix()
    store = MemoryToolStore()
    store.tickets["T10086"] = {
        "ticket_id": "T10086",
        "tenant_id": "tenant-A",
        "customer_id": "C9527",
        "title": "Refund request",
        "description": TICKET_DESCRIPTION,
        "status": "OPEN",
    }
    store.documents["DOC-001"] = {
        "document_id": "DOC-001",
        "tenant_id": "tenant-A",
        "title": "Refund policy",
        "content": POLICY_CONTENT,
        "sensitivity": "INTERNAL",
    }
    store.ticket_documents["T10086"] = ["DOC-001"]
    payment: dict[str, Any] = {
        "tenant_id": "tenant-A",
        "original_transaction_id": "PAY-10086",
        "customer_id": "C9527",
        "verification_status": verification_status,
        "refundable_amount_fen": amount_fen if verification_status == "VERIFIED" else 0,
        "evidence_reference": "fixture://payment-review/10086",
        "verified_at": current if verification_status == "VERIFIED" else None,
    }
    store.payment_verifications[("tenant-A", "PAY-10086")] = payment
    store.refund_eligibility[("T10086", PRIMARY_REFUND_SLOT)] = {
        **payment,
        "ticket_id": "T10086",
        "trusted_action_slot": PRIMARY_REFUND_SLOT,
        "refund_reason_code": "DUPLICATE_CHARGE",
    }
    add_memory_refund_task(store, task_id=task_id, action_id=action_id)
    return store
