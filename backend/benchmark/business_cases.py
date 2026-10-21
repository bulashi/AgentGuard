from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from backend.business_action.policy import APPROVED_SECOND_REFUND_SLOT, PRIMARY_REFUND_SLOT
from backend.state.database import connect
from scripts.seed_demo import seed_fresh_business_case

REFUNDABLE_AMOUNT_FEN = 50_000


@dataclass(frozen=True)
class BenchmarkBusinessCase:
    tenant_id: str
    ticket_id: str
    customer_id: str
    document_id: str
    original_transaction_id: str
    refundable_amount_fen: int
    approved_second_slot: bool = False

    def binding(self) -> dict[str, str]:
        return {
            "tenant_id": self.tenant_id,
            "ticket_id": self.ticket_id,
            "customer_id": self.customer_id,
        }

    def public(self) -> dict[str, Any]:
        return asdict(self) | {
            "verification_status": "VERIFIED",
            "ticket_status": "OPEN",
            "refund_reason_code": "DUPLICATE_CHARGE",
            "trusted_action_slots": [PRIMARY_REFUND_SLOT]
            + ([APPROVED_SECOND_REFUND_SLOT] if self.approved_second_slot else []),
            "source": "trusted benchmark fixture, not a bank settlement attestation",
        }


def provision_business_case(
    database_url: str, *, approved_second_slot: bool = False
) -> BenchmarkBusinessCase:
    value = seed_fresh_business_case(
        database_url,
        tenant_id="tenant-A",
        refundable_amount_fen=REFUNDABLE_AMOUNT_FEN,
        verification_status="VERIFIED",
    )
    if (
        value.get("verification_status") != "VERIFIED"
        or value.get("refundable_amount_fen") != REFUNDABLE_AMOUNT_FEN
        or value.get("tenant_id") != "tenant-A"
        or any(
            not isinstance(value.get(name), str) or not value[name]
            for name in ("ticket_id", "customer_id", "document_id", "original_transaction_id")
        )
    ):
        raise RuntimeError("trusted benchmark case provisioning returned invalid evidence")
    case = BenchmarkBusinessCase(
        tenant_id="tenant-A",
        ticket_id=str(value["ticket_id"]),
        customer_id=str(value["customer_id"]),
        document_id=str(value["document_id"]),
        original_transaction_id=str(value["original_transaction_id"]),
        refundable_amount_fen=REFUNDABLE_AMOUNT_FEN,
        approved_second_slot=approved_second_slot,
    )
    if approved_second_slot:
        # A trusted fixture approves this slot before timing, never an agent or model request.
        with connect(database_url) as connection, connection.transaction():
            inserted = connection.execute(
                """
                INSERT INTO refund_eligibility (
                    ticket_id, trusted_action_slot, tenant_id, customer_id,
                    verification_status, original_transaction_id, refund_reason_code,
                    refundable_amount_fen, evidence_reference, verified_at, created_at, updated_at
                )
                SELECT ticket_id, %s, tenant_id, customer_id, verification_status,
                       original_transaction_id, refund_reason_code, refundable_amount_fen,
                       evidence_reference, verified_at, created_at, updated_at
                FROM refund_eligibility
                WHERE ticket_id = %s AND trusted_action_slot = %s
                  AND verification_status = 'VERIFIED'
                """,
                (APPROVED_SECOND_REFUND_SLOT, case.ticket_id, PRIMARY_REFUND_SLOT),
            )
            if inserted.rowcount != 1:
                raise RuntimeError("second benchmark slot was not independently provisioned")
    return case
