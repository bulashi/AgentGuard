from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from backend.business_action.facts import (
    BusinessFactsError,
    BusinessFactTargetProcessed,
    refresh_fact_eligibility,
)
from backend.business_action.policy import APPROVED_REFUND_SLOTS, TrustedTaskContext
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex

MAX_SAFE_INTEGER = 9_007_199_254_740_991
REFUND_BUSINESS_DOMAIN = "AGENTGUARD_REFUND_BUSINESS_V1"


class BusinessEligibilityReason(StrEnum):
    BUSINESS_VERIFICATION_PENDING = "BUSINESS_VERIFICATION_PENDING"
    BUSINESS_VERIFICATION_REJECTED = "BUSINESS_VERIFICATION_REJECTED"
    BUSINESS_ELIGIBILITY_INVALID = "BUSINESS_ELIGIBILITY_INVALID"
    BUSINESS_AMOUNT_EXCEEDED = "BUSINESS_AMOUNT_EXCEEDED"
    BUSINESS_ALREADY_PROCESSED = "BUSINESS_ALREADY_PROCESSED"
    BUSINESS_TICKET_INACTIVE = "BUSINESS_TICKET_INACTIVE"


class EligibilityError(RuntimeError):
    def __init__(self, reason_code: BusinessEligibilityReason, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class VerifiedRefundBusiness:
    business_key: str
    original_transaction_id: str
    refund_reason_code: str
    trusted_action_slot: str
    slot_amount_fen: int
    transaction_amount_fen: int


def refund_business_key(
    *,
    tenant_id: str,
    original_transaction_id: str,
    refund_reason_code: str,
    trusted_action_slot: str,
) -> str:
    # This business extension deliberately excludes task IDs; signed V1 scopes are unchanged.
    payload = {
        "tenant_id": tenant_id,
        "original_transaction_id": original_transaction_id,
        "refund_reason_code": refund_reason_code,
        "trusted_action_slot": trusted_action_slot,
    }
    return sm3_hex(REFUND_BUSINESS_DOMAIN.encode("ascii") + b"\x00" + canonicalize(payload))


def _invalid(message: str) -> None:
    raise EligibilityError(BusinessEligibilityReason.BUSINESS_ELIGIBILITY_INVALID, message)


def _verified_record(record: dict[str, Any] | None, name: str) -> dict[str, Any]:
    if record is None or record.get("verification_status") == "PENDING":
        raise EligibilityError(
            BusinessEligibilityReason.BUSINESS_VERIFICATION_PENDING,
            f"{name} requires an independent trusted verification record",
        )
    if record.get("verification_status") == "REJECTED":
        raise EligibilityError(
            BusinessEligibilityReason.BUSINESS_VERIFICATION_REJECTED,
            f"{name} was rejected by the trusted business verification",
        )
    if record.get("verification_status") != "VERIFIED":
        _invalid(f"{name} has an invalid verification status")
    amount = record.get("refundable_amount_fen")
    verified_at = record.get("verified_at")
    if (
        type(amount) is not int
        or not 0 < amount <= MAX_SAFE_INTEGER
        or type(verified_at) is not int
        or not 0 <= verified_at <= MAX_SAFE_INTEGER
        or not isinstance(record.get("evidence_reference"), str)
        or not record["evidence_reference"].strip()
    ):
        _invalid(f"{name} lacks valid verified amount or verification evidence")
    return record


def validate_refund_business(
    context: TrustedTaskContext,
    *,
    ticket: dict[str, Any] | None,
    eligibility: dict[str, Any] | None,
    payment: dict[str, Any] | None,
    trusted_action_slot: str,
    amount_fen: int | None = None,
) -> VerifiedRefundBusiness:
    if trusted_action_slot not in APPROVED_REFUND_SLOTS:
        _invalid("refund slot is not approved by the server policy")
    identity = (context.tenant_id, context.ticket_id, context.customer_id)
    if (
        ticket is None
        or tuple(
            ticket.get(k)
            for k in (
                "tenant_id",
                "ticket_id",
                "customer_id",
            )
        )
        != identity
    ):
        _invalid("ticket identity does not match the authorized task")
    if ticket.get("status") not in {"OPEN", "IN_PROGRESS"}:
        raise EligibilityError(
            BusinessEligibilityReason.BUSINESS_TICKET_INACTIVE,
            "ticket is not open for refund processing",
        )
    if eligibility is not None and (
        tuple(eligibility.get(k) for k in ("tenant_id", "ticket_id", "customer_id")) != identity
        or eligibility.get("trusted_action_slot") != trusted_action_slot
    ):
        _invalid("trusted refund slot is bound to a different business identity")
    slot = _verified_record(eligibility, "refund eligibility")
    transaction_id = slot.get("original_transaction_id")
    reason = slot.get("refund_reason_code")
    if (
        not isinstance(transaction_id, str)
        or not transaction_id.strip()
        or not isinstance(reason, str)
        or not reason.strip()
    ):
        _invalid("verified refund slot lacks original transaction or business reason")
    if payment is not None and tuple(
        payment.get(k)
        for k in (
            "tenant_id",
            "original_transaction_id",
            "customer_id",
        )
    ) != (context.tenant_id, transaction_id, context.customer_id):
        _invalid("payment verification is bound to a different business identity")
    transaction = _verified_record(payment, "original payment")
    if slot["refundable_amount_fen"] > transaction["refundable_amount_fen"]:
        _invalid("approved refund slot exceeds the original transaction's refundable amount")
    if amount_fen is not None:
        if type(amount_fen) is not int or not 0 < amount_fen <= MAX_SAFE_INTEGER:
            _invalid("refund amount must be a positive safe integer in fen")
        if amount_fen > slot["refundable_amount_fen"]:
            raise EligibilityError(
                BusinessEligibilityReason.BUSINESS_AMOUNT_EXCEEDED,
                "requested refund exceeds the independently verified business amount",
            )
    return VerifiedRefundBusiness(
        business_key=refund_business_key(
            tenant_id=context.tenant_id,
            original_transaction_id=transaction_id,
            refund_reason_code=reason,
            trusted_action_slot=trusted_action_slot,
        ),
        original_transaction_id=transaction_id,
        refund_reason_code=reason,
        trusted_action_slot=trusted_action_slot,
        slot_amount_fen=slot["refundable_amount_fen"],
        transaction_amount_fen=transaction["refundable_amount_fen"],
    )


def load_verified_refund_business(
    connection: Any,
    context: TrustedTaskContext,
    *,
    trusted_action_slot: str,
    amount_fen: int | None = None,
    for_execution: bool = False,
) -> VerifiedRefundBusiness:
    ticket_fields = ("ticket_id", "tenant_id", "customer_id", "status")
    ticket_row = connection.execute(
        "SELECT ticket_id, tenant_id, customer_id, status FROM tickets "
        "WHERE ticket_id = %s FOR SHARE",
        (context.ticket_id,),
    ).fetchone()
    try:
        fact_result = refresh_fact_eligibility(
            connection, context, trusted_action_slot=trusted_action_slot, current_time=now_unix(),
        )
    except BusinessFactTargetProcessed as exc:
        raise EligibilityError(
            BusinessEligibilityReason.BUSINESS_ALREADY_PROCESSED, str(exc),
        ) from exc
    except BusinessFactsError as exc:
        _invalid(str(exc))
    if fact_result is not None and fact_result["status"] != "VERIFIED":
        reason = (
            BusinessEligibilityReason.BUSINESS_VERIFICATION_REJECTED
            if fact_result["status"] == "REJECTED"
            else BusinessEligibilityReason.BUSINESS_VERIFICATION_PENDING
        )
        raise EligibilityError(reason, fact_result["reason"])
    slot_fields = (
        "tenant_id",
        "ticket_id",
        "customer_id",
        "trusted_action_slot",
        "verification_status",
        "original_transaction_id",
        "refund_reason_code",
        "refundable_amount_fen",
        "evidence_reference",
        "verified_at",
    )
    slot_row = connection.execute(
        "SELECT " + ", ".join(slot_fields) + " FROM refund_eligibility "
        "WHERE ticket_id = %s AND trusted_action_slot = %s FOR SHARE",
        (context.ticket_id, trusted_action_slot),
    ).fetchone()
    ticket = dict(zip(ticket_fields, ticket_row, strict=True)) if ticket_row else None
    slot = dict(zip(slot_fields, slot_row, strict=True)) if slot_row else None
    payment = None
    if slot and slot["original_transaction_id"] is not None:
        fields = (
            "tenant_id",
            "original_transaction_id",
            "customer_id",
            "verification_status",
            "refundable_amount_fen",
            "evidence_reference",
            "verified_at",
        )
        payment_row = connection.execute(
            "SELECT " + ", ".join(fields) + " FROM business_payment_verifications "
            "WHERE tenant_id = %s AND original_transaction_id = %s "
            + ("FOR UPDATE" if for_execution else "FOR SHARE"),
            (context.tenant_id, slot["original_transaction_id"]),
        ).fetchone()
        if payment_row:
            payment = dict(zip(fields, payment_row, strict=True))
    return validate_refund_business(
        context,
        ticket=ticket,
        eligibility=slot,
        payment=payment,
        trusted_action_slot=trusted_action_slot,
        amount_fen=amount_fen,
    )


def check_unprocessed_business(
    connection: Any,
    context: TrustedTaskContext,
    business: VerifiedRefundBusiness,
    *,
    allow_same_task: bool = False,
) -> None:
    # Do not retrofit unverifiable transaction IDs into historical refund effects.
    if connection.execute(
        "SELECT 1 FROM refunds WHERE tenant_id = %s AND ticket_id = %s "
        "AND original_transaction_id IS NULL LIMIT 1",
        (context.tenant_id, context.ticket_id),
    ).fetchone():
        raise EligibilityError(
            BusinessEligibilityReason.BUSINESS_ALREADY_PROCESSED,
            "historical refund effects require independent reconciliation before new processing",
        )
    existing = connection.execute(
        "SELECT task_id FROM refunds WHERE refund_business_key = %s",
        (business.business_key,),
    ).fetchone()
    if existing is not None and not (allow_same_task and str(existing[0]) == context.task_id):
        raise EligibilityError(
            BusinessEligibilityReason.BUSINESS_ALREADY_PROCESSED,
            "this refund business has already been processed; no new effect was created",
        )


def payment_refunded_amount(
    connection: Any, context: TrustedTaskContext, business: VerifiedRefundBusiness
) -> int:
    row = connection.execute(
        "SELECT COALESCE(sum(amount_fen), 0) FROM refunds "
        "WHERE tenant_id = %s AND original_transaction_id = %s",
        (context.tenant_id, business.original_transaction_id),
    ).fetchone()
    return int(row[0])
