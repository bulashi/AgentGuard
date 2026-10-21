"""Pure source-input validation tests; no network, database or cloud calls are used."""

from __future__ import annotations

from copy import deepcopy

import pytest

from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from scripts.verify_business_workspace import validate_refund_ticket_input

TASK = {"ticket_id": "T-FACT", "tenant_id": "tenant-A", "customer_id": "C-FACT"}


@pytest.fixture
def fact_ticket() -> dict:
    facts = {
        "schema_version": "1.0",
        "order": {"order_id": "ORDER-FACT", "amount_fen": 7000, "currency": "CNY"},
        "payments": [
            {
                "transaction_id": f"PAY-FACT-{index}",
                "amount_fen": 7000,
                "status": "SUCCESS",
                "refunded_amount_fen": 0,
            }
            for index in (1, 2)
        ],
        "claim_text": "Please check whether this order was charged twice.",
    }
    return {
        **TASK,
        "status": "OPEN",
        "business_facts": facts,
        "facts_hash": sm3_hex(canonicalize(facts)),
    }


def test_legacy_fixture_accepts_its_nonempty_description():
    validate_refund_ticket_input({**TASK, "description": "Actual fixture ticket source."}, TASK)


@pytest.mark.parametrize("description", [None, "", "   ", 1, []])
def test_legacy_fixture_rejects_missing_empty_or_non_text_description(description):
    ticket = {**TASK, "description": description}
    if description is None:
        ticket.pop("description")
    with pytest.raises(RuntimeError, match="fixture ticket description"):
        validate_refund_ticket_input(ticket, TASK)


def test_raw_fact_ticket_accepts_the_real_six_field_shape_without_description(fact_ticket):
    before = deepcopy(fact_ticket)
    validate_refund_ticket_input(fact_ticket, TASK)
    assert fact_ticket == before and "description" not in fact_ticket


@pytest.mark.parametrize("key", ["ticket_id", "tenant_id", "customer_id"])
def test_raw_fact_ticket_rejects_mismatched_task_scope(fact_ticket, key):
    fact_ticket[key] = "different-source"
    with pytest.raises(RuntimeError):
        validate_refund_ticket_input(fact_ticket, TASK)


@pytest.mark.parametrize(
    "key", ["business_facts", "facts_hash", "tenant_id", "customer_id", "status"]
)
def test_raw_fact_ticket_rejects_missing_source_fields(fact_ticket, key):
    fact_ticket.pop(key)
    with pytest.raises(RuntimeError, match="missing source fields"):
        validate_refund_ticket_input(fact_ticket, TASK)


@pytest.mark.parametrize("facts", [None, {}, []])
def test_raw_fact_ticket_rejects_empty_or_non_object_facts(fact_ticket, facts):
    fact_ticket["business_facts"] = facts
    with pytest.raises(RuntimeError, match="raw business facts are missing"):
        validate_refund_ticket_input(fact_ticket, TASK)


@pytest.mark.parametrize("claim", [None, "", "  \n\t", 1, "x" * 4001])
def test_raw_fact_ticket_requires_valid_nonempty_claim_text(fact_ticket, claim):
    facts = fact_ticket["business_facts"]
    if claim is None:
        facts.pop("claim_text")
    else:
        facts["claim_text"] = claim
    fact_ticket["facts_hash"] = sm3_hex(canonicalize(facts))
    with pytest.raises(RuntimeError, match="claim text are invalid"):
        validate_refund_ticket_input(fact_ticket, TASK)


@pytest.mark.parametrize("digest", [None, "", "0" * 64, "a" * 63, "g" * 64, 123])
def test_raw_fact_ticket_rejects_missing_invalid_or_changed_hash(fact_ticket, digest):
    fact_ticket["facts_hash"] = digest
    with pytest.raises(RuntimeError, match="facts hash"):
        validate_refund_ticket_input(fact_ticket, TASK)


def test_changed_raw_facts_cannot_reuse_the_original_hash(fact_ticket):
    fact_ticket["business_facts"]["payments"][0]["amount_fen"] = 6000
    with pytest.raises(RuntimeError, match="facts hash"):
        validate_refund_ticket_input(fact_ticket, TASK)


@pytest.mark.parametrize(
    "field",
    [
        "business_verification",
        "refund_verifications",
        "verification_status",
        "payment_verification_status",
        "refundable_amount_fen",
        "description",
    ],
)
def test_raw_fact_ticket_rejects_precomputed_verdict_or_description_fields(fact_ticket, field):
    fact_ticket[field] = "VERIFIED"
    with pytest.raises(RuntimeError, match="precomputed verdict"):
        validate_refund_ticket_input(fact_ticket, TASK)


@pytest.mark.parametrize("location", ["facts", "order", "payment"])
def test_raw_contract_rejects_nested_precomputed_verdict_even_with_recomputed_hash(
    fact_ticket, location
):
    facts = fact_ticket["business_facts"]
    target = (
        facts
        if location == "facts"
        else facts["order"]
        if location == "order"
        else facts["payments"][0]
    )
    target["verification_status"] = "VERIFIED"
    fact_ticket["facts_hash"] = sm3_hex(canonicalize(facts))
    with pytest.raises(RuntimeError, match="raw business facts"):
        validate_refund_ticket_input(fact_ticket, TASK)


def test_incomplete_fact_input_cannot_fall_back_to_legacy_description(fact_ticket):
    fact_ticket.pop("business_facts")
    fact_ticket["description"] = "Do not hide a missing raw source with fixture text."
    with pytest.raises(RuntimeError, match="missing source fields"):
        validate_refund_ticket_input(fact_ticket, TASK)
