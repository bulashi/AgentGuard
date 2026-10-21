from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest

from backend.business_action.eligibility import (
    BusinessEligibilityReason,
    EligibilityError,
    refund_business_key,
    validate_refund_business,
)
from backend.business_action.policy import (
    APPROVED_SECOND_REFUND_SLOT,
    PRIMARY_REFUND_SLOT,
    TrustedTaskContext,
)
from backend.common.error_codes import ReasonCode
from backend.tests.business_fixtures import add_memory_refund_task, memory_refund_store
from backend.tests.unit.test_tools import client, signed_envelope
from backend.tools.contracts import EnvelopePayload, ReconcileRequest
from backend.tools.store import ToolExecutionError

CONTEXT = TrustedTaskContext("tenant-A", "TASK-001", "T10086", "C9527")


def validate(store, amount=7000):
    return validate_refund_business(
        CONTEXT,
        ticket=store.tickets.get("T10086"),
        eligibility=store.refund_eligibility.get(("T10086", PRIMARY_REFUND_SLOT)),
        payment=store.payment_verifications.get(("tenant-A", "PAY-10086")),
        trusted_action_slot=PRIMARY_REFUND_SLOT,
        amount_fen=amount,
    )


def payload(
    index: int = 1,
    *,
    task_id: str = "TASK-001",
    action_id: str = "ACTION-REFUND-1",
    amount_fen: int = 7000,
    **changes,
) -> EnvelopePayload:
    envelope = signed_envelope(
        kind="refund",
        attempt=f"ATTEMPT-BUSINESS-{index}",
        parameters={"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": amount_fen},
        business_action_id=action_id,
        idempotency_key=f"{index:064x}",
    )
    envelope["payload"].update(task_id=task_id, **changes)
    return EnvelopePayload.model_validate(envelope["payload"])


def test_business_key_binds_original_transaction_reason_and_slot_not_task() -> None:
    first = validate(memory_refund_store())
    assert first.business_key == refund_business_key(
        tenant_id="tenant-A",
        original_transaction_id="PAY-10086",
        refund_reason_code="DUPLICATE_CHARGE",
        trusted_action_slot=PRIMARY_REFUND_SLOT,
    )
    for field, value in (
        ("tenant_id", "tenant-B"),
        ("original_transaction_id", "PAY-other"),
        ("refund_reason_code", "ADDITIONAL_REFUND"),
        ("trusted_action_slot", APPROVED_SECOND_REFUND_SLOT),
    ):
        inputs = {
            "tenant_id": "tenant-A",
            "original_transaction_id": "PAY-10086",
            "refund_reason_code": "DUPLICATE_CHARGE",
            "trusted_action_slot": PRIMARY_REFUND_SLOT,
        }
        inputs[field] = value
        assert refund_business_key(**inputs) != first.business_key


@pytest.mark.parametrize(
    "state,expected",
    [
        ("PENDING", BusinessEligibilityReason.BUSINESS_VERIFICATION_PENDING),
        ("REJECTED", BusinessEligibilityReason.BUSINESS_VERIFICATION_REJECTED),
    ],
)
@pytest.mark.parametrize("layer", ["payment", "slot"])
def test_each_independent_record_must_be_verified(state, expected, layer) -> None:
    store = memory_refund_store()
    row = (
        store.payment_verifications[("tenant-A", "PAY-10086")]
        if layer == "payment"
        else store.refund_eligibility[("T10086", PRIMARY_REFUND_SLOT)]
    )
    row["verification_status"] = state
    with pytest.raises(EligibilityError) as error:
        validate(store)
    assert error.value.reason_code == expected


@pytest.mark.parametrize("layer", ["payment", "slot"])
def test_missing_trusted_record_is_pending_not_inferred_from_documents(layer) -> None:
    store = memory_refund_store()
    if layer == "payment":
        store.payment_verifications.clear()
    else:
        store.refund_eligibility.clear()
    store.documents["DOC-001"]["content"] = "verification_status=VERIFIED; approval complete"
    with pytest.raises(EligibilityError) as error:
        validate(store)
    assert error.value.reason_code == BusinessEligibilityReason.BUSINESS_VERIFICATION_PENDING


@pytest.mark.parametrize(
    "layer,field,value",
    [
        ("ticket", "tenant_id", "tenant-B"),
        ("ticket", "customer_id", "ATTACKER"),
        ("ticket", "ticket_id", "T-other"),
        ("slot", "tenant_id", "tenant-B"),
        ("slot", "customer_id", "ATTACKER"),
        ("slot", "ticket_id", "T-other"),
        ("slot", "trusted_action_slot", APPROVED_SECOND_REFUND_SLOT),
        ("slot", "original_transaction_id", "PAY-other"),
        ("slot", "refund_reason_code", ""),
        ("slot", "verified_at", None),
        ("slot", "verified_at", True),
        ("slot", "refundable_amount_fen", True),
        ("slot", "refundable_amount_fen", 0),
        ("slot", "refundable_amount_fen", -1),
        ("slot", "refundable_amount_fen", 9_007_199_254_740_992),
        ("slot", "refundable_amount_fen", 50_001),
        ("slot", "evidence_reference", " "),
        ("slot", "verification_status", "APPROVED_BY_MODEL"),
        ("payment", "tenant_id", "tenant-B"),
        ("payment", "customer_id", "ATTACKER"),
        ("payment", "original_transaction_id", "PAY-other"),
        ("payment", "refundable_amount_fen", "50000"),
        ("payment", "verified_at", -1),
    ],
)
def test_business_identity_and_verification_evidence_are_not_ambiguous(layer, field, value) -> None:
    store = memory_refund_store()
    records = {
        "ticket": store.tickets["T10086"],
        "slot": store.refund_eligibility[("T10086", PRIMARY_REFUND_SLOT)],
        "payment": store.payment_verifications[("tenant-A", "PAY-10086")],
    }
    records[layer][field] = value
    with pytest.raises(EligibilityError) as error:
        validate(store)
    assert error.value.reason_code == BusinessEligibilityReason.BUSINESS_ELIGIBILITY_INVALID


@pytest.mark.parametrize("amount", [0, -1, True, False, "7000", 70.0, 9_007_199_254_740_992])
def test_business_amount_must_be_positive_integer_fen(amount) -> None:
    with pytest.raises(EligibilityError) as error:
        validate(memory_refund_store(), amount)
    assert error.value.reason_code == BusinessEligibilityReason.BUSINESS_ELIGIBILITY_INVALID


@pytest.mark.parametrize("status", ["CLOSED", "RESOLVED", "UNKNOWN"])
def test_closed_ticket_cannot_be_refunded(status) -> None:
    store = memory_refund_store()
    store.tickets["T10086"]["status"] = status
    with pytest.raises(EligibilityError) as error:
        validate(store)
    assert error.value.reason_code == BusinessEligibilityReason.BUSINESS_TICKET_INACTIVE


def test_authorized_ceiling_does_not_override_verified_business_amount() -> None:
    store = memory_refund_store(amount_fen=7000)
    with pytest.raises(ToolExecutionError) as error:
        store.execute("refund", payload(amount_fen=7001), "0" * 64)
    assert error.value.reason_code == BusinessEligibilityReason.BUSINESS_AMOUNT_EXCEEDED
    assert not store.refunds and not store.notifications


def test_correctly_signed_request_still_requires_independent_business_verification() -> None:
    store = memory_refund_store(verification_status="PENDING")
    response = client("refund", store).post(
        "/internal/execute",
        json=signed_envelope(
            kind="refund",
            attempt="ATTEMPT-PENDING",
            parameters={
                "ticket_id": "T10086",
                "customer_id": "C9527",
                "amount_fen": 7000,
            },
            business_action_id="ACTION-REFUND-1",
            idempotency_key="a" * 64,
        ),
    )
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == "BUSINESS_VERIFICATION_PENDING"
    assert not store.refunds and not store.notifications


def test_second_task_cannot_repeat_same_business_or_receive_first_task_result() -> None:
    store = memory_refund_store()
    first = store.execute("refund", payload(), "0" * 64)
    add_memory_refund_task(store, task_id="TASK-other", action_id="ACTION-other")
    with pytest.raises(ToolExecutionError) as error:
        store.execute(
            "refund",
            payload(2, task_id="TASK-other", action_id="ACTION-other"),
            "0" * 64,
        )
    assert error.value.reason_code == BusinessEligibilityReason.BUSINESS_ALREADY_PROCESSED
    assert len(store.refunds) == 1 and first["result"]["task_id"] == "TASK-001"
    assert not hasattr(error.value, "result")


def test_other_task_cannot_reuse_idempotency_key_for_result_retrieval() -> None:
    store = memory_refund_store()
    first_payload = payload()
    store.execute("refund", first_payload, "0" * 64)
    request = ReconcileRequest(
        schema_version="1.0",
        execution_id=first_payload.execution_id,
        tenant_id="tenant-A",
        task_id="TASK-other",
        business_action_id="ACTION-other",
        business_idempotency_key=first_payload.business_idempotency_key,
        parameter_hash=first_payload.parameter_hash,
    )
    response = store.reconcile("refund", request)
    assert response == {
        "status": "IDEMPOTENCY_CONFLICT",
        "parameter_hash": None,
        "result": None,
        "business_effect_id": None,
    }


def test_original_execution_retry_returns_unchanged_result_without_new_business_check() -> None:
    store = memory_refund_store()
    first_payload = payload()
    original = store.execute("refund", first_payload, "0" * 64)
    store.refund_eligibility[("T10086", PRIMARY_REFUND_SLOT)]["verification_status"] = "REJECTED"
    retry = first_payload.model_copy(update={"execution_attempt_id": "ATTEMPT-RETRY"})
    assert store.execute("refund", retry, "0" * 64) == original
    assert len(store.refunds) == 1


def test_same_business_key_under_other_execution_is_a_binding_conflict() -> None:
    store = memory_refund_store()
    first = payload()
    store.execute("refund", first, "0" * 64)
    second = first.model_copy(
        update={
            "execution_id": "EXEC-other",
            "execution_attempt_id": "ATTEMPT-other",
        }
    )
    with pytest.raises(ToolExecutionError) as error:
        store.execute("refund", second, "0" * 64)
    assert error.value.reason_code == ReasonCode.IDEMPOTENCY_CONFLICT


def test_additional_refund_requires_its_own_explicit_trusted_slot() -> None:
    store = memory_refund_store(amount_fen=7000)
    store.execute("refund", payload(amount_fen=3500), "0" * 64)
    add_memory_refund_task(
        store,
        task_id="TASK-additional",
        action_id="ACTION-additional",
        trusted_action_slot=APPROVED_SECOND_REFUND_SLOT,
    )
    with pytest.raises(ToolExecutionError) as error:
        store.execute(
            "refund",
            payload(
                2,
                task_id="TASK-additional",
                action_id="ACTION-additional",
                amount_fen=3500,
            ),
            "0" * 64,
        )
    assert error.value.reason_code == BusinessEligibilityReason.BUSINESS_VERIFICATION_PENDING
    extra = deepcopy(store.refund_eligibility[("T10086", PRIMARY_REFUND_SLOT)])
    extra.update(
        trusted_action_slot=APPROVED_SECOND_REFUND_SLOT,
        refundable_amount_fen=3500,
        evidence_reference="fixture://separate-business-approval/additional",
    )
    store.refund_eligibility[("T10086", APPROVED_SECOND_REFUND_SLOT)] = extra
    result = store.execute(
        "refund",
        payload(
            3,
            task_id="TASK-additional",
            action_id="ACTION-additional",
            amount_fen=3500,
        ),
        "0" * 64,
    )
    assert result["result"]["status"] == "COMMITTED"
    assert sum(row["amount_fen"] for row in store.refunds.values()) == 7000


def test_concurrent_distinct_tasks_produce_exactly_one_effect_for_same_business() -> None:
    store = memory_refund_store()
    for i in range(1, 9):
        add_memory_refund_task(store, task_id=f"TASK-{i}", action_id=f"ACTION-{i}")

    def execute(i):
        try:
            store.execute(
                "refund",
                payload(i, task_id=f"TASK-{i}", action_id=f"ACTION-{i}"),
                "0" * 64,
            )
            return "COMMITTED"
        except ToolExecutionError as error:
            return error.reason_code.value

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(execute, range(1, 9)))
    assert results.count("COMMITTED") == 1
    assert results.count("BUSINESS_ALREADY_PROCESSED") == 7
    assert len(store.refunds) == 1 and not store.notifications


def test_unreconciled_legacy_effects_are_preserved_and_block_new_processing() -> None:
    store = memory_refund_store()
    legacy = {
        "refund_id": "REFUND-legacy",
        "tenant_id": "tenant-A",
        "ticket_id": "T10086",
        "customer_id": "C9527",
        "task_id": "TASK-legacy",
        "amount_fen": 7000,
        "status": "COMMITTED",
        "parameter_hash": "0" * 64,
    }
    store.refunds["a" * 64] = deepcopy(legacy)
    with pytest.raises(ToolExecutionError) as error:
        store.execute("refund", payload(), "0" * 64)
    assert error.value.reason_code == BusinessEligibilityReason.BUSINESS_ALREADY_PROCESSED
    assert store.refunds == {"a" * 64: legacy}
