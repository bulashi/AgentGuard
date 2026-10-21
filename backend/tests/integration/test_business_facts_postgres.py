from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Event
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from psycopg import errors

from backend.business_action.contracts import (
    CreateBusinessCaseRequest,
    EvaluateRefundFactsRequest,
    ResolveRefundActionRequest,
)
from backend.business_action.facts import load_business_case_facts
from backend.business_action.policy import PRIMARY_REFUND_SLOT, TrustedTaskContext
from backend.business_action.service import BusinessActionError, BusinessActionRegistryService
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.state.database import connect
from backend.tests.integration.test_business_eligibility_postgres import dispatch_fixture
from backend.tests.unit.test_business_facts import case_request
from backend.tools.store import PostgresToolStore, ToolExecutionError

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database_url() -> str:
    candidate = os.getenv("AGENTGUARD_BUSINESS_FACTS_TEST_DATABASE_URL") or os.getenv(
        "AGENTGUARD_DATABASE_URL",
    )
    if not candidate:
        pytest.skip("business facts tests require an isolated local PostgreSQL database")
    target = urlsplit(candidate)
    name = target.path.removeprefix("/")
    if target.hostname not in {"localhost", "127.0.0.1", "::1"} or not re.fullmatch(
        r"agentguard_(?:test|coauth_test)_backend_[A-Za-z0-9_]+", name,
    ):
        pytest.fail("refusing business facts writes outside an isolated native test database")
    with connect(candidate) as connection:
        connection.execute("SET TRANSACTION READ ONLY")
        assert connection.execute("SELECT current_database()").fetchone() == (name,)
        assert connection.execute("SELECT to_regclass('business_case_facts')").fetchone()[0]
    return candidate


def fresh_case(database_url, *, status="SUCCESS", refunded=0, request_changes=None):
    suffix = uuid4().hex
    document = case_request(
        tenant_id=f"tenant-facts-{suffix}", customer_id=f"C-{suffix}",
        ticket_id=f"T-{suffix}", order_id=f"ORDER-{suffix}",
    )
    document["payments"][0]["transaction_id"] = f"PAY-a-{suffix}"
    document["payments"][1].update(
        transaction_id=f"PAY-b-{suffix}", status=status, refunded_amount_fen=refunded,
    )
    document.update(request_changes or {})
    service = BusinessActionRegistryService(database_url)
    result = service.create_business_case(
        CreateBusinessCaseRequest.model_validate(document), current_time=now_unix(),
    )
    return document, result


def evaluate(database_url, task_id):
    return BusinessActionRegistryService(database_url).evaluate_refund_facts(
        EvaluateRefundFactsRequest(task_id=task_id), current_time=now_unix(),
    )


def test_creation_stores_only_hashed_original_facts_without_qualification(database_url):
    document, created = fresh_case(database_url)
    assert created["cloud_shareable"] is False
    assert created["facts_hash"] == sm3_hex(canonicalize(created["business_facts"]))
    with connect(database_url) as connection:
        original = load_business_case_facts(connection, created["ticket_id"])
        assert original["facts"] == created["business_facts"]
        for table in ("refund_eligibility", "business_fact_evaluations"):
            assert connection.execute(
                f"SELECT count(*) FROM {table} WHERE ticket_id = %s", (created["ticket_id"],),
            ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM business_payment_verifications WHERE tenant_id = %s",
            (document["tenant_id"],),
        ).fetchone() == (0,)
        policy = connection.execute(
            "SELECT content FROM knowledge_documents d JOIN ticket_document_relations r "
            "ON r.document_id=d.document_id WHERE r.ticket_id=%s", (created["ticket_id"],),
        ).fetchone()[0]
        assert "VERIFIED" not in policy and created["ticket_id"] not in policy


@pytest.mark.parametrize("status", ["FAILED", "PROCESSING"])
def test_nonrefundable_evaluation_persists_despite_later_resolve_rejection(database_url, status):
    document, created = fresh_case(database_url, status=status)
    payload = dispatch_fixture(database_url, document)
    result = evaluate(database_url, payload.task_id)
    assert result["status"] == ("REJECTED" if status == "FAILED" else "PENDING")
    with pytest.raises(BusinessActionError):
        BusinessActionRegistryService(database_url).resolve_refund(
            ResolveRefundActionRequest(task_id=payload.task_id), current_time=now_unix(),
        )
    with connect(database_url) as connection:
        saved = connection.execute(
            "SELECT result FROM business_fact_evaluations WHERE task_id=%s", (payload.task_id,),
        ).fetchone()[0]
        assert saved == result and saved["facts_hash"] == created["facts_hash"]
        assert connection.execute(
            "SELECT count(*) FROM refunds WHERE ticket_id=%s", (created["ticket_id"],),
        ).fetchone() == (0,)
    assert evaluate(database_url, payload.task_id) == result


def test_resolve_alone_keeps_rejection_evidence_in_a_separate_committed_transaction(database_url):
    document, _ = fresh_case(database_url, status="FAILED")
    payload = dispatch_fixture(database_url, document)
    with pytest.raises(BusinessActionError):
        BusinessActionRegistryService(database_url).resolve_refund(
            ResolveRefundActionRequest(task_id=payload.task_id), current_time=now_unix(),
        )
    with connect(database_url) as connection:
        assert connection.execute(
            "SELECT result->>'status' FROM business_fact_evaluations WHERE task_id=%s",
            (payload.task_id,),
        ).fetchone() == ("REJECTED",)


@pytest.mark.parametrize("reuse", ["order", "payment", "ticket"])
def test_new_ticket_cannot_reuse_the_same_tenant_order_or_payment(database_url, reuse):
    document, _ = fresh_case(database_url)
    repeated = deepcopy(document)
    suffix = uuid4().hex
    repeated.update(ticket_id=f"T-{suffix}", order_id=f"ORDER-{suffix}")
    for index, payment in enumerate(repeated["payments"]):
        payment["transaction_id"] = f"PAY-{index}-{suffix}"
    if reuse == "order":
        repeated["order_id"] = document["order_id"]
    elif reuse == "payment":
        repeated["payments"][1]["transaction_id"] = document["payments"][1]["transaction_id"]
    else:
        repeated["ticket_id"] = document["ticket_id"]
    with pytest.raises(BusinessActionError) as error:
        BusinessActionRegistryService(database_url).create_business_case(
            CreateBusinessCaseRequest.model_validate(repeated), current_time=now_unix(),
        )
    assert error.value.status_code == 409
    if reuse != "ticket":
        with connect(database_url) as connection:
            assert connection.execute(
                "SELECT 1 FROM tickets WHERE ticket_id=%s", (repeated["ticket_id"],),
            ).fetchone() is None


def test_concurrent_creation_of_same_order_commits_one_case(database_url):
    suffix = uuid4().hex
    base = case_request(tenant_id=f"tenant-{suffix}", order_id=f"ORDER-{suffix}")

    def create(index):
        document = deepcopy(base)
        document["ticket_id"] = f"T-{index}-{suffix}"
        for payment_index, payment in enumerate(document["payments"]):
            payment["transaction_id"] = f"PAY-{index}-{payment_index}-{suffix}"
        try:
            BusinessActionRegistryService(database_url).create_business_case(
                CreateBusinessCaseRequest.model_validate(document), current_time=now_unix(),
            )
            return "CREATED"
        except BusinessActionError as exc:
            return exc.reason_code.value

    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(create, range(4)))
    assert results.count("CREATED") == 1
    assert results.count("BUSINESS_ACTION_CONFLICT") == 3


def test_original_facts_payment_bindings_and_first_evaluation_cannot_be_changed(database_url):
    document, _ = fresh_case(database_url)
    payload = dispatch_fixture(database_url, document)
    evaluate(database_url, payload.task_id)
    with connect(database_url) as connection:
        for statement, identity in (
            ("UPDATE business_case_facts SET facts_hash=repeat('0',64) WHERE ticket_id=%s",
             document["ticket_id"]),
            ("DELETE FROM business_case_facts WHERE ticket_id=%s", document["ticket_id"]),
            ("DELETE FROM business_case_payment_ids WHERE ticket_id=%s", document["ticket_id"]),
            ("DELETE FROM business_fact_evaluations WHERE task_id=%s", payload.task_id),
        ):
            with pytest.raises(errors.ObjectNotInPrerequisiteState), connection.transaction():
                connection.execute(statement, (identity,))


@pytest.mark.parametrize("previous,expected", [(0, 7000), (2000, 5000)])
def test_actual_refund_recomputes_facts_and_binds_original_transaction(
    database_url, previous, expected,
):
    document, _ = fresh_case(database_url, refunded=previous)
    payload = dispatch_fixture(database_url, document, amount=expected)
    first = evaluate(database_url, payload.task_id)
    assert first["refundable_amount_fen"] == expected
    store = PostgresToolStore(database_url)
    effect = store.execute("refund", payload, "0" * 64)
    assert effect["result"]["amount_fen"] == expected
    with connect(database_url) as connection:
        refund = connection.execute(
            "SELECT original_transaction_id, amount_fen FROM refunds WHERE refund_id=%s",
            (effect["business_effect_id"],),
        ).fetchone()
        assert refund == (document["payments"][1]["transaction_id"], expected)
        assert load_business_case_facts(connection, document["ticket_id"])["facts"]["payments"][1][
            "refunded_amount_fen"
        ] == previous
    # First evidence stays stable while a new task independently sees the current refund balance.
    assert evaluate(database_url, payload.task_id) == first
    next_payload = dispatch_fixture(database_url, document, amount=expected)
    later = evaluate(database_url, next_payload.task_id)
    assert later["status"] == "REJECTED" and later["refundable_amount_fen"] == 0
    with pytest.raises(ToolExecutionError):
        store.execute("refund", next_payload, "0" * 64)


def test_prepopulated_derived_approval_cannot_override_a_failed_payment(database_url):
    document, _ = fresh_case(database_url, status="FAILED")
    payload = dispatch_fixture(database_url, document)
    current = now_unix()
    with connect(database_url) as connection, connection.transaction():
        connection.execute(
            "INSERT INTO business_payment_verifications VALUES (%s,%s,%s,'VERIFIED',"
            "7000,'forged-derived-record',%s,%s,%s)",
            (document["tenant_id"], document["payments"][1]["transaction_id"],
             document["customer_id"], current, current, current),
        )
        connection.execute(
            "INSERT INTO refund_eligibility VALUES (%s,'primary-refund',%s,%s,'VERIFIED',"
            "%s,'DUPLICATE_CHARGE',7000,'forged-derived-record',%s,%s,%s)",
            (document["ticket_id"], document["tenant_id"], document["customer_id"],
             document["payments"][1]["transaction_id"], current, current, current),
        )
    with pytest.raises(ToolExecutionError) as error:
        PostgresToolStore(database_url).execute("refund", payload, "0" * 64)
    assert error.value.reason_code.value == "BUSINESS_VERIFICATION_REJECTED"
    assert "失败支付 1 笔" in str(error.value)


def test_concurrent_tasks_with_same_saved_target_commit_one_refund(database_url):
    document, _ = fresh_case(database_url)
    payloads = [dispatch_fixture(database_url, document) for _ in range(4)]
    for payload in payloads:
        assert evaluate(database_url, payload.task_id)["status"] == "VERIFIED"

    def execute(payload):
        try:
            PostgresToolStore(database_url).execute("refund", payload, "0" * 64)
            return "COMMITTED"
        except ToolExecutionError as exc:
            return exc.reason_code.value

    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(execute, payloads))
    assert results.count("COMMITTED") == 1
    assert results.count("BUSINESS_ALREADY_PROCESSED") == 3
    with connect(database_url) as connection:
        assert connection.execute(
            "SELECT sum(amount_fen), count(*) FROM refunds WHERE ticket_id=%s",
            (document["ticket_id"],),
        ).fetchone() == (7000, 1)


def test_resolve_and_execution_do_not_deadlock_on_existing_action(database_url):
    document, _ = fresh_case(database_url)
    payload = dispatch_fixture(database_url, document)
    evaluate(database_url, payload.task_id)
    action_shared = Event()
    resolver_has_order = Event()

    class CoordinatedRegistry(BusinessActionRegistryService):
        def _resolve(self, connection, **kwargs):
            # The resolver already holds the order lock here.
            resolver_has_order.set()
            return super()._resolve(connection, **kwargs)

    def resolver():
        assert action_shared.wait(timeout=5)
        return CoordinatedRegistry(database_url).resolve_refund(
            ResolveRefundActionRequest(task_id=payload.task_id), current_time=now_unix(),
        )

    def tool_lock_order():
        # Reproduce the tool's action-SHARE then order-entity-lock sequence.
        context = TrustedTaskContext(
            document["tenant_id"], payload.task_id, document["ticket_id"], document["customer_id"],
        )
        from backend.business_action.eligibility import load_verified_refund_business

        with connect(database_url) as connection, connection.transaction():
            connection.execute("SET LOCAL lock_timeout='5s'")
            connection.execute(
                "SELECT 1 FROM business_actions WHERE business_action_id=%s FOR SHARE",
                (payload.business_action_id,),
            )
            action_shared.set()
            assert resolver_has_order.wait(timeout=5)
            return load_verified_refund_business(
                connection, context, trusted_action_slot=PRIMARY_REFUND_SLOT, for_execution=True,
            )

    with ThreadPoolExecutor(max_workers=2) as workers:
        tool = workers.submit(tool_lock_order)
        action = workers.submit(resolver)
        assert action.result(timeout=10)["business_action_id"] == payload.business_action_id
        assert tool.result(timeout=10).slot_amount_fen == 7000
