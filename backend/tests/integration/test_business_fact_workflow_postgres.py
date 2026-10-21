"""Facts-only cases through the parent-owned authenticated native HTTP stack.

The operator enters source records through the BFF, then authorizes and runs a
persistent four-Agent workflow. These tests use the declared deterministic rules
and real gateway/tool/receipt services; they do not claim cloud-model coverage.
The test process reads PostgreSQL for evidence and never inserts a ready-made
eligibility verdict, refund, receipt, or workflow event.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from uuid import uuid4

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import EXECUTION_RECEIPT
from backend.crypto.sm import sm3_hex, verify_payload
from backend.identity.key_registry import PostgresKeyRegistry
from backend.state.database import connect
from backend.tests.integration.test_authenticated_runtime_workflow_postgres import owned_stack

pytestmark = [pytest.mark.integration, pytest.mark.security]


def case_input(
    *, second_status: str = "SUCCESS", prior_refund: int = 0, payment_count: int = 2,
) -> dict:
    suffix = uuid4().hex
    return {
        "tenant_id": "tenant-A", "ticket_id": f"T-FACT-WORKFLOW-{suffix}",
        "customer_id": f"C-FACT-{suffix}", "order_id": f"ORDER-FACT-{suffix}",
        "order_amount_fen": 7000,
        # A claim is a customer's statement, not a trusted qualification result.
        "claim_text": "客户认为同一订单多扣了一笔款, 请核对实际支付后办理。",
        "payments": [
            {
                "transaction_id": f"PAY-FACT-{suffix}-{index + 1}", "amount_fen": 7000,
                "status": second_status if index == 1 else "SUCCESS",
                "refunded_amount_fen": prior_refund if index == 1 else 0,
            }
            for index in range(payment_count)
        ],
        "cloud_shareable": False,
    }


@contextmanager
def operator_client(ui_url: str) -> Iterator[httpx.Client]:
    with httpx.Client(base_url=ui_url, timeout=30, trust_env=False) as client:
        anonymous = client.get("/api/tasks")
        assert anonymous.status_code == 401
        assert anonymous.json()["reason_code"] == "OPERATOR_SESSION_REQUIRED"
        session = client.post("/api/operator-session", json={
            "launch_token": os.environ["AGENTGUARD_OPERATOR_SESSION_SECRET"],
        })
        assert session.status_code == 200 and session.json() == {"authenticated": True}
        yield client


def create_and_authorize(client: httpx.Client, request: dict, *, budget: int) -> tuple[str, dict]:
    created_case = client.post("/api/business/cases", json=request)
    assert created_case.status_code == 201, created_case.text
    case = created_case.json()
    assert case["business_facts"] == {
        "schema_version": "1.0",
        "order": {
            "order_id": request["order_id"], "amount_fen": request["order_amount_fen"],
            "currency": "CNY",
        },
        "payments": request["payments"], "claim_text": request["claim_text"],
    }
    assert case["facts_hash"] == sm3_hex(canonicalize(case["business_facts"]))
    assert "business_verification" not in case
    created_task = client.post("/api/tasks", json={
        "tenant_id": request["tenant_id"], "ticket_id": request["ticket_id"],
        "customer_id": request["customer_id"], "refund_total_fen": budget,
        "max_tool_calls": 4, "expires_in_seconds": 1800,
    })
    assert created_task.status_code == 201, created_task.text
    task_id = created_task.json()["task_id"]
    authorized = client.post(f"/api/tasks/{task_id}/authorize", json={
        "confirmed": True, "confirmer_id": "policy-refund-v1",
        "holder_agent_id": "agent-coordinator", "holder_key_id": "agent-coordinator-key-01",
        "delegation_depth": 2,
    })
    assert authorized.status_code == 201, authorized.text
    snapshot = client.get(f"/api/tasks/{task_id}")
    assert snapshot.status_code == 200, snapshot.text
    body = snapshot.json()
    assert body["business_context"]["ticket"]["business_facts"] == case["business_facts"]
    assert body["business_context"]["ticket"]["business_verification"] is None
    assert body["workflow_runs"] == []
    assert body["business_effects"]["refunds"] == []
    assert body["business_effects"]["notifications"] == []
    return task_id, case


def assert_no_initial_verdict(database: str, request: dict, task_id: str) -> None:
    with connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM refund_eligibility WHERE ticket_id = %s",
            (request["ticket_id"],),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM business_payment_verifications WHERE tenant_id = %s "
            "AND original_transaction_id = ANY(%s)",
            (request["tenant_id"], [payment["transaction_id"] for payment in request["payments"]]),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM business_fact_evaluations WHERE task_id = %s", (task_id,),
        ).fetchone() == (0,)


def terminal_snapshot(client: httpx.Client, task_id: str, run_id: str) -> dict:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        response = client.get(f"/api/tasks/{task_id}")
        assert response.status_code == 200, response.text
        snapshot = response.json()
        runs = snapshot["workflow_runs"]
        assert len(runs) == 1 and runs[0]["run_id"] == run_id
        if runs[0]["state"] not in {"QUEUED", "RUNNING"}:
            return snapshot
        time.sleep(0.15)
    pytest.fail(f"facts workflow did not finish within 90 seconds: {run_id}")


def assert_signed_receipts(connection, task_id: str, snapshot: dict, count: int) -> None:
    assert len(snapshot["receipts"]) == count
    for receipt in snapshot["receipts"]:
        assert receipt["signature"]["valid"] is True
        assert all(receipt["source_verification"][name] is True for name in (
            "schema_valid", "stored_hash_valid", "row_binding_valid", "execution_binding_valid",
        ))
    rows = connection.execute(
        "SELECT r.signed_receipt, r.created_at, r.receipt_status, e.execution_id, "
        "e.initial_request_id, e.request_hash, e.credential_chain_hash, e.tool_service, "
        "e.tool_name, e.tool_version, e.parameter_hash, e.business_action_id, "
        "e.business_effect_id, e.business_result_hash, e.result "
        "FROM execution_receipts r JOIN execution_records e USING (execution_id) "
        "WHERE e.task_id = %s", (task_id,),
    ).fetchall()
    assert len(rows) == count
    fields = (
        "execution_id", "request_id", "request_hash", "credential_chain_hash",
        "tool_service", "tool_name", "tool_version", "parameter_hash",
        "business_action_id", "business_effect_id", "business_result_hash",
    )
    schemas = SchemaStore()
    for signed, registered_at, status, *values in rows:
        assert status == "SIGNED"
        schemas.validate("execution-receipt.schema.json", signed)
        payload, signature = signed["payload"], signed["signature"]
        expected = dict(zip(fields, values[:-1], strict=True))
        assert all(payload[name] == value for name, value in expected.items())
        assert payload["business_result_hash"] == sm3_hex(canonicalize(values[-1]))
        assert payload["task_id"] == task_id and payload["tenant_id"] == "tenant-A"
        assert payload["decision"] == "ALLOW" and payload["reason_code"] == "ALLOWED"
        assert signature["signed_at"] == payload["receipt_issued_at"]
        key = PostgresKeyRegistry.resolve_for_verification_with_connection(
            connection, signature["key_id"], expected_subject_id="receipt-service",
            expected_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
            signed_at=signature["signed_at"], trusted_registered_at=registered_at,
        )
        assert verify_payload(
            payload, signature, domain_separator=EXECUTION_RECEIPT,
            expected_key_id=key.key_id, expected_key_purpose=key.purpose,
            public_key_hex=key.public_key_hex,
        )


@pytest.mark.parametrize(
    ("second_status", "prior_refund", "payment_count", "budget", "qualification",
     "qualification_reason", "amount", "workflow_reason"),
    [
        pytest.param("SUCCESS", 0, 2, 7000, "VERIFIED", "DUPLICATE_FULL_CHARGE", 7000, None,
                     id="two-full-payments-refund-70"),
        pytest.param("SUCCESS", 2000, 2, 7000, "VERIFIED", "DUPLICATE_FULL_CHARGE", 5000, None,
                     id="prior-refund-20-now-refund-50"),
        pytest.param("FAILED", 0, 2, 7000, "REJECTED", "NO_EXCESS_SUCCESSFUL_CHARGE", 0,
                     "BUSINESS_VERIFICATION_REJECTED", id="failed-payment-is-not-a-second-charge"),
        pytest.param("PROCESSING", 0, 2, 7000, "PENDING", "PAYMENT_STILL_PROCESSING", 0,
                     "BUSINESS_VERIFICATION_PENDING", id="processing-payment-awaits-verification"),
        pytest.param("SUCCESS", 0, 2, 5000, "VERIFIED", "DUPLICATE_FULL_CHARGE", 7000,
                     "PLANNER_DECLINED", id="eligible-rule-declines-insufficient-authorization"),
        pytest.param("SUCCESS", 0, 3, 7000, "PENDING", "MULTIPLE_EXTRA_PAYMENTS", 0,
                     "BUSINESS_VERIFICATION_PENDING", id="three-payments-need-manual-review"),
    ],
)
def test_fact_case_authenticated_persistent_four_agent_workflow(
    second_status: str, prior_refund: int, payment_count: int, budget: int,
    qualification: str, qualification_reason: str, amount: int, workflow_reason: str | None,
):
    database, _ui_database, ui_url, _coordinator_url = owned_stack()
    request = case_input(
        second_status=second_status, prior_refund=prior_refund, payment_count=payment_count,
    )
    with operator_client(ui_url) as client:
        task_id, case = create_and_authorize(client, request, budget=budget)
        assert_no_initial_verdict(database, request, task_id)
        queued = client.post(f"/api/tasks/{task_id}/workflow", json={
            "runtime_mode": "deterministic", "scenario": "normal",
        })
        assert queued.status_code == 202, queued.text
        started = queued.json()
        assert started["state"] == "QUEUED" and started["runtime_mode"] == "deterministic"
        snapshot = terminal_snapshot(client, task_id, started["run_id"])

    run = snapshot["workflow_runs"][0]
    assert run["state"] == ("COMPLETED" if workflow_reason is None else "DENIED"), run
    assert run["reason_code"] == workflow_reason
    events = run["events"]
    assert {event["agent_id"] for event in events} == {
        "agent-coordinator", "agent-knowledge", "agent-case", "agent-refund",
    }
    planned = [
        event for event in events
        if event["agent_id"] == "agent-refund" and event["action"] == "plan_started"
    ]
    assert len(planned) == 1
    inputs = planned[0]["details"]["input"]
    assert inputs["authorized_task"] == {
        "ticket_id": request["ticket_id"], "customer_id": request["customer_id"],
        "refund_limit_fen": budget,
    }
    assert inputs["committed_refund"] == {}
    assert inputs["ticket"]["business_facts"] == case["business_facts"]
    assert inputs["ticket"]["facts_hash"] == case["facts_hash"]
    assert set(inputs["ticket"]) <= {
        "ticket_id", "tenant_id", "customer_id", "status", "facts_hash", "business_facts",
    }
    decisions = [
        event for event in events
        if event["agent_id"] == "agent-refund" and event["action"] == "plan"
    ]
    evaluations = [
        event for event in events
        if event["agent_id"] == "agent-refund" and event["action"] == "business_verification"
    ]
    assert len(decisions) == len(evaluations) == 1
    assert planned[0]["sequence"] < decisions[0]["sequence"] < evaluations[0]["sequence"]
    assert decisions[0]["details"]["provider"] == "rules"
    assert decisions[0]["details"]["source"] == "raw-business-facts-rules"
    evaluation = evaluations[0]["details"]
    assert (evaluation["status"], evaluation["reason_code"]) == (
        qualification, qualification_reason,
    )
    assert evaluation["refundable_amount_fen"] == amount
    assert evaluation["facts_hash"] == case["facts_hash"]
    assert f"FACTS:{case['facts_hash']}" in evaluation["evidence_ids"]
    if qualification == "VERIFIED":
        assert evaluation["original_transaction_id"] == request["payments"][1]["transaction_id"]
    else:
        assert evaluation["original_transaction_id"] is None
    if second_status == "FAILED":
        assert "失败支付 1 笔" in evaluation["reason"]
        assert "70.00 元未扣款" in evaluation["reason"]
        assert "净扣款没有超过订单应付金额" in evaluation["reason"]
    elif second_status == "PROCESSING":
        assert "支付仍在处理中" in evaluation["reason"]
    elif payment_count == 3:
        assert "当前自动流程不支持在同一任务中安全拆分多笔退款" in evaluation["reason"]
        assert "需人工逐笔核验" in evaluation["reason"]
    if workflow_reason == "PLANNER_DECLINED":
        # Independent eligibility passes; stopping here is a proposal/authorization
        # limit decision. No refund request reached the gateway, so this does not
        # demonstrate a gateway denial of an unauthorized refund.
        assert decisions[0]["status"] == "DENIED"
        assert "超过任务授权上限" in decisions[0]["details"]["message"]
        assert decisions[0]["details"]["intents"] == []
        assert evaluations[0]["status"] == "COMPLETED"
    elif workflow_reason is None:
        assert decisions[0]["details"]["intents"][0]["parameters"]["amount_fen"] == amount

    with connect(database) as connection:
        assert connection.execute(
            "SELECT state, reason_code FROM agent_workflow_runs WHERE task_id = %s", (task_id,),
        ).fetchall() == [(run["state"], workflow_reason)]
        assert set(connection.execute(
            "SELECT holder_agent_id, credential_type, delegation_depth "
            "FROM credentials WHERE task_id = %s", (task_id,),
        ).fetchall()) == {
            ("agent-coordinator", "ROOT", 2), ("agent-knowledge", "DELEGATION", 1),
            ("agent-case", "DELEGATION", 1), ("agent-refund", "DELEGATION", 0),
        }
        saved = connection.execute(
            "SELECT result FROM business_fact_evaluations WHERE task_id = %s", (task_id,),
        ).fetchall()
        assert len(saved) == 1
        assert saved[0][0] == {key: value for key, value in evaluation.items() if key != "stage"}
        assert snapshot["business_context"]["ticket"]["business_verification"] == saved[0][0]
        assert connection.execute(
            "SELECT facts, facts_hash FROM business_case_facts WHERE ticket_id = %s",
            (request["ticket_id"],),
        ).fetchone() == (case["business_facts"], case["facts_hash"])
        refunds = connection.execute(
            "SELECT refund_id, customer_id, original_transaction_id, amount_fen, status "
            "FROM refunds WHERE task_id = %s", (task_id,),
        ).fetchall()
        notifications = connection.execute(
            "SELECT related_business_effect_id, customer_id, template_id, status "
            "FROM notifications WHERE task_id = %s", (task_id,),
        ).fetchall()
        expected_executions = {
            ("knowledge.read_associated", "COMMITTED", "ALLOW"),
            ("ticket.read", "COMMITTED", "ALLOW"),
        }
        if workflow_reason is None:
            assert len(refunds) == 1 and refunds[0][1:] == (
                request["customer_id"], request["payments"][1]["transaction_id"],
                amount, "COMMITTED",
            )
            assert notifications == [(
                refunds[0][0], request["customer_id"], "REFUND_SUCCESS", "SENT",
            )]
            expected_executions |= {
                ("refund.create", "COMMITTED", "ALLOW"),
                ("notification.send_template", "COMMITTED", "ALLOW"),
            }
        else:
            assert refunds == notifications == []
        executions = connection.execute(
            "SELECT tool_name, state, decision FROM execution_records WHERE task_id = %s",
            (task_id,),
        ).fetchall()
        assert len(executions) == len(expected_executions)
        assert set(executions) == expected_executions
        assert connection.execute(
            "SELECT count(*) FROM credential_budget_state b JOIN credentials c "
            "USING (credential_id) WHERE c.task_id = %s AND (b.reserved_value <> 0 "
            "OR b.committed_value < 0 OR b.committed_value > b.limit_value)", (task_id,),
        ).fetchone() == (0,)
        assert_signed_receipts(connection, task_id, snapshot, len(expected_executions))


def test_authorizing_a_raw_case_does_not_precompute_business_result_or_execute_refund():
    database, _ui_database, ui_url, _coordinator_url = owned_stack()
    request = case_input(second_status="FAILED")
    with operator_client(ui_url) as client:
        task_id, _case = create_and_authorize(client, request, budget=7000)
    assert_no_initial_verdict(database, request, task_id)
    with connect(database) as connection:
        assert connection.execute(
            "SELECT status FROM tasks WHERE task_id = %s", (task_id,),
        ).fetchone() == ("AUTHORIZED",)
        for table in ("execution_records", "refunds", "notifications", "agent_workflow_runs"):
            assert connection.execute(
                f"SELECT count(*) FROM {table} WHERE task_id = %s", (task_id,),
            ).fetchone() == (0,)
