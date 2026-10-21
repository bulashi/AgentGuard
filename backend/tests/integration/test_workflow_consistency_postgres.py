from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.crypto.domains import EXECUTION_RECEIPT
from backend.crypto.sm import verify_payload
from backend.identity.key_registry import PostgresKeyRegistry
from backend.state.database import connect
from backend.tests.business_fixtures import verified_postgres_case

pytestmark = pytest.mark.integration
DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")
COORDINATOR_URL = os.getenv("AGENTGUARD_COORDINATOR_AGENT_URL")
if not all((DATABASE_URL, AUTHORITY_URL, COORDINATOR_URL)):
    pytest.skip("native integration services are not configured", allow_module_level=True)


def authorized_root(*, chinese: bool = False) -> dict:
    assert DATABASE_URL is not None
    case = verified_postgres_case(
        DATABASE_URL,
        tenant_id="演示企业" if chinese else "tenant-A",
        customer_id="张三" if chinese else "C9527",
    )
    with httpx.Client(base_url=AUTHORITY_URL, timeout=20, trust_env=False) as client:
        created = client.post(
            "/tasks",
            json={
                "tenant_id": "演示企业" if chinese else "tenant-A",
                "ticket_id": case["ticket_id"],
                "customer_id": "张三" if chinese else "C9527",
                "refund_total_fen": 7000,
                "max_tool_calls": 4,
                "expires_in_seconds": 1800,
            },
        )
        assert created.status_code == 201, created.text
        authorized = client.post(
            f"/tasks/{created.json()['task_id']}/authorize",
            json={
                "confirmed": True,
                "confirmer_id": "policy-refund-v1",
                "holder_agent_id": "agent-coordinator",
                "holder_key_id": "agent-coordinator-key-01",
                "delegation_depth": 2,
            },
        )
        assert authorized.status_code == 201, authorized.text
        return authorized.json()


def start(root: dict, scenario: str = "normal") -> httpx.Response:
    refund_capability = next(
        item for item in root["payload"]["capabilities"] if item["tool"] == "refund.create"
    )
    with httpx.Client(base_url=COORDINATOR_URL, timeout=60, trust_env=False) as client:
        return client.post(
            "/agents/workflows",
            json={
                "credential_chain": [root],
                "context": {
                    "ticket_id": refund_capability["resources"]["ticket_ids"][0],
                    "customer_id": refund_capability["resources"]["customer_ids"][0],
                    "refund_amount_fen": 7000,
                    "runtime_mode": "deterministic",
                    "scenario": scenario,
                },
            },
        )


def completed(run_id: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        with connect(DATABASE_URL) as connection:
            row = connection.execute(
                "SELECT state, reason_code FROM agent_workflow_runs WHERE run_id = %s",
                (run_id,),
            ).fetchone()
        if row and row[0] not in {"QUEUED", "RUNNING"}:
            assert row == ("COMPLETED", None), row
            return
        time.sleep(0.15)
    pytest.fail(f"workflow did not finish within 90 seconds: {run_id}")


def verify_task(root: dict, run_id: str, scenario: str) -> None:
    task_id = root["payload"]["task_id"]
    customer = next(
        item for item in root["payload"]["capabilities"] if item["tool"] == "refund.create"
    )["resources"]["customer_ids"][0]
    with connect(DATABASE_URL) as connection:
        events = connection.execute(
            "SELECT sequence, agent_id, action, status, details FROM agent_workflow_events "
            "WHERE run_id = %s ORDER BY sequence",
            (run_id,),
        ).fetchall()
        refunds = connection.execute(
            "SELECT refund_id, customer_id, amount_fen, status, created_at FROM refunds "
            "WHERE task_id = %s",
            (task_id,),
        ).fetchall()
        notices = connection.execute(
            "SELECT related_business_effect_id, customer_id, template_id, status, created_at "
            "FROM notifications WHERE task_id = %s",
            (task_id,),
        ).fetchall()
        executions = connection.execute(
            "SELECT state, decision FROM execution_records WHERE task_id = %s",
            (task_id,),
        ).fetchall()
        receipts = connection.execute(
            "SELECT r.signed_receipt FROM execution_receipts r JOIN execution_records e "
            "USING (execution_id) WHERE e.task_id = %s",
            (task_id,),
        ).fetchall()
        invalid_budgets = connection.execute(
            "SELECT count(*) FROM credential_budget_state b "
            "JOIN credentials c USING (credential_id) "
            "WHERE c.task_id = %s AND (b.reserved_value <> 0 OR b.committed_value < 0 "
            "OR b.committed_value > b.limit_value)",
            (task_id,),
        ).fetchone()
        runs = connection.execute(
            "SELECT count(*) FROM agent_workflow_runs WHERE task_id = %s",
            (task_id,),
        ).fetchone()
    assert runs == (1,)
    assert len(events) == 36
    assert [event[0] for event in events] == list(range(1, 37))
    plans = [event for event in events if event[2] == "plan"]
    assert [event[4]["stage"] for event in plans] == [
        "coordinate",
        "knowledge_read",
        "knowledge_summary",
        "case_read",
        "refund",
        "case_notify",
    ]
    assert all(event[3] == "COMPLETED" and event[4]["decision"] == "propose" for event in plans)

    def sequence(action: str, *, agent: str | None = None, tool: str | None = None) -> int:
        matches = [
            event
            for event in events
            if event[2] == action
            and (agent is None or event[1] == agent)
            and (tool is None or event[4].get("tool") == tool)
        ]
        assert len(matches) == 1, matches
        return matches[0][0]

    assert sequence("agent_finished", agent="agent-knowledge") < sequence(
        "agent_started", agent="agent-case"
    )
    assert sequence("call_tool", tool="ticket.read") < sequence(
        "agent_started", agent="agent-refund"
    )
    assert sequence("gateway_decision", tool="refund.create") < sequence(
        "call_tool", tool="refund.create"
    )
    assert sequence("call_tool", tool="refund.create") < plans[-1][0]
    assert plans[-1][0] < sequence("gateway_request", tool="notification.send_template")
    assert plans[-1][4]["input"]["committed_refund"]["refund_id"] == refunds[0][0]
    knowledge = next(event[4] for event in events if event[2] == "knowledge_result")
    assert bool(knowledge.get("injection_applied")) == (scenario == "policy_injection")
    assert len(refunds) == len(notices) == 1
    assert refunds[0][1:4] == (customer, 7000, "COMMITTED")
    assert notices[0][:4] == (refunds[0][0], customer, "REFUND_SUCCESS", "SENT")
    assert notices[0][4] >= refunds[0][4]
    assert executions == [("COMMITTED", "ALLOW")] * 4
    assert invalid_budgets == (0,)
    assert len(receipts) == 4
    registry = PostgresKeyRegistry(DATABASE_URL)
    for (receipt,) in receipts:
        key = registry.get(receipt["signature"]["key_id"])
        assert receipt["payload"]["task_id"] == task_id
        assert receipt["payload"]["tenant_id"] == root["payload"]["tenant_id"]
        assert verify_payload(
            receipt["payload"],
            receipt["signature"],
            domain_separator=EXECUTION_RECEIPT,
            expected_key_id=key.key_id,
            expected_key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
            public_key_hex=key.public_key_hex,
        )


@pytest.mark.parametrize("scenario", ["normal", "policy_injection"])
@pytest.mark.parametrize("chinese", [False, True])
def test_persisted_workflow_dependencies_and_real_business_effects(
    scenario: str, chinese: bool
) -> None:
    root = authorized_root(chinese=chinese)
    response = start(root, scenario)
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    completed(run_id)
    verify_task(root, run_id, scenario)


@pytest.mark.parametrize("workers", [8, 16])
def test_concurrent_same_task_start_has_one_run_and_one_refund(workers: int) -> None:
    root = authorized_root()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        responses = list(pool.map(lambda _: start(root), range(workers)))
    accepted = [response for response in responses if response.status_code == 202]
    assert len(accepted) == 1, [response.status_code for response in responses]
    rejected = [response for response in responses if response.status_code != 202]
    assert len(rejected) == workers - 1
    assert all(
        response.status_code == 409 and response.json()["reason_code"] == "WORKFLOW_ALREADY_EXISTS"
        for response in rejected
    )
    run_id = accepted[0].json()["run_id"]
    completed(run_id)
    verify_task(root, run_id, "normal")


def test_concurrent_distinct_tasks_do_not_cross_result_dependencies() -> None:
    roots = [authorized_root(), authorized_root()]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(start, roots))
    for root, response in zip(roots, responses, strict=True):
        assert response.status_code == 202, response.text
        run_id = response.json()["run_id"]
        completed(run_id)
        verify_task(root, run_id, "normal")
