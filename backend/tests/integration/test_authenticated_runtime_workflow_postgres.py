"""Normal operator/BFF workflow on the parent-owned authenticated native stack.

All four Agents, HMAC admission edges, tools and receipts use live native HTTP.
Only a disposable localhost database may receive the fresh business fixture.
The workflow is deterministic; this acceptance never invokes a cloud model.
"""

from __future__ import annotations

import os
import re
import time
from urllib.parse import urlsplit

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import EXECUTION_RECEIPT
from backend.crypto.sm import sm3_hex, verify_payload
from backend.identity.key_registry import PostgresKeyRegistry
from backend.state.database import connect
from backend.tests.business_fixtures import verified_postgres_case
from backend.ui_api.store import UiReadStore

pytestmark = [pytest.mark.integration, pytest.mark.security]
REQUIRED_ENV = (
    "AGENTGUARD_DATABASE_URL", "AGENTGUARD_UI_DATABASE_URL", "AGENTGUARD_UI_API_URL",
    "AGENTGUARD_COORDINATOR_AGENT_URL", "AGENTGUARD_OPERATOR_AUTH_REQUIRED",
    "AGENTGUARD_OPERATOR_SESSION_SECRET",
)
if not all(os.getenv(name) for name in REQUIRED_ENV):
    pytest.skip(
        "parent-owned authenticated native stack is not configured", allow_module_level=True,
    )


def owned_stack() -> tuple[str, str, str, str]:
    assert os.environ["AGENTGUARD_OPERATOR_AUTH_REQUIRED"] == "true"
    database, ui_database, ui_url, coordinator_url = (
        os.environ[name] for name in REQUIRED_ENV[:4]
    )
    main, reader = urlsplit(database), urlsplit(ui_database)
    for target in (main, reader, urlsplit(ui_url), urlsplit(coordinator_url)):
        assert target.hostname in {"127.0.0.1", "localhost", "::1"}, (
            "authenticated workflow acceptance requires the parent-owned localhost stack"
        )
    assert re.fullmatch(r"/agentguard_test_backend_[a-f0-9]+", main.path)
    assert (reader.hostname, reader.port, reader.path) == (main.hostname, main.port, main.path)
    return database, ui_database, ui_url, coordinator_url


def completed_snapshot(client: httpx.Client, task_id: str, run_id: str) -> dict:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        response = client.get(f"/api/tasks/{task_id}")
        assert response.status_code == 200, response.text
        snapshot = response.json()
        runs = snapshot["workflow_runs"]
        assert len(runs) == 1 and runs[0]["run_id"] == run_id
        if runs[0]["state"] not in {"QUEUED", "RUNNING"}:
            assert runs[0]["state"] == "COMPLETED", runs[0]
            assert runs[0]["reason_code"] is None
            return snapshot
        time.sleep(0.15)
    pytest.fail(f"authenticated workflow did not finish within 90 seconds: {run_id}")


def test_operator_bff_authenticated_four_agent_workflow_commits_once_and_verifies_receipts():
    database, ui_database, ui_url, coordinator_url = owned_stack()
    business = verified_postgres_case(database)
    workflow = {"runtime_mode": "deterministic", "scenario": "normal"}
    with httpx.Client(base_url=ui_url, timeout=30, trust_env=False) as client:
        anonymous = client.get("/api/tasks")
        assert anonymous.status_code == 401
        assert anonymous.json()["reason_code"] == "OPERATOR_SESSION_REQUIRED"
        session = client.post("/api/operator-session", json={
            "launch_token": os.environ["AGENTGUARD_OPERATOR_SESSION_SECRET"],
        })
        assert session.status_code == 200 and session.json() == {"authenticated": True}
        created = client.post("/api/tasks", json={
            "tenant_id": "tenant-A", "ticket_id": business["ticket_id"],
            "customer_id": "C9527", "refund_total_fen": 7000,
            "max_tool_calls": 4, "expires_in_seconds": 1800,
        })
        assert created.status_code == 201, created.text
        task_id = created.json()["task_id"]
        authorized = client.post(f"/api/tasks/{task_id}/authorize", json={
            "confirmed": True, "confirmer_id": "policy-refund-v1",
            "holder_agent_id": "agent-coordinator", "holder_key_id": "agent-coordinator-key-01",
            "delegation_depth": 2,
        })
        assert authorized.status_code == 201, authorized.text
        root = UiReadStore(ui_database).root_credential(task_id)
        assert root is not None
        with httpx.Client(base_url=coordinator_url, timeout=15, trust_env=False) as direct:
            unsigned = direct.post("/agents/workflows", json={
                "credential_chain": [root], "context": {
                    "ticket_id": business["ticket_id"], "customer_id": "C9527",
                    "refund_amount_fen": 7000, **workflow,
                },
            })
        assert unsigned.status_code == 403
        assert unsigned.json()["detail"]["reason_code"] == "TOOL_NOT_ALLOWED"
        queued = client.post(f"/api/tasks/{task_id}/workflow", json=workflow)
        assert queued.status_code == 202, queued.text
        started = queued.json()
        assert started["task_id"] == task_id and started["runtime_mode"] == "deterministic"
        assert started["state"] == "QUEUED"
        run_id = started["run_id"]
        snapshot = completed_snapshot(client, task_id, run_id)

    roles = {"agent-coordinator", "agent-knowledge", "agent-case", "agent-refund"}
    assert {event["agent_id"] for event in snapshot["workflow_runs"][0]["events"]} == roles
    assert all(receipt["signature"]["valid"] is True for receipt in snapshot["receipts"])
    assert len(snapshot["receipts"]) == 4
    for receipt in snapshot["receipts"]:
        assert all(receipt["source_verification"][name] is True for name in (
            "schema_valid", "stored_hash_valid", "row_binding_valid", "execution_binding_valid",
        ))

    schemas = SchemaStore()
    with connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM agent_workflow_runs WHERE task_id = %s", (task_id,),
        ).fetchone() == (1,)
        holders = connection.execute(
            "SELECT holder_agent_id, credential_type, delegation_depth "
            "FROM credentials WHERE task_id = %s", (task_id,),
        ).fetchall()
        assert set(holders) == {
            ("agent-coordinator", "ROOT", 2), ("agent-knowledge", "DELEGATION", 1),
            ("agent-case", "DELEGATION", 1), ("agent-refund", "DELEGATION", 0),
        }
        executions = connection.execute(
            "SELECT tool_name, state, decision FROM execution_records WHERE task_id = %s",
            (task_id,),
        ).fetchall()
        assert len(executions) == 4 and set(executions) == {
            ("knowledge.read_associated", "COMMITTED", "ALLOW"),
            ("ticket.read", "COMMITTED", "ALLOW"),
            ("refund.create", "COMMITTED", "ALLOW"),
            ("notification.send_template", "COMMITTED", "ALLOW"),
        }
        refunds = connection.execute(
            "SELECT refund_id, customer_id, amount_fen, status FROM refunds WHERE task_id = %s",
            (task_id,),
        ).fetchall()
        assert len(refunds) == 1 and refunds[0][1:] == ("C9527", 7000, "COMMITTED")
        notices = connection.execute(
            "SELECT related_business_effect_id, customer_id, template_id, status "
            "FROM notifications WHERE task_id = %s", (task_id,),
        ).fetchall()
        assert notices == [(refunds[0][0], "C9527", "REFUND_SUCCESS", "SENT")]
        assert connection.execute(
            "SELECT count(*) FROM credential_budget_state b JOIN credentials c "
            "USING (credential_id) WHERE c.task_id = %s AND (b.reserved_value <> 0 "
            "OR b.committed_value < 0 OR b.committed_value > b.limit_value)", (task_id,),
        ).fetchone() == (0,)
        receipts = connection.execute(
            "SELECT r.signed_receipt, r.created_at, r.receipt_status, e.execution_id, "
            "e.initial_request_id, e.request_hash, e.credential_chain_hash, e.tool_service, "
            "e.tool_name, e.tool_version, e.parameter_hash, e.business_action_id, "
            "e.business_effect_id, e.business_result_hash, e.result "
            "FROM execution_receipts r JOIN execution_records e USING (execution_id) "
            "WHERE e.task_id = %s", (task_id,),
        ).fetchall()
        assert len(receipts) == 4
        fields = (
            "execution_id", "request_id", "request_hash", "credential_chain_hash",
            "tool_service", "tool_name", "tool_version", "parameter_hash",
            "business_action_id", "business_effect_id", "business_result_hash",
        )
        for signed, registered_at, status, *values in receipts:
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
