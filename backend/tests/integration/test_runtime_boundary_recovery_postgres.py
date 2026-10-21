"""Runtime boundaries and same-process recovery on the parent-owned native test stack.

Faults are injected at HTTP/tool response boundaries. Admission, tools, PostgreSQL,
reconciliation, result retrieval and signed receipts use their real implementations.
No model is invoked and no test is permitted to use a persistent production database.
"""

from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from urllib.parse import urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

import backend.gateway.app as gateway_app
from backend.admission.service import AdmissionService
from backend.agent_runtime.app import make_app as make_agent_app
from backend.agent_runtime.contracts import AgentContext, PlanDecision, ToolIntent
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.config.settings import Settings
from backend.gateway.dispatch import GatewayDispatchService, _ToolDispatchFailure
from backend.gateway.service import SecureGatewayService
from backend.state.database import connect
from backend.tests.business_fixtures import verified_postgres_case

pytestmark = [pytest.mark.integration]

DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
REQUIRED_ENV = (
    "AGENTGUARD_AUTHORITY_URL", "AGENTGUARD_BUSINESS_ACTION_REGISTRY_URL",
    "AGENTGUARD_RECOVERY_URL", "AGENTGUARD_RECEIPT_SERVICE_URL",
    "AGENTGUARD_COORDINATOR_DELEGATION_URL", "AGENTGUARD_CASE_DELEGATION_URL",
    "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE", "AGENTGUARD_HOLDER_PRIVATE_KEY_FILE",
    "AGENTGUARD_TICKET_TOOL_URL", "AGENTGUARD_KNOWLEDGE_TOOL_URL",
    "AGENTGUARD_REFUND_TOOL_URL", "AGENTGUARD_NOTIFICATION_TOOL_URL",
)
if not DATABASE_URL or not all(os.getenv(name) for name in REQUIRED_ENV):
    pytest.skip("parent-owned native integration stack is not configured", allow_module_level=True)


def isolated_database() -> str:
    assert DATABASE_URL
    target = urlsplit(DATABASE_URL)
    assert target.hostname in {"localhost", "127.0.0.1", "::1"}
    assert re.fullmatch(r"/agentguard_test_backend_[a-f0-9]+", target.path), (
        "runtime boundary tests require the parent-owned disposable PostgreSQL database"
    )
    return DATABASE_URL


def authorized_request():
    database = isolated_database()
    business = verified_postgres_case(database)
    with httpx.Client(base_url=os.environ["AGENTGUARD_AUTHORITY_URL"], trust_env=False) as client:
        created = client.post("/tasks", json={
            "tenant_id": "tenant-A", "ticket_id": business["ticket_id"],
            "customer_id": business["customer_id"], "refund_total_fen": 7000,
            "max_tool_calls": 4, "expires_in_seconds": 1800,
        })
        assert created.status_code == 201, created.text
        task_id = created.json()["task_id"]
        issued = client.post(f"/tasks/{task_id}/authorize", json={
            "confirmed": True, "confirmer_id": "policy-refund-v1",
            "holder_agent_id": "agent-coordinator", "holder_key_id": "agent-coordinator-key-01",
            "delegation_depth": 2,
        })
        assert issued.status_code == 201, issued.text
    context = AgentContext(
        ticket_id=str(business["ticket_id"]), customer_id=str(business["customer_id"]),
        refund_amount_fen=7000, runtime_mode="deterministic",
    )
    return issued.json(), context, task_id


def runtime(role: str) -> AgentRuntimeService:
    private_root = Path(os.environ["AGENTGUARD_HOLDER_PRIVATE_KEY_FILE"]).parent
    settings = Settings(
        agent_role=role, agent_id=f"agent-{role}", agent_key_id=f"agent-{role}-key-01",
        agent_private_key_file=str(private_root / f"agent-{role}.private"),
        receipt_public_key_file=str(private_root.parent / "public" / "receipt.public"),
        gateway_url="http://runtime-gateway.test",
        coordinator_agent_url="http://runtime-coordinator.test",
        knowledge_agent_url="http://runtime-knowledge.test",
        case_agent_url="http://runtime-case.test", refund_agent_url="http://runtime-refund.test",
        business_action_registry_url=os.environ["AGENTGUARD_BUSINESS_ACTION_REGISTRY_URL"],
        agent_delegation_url=os.getenv(f"AGENTGUARD_{role.upper()}_DELEGATION_URL", ""),
        workflow_database_url=isolated_database() if role == "coordinator" else "",
        cloud_llm_enabled=False, llm_mode="deterministic", internal_auth_required=False,
        internal_auth_service_id=f"agent-{role}", internal_auth_keys="{}",
        agent_request_timeout_seconds=15, tool_request_timeout_seconds=15,
        recovery_interval_seconds=1, recovery_deadline_seconds=20, workflow_timeout_seconds=60,
    )
    return AgentRuntimeService(settings)


@pytest.mark.parametrize("fault", ["unknown-tool-response", "temporary-receipt-503"])
def test_same_running_workflow_continues_after_real_recovery_to_one_notification(
    fault, monkeypatch,
):
    root, context, task_id = authorized_request()
    database = isolated_database()
    gateway_settings = Settings(
        database_url=database, internal_auth_required=False,
        receipt_service_url=os.environ["AGENTGUARD_RECEIPT_SERVICE_URL"],
        internal_auth_service_id="secure-gateway", internal_auth_keys="{}",
    )
    gateway = SecureGatewayService(database_url=database)
    dispatcher = GatewayDispatchService(
        gateway, AdmissionService(gateway), gateway_key_id="gateway-key-01",
        gateway_private_key_file=os.environ["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"],
        tool_urls={
            ("ticket-service", "ticket.read"): os.environ["AGENTGUARD_TICKET_TOOL_URL"],
            ("knowledge-service", "knowledge.read_associated"): os.environ[
                "AGENTGUARD_KNOWLEDGE_TOOL_URL"
            ],
            ("refund-service", "refund.create"): os.environ["AGENTGUARD_REFUND_TOOL_URL"],
            ("notification-service", "notification.send_template"): os.environ[
                "AGENTGUARD_NOTIFICATION_TOOL_URL"
            ],
        },
    )
    ready = Event()
    dispatches = []
    failed = {"once": False, "execution_id": None}
    real_tool = dispatcher._call_tool
    real_dispatch = dispatcher.dispatch

    def tool_response_loss(envelope):
        response = real_tool(envelope)
        if envelope.payload.tool_name == "refund.create" and not failed["once"] and (
            fault == "unknown-tool-response"
        ):
            failed["once"] = True
            failed["execution_id"] = envelope.payload.execution_id
            raise _ToolDispatchFailure("controlled loss after the real refund tool committed")
        return response

    def recorded_dispatch(request, *, current_time):
        dispatches.append(request.tool_name)
        response = real_dispatch(request, current_time=current_time)
        if request.tool_name == "refund.create" and response.body["state"] == "UNKNOWN":
            ready.set()
        return response

    monkeypatch.setattr(dispatcher, "_call_tool", tool_response_loss)
    monkeypatch.setattr(dispatcher, "dispatch", recorded_dispatch)
    monkeypatch.setattr(gateway_app, "GatewayDispatchService", lambda *_args, **_kwargs: dispatcher)
    agents = {role: runtime(role) for role in ("coordinator", "knowledge", "case", "refund")}
    peers = {"http://runtime-gateway.test": TestClient(gateway_app.make_app(
        settings=gateway_settings, service=gateway,
    ))}
    for role, service in agents.items():
        peers[f"http://runtime-{role}.test"] = TestClient(make_agent_app(
            settings=service.settings, service=service,
        ))
    real_client = httpx.Client

    class RoutedTransport(httpx.BaseTransport):
        def __init__(self):
            self.network = httpx.HTTPTransport()

        def handle_request(self, request):
            origin = f"{request.url.scheme}://{request.url.netloc.decode('ascii')}"
            if origin in peers:
                result = peers[origin].request(
                    request.method, request.url.raw_path.decode("ascii"),
                    content=request.content, headers=dict(request.headers),
                )
                return httpx.Response(result.status_code, content=result.content, headers={
                    "Content-Type": "application/json",
                })
            if fault == "temporary-receipt-503" and not failed["once"] and (
                request.url.path == "/internal/receipts/issue"
            ):
                execution_id = json.loads(request.content)["execution_id"]
                with connect(database) as connection:
                    tool = connection.execute(
                        "SELECT tool_name FROM execution_records WHERE execution_id = %s",
                        (execution_id,),
                    ).fetchone()
                if tool == ("refund.create",):
                    failed["once"], failed["execution_id"] = True, execution_id
                    ready.set()
                    return httpx.Response(503, json={"reason_code": "TOOL_EXECUTION_UNKNOWN"})
            return self.network.handle_request(request)

        def close(self):
            self.network.close()

    monkeypatch.setattr(httpx, "Client", lambda *args, **kwargs: real_client(
        *args, **kwargs, transport=RoutedTransport(),
    ))
    with ThreadPoolExecutor(max_workers=1) as pool:
        submitted = pool.submit(
            peers["http://runtime-coordinator.test"].post, "/agents/workflows",
            json={"credential_chain": [root], "context": context.model_dump(mode="json")},
        )
        try:
            assert ready.wait(20), "the controlled runtime fault was not reached"
            with connect(database) as connection:
                assert connection.execute(
                    "SELECT state FROM agent_workflow_runs WHERE task_id = %s", (task_id,),
                ).fetchone() == ("RUNNING",)
                assert connection.execute(
                    "SELECT count(*) FROM refunds WHERE task_id = %s", (task_id,),
                ).fetchone() == (1,)
                assert connection.execute(
                    "SELECT count(*) FROM notifications WHERE task_id = %s", (task_id,),
                ).fetchone() == (0,)
            with httpx.Client(
                base_url=os.environ["AGENTGUARD_RECOVERY_URL"], timeout=15, trust_env=False,
            ) as client:
                recovered = client.post(
                    "/internal/recovery/run", headers={"X-AgentGuard-Internal": "recovery-trigger"},
                    json={"execution_id": failed["execution_id"]},
                )
            assert recovered.status_code == 200, recovered.text
            decision = recovered.json()["decisions"][0]
            assert decision["state"] == "COMMITTED" and isinstance(decision["receipt"], dict)
            queued = submitted.result(timeout=30)
            assert queued.status_code == 202, queued.text
        finally:
            if not submitted.done():
                submitted.result(timeout=30)
    with connect(database) as connection:
        assert connection.execute(
            "SELECT state, reason_code FROM agent_workflow_runs WHERE task_id = %s", (task_id,),
        ).fetchone() == ("COMPLETED", None)
        assert connection.execute(
            "SELECT count(*) FROM refunds WHERE task_id = %s", (task_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*) FROM notifications WHERE task_id = %s", (task_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*), count(*) FILTER (WHERE state = 'COMMITTED') "
            "FROM execution_records WHERE task_id = %s", (task_id,),
        ).fetchone() == (4, 4)
        assert connection.execute(
            "SELECT count(*), count(*) FILTER (WHERE r.receipt_status = 'SIGNED') "
            "FROM execution_receipts r JOIN execution_records e USING (execution_id) "
            "WHERE e.task_id = %s", (task_id,),
        ).fetchone() == (4, 4)
        assert connection.execute(
            "SELECT count(*) FROM credential_budget_state b JOIN credentials c "
            "USING (credential_id) WHERE c.task_id = %s "
            "AND (b.reserved_value <> 0 OR b.committed_value > b.limit_value)", (task_id,),
        ).fetchone() == (0,)
    assert dispatches == [
        "knowledge.read_associated", "ticket.read", "refund.create", "notification.send_template",
    ]


def test_refund_amount_mismatch_cannot_consume_real_budgets_or_create_a_refund(monkeypatch):
    root, context, task_id = authorized_request()
    database = isolated_database()
    coordinator = runtime("coordinator")
    case = coordinator._delegate(
        [root], child_role="case",
        tools=("ticket.read", "refund.create", "notification.send_template"),
        refund_total_fen=7000, max_tool_calls=3,
    )
    case_service = runtime("case")
    leaf = case_service._delegate(
        [root, case], child_role="refund", tools=("refund.create",),
        refund_total_fen=7000, max_tool_calls=1,
    )
    chain = [root, case, leaf]
    service = runtime("refund")
    intent = ToolIntent(service="refund-service", name="refund.create", parameters={
        "ticket_id": context.ticket_id, "customer_id": context.customer_id, "amount_fen": 6000,
    })
    monkeypatch.setattr(service, "_plan", lambda *_args, **_kwargs: PlanDecision(
        planner="deterministic", intents=(intent,),
    ))
    with pytest.raises(AgentRuntimeError) as caught:
        service._run_refund(chain, context, [])
    assert caught.value.reason_code == "BUSINESS_RESULT_MISMATCH"
    with connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM refunds WHERE task_id = %s", (task_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM business_actions WHERE task_id = %s", (task_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM execution_records WHERE task_id = %s", (task_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM credential_budget_state b JOIN credentials c "
            "USING (credential_id) WHERE c.task_id = %s "
            "AND (b.reserved_value <> 0 OR b.committed_value <> 0)", (task_id,),
        ).fetchone() == (0,)
