from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import yaml
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import backend.agent_runtime.app as agent_app
import backend.agent_runtime.workflow_store as workflow_store
from backend.agent_runtime.contracts import AgentContext, AgentStep, PlanDecision, ToolIntent
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.agent_runtime.workflow_store import (
    WORKFLOW_TRANSITIONS,
    WorkflowStore,
    WorkflowStoreError,
)
from backend.config.settings import Settings
from backend.ui_api.app import make_app as make_ui_app
from backend.ui_api.contracts import StartWorkflowRequest
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore
from scripts.native_config import service_specs

ROOT = Path(__file__).parents[3]


class RecordingUi(UiService):
    def __init__(self, *, available: bool = True, coauthorization: bool = False) -> None:
        store = SimpleNamespace(
            list_business_tickets=lambda: [
                {
                    "tenant_id": "tenant-A",
                    "ticket_id": "T10086",
                    "customer_id": "C9527",
                    "cloud_shareable": True,
                    "can_refund": True,
                    "refundable_amount_fen": 7000,
                    "transaction_remaining_fen": 7000,
                }
            ]
        )
        super().__init__(Settings(coauthorization_required=False), cast(UiReadStore, store))
        self.available = available
        self.coauthorization = coauthorization
        self.profile_reads = 0
        self.calls: list[tuple[str, dict, int]] = []

    def coauthorization_status(self) -> dict[str, Any]:
        return {"enabled": self.coauthorization}

    def runtime_profiles(self) -> dict[str, Any]:
        self.profile_reads += 1
        return {
            "workflow_enabled": True,
            "items": [
                {"mode": mode, "available": self.available, "message": "test profile"}
                for mode in ("deterministic", "cloud")
            ],
        }

    def _workflow_request(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._post("test-only", "/agents/workflows", body, expected_status=202)

    def _post(self, base_url: str, path: str, body: dict, *, expected_status: int = 200) -> dict:
        del base_url
        self.calls.append((path, body, expected_status))
        if path == "/tasks":
            return {"task_id": "TASK-test"}
        if path.endswith("/authorize"):
            return {"payload": {"credential_id": "ROOT-test"}, "signature": {"value": "test-only"}}
        return {
            "run_id": "RUN-test",
            "task_id": "TASK-test",
            "state": "QUEUED",
            "runtime_mode": body["context"]["runtime_mode"],
        }


@pytest.mark.parametrize("mode", ["deterministic", "local", "cloud"])
def test_unavailable_modes_do_not_create_or_authorize_a_task(mode: str) -> None:
    subject = RecordingUi(available=False)
    with pytest.raises(UiApiError) as caught:
        subject.start_workflow(StartWorkflowRequest(runtime_mode=mode))
    assert caught.value.reason_code == "MODEL_MODE_UNAVAILABLE"
    assert subject.calls == []


def test_cloud_confirmation_precedes_task_creation() -> None:
    subject = RecordingUi()
    with pytest.raises(UiApiError) as caught:
        subject.start_workflow(StartWorkflowRequest(runtime_mode="cloud"))
    assert caught.value.reason_code == "CLOUD_CONFIRMATION_REQUIRED"
    assert subject.calls == []


@pytest.mark.parametrize("mode", ["deterministic", "local", "cloud"])
def test_coauthorization_requirement_precedes_model_lookup_and_task_creation(mode: str) -> None:
    subject = RecordingUi()
    subject.settings.coauthorization_required = True
    with pytest.raises(UiApiError) as caught:
        subject.start_workflow(
            StartWorkflowRequest(runtime_mode=mode, cloud_data_confirmed=mode == "cloud")
        )
    assert caught.value.reason_code == "COAUTH_REQUIRED"
    assert caught.value.status_code == 403
    assert subject.profile_reads == 0
    assert subject.calls == []


@pytest.mark.parametrize("entry", ["workflow", "normal", "injection"])
def test_authority_switch_blocks_legacy_creation_even_when_bff_flag_is_off(entry: str) -> None:
    subject = RecordingUi(coauthorization=True)
    subject.settings.coauthorization_required = False
    subject.settings.live_refund_agent_url = "http://127.0.0.1:8810"
    with pytest.raises(UiApiError) as caught:
        if entry == "workflow":
            subject.start_workflow(StartWorkflowRequest())
        elif entry == "normal":
            subject.run_normal_demo()
        else:
            subject.run_prompt_injection_demo("display-only test input")
    assert caught.value.reason_code == "COAUTH_REQUIRED"
    assert subject.calls == []
    assert subject.profile_reads == 0


def test_direct_legacy_authorization_observes_authority_switch_before_issuing_root() -> None:
    from backend.authorization.contracts import AuthorizeTaskRequest

    subject = RecordingUi(coauthorization=True)
    with pytest.raises(UiApiError) as caught:
        subject.authorize_task(
            "TASK-test",
            AuthorizeTaskRequest(
                confirmed=True,
                confirmer_id="policy-refund-v1",
                holder_agent_id="agent-coordinator",
                holder_key_id="agent-coordinator-key-01",
                delegation_depth=2,
            ),
        )
    assert caught.value.reason_code == "COAUTH_REQUIRED"
    assert subject.calls == []


def test_authority_status_failure_is_not_a_single_sign_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = RecordingUi()

    def unavailable() -> dict[str, Any]:
        raise UiApiError("UPSTREAM_UNAVAILABLE", "test-only unavailable", status_code=503)

    monkeypatch.setattr(subject, "coauthorization_status", unavailable)
    with pytest.raises(UiApiError) as caught:
        subject.start_workflow(StartWorkflowRequest())
    assert caught.value.reason_code == "UPSTREAM_UNAVAILABLE"
    assert subject.calls == []


@pytest.mark.parametrize("mode", ["deterministic", "cloud"])
def test_public_start_returns_only_queued_identifier_and_bounded_synthetic_context(
    mode: str,
) -> None:
    subject = RecordingUi()
    client = TestClient(make_ui_app(settings=Settings(), service=subject))
    response = client.post(
        "/api/workflows",
        json={
            "runtime_mode": mode,
            "scenario": "policy_injection",
            "cloud_data_confirmed": mode == "cloud",
        },
    )
    assert response.status_code == 202
    assert set(response.json()) == {"run_id", "task_id", "state", "runtime_mode"}
    assert response.json()["state"] == "QUEUED"
    assert [item[0] for item in subject.calls] == [
        "/tasks",
        "/tasks/TASK-test/authorize",
        "/agents/workflows",
    ]
    assert subject.calls[1][1]["holder_agent_id"] == "agent-coordinator"
    assert subject.calls[1][1]["delegation_depth"] == 2
    context = subject.calls[2][1]["context"]
    assert (context["ticket_id"], context["customer_id"], context["refund_amount_fen"]) == (
        "T10086",
        "C9527",
        7000,
    )
    assert context["runtime_mode"] == mode
    assert context["scenario"] == "policy_injection"
    assert "workflow_token" not in context


def test_retired_local_public_start_never_creates_task_or_calls_upstream() -> None:
    subject = RecordingUi()
    response = TestClient(make_ui_app(settings=Settings(), service=subject)).post(
        "/api/workflows",
        json={"runtime_mode": "local"},
    )
    assert response.status_code == 503
    assert response.json()["reason_code"] == "MODEL_MODE_UNAVAILABLE"
    assert subject.calls == []


@pytest.mark.parametrize(
    "extra",
    [
        {"api_key": "not-allowed"},
        {"credential_chain": []},
        {"runtime_mode": "other"},
        {"cloud_data_confirmed": "true"},
    ],
)
def test_public_start_schema_rejects_authority_fields_and_coercion(extra: dict) -> None:
    subject = RecordingUi()
    response = TestClient(make_ui_app(settings=Settings(), service=subject)).post(
        "/api/workflows", json=extra
    )
    assert response.status_code == 400
    assert "not-allowed" not in response.text
    assert subject.calls == []


def test_observation_endpoint_checks_token_and_role(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    class Observer:
        def __init__(self, _url: str) -> None:
            pass

        def append(self, run_id: str, token: str, event: AgentStep) -> None:
            if token != "test-token":
                raise WorkflowStoreError("test token rejected")
            calls.append((run_id, event.agent_id))

    monkeypatch.setattr(agent_app, "WorkflowStore", Observer)
    event = {
        "sequence": 1,
        "agent_id": "agent-refund",
        "action": "agent_started",
        "status": "RUNNING",
        "details": {},
    }
    client = TestClient(agent_app.make_app(settings=Settings(agent_role="coordinator")))
    assert client.post("/agents/workflows/RUN-test/observe", json=event).status_code == 403
    assert client.post(
        "/agents/workflows/RUN-test/observe", json=event, headers={"X-Workflow-Token": "test-token"}
    ).json() == {"recorded": True}
    assert (
        client.post(
            "/agents/workflows/RUN-test/observe",
            json=event | {"agent_id": "attacker"},
            headers={"X-Workflow-Token": "test-token"},
        ).status_code
        == 400
    )
    child = TestClient(agent_app.make_app(settings=Settings(agent_role="refund")))
    assert (
        child.post(
            "/agents/workflows/RUN-test/observe",
            json=event,
            headers={"X-Workflow-Token": "test-token"},
        ).status_code
        == 400
    )
    assert calls == [("RUN-test", "agent-refund")]


class StateConnection:
    def __init__(self, state: str) -> None:
        self.state = state
        self.updated = False

    def __enter__(self) -> StateConnection:
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def transaction(self) -> StateConnection:
        return self

    def execute(self, query: str, args: tuple) -> StateConnection:
        if query.lstrip().startswith("UPDATE"):
            self.updated = True
            self.state = args[0]
        return self

    def fetchone(self) -> tuple[str]:
        return (self.state,)


@pytest.mark.parametrize("previous", list(WORKFLOW_TRANSITIONS))
@pytest.mark.parametrize("target", [*WORKFLOW_TRANSITIONS, "INVALID"])
def test_operational_state_transitions_match_the_declared_machine(
    previous: str, target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = StateConnection(previous)
    monkeypatch.setattr(workflow_store, "connect", lambda _url: connection)
    store = WorkflowStore("test-only")
    if target in WORKFLOW_TRANSITIONS[previous]:
        store.state("RUN-test", target)
        assert connection.updated and connection.state == target
    else:
        with pytest.raises(WorkflowStoreError, match="state transition"):
            store.state("RUN-test", target)
        assert not connection.updated


def test_operational_contracts_and_frozen_security_contracts_remain_separate() -> None:
    machine = json.loads(
        (ROOT / "protocol/workflow-state-machine.json").read_text(encoding="utf-8")
    )
    assert machine["evidence_kind"] == "operational_not_signed_audit"
    assert {
        key: set(value) for key, value in machine["transitions"].items()
    } == WORKFLOW_TRANSITIONS
    schema = json.loads(
        (ROOT / "protocol/schemas/workflow-start.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for mode in ("deterministic", "local", "cloud"):
        validator.validate(StartWorkflowRequest(runtime_mode=mode).model_dump(mode="json"))
    assert not validator.is_valid({"api_key": "not-allowed"})
    run_schema = json.loads(
        (ROOT / "protocol/schemas/workflow-run.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(run_schema)
    openapi = yaml.safe_load((ROOT / "protocol/openapi.yaml").read_text(encoding="utf-8"))
    assert {
        "/api/workflows",
        "/api/runtime-profiles",
        "/agents/workflows",
        "/agents/runtime-profiles",
        "/agents/workflows/{run_id}/observe",
    } <= set(openapi["paths"])
    assert "MODEL_MODE_UNAVAILABLE" not in openapi["components"]["schemas"]["ReasonCode"]["enum"]


def test_native_roles_do_not_receive_authority_database_or_other_roles_private_key(
    tmp_path: Path,
) -> None:
    services = [
        service
        for group in service_specs(
            "main-secret",
            "audit-secret",
            "ui-secret",
            tmp_path,
            with_llm=False,
            workflow_url="workflow-secret",
        )
        for service in group
    ]
    agents = [service for service in services if "agent_runtime" in service.module]
    assert len(agents) == 4
    for agent in agents:
        assert "AGENTGUARD_DATABASE_URL" not in agent.environment
        assert "AGENTGUARD_AUDIT_DATABASE_URL" not in agent.environment
        assert agent.environment.get("AGENTGUARD_WORKFLOW_DATABASE_URL", "") == (
            "workflow-secret" if agent.name == "coordinator-agent" else ""
        )
        assert len([key for key in agent.environment if "PRIVATE_KEY" in key]) == 1


@pytest.mark.parametrize("enabled", ["true", "false"])
def test_native_bff_and_authority_receive_the_same_explicit_coauthorization_switch(
    enabled: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_COAUTHORIZATION_REQUIRED", enabled)
    services = [
        service
        for group in service_specs("main", "audit", "ui", tmp_path, with_llm=False)
        for service in group
    ]
    authority = next(service for service in services if service.name == "authorization-authority")
    ui = next(service for service in services if service.name == "ui-api")
    assert authority.environment["AGENTGUARD_COAUTHORIZATION_REQUIRED"] == enabled
    assert ui.environment["AGENTGUARD_COAUTHORIZATION_REQUIRED"] == enabled
    assert not any("PRIVATE_KEY" in key for key in ui.environment)


def test_observation_contract_bounds_untrusted_action_length() -> None:
    with pytest.raises(ValidationError):
        AgentStep(sequence=1, agent_id="agent-refund", action="a" * 65, status="RUNNING")


@pytest.mark.parametrize(
    "change,proposal_change",
    [
        ({}, {}),
        ({"amount_fen": 7}, {"amount_fen": 7}),
        ({"customer_id": "OTHER"}, {}),
        ({"ticket_id": "OTHER"}, {}),
        ({"task_id": "TASK-other"}, {}),
        ({"status": "UNKNOWN"}, {}),
        ({"refund_id": ""}, {}),
        ({"refund_id": None}, {}),
        ({}, {"customer_id": "OTHER"}),
        ({}, {"ticket_id": "OTHER"}),
        ({}, {"amount_fen": 7}),
    ],
)
@pytest.mark.parametrize("extended_result", [False, True])
def test_committed_refund_must_fulfill_the_business_task_without_rewriting_the_proposal(
    change: dict,
    proposal_change: dict,
    extended_result: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = object.__new__(AgentRuntimeService)
    service.agent_id = "agent-refund"
    service.settings = Settings()
    context = AgentContext(
        ticket_id="T10086", customer_id="C9527", refund_amount_fen=7000, runtime_mode="local"
    )
    refund = {
        "refund_id": "REFUND-test",
        "amount_fen": 7000,
        "status": "COMMITTED",
    }
    if extended_result:
        refund.update(customer_id="C9527", ticket_id="T10086", task_id="TASK-test")
    refund.update(change)
    intent = ToolIntent(
        service="refund-service",
        name="refund.create",
        parameters={
            "ticket_id": "T10086",
            "customer_id": "C9527",
            "amount_fen": 7000,
        }
        | proposal_change,
    )
    monkeypatch.setattr(
        service, "_plan", lambda *_args, **_kwargs: PlanDecision(planner="llm", intents=(intent,))
    )
    monkeypatch.setattr(service, "_task_id", lambda _chain: "TASK-test")
    monkeypatch.setattr(
        service, "_post_json", lambda *_args, **_kwargs: {"business_action_id": "ACTION-test"}
    )
    sent = []

    def call_tool(_chain: list, actual: ToolIntent, **_kwargs: Any) -> dict:
        sent.append(actual.parameters)
        return {"execution_id": "EXEC-test", "result": refund}

    monkeypatch.setattr(service, "_call_tool", call_tool)
    trace = []
    if change or proposal_change:
        with pytest.raises(AgentRuntimeError) as caught:
            service._run_refund([], context, trace)
        assert caught.value.reason_code == "BUSINESS_RESULT_MISMATCH"
    else:
        assert service._run_refund([], context, trace) == {"refund": refund}
    if proposal_change:
        assert sent == []
        assert trace == []
    else:
        assert sent == [intent.parameters]
        assert sent[0]["amount_fen"] == intent.parameters["amount_fen"]
        assert trace[0].details["output"] == refund
