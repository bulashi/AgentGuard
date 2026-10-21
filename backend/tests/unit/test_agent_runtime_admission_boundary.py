"""Runtime admission tests with in-memory peers; no model, database or service is used."""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import backend.agent_runtime.service as runtime_module
from backend.agent_runtime.app import make_app
from backend.agent_runtime.contracts import AgentRunRequest, AgentRunResponse, PlanDecision
from backend.agent_runtime.service import ROLE_IDENTITIES, AgentRuntimeError, AgentRuntimeService
from backend.common.internal_auth import CALLER_HEADER, InternalAuthenticator
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex


class MemoryNonces:
    def __init__(self) -> None:
        self.seen: set[tuple[str, str, str]] = set()

    def claim(self, *, caller, recipient, nonce, **_kwargs):
        key = caller, recipient, nonce
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


def settings_for(role: str, *, required: bool = True, keys: str = "{}") -> Settings:
    agent_id, key_id = ROLE_IDENTITIES[role]
    return Settings(
        agent_role=role, agent_id=agent_id, agent_key_id=key_id,
        internal_auth_required=required, internal_auth_service_id=agent_id,
        internal_auth_keys=keys, gateway_url="http://gateway.test",
        knowledge_agent_url="http://knowledge.test", case_agent_url="http://case.test",
        refund_agent_url="http://refund.test",
    )


def document_for(role: str = "coordinator") -> dict:
    agent_id, key_id = ROLE_IDENTITIES[role]
    return {
        "credential_chain": [{"payload": {
            "credential_id": "ROOT-runtime-boundary", "task_id": "TASK-runtime-boundary",
            "tenant_id": "tenant-A", "holder": {"agent_id": agent_id, "key_id": key_id},
        }}],
        "context": {
            "ticket_id": "T-test", "customer_id": "C-test", "refund_amount_fen": 7000,
            "runtime_mode": "cloud", "cloud_data_confirmed": True,
        },
    }


class EntrySpy:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(self, request: AgentRunRequest) -> AgentRunResponse:
        self.calls.append("run")
        return AgentRunResponse(
            root_task_id=request.credential_chain[0]["payload"]["task_id"],
            status="COMPLETED", result={}, trace=[],
        )

    def prepare_workflow(self, request):
        self.calls.append("prepare")
        return {"run_id": "RUN-test", "state": "QUEUED"}, request

    def execute_workflow(self, _request):
        self.calls.append("execute")


def client_for(role: str, caller: str, *, required: bool = True):
    recipient = ROLE_IDENTITIES[role][0]
    keys = json.dumps({f"{caller}->{recipient}": "1" * 64})
    settings = settings_for(role, required=required, keys=keys)
    receiver = InternalAuthenticator(
        service_id=recipient, keys_json=keys, required=required,
        nonce_store=MemoryNonces(), clock=lambda: 100,
    )
    sender = InternalAuthenticator(
        service_id=caller, keys_json=keys, required=required,
        nonce_store=MemoryNonces(), clock=lambda: 100,
    )
    spy = EntrySpy()
    client = TestClient(make_app(settings=settings, service=spy, internal_auth=receiver))
    return client, sender, spy


@pytest.mark.parametrize("role", tuple(ROLE_IDENTITIES))
@pytest.mark.parametrize("path", ["/agents/run", "/agents/workflows"])
@pytest.mark.parametrize("spoofed_header", [False, True])
def test_required_entry_auth_rejects_before_runtime_or_workflow_preparation(
    role, path, spoofed_header,
):
    caller = "agent-case" if role == "refund" else (
        "ui-api" if role == "coordinator" else "agent-coordinator"
    )
    client, _sender, spy = client_for(role, caller)
    headers = {CALLER_HEADER: caller} if spoofed_header else {}
    response = client.post(path, json=document_for(role), headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"]["reason_code"] == "TOOL_NOT_ALLOWED"
    assert spy.calls == []


@pytest.mark.parametrize("role,caller", [
    ("coordinator", "ui-api"), ("knowledge", "agent-coordinator"),
    ("case", "agent-coordinator"), ("refund", "agent-case"), ("refund", "ui-api"),
])
def test_valid_allowed_peer_can_call_run(role, caller):
    client, sender, spy = client_for(role, caller)
    body = canonicalize(document_for(role))
    headers = sender.request_headers(
        recipient=ROLE_IDENTITIES[role][0], method="POST", path="/agents/run", body=body,
    )
    response = client.post("/agents/run", content=body, headers=headers)
    assert response.status_code == 200
    assert spy.calls == ["run"]


@pytest.mark.parametrize("path", ["/agents/run", "/agents/workflows"])
def test_signed_unknown_peer_is_rejected_even_with_a_valid_mac(path):
    client, sender, spy = client_for("coordinator", "agent-refund")
    body = canonicalize(document_for())
    headers = sender.request_headers(
        recipient="agent-coordinator", method="POST", path=path, body=body,
    )
    assert client.post(path, content=body, headers=headers).status_code == 403
    assert spy.calls == []


def test_workflow_body_tampering_and_replay_cannot_queue_more_work():
    client, sender, spy = client_for("coordinator", "ui-api")
    body = canonicalize(document_for())
    headers = sender.request_headers(
        recipient="agent-coordinator", method="POST", path="/agents/workflows", body=body,
    )
    altered = document_for()
    altered["context"]["refund_amount_fen"] = 6000
    assert client.post(
        "/agents/workflows", content=canonicalize(altered), headers=headers,
    ).status_code == 403
    assert spy.calls == []
    assert client.post("/agents/workflows", content=body, headers=headers).status_code == 202
    assert client.post("/agents/workflows", content=body, headers=headers).status_code == 409
    assert spy.calls == ["prepare", "execute"]


@pytest.mark.parametrize("path,status", [("/agents/run", 200), ("/agents/workflows", 202)])
def test_explicit_unsigned_test_mode_remains_available(path, status):
    client, _sender, spy = client_for("coordinator", "ui-api", required=False)
    assert client.post(path, json=document_for()).status_code == status
    assert spy.calls == (["run"] if path.endswith("run") else ["prepare", "execute"])


@pytest.mark.parametrize("entry", ["run", "prepare_workflow"])
@pytest.mark.parametrize("code", [
    "INVALID_SIGNATURE", "CROSS_TASK", "WRONG_HOLDER", "KEY_REVOKED",
    "CREDENTIAL_EXPIRED", "TOOL_NOT_ALLOWED", "PARAMETER_CONSTRAINT_VIOLATION",
])
def test_gateway_admission_denial_precedes_planning_and_workflow_storage(
    entry, code, monkeypatch,
):
    service = object.__new__(AgentRuntimeService)
    service.settings = settings_for("coordinator", required=False)
    service.role, service.agent_id, service.key_id = "coordinator", *ROLE_IDENTITIES["coordinator"]
    service.planner_name = "deterministic"
    calls = []

    def admission(_base, path, _body, **_kwargs):
        calls.append(path)
        raise AgentRuntimeError(code, "unit-only admission rejection")

    def forbidden(*_args, **_kwargs):
        pytest.fail("no planner, model-profile or workflow storage may run after rejection")

    monkeypatch.setattr(service, "_post_json", admission)
    monkeypatch.setattr(service, "_plan", forbidden)
    monkeypatch.setattr(runtime_module, "runtime_profiles", forbidden)
    monkeypatch.setattr(runtime_module, "WorkflowStore", forbidden)
    with pytest.raises(AgentRuntimeError) as caught:
        getattr(service, entry)(AgentRunRequest.model_validate(document_for()))
    assert caught.value.reason_code == code
    assert calls == ["/gateway/runtime/authorize"]


@pytest.mark.parametrize("ack_change", [
    {"authorized": False}, {"authorized": "true"}, {"task_id": "TASK-other"},
    {"agent_id": "agent-refund"}, {"credential_chain_hash": "0" * 64},
])
def test_admission_ack_must_bind_this_exact_agent_task_and_chain(ack_change, monkeypatch):
    service = object.__new__(AgentRuntimeService)
    service.settings = settings_for("coordinator", required=False)
    service.agent_id = "agent-coordinator"
    request = AgentRunRequest.model_validate(document_for())
    ack = {
        "authorized": True, "task_id": "TASK-runtime-boundary",
        "agent_id": service.agent_id,
        "credential_chain_hash": sm3_hex(canonicalize(request.credential_chain)),
    } | ack_change
    monkeypatch.setattr(service, "_post_json", lambda *_args, **_kwargs: ack)
    with pytest.raises(AgentRuntimeError) as caught:
        service._authorize_run(request.credential_chain, request.context)
    assert caught.value.reason_code == "CONTROLLED_RESULT_INVALID"


def test_admission_body_excludes_prompts_tool_results_and_observation_tokens(monkeypatch):
    service = object.__new__(AgentRuntimeService)
    service.settings = settings_for("coordinator", required=False)
    service.agent_id = "agent-coordinator"
    request = AgentRunRequest.model_validate(document_for())
    context = request.context.model_copy(update={
        "prompt_text": "untrusted prompt", "knowledge_context": {"document": "business"},
        "ticket_context": {"ticket": "business"}, "refund_context": {"refund": "business"},
        "authorization_context": {"injected": True}, "workflow_run_id": "RUN-private",
        "workflow_token": "must-not-be-forwarded",
    })
    sent = []

    def admission(_base, path, body, **_kwargs):
        assert path == "/gateway/runtime/authorize"
        sent.append(body)
        return {"authorized": True, "task_id": "TASK-runtime-boundary",
                "agent_id": service.agent_id,
                "credential_chain_hash": sm3_hex(canonicalize(request.credential_chain))}

    monkeypatch.setattr(service, "_post_json", admission)
    service._authorize_run(request.credential_chain, context)
    assert sent == [{"credential_chain": request.credential_chain, "context": {
        "ticket_id": "T-test", "customer_id": "C-test", "refund_amount_fen": 7000,
        "runtime_mode": "cloud", "scenario": "normal", "cloud_data_confirmed": True,
    }}]


@pytest.mark.parametrize("role,stage", [
    ("knowledge", "knowledge_summary"), ("case", "case_notify"),
])
@pytest.mark.parametrize("mode", ["local", "cloud"])
@pytest.mark.parametrize("code", ["KEY_REVOKED", "CREDENTIAL_EXPIRED"])
def test_permission_loss_before_a_later_model_stage_prevents_any_model_call(
    role, stage, mode, code, monkeypatch,
):
    service = object.__new__(AgentRuntimeService)
    service.settings = settings_for(role, required=False)
    service.role, service.agent_id, service.key_id = role, *ROLE_IDENTITIES[role]
    request = AgentRunRequest.model_validate(document_for(role))
    context = request.context.model_copy(update={"runtime_mode": mode})
    calls = []

    def admission(_chain, _context):
        calls.append("revalidated")
        raise AgentRuntimeError(code, "unit permission changed during prior tool wait")

    class ModelProbe:
        def __init__(self, _settings):
            calls.append("model-constructed")

        def plan(self, *_args, **_kwargs):
            pytest.fail("the later model stage must not start after permission loss")

    monkeypatch.setattr(service, "_authorize_run", admission)
    monkeypatch.setattr(runtime_module, "WorkflowPlanner", ModelProbe)
    trace = []
    with pytest.raises(AgentRuntimeError) as caught:
        service._plan(
            role, context, trace, expected_tools=(), stage=stage,
            chain=request.credential_chain,
        )
    assert caught.value.reason_code == code
    assert calls == ["revalidated"] and trace == []


def test_deterministic_stage_does_not_add_another_authorization_rpc(monkeypatch):
    service = object.__new__(AgentRuntimeService)
    service.settings = settings_for("knowledge", required=False)
    service.agent_id = "agent-knowledge"
    request = AgentRunRequest.model_validate(document_for("knowledge"))
    context = request.context.model_copy(update={"runtime_mode": "deterministic"})
    calls = []

    class DeterministicProbe:
        def __init__(self, _settings):
            pass

        def plan(self, *_args, **_kwargs):
            calls.append("deterministic-plan")
            return PlanDecision(planner="deterministic", intents=())

    monkeypatch.setattr(service, "_authorize_run", lambda *_args: pytest.fail(
        "deterministic stages use the run-level admission and gateway tool authorization",
    ))
    monkeypatch.setattr(runtime_module, "WorkflowPlanner", DeterministicProbe)
    service._plan(
        "knowledge", context, [], expected_tools=(), stage="knowledge_summary",
        chain=request.credential_chain,
    )
    assert calls == ["deterministic-plan"]


@pytest.mark.parametrize("role,target,base,path", [
    ("coordinator", "agent-knowledge", "http://knowledge.test", "/agents/run"),
    ("coordinator", "agent-case", "http://case.test", "/agents/run"),
    ("case", "agent-refund", "http://refund.test", "/agents/run"),
    *[(role, "secure-gateway", "http://gateway.test", "/gateway/runtime/authorize")
      for role in ROLE_IDENTITIES],
])
def test_runtime_signs_each_real_run_and_admission_peer_edge(role, target, base, path, monkeypatch):
    service = object.__new__(AgentRuntimeService)
    caller = ROLE_IDENTITIES[role][0]
    keys = json.dumps({f"{caller}->{target}": "a" * 64})
    service.settings = settings_for(role, keys=keys)
    service.role, service.agent_id = role, caller
    receiver = InternalAuthenticator(
        service_id=target, keys_json=keys, nonce_store=MemoryNonces(),
    )
    real_client = httpx.Client
    seen = []

    def handler(request):
        assert receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={caller},
        ) == caller
        seen.append(request)
        return httpx.Response(200, json={"ack": True})

    monkeypatch.setattr(runtime_module.httpx, "Client", lambda *args, **kwargs: real_client(
        *args, **kwargs, transport=httpx.MockTransport(handler),
    ))
    assert service._post_json(base, path, {"test": "中文"}) == {"ack": True}
    assert len(seen) == 1 and seen[0].content == canonicalize({"test": "中文"})


def test_missing_run_edge_key_never_falls_back_to_unsigned_transport(monkeypatch):
    service = object.__new__(AgentRuntimeService)
    service.settings = settings_for("coordinator")
    service.role, service.agent_id = "coordinator", "agent-coordinator"
    monkeypatch.setattr(runtime_module.httpx, "Client", lambda **_kwargs: pytest.fail(
        "missing authentication keys must fail before opening a client",
    ))
    with pytest.raises(AgentRuntimeError) as caught:
        service._post_json("http://knowledge.test", "/agents/run", {})
    assert caught.value.reason_code == "INTERNAL_AUTH_UNAVAILABLE"


def test_unsigned_test_admission_still_forwards_an_explicit_peer_identity(monkeypatch):
    service = object.__new__(AgentRuntimeService)
    service.settings = settings_for("refund", required=False)
    service.role, service.agent_id = "refund", "agent-refund"
    seen = []
    real_client = httpx.Client

    def handler(request):
        seen.append(request)
        assert request.headers[CALLER_HEADER] == "agent-refund"
        return httpx.Response(200, json={"ack": True})

    monkeypatch.setattr(runtime_module.httpx, "Client", lambda *args, **kwargs: real_client(
        *args, **kwargs, transport=httpx.MockTransport(handler),
    ))
    service._post_json("http://gateway.test", "/gateway/runtime/authorize", {})
    assert len(seen) == 1
