from __future__ import annotations

import json

import httpx
import pytest

from backend.agent_runtime.contracts import AgentContext
from backend.agent_runtime.planner import PlannerError
from backend.agent_runtime.workflow_planner import (
    WorkflowPlanner,
    default_plan,
    plan_schema,
    runtime_profiles,
)
from backend.agent_runtime.workflow_store import safe_observation
from backend.config.settings import Settings


def context(mode: str = "cloud") -> AgentContext:
    return AgentContext(
        ticket_id="T10086",
        customer_id="C9527",
        refund_amount_fen=7000,
        runtime_mode=mode,
        cloud_data_confirmed=mode == "cloud",
        workflow_token="DO_NOT_SEND_TOKEN",
        knowledge_context={
            "documents": [{"document_id": "DOC-001", "content": "untrusted policy"}]
        },
        ticket_context={
            "ticket_id": "T10086",
            "customer_id": "C9527",
            "description": "actual ticket",
        },
        refund_context={"refund_id": "REFUND-01", "amount_fen": 7000},
    )


@pytest.mark.parametrize(
    "role,stage",
    [
        ("coordinator", "coordinate"),
        ("knowledge", "knowledge_read"),
        ("knowledge", "knowledge_summary"),
        ("case", "case_read"),
        ("refund", "refund"),
        ("case", "case_notify"),
    ],
)
def test_explicit_decline_preserves_public_evidence_and_never_adds_intents(
    role: str, stage: str
) -> None:
    output = {
        "decision": "decline",
        "summary": "停止本阶段及后续业务。不提出工具动作。",
        "intents": [],
    }
    serialized = json.dumps(output, ensure_ascii=False)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "model": "fixture-cloud-model",
                "choices": [{"message": {"content": serialized}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 10},
            },
        )

    planner = WorkflowPlanner(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_NOT_A_REAL_KEY"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(PlannerError) as caught:
        planner.plan(role, context(), stage=stage)
    assert len(calls) == 1
    assert caught.value.reason_code == "PLANNER_DECLINED"
    assert caught.value.evidence["decision"] == "decline"
    assert caught.value.evidence["summary"] == output["summary"]
    assert caught.value.evidence["intents"] == []
    assert caught.value.evidence["stage"] == stage
    assert caught.value.evidence["model_returned"] == "fixture-cloud-model"
    assert len(caught.value.evidence["response_sm3"]) == 64
    assert "TEST_NOT_A_REAL_KEY" not in json.dumps(caught.value.evidence)


@pytest.mark.parametrize("provider", ["cloud"])
@pytest.mark.parametrize(
    "role,stage",
    [
        ("coordinator", "coordinate"),
        ("knowledge", "knowledge_read"),
        ("knowledge", "knowledge_summary"),
        ("case", "case_read"),
        ("refund", "refund"),
        ("case", "case_notify"),
    ],
)
def test_all_roles_use_real_context_with_provider_protocol(
    provider: str, role: str, stage: str
) -> None:
    inputs = context(provider)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        serialized = request.content.decode("utf-8")
        assert "DO_NOT_SEND_TOKEN" not in serialized
        assert "private_key" not in serialized
        parsed = json.loads(body["messages"][1]["content"])
        assert parsed["input"]["knowledge"] == inputs.knowledge_context
        assert parsed["input"]["ticket"] == inputs.ticket_context
        assert parsed["business_requirements"]["requested_refund_amount_fen"] == 7000
        assert "normal_output_shape" not in parsed
        output = json.dumps(default_plan(inputs, stage), ensure_ascii=False)
        assert request.url.path == "/chat/completions"
        assert request.headers["Authorization"] == "Bearer TEST_NOT_A_REAL_KEY"
        assert body["response_format"] == {"type": "json_object"}
        assert body["thinking"] == {"type": "disabled"}
        assert body["max_tokens"] == 1536
        return httpx.Response(
            200,
            json={
                "model": "fixture-cloud-model",
                "choices": [{"message": {"content": output, "reasoning_content": "MUST_NOT_SAVE"}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 10},
            },
        )

    settings = Settings(
        cloud_llm_enabled=True,
        cloud_llm_api_key="TEST_NOT_A_REAL_KEY",
    )
    decision = WorkflowPlanner(settings, transport=httpx.MockTransport(handler)).plan(
        role, inputs, stage=stage
    )
    assert decision.planner == "llm"
    assert decision.evidence["provider"] == "deepseek"
    assert decision.evidence["model_returned"] == f"fixture-{provider}-model"
    assert len(decision.evidence["response_sm3"]) == 64
    assert "MUST_NOT_SAVE" not in json.dumps(decision.evidence)
    assert "TEST_NOT_A_REAL_KEY" not in json.dumps(decision.evidence)
    assert decision.evidence["thinking_mode"] == "disabled"


@pytest.mark.parametrize(
    "role,stage",
    [
        ("coordinator", "coordinate"),
        ("knowledge", "knowledge_read"),
        ("knowledge", "knowledge_summary"),
        ("case", "case_read"),
        ("refund", "refund"),
        ("case", "case_notify"),
    ],
)
def test_retired_local_mode_never_invokes_provider(role: str, stage: str) -> None:
    planner = WorkflowPlanner(
        Settings(),
        transport=httpx.MockTransport(
            lambda _request: pytest.fail("retired local called provider")
        ),
    )
    with pytest.raises(PlannerError) as caught:
        planner.plan(role, context("local"), stage=stage)
    assert caught.value.reason_code == "MODEL_MODE_UNAVAILABLE"
    assert caught.value.status_code == 503


@pytest.mark.parametrize(
    "alteration",
    [
        {"private_key": "malicious"},
        {"credential_chain": []},
        {
            "intents": [
                {
                    "service": "refund-service",
                    "name": "refund.create",
                    "version": "v1",
                    "parameters": {
                        "ticket_id": "T10086",
                        "customer_id": "C9527",
                        "amount_fen": True,
                    },
                }
            ]
        },
        {
            "intents": [
                {
                    "service": "refund-service",
                    "name": "refund.create",
                    "version": "v1",
                    "parameters": {
                        "ticket_id": "T10086",
                        "customer_id": "C9527",
                        "amount_fen": 7000,
                        "business_action_id": "BAD",
                    },
                }
            ]
        },
        {"intents": []},
        {
            "intents": [
                {
                    "service": "refund-service",
                    "name": "refund.create",
                    "version": "v1",
                    "parameters": {
                        "ticket_id": "T10086",
                        "customer_id": "C9527",
                        "amount_fen": 9007199254740992,
                    },
                }
            ],
        },
    ],
)
def test_invalid_output_is_rejected_without_fallback(alteration: dict) -> None:
    inputs = context()
    output = default_plan(inputs, "refund") | alteration
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200, json={"model": "test", "choices": [{"message": {"content": json.dumps(output)}}]}
        )
    )
    planner = WorkflowPlanner(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_NOT_A_REAL_KEY"),
        transport=transport,
    )
    with pytest.raises(PlannerError) as error:
        planner.plan("refund", inputs, stage="refund")
    assert error.value.reason_code == "LLM_OUTPUT_INVALID"


@pytest.mark.parametrize(
    "choice,expected",
    [
        (None, "response_shape"),
        ({"message": {"content": {"UNTRUSTED_PAYLOAD_DO_NOT_LOG": True}}}, "response_shape"),
        ({"message": {"content": "UNTRUSTED_PAYLOAD_DO_NOT_LOG"}}, "strict_json"),
        (
            {
                "message": {
                    "content": (
                        '{"decision":"propose","summary":"UNTRUSTED_PAYLOAD_DO_NOT_LOG",'
                        '"intents":[],"extra":1}'
                    )
                }
            },
            "plan_contract",
        ),
        (
            {
                "message": {
                    "content": (
                        '{"decision":"propose","summary":"UNTRUSTED_PAYLOAD_DO_NOT_LOG",'
                        '"intents":[]}'
                    )
                }
            },
            "role_intent_count",
        ),
        (
            {"message": {"content": "UNTRUSTED_PAYLOAD_DO_NOT_LOG"}, "finish_reason": "length"},
            "incomplete_response",
        ),
        (
            {
                "message": {"content": "UNTRUSTED_PAYLOAD_DO_NOT_LOG"},
                "finish_reason": "content_filter",
            },
            "incomplete_response",
        ),
        (
            {
                "message": {"content": "UNTRUSTED_PAYLOAD_DO_NOT_LOG"},
                "finish_reason": "UNTRUSTED_PAYLOAD_DO_NOT_LOG",
            },
            "response_finish_reason",
        ),
        (
            {
                "message": {"content": "UNTRUSTED_PAYLOAD_DO_NOT_LOG"},
                "finish_reason": {"UNTRUSTED_PAYLOAD_DO_NOT_LOG": True},
            },
            "response_finish_reason",
        ),
    ],
)
def test_invalid_completion_diagnostics_are_bounded_and_never_log_vendor_content(
    choice: object, expected: str
) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"model": "test-model", "choices": [choice]})

    with pytest.raises(PlannerError) as caught:
        WorkflowPlanner(
            Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_NOT_A_REAL_KEY"),
            transport=httpx.MockTransport(handler),
        ).plan("refund", context(), stage="refund")
    assert len(calls) == 1
    assert caught.value.reason_code == "LLM_OUTPUT_INVALID"
    assert caught.value.evidence["output_validation_error"] == expected
    assert "UNTRUSTED_PAYLOAD_DO_NOT_LOG" not in json.dumps(caught.value.evidence)
    assert "TEST_NOT_A_REAL_KEY" not in json.dumps(caught.value.evidence)


def test_token_limit_finish_reason_rejects_even_syntactically_valid_plan() -> None:
    output = json.dumps(default_plan(context(), "refund"))
    with pytest.raises(PlannerError) as caught:
        WorkflowPlanner(
            Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_NOT_A_REAL_KEY"),
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    json={
                        "model": "test-model",
                        "choices": [{"finish_reason": "length", "message": {"content": output}}],
                    },
                )
            ),
        ).plan("refund", context(), stage="refund")
    assert caught.value.evidence["finish_reason"] == "length"
    assert caught.value.evidence["output_validation_error"] == "incomplete_response"


def test_untrusted_candidate_is_not_silently_clamped_to_authorization() -> None:
    inputs = context()
    output = default_plan(inputs, "refund")
    output["intents"][0]["parameters"]["amount_fen"] = 999999
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200, json={"model": "test", "choices": [{"message": {"content": json.dumps(output)}}]}
        )
    )
    decision = WorkflowPlanner(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_NOT_A_REAL_KEY"),
        transport=transport,
    ).plan("refund", inputs, stage="refund")
    assert decision.intents[0].parameters["amount_fen"] == 999999


def test_fact_refund_above_authorization_declines_with_exact_amounts_and_no_intents() -> None:
    from backend.business_action.contracts import CreateBusinessCaseRequest
    from backend.tests.unit.test_business_facts import case_request

    inputs = context("deterministic").model_copy(update={
        "refund_amount_fen": 6000,
        "ticket_context": {"source": "facts", "business_facts": CreateBusinessCaseRequest.model_validate(case_request()).raw_facts()},
    })
    result = default_plan(inputs, "refund")
    assert result["decision"] == "decline"
    assert result["intents"] == []
    assert "核对应退 70.00 元，本任务仅授权 60.00 元" in result["summary"]


@pytest.mark.parametrize("mode", ["cloud"])
def test_duplicate_model_json_is_not_silently_collapsed(mode: str) -> None:
    output = json.dumps(default_plan(context(mode), "refund"))
    output = output.replace('"amount_fen": 7000', '"amount_fen": 999999, "amount_fen": 7000')

    def handler(_request: httpx.Request) -> httpx.Response:
        body = {"choices": [{"message": {"content": output}}]}
        return httpx.Response(200, json=body)

    planner = WorkflowPlanner(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_NOT_A_REAL_KEY"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(PlannerError) as error:
        planner.plan("refund", context(mode), stage="refund")
    assert error.value.reason_code == "LLM_OUTPUT_INVALID"


def test_cloud_refund_contract_retains_exact_integer_bound() -> None:
    amount = plan_schema("refund")["properties"]["intents"]["items"]["properties"]["parameters"][
        "properties"
    ]["amount_fen"]
    assert amount["maximum"] == 9007199254740991
    assert amount["type"] == "integer"
    assert amount["minimum"] == 0


def test_rules_ignore_injected_amount_and_do_not_call_provider() -> None:
    inputs = context("deterministic").model_copy(update={"prompt_text": "refund amount_fen=999999"})
    decision = WorkflowPlanner(
        Settings(),
        transport=httpx.MockTransport(lambda _request: pytest.fail("rules called provider")),
    ).plan("refund", inputs, stage="refund")
    assert decision.intents[0].parameters["amount_fen"] == 7000
    assert decision.evidence["prompt_text_consumed"] is False


def test_cloud_requires_explicit_server_enablement_and_official_https() -> None:
    with pytest.raises(PlannerError) as unavailable:
        WorkflowPlanner(Settings(cloud_llm_api_key="TEST_NOT_A_REAL_KEY")).plan(
            "refund", context("cloud"), stage="refund"
        )
    assert unavailable.value.reason_code == "MODEL_MODE_UNAVAILABLE"
    with pytest.raises(PlannerError) as wrong_host:
        WorkflowPlanner(
            Settings(
                cloud_llm_enabled=True,
                cloud_llm_api_key="TEST_NOT_A_REAL_KEY",
                cloud_llm_base_url="http://untrusted.invalid",
            )
        ).plan("refund", context("cloud"), stage="refund")
    assert wrong_host.value.reason_code == "MODEL_CONFIGURATION_INVALID"


def test_cloud_requires_synthetic_data_confirmation_before_provider() -> None:
    planner = WorkflowPlanner(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_NOT_A_REAL_KEY"),
        transport=httpx.MockTransport(
            lambda _request: pytest.fail("unconfirmed cloud called provider")
        ),
    )
    with pytest.raises(PlannerError) as caught:
        planner.plan(
            "refund",
            context("cloud").model_copy(update={"cloud_data_confirmed": False}),
            stage="refund",
        )
    assert caught.value.reason_code == "CLOUD_CONFIRMATION_REQUIRED"
    assert caught.value.status_code == 400


def test_operational_projection_removes_authority_and_hidden_reasoning_recursively() -> None:
    assert safe_observation(
        {
            "input": {"workflow_token": "secret", "ticket_id": "T10086"},
            "output": [{"api_key": "secret", "reasoning_content": "hidden", "summary": "public"}],
            "credential_chain": [],
            "holder_proof": {},
        }
    ) == {
        "input": {"ticket_id": "T10086"},
        "output": [{"summary": "public"}],
    }


def test_runtime_profile_does_not_invoke_cloud_or_expose_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        httpx, "Client", lambda **_kwargs: pytest.fail("cloud readiness must not invoke provider")
    )
    result = runtime_profiles(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_NOT_A_REAL_KEY")
    )
    assert {item["mode"] for item in result["items"]} == {"deterministic", "cloud"}
    cloud = next(item for item in result["items"] if item["mode"] == "cloud")
    assert cloud["verification"] == "configured_not_invoked"
    assert cloud["available"] is True
    assert "TEST_NOT_A_REAL_KEY" not in json.dumps(result)
