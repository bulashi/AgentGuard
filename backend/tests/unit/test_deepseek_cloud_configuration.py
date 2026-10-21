from __future__ import annotations

import json

import httpx
import pytest

from backend.agent_runtime.contracts import AgentContext
from backend.agent_runtime.planner import PlannerError
from backend.agent_runtime.workflow_planner import WorkflowPlanner, default_plan, runtime_profiles
from backend.config.settings import Settings


def cloud_context(*, confirmed: bool = True) -> AgentContext:
    return AgentContext(
        ticket_id="T10086", customer_id="C9527", refund_amount_fen=7000,
        runtime_mode="cloud", cloud_data_confirmed=confirmed,
        workflow_token="PRIVATE_WORKFLOW_TOKEN",
    )


def cloud_settings(**overrides: object) -> Settings:
    return Settings(**{
        "cloud_llm_enabled": True, "cloud_llm_api_key": "TEST_ONLY_NOT_A_REAL_KEY",
        **overrides,
    })


@pytest.mark.parametrize("stage,role", [
    ("coordinate", "coordinator"), ("knowledge_read", "knowledge"),
    ("knowledge_summary", "knowledge"), ("case_read", "case"),
    ("refund", "refund"), ("case_notify", "case"),
])
def test_official_cloud_contract(stage: str, role: str) -> None:
    context = cloud_context()

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.deepseek.com/chat/completions"
        assert request.headers["Authorization"] == "Bearer TEST_ONLY_NOT_A_REAL_KEY"
        body = json.loads(request.content)
        assert body["model"] == "deepseek-flash"
        assert body["thinking"] == {"type": "disabled"}
        assert body["response_format"] == {"type": "json_object"}
        assert "PRIVATE_WORKFLOW_TOKEN" not in request.content.decode()
        assert "TEST_ONLY_NOT_A_REAL_KEY" not in request.content.decode()
        return httpx.Response(200, json={
            "model": "deepseek-flash",
            "choices": [{"message": {
                "content": json.dumps(default_plan(context, stage)),
                "reasoning_content": "HIDDEN_REASONING",
            }}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10},
        })

    decision = WorkflowPlanner(cloud_settings(), transport=httpx.MockTransport(handler)).plan(
        role, context, stage=stage,
    )
    assert decision.planner == "llm"
    evidence = json.dumps(decision.evidence)
    for forbidden in ("TEST_ONLY_NOT_A_REAL_KEY", "PRIVATE_WORKFLOW_TOKEN", "HIDDEN_REASONING"):
        assert forbidden not in evidence


@pytest.mark.parametrize("status", [401, 402, 429, 500])
def test_upstream_failures_never_fall_back(status: int) -> None:
    planner = WorkflowPlanner(cloud_settings(), transport=httpx.MockTransport(
        lambda _request: httpx.Response(status, json={"error": "test"}),
    ))
    with pytest.raises(PlannerError) as error:
        planner.plan("refund", cloud_context(), stage="refund")
    assert error.value.reason_code == "LLM_UPSTREAM_UNAVAILABLE"


def test_cloud_confirmation_is_required_before_request() -> None:
    planner = WorkflowPlanner(cloud_settings(), transport=httpx.MockTransport(
        lambda _request: pytest.fail("unconfirmed cloud request was sent"),
    ))
    with pytest.raises(PlannerError) as error:
        planner.plan("refund", cloud_context(confirmed=False), stage="refund")
    assert error.value.reason_code == "CLOUD_CONFIRMATION_REQUIRED"


@pytest.mark.parametrize("override", [
    {"cloud_llm_base_url": "https://untrusted.invalid"},
    {"cloud_llm_model": "deepseek-v4-pro"},
])
def test_wrong_provider_or_model_is_rejected(override: dict) -> None:
    planner = WorkflowPlanner(cloud_settings(**override), transport=httpx.MockTransport(
        lambda _request: pytest.fail("unsupported configuration was used"),
    ))
    with pytest.raises(PlannerError) as error:
        planner.plan("refund", cloud_context(), stage="refund")
    assert error.value.reason_code == "MODEL_CONFIGURATION_INVALID"


def test_runtime_profiles_never_expose_key() -> None:
    profiles = runtime_profiles(cloud_settings())
    assert [item["mode"] for item in profiles["items"]] == ["deterministic", "cloud"]
    assert profiles["items"][1]["available"] is True
    assert profiles["items"][1]["verification"] == "configured_not_invoked"
    assert "TEST_ONLY_NOT_A_REAL_KEY" not in json.dumps(profiles)
