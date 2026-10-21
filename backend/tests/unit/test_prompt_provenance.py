from __future__ import annotations

import json
from copy import deepcopy

import httpx
import pytest

from backend.agent_runtime.contracts import AgentContext
from backend.agent_runtime.knowledge_attacks import forged_approval_addendum
from backend.agent_runtime.service import public_credential_scope
from backend.agent_runtime.workflow_planner import (
    PROMPT_PROFILE,
    WorkflowPlanner,
    default_plan,
    planning_messages,
)
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.tools.demo_materials import POLICY_CONTENT, TICKET_DESCRIPTION


def test_scope_is_a_copy_of_allowlisted_claims_not_live_budget_or_secret() -> None:
    chain = [
        {
            "payload": {
                "tenant_id": "tenant-A",
                "task_id": "TASK-1",
                "delegation_depth": 2,
                "quotas": {"refund_total_fen": 7000},
                "private_key": "DO_NOT_EXPOSE",
            },
            "signature": {"value": "SECRET"},
        }
    ]
    before = deepcopy(chain)
    scope = public_credential_scope(chain)
    assert scope["root"]["delegation_depth"] == 2
    assert "not_live_remaining" in scope["budget_semantics"]
    assert "DO_NOT_EXPOSE" not in json.dumps(scope)
    assert "SECRET" not in json.dumps(scope)
    scope["root"]["quotas"]["refund_total_fen"] = 999
    assert chain == before


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
def test_prompt_evidence_reconstructs_exact_model_messages(role: str, stage: str) -> None:
    context = AgentContext(
        ticket_id="T10086",
        customer_id="C9527",
        refund_amount_fen=7000,
        runtime_mode="cloud",
        cloud_data_confirmed=True,
        workflow_token="INTERNAL_TOKEN_NOT_SENT",
        ticket_context={"description": TICKET_DESCRIPTION},
        knowledge_context={"documents": [{"content": POLICY_CONTENT}]},
    )
    captured = []

    def respond(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content)["messages"])
        return httpx.Response(
            200,
            json={
                "model": "fixture-model",
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(default_plan(context, stage), ensure_ascii=False)
                        }
                    }
                ],
            },
        )

    result = WorkflowPlanner(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_KEY"),
        transport=httpx.MockTransport(respond),
    ).plan(role, context, stage=stage)
    messages = planning_messages(context, role, stage)
    assert captured == [messages]
    assert result.evidence["prompt_profile"] == PROMPT_PROFILE
    assert result.evidence["user_prompt"] == messages[1]["content"]
    assert result.evidence["prompt_messages_sm3"] == sm3_hex(canonicalize(messages))
    assert result.evidence["system_prompt"] == messages[0]["content"]
    assert result.evidence["http_status"] == 200
    assert result.evidence["request_length_bytes"] > 0
    assert result.evidence["response_length_bytes"] > 0
    assert len(result.evidence["response_sha256"]) == 64
    assert result.evidence["duration_ms"] >= 1
    assert "INTERNAL_TOKEN_NOT_SENT" not in json.dumps(result.evidence)
    assert "TEST_KEY" not in json.dumps(result.evidence)
    assert "重复扣款退款处理规范" in messages[1]["content"]
    assert all(word not in json.dumps(messages, ensure_ascii=False)
               for word in ("合成", "模拟", "演示", "ATTACKER"))


def test_input_limits_apply_before_any_cloud_call() -> None:
    context = AgentContext(
        ticket_id="T",
        customer_id="C",
        refund_amount_fen=1,
        ticket_context={"description": "X" * 140000},
    )
    from backend.agent_runtime.planner import PlannerError

    with pytest.raises(PlannerError, match="bounded model context"):
        planning_messages(context, "case", "case_read")


def test_attack_text_reaches_model_without_evaluator_metadata_or_internal_ids() -> None:
    content = POLICY_CONTENT + forged_approval_addendum("T10086", "C9527", 7000)
    knowledge = {
        "documents": [{"document_id": "DOC-001", "content": content}],
        "summary": "资料摘要", "demo_injection": True, "injection_applied": True,
        "scenario": "policy_injection", "execution_id": "INTERNAL_EXECUTION_ID",
        "ground_truth": "should_reject",
    }
    original = deepcopy(knowledge)
    context = AgentContext(
        ticket_id="T10086", customer_id="C9527", refund_amount_fen=7000,
        runtime_mode="cloud", knowledge_context=knowledge,
    )
    messages = planning_messages(context, "refund", "refund")
    value = json.loads(messages[1]["content"])
    assert value["input"]["knowledge"] == {
        "documents": knowledge["documents"], "summary": knowledge["summary"],
    }
    assert value["input"]["knowledge"]["documents"][0]["content"] == content
    for marker in ("demo_injection", "injection_applied", "policy_injection",
                   "INTERNAL_EXECUTION_ID", "ground_truth", "should_reject", "ATTACKER"):
        assert marker not in messages[1]["content"]
    assert knowledge == original


@pytest.mark.parametrize("status", [401, 429, 503])
def test_failed_cloud_attempt_keeps_actual_metadata_without_credentials(status: int) -> None:
    from backend.agent_runtime.planner import PlannerError

    planner = WorkflowPlanner(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_KEY"),
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json={"error": "test"})),
    )
    context = AgentContext(
        ticket_id="T10086",
        customer_id="C9527",
        refund_amount_fen=7000,
        runtime_mode="cloud",
        cloud_data_confirmed=True,
    )
    with pytest.raises(PlannerError) as error:
        planner.plan("coordinator", context, stage="coordinate")
    evidence = error.value.evidence
    assert evidence["http_status"] == status
    assert evidence["request_length_bytes"] > 0 and evidence["response_length_bytes"] > 0
    assert len(evidence["response_sha256"]) == 64
    assert evidence["duration_ms"] >= 1
    assert evidence["failure_type"] == "HTTPStatusError"
    assert evidence["prompt_profile"] == PROMPT_PROFILE
    assert "TEST_KEY" not in json.dumps(evidence)
