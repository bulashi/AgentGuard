"""Independent regression checks for fact-based planning and its RPC boundary.

Cloud responses and business RPCs are explicitly isolated stubs. These tests do
not establish vendor/model accuracy, PostgreSQL effects, or cryptographic proof.
"""

from __future__ import annotations

import json
from copy import deepcopy

import httpx
import pytest

from backend.agent_runtime.contracts import AgentContext, PlanDecision, ToolIntent
from backend.agent_runtime.planner import PlannerError
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.agent_runtime.workflow_planner import (
    WorkflowPlanner,
    default_plan,
    planning_input,
)
from backend.business_action.facts import evaluate_business_facts
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex

TASK_ID = "TASK-facts-planning"
TICKET_ID = "T-facts-planning"
CUSTOMER_ID = "customer-facts"
ROOT = [{"payload": {"task_id": TASK_ID, "tenant_id": "tenant-facts"}}]
FORBIDDEN_ANSWER = "PREFILLED_ANSWER_DO_NOT_SEND"


def raw_facts(second_status="SUCCESS", *, refunded=2000, third_status=None):
    payments = [
        {
            "transaction_id": "PAY-FIRST",
            "amount_fen": 7000,
            "status": "SUCCESS",
            "refunded_amount_fen": 0,
        },
        {
            "transaction_id": "PAY-SECOND",
            "amount_fen": 7000,
            "status": second_status,
            "refunded_amount_fen": refunded if second_status == "SUCCESS" else 0,
        },
    ]
    if third_status is not None:
        payments.append(
            {
                "transaction_id": "PAY-THIRD",
                "amount_fen": 7000,
                "status": third_status,
                "refunded_amount_fen": 0,
            }
        )
    return {
        "schema_version": "1.0",
        "order": {"order_id": "ORDER-facts", "amount_fen": 7000, "currency": "CNY"},
        "payments": payments,
        "claim_text": "客户申报可能重复扣款。请核对交易记录。",
    }


def context(*, mode="deterministic", facts=None):
    source = raw_facts() if facts is None else facts
    return AgentContext(
        ticket_id=TICKET_ID,
        customer_id=CUSTOMER_ID,
        refund_amount_fen=7000,
        runtime_mode=mode,
        cloud_data_confirmed=mode == "cloud",
        workflow_token="WORKFLOW_TOKEN_DO_NOT_SEND",
        ticket_context={
            "ticket_id": TICKET_ID,
            "tenant_id": "tenant-facts",
            "customer_id": CUSTOMER_ID,
            "status": "OPEN",
            "title": "退款申请",
            "description": source["claim_text"],
            "business_facts": deepcopy(source),
            "facts_hash": sm3_hex(canonicalize(source)),
            "verification_status": FORBIDDEN_ANSWER,
            "payment_verification_status": FORBIDDEN_ANSWER,
            "refund_verifications": [{"verification_status": FORBIDDEN_ANSWER}],
            "business_verification": {"reason": FORBIDDEN_ANSWER},
            "refundable_amount_fen": 1,
            "unrecognized_internal_field": FORBIDDEN_ANSWER,
        },
        authorization_context={"root": {"quotas": {"refund_total_fen": 7000}}},
    )


def test_fact_ticket_model_input_excludes_precomputed_outcomes_and_unknown_fields():
    inputs = planning_input(context(), "refund", "refund")
    assert inputs["ticket"]["business_facts"] == raw_facts()
    serialized = json.dumps(inputs, ensure_ascii=False)
    assert FORBIDDEN_ANSWER not in serialized
    assert "WORKFLOW_TOKEN_DO_NOT_SEND" not in serialized
    for field in (
        "refund_verifications",
        "verification_status",
        "payment_verification_status",
        "business_verification",
        "refundable_amount_fen",
        "unrecognized_internal_field",
    ):
        assert field not in inputs["ticket"]
    assert inputs["committed_refund"] == {}
    assert inputs["authorized_task"]["refund_limit_fen"] == 7000
    assert "refund_amount_fen" not in inputs["authorized_task"]


def test_deterministic_candidate_uses_facts_amount_instead_of_authorization_ceiling():
    request = context()
    output = default_plan(request, "refund")
    assert output["decision"] == "propose"
    assert len(output["intents"]) == 1
    assert output["intents"][0]["parameters"] == {
        "ticket_id": TICKET_ID,
        "customer_id": CUSTOMER_ID,
        "amount_fen": 5000,
    }
    assert request.refund_amount_fen == 7000


@pytest.mark.parametrize(
    "second,third,expected_word",
    [
        ("FAILED", None, "失败"),
        ("PROCESSING", None, "处理"),
        ("SUCCESS", "SUCCESS", "多笔"),
    ],
)
def test_deterministic_stopping_reason_is_derived_from_changed_payment_facts(
    second, third, expected_word
):
    facts = raw_facts(second, refunded=0, third_status=third)
    output = default_plan(context(facts=facts), "refund")
    assert output["decision"] == "decline"
    assert output["intents"] == []
    assert expected_word in output["summary"]
    assert FORBIDDEN_ANSWER not in output["summary"]


def test_cloud_http_json_contains_raw_facts_without_precomputed_verification():
    requests = []
    output = {
        "decision": "propose",
        "summary": "根据原始交易提出退回50元候选。等待独立核验。",
        "intents": [
            {
                "service": "refund-service",
                "name": "refund.create",
                "version": "v1",
                "parameters": {
                    "ticket_id": TICKET_ID,
                    "customer_id": CUSTOMER_ID,
                    "amount_fen": 5000,
                },
            }
        ],
    }

    def handler(request):
        requests.append(request)
        body = json.loads(request.content)
        user = json.loads(body["messages"][1]["content"])
        assert user["input"]["ticket"]["business_facts"] == raw_facts()
        serialized = json.dumps(user, ensure_ascii=False)
        assert FORBIDDEN_ANSWER not in serialized
        assert "WORKFLOW_TOKEN_DO_NOT_SEND" not in serialized
        assert "refund_verifications" not in serialized
        assert "verification_status" not in serialized
        assert request.url.path == "/chat/completions"
        return httpx.Response(
            200,
            json={
                "model": "test-cloud-facts",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(output, ensure_ascii=False)},
                    }
                ],
            },
        )

    planner = WorkflowPlanner(
        Settings(cloud_llm_enabled=True, cloud_llm_api_key="TEST_KEY_ONLY"),
        transport=httpx.MockTransport(handler),
    )
    decision = planner.plan("refund", context(mode="cloud"), stage="refund")
    assert len(requests) == 1
    assert decision.planner == "llm"
    assert decision.intents[0].parameters["amount_fen"] == 5000
    assert decision.evidence["model_returned"] == "test-cloud-facts"
    assert "TEST_KEY_ONLY" not in json.dumps(decision.evidence)


def test_deterministic_decline_is_a_stop_without_a_fabricated_tool_candidate():
    planner = WorkflowPlanner(Settings())
    with pytest.raises(PlannerError) as caught:
        planner.plan("refund", context(facts=raw_facts("FAILED", refunded=0)), stage="refund")
    assert caught.value.reason_code == "PLANNER_DECLINED"
    assert caught.value.evidence["decision"] == "decline"
    assert caught.value.evidence["intents"] == []
    assert "失败" in caught.value.evidence["summary"]


class RefundHarness:
    """Real runtime orchestration with isolated planner/registry/tool boundaries."""

    def __init__(self, monkeypatch, *, facts=None, candidate=None, decline=False):
        self.context = context(facts=facts)
        self.service = object.__new__(AgentRuntimeService)
        self.service.settings = Settings()
        self.service.agent_id = "agent-refund"
        self.calls = []
        self.trace = []
        self.decline = decline
        self.intent = ToolIntent(
            service="refund-service",
            name="refund.create",
            parameters={"ticket_id": TICKET_ID, "customer_id": CUSTOMER_ID, "amount_fen": 5000}
            | (candidate or {}),
        )
        self.evaluation = evaluate_business_facts(self.context.ticket_context["business_facts"])
        self.evaluation.update(
            schema_version="1.0",
            task_id=TASK_ID,
            ticket_id=TICKET_ID,
            facts_hash=self.context.ticket_context["facts_hash"],
            evaluated_at=1800000000,
        )
        monkeypatch.setattr(self.service, "_plan", self.plan)
        monkeypatch.setattr(self.service, "_post_json", self.post)
        monkeypatch.setattr(self.service, "_call_tool", self.call_tool)

    def plan(self, _role, _context, trace, **_kwargs):
        self.calls.append("plan")
        self.service._step(
            trace,
            "plan",
            {
                "stage": "refund",
                "decision": "decline" if self.decline else "propose",
                "intents": [] if self.decline else [self.intent.model_dump()],
            },
            status="DENIED" if self.decline else "COMPLETED",
        )
        if self.decline:
            raise AgentRuntimeError(
                "PLANNER_DECLINED", "模型决定暂不办理。尚未执行退款。", status_code=409
            )
        return PlanDecision(planner="deterministic", intents=(self.intent,))

    def post(self, _base, path, body, **_kwargs):
        self.calls.append(path)
        assert body == {"task_id": TASK_ID}
        if path == "/business-actions/refund/evaluate":
            return deepcopy(self.evaluation)
        assert path == "/business-actions/refund/resolve"
        return {"business_action_id": "ACTION-facts"}

    def call_tool(self, _chain, intent, **kwargs):
        self.calls.append("dispatch")
        assert kwargs["business_action_id"] == "ACTION-facts"
        assert intent == self.intent
        return {
            "execution_id": "EXEC-facts",
            "result": {
                "refund_id": "REFUND-facts",
                "status": "COMMITTED",
                "tenant_id": "tenant-facts",
                "task_id": TASK_ID,
                "ticket_id": TICKET_ID,
                "customer_id": CUSTOMER_ID,
                "amount_fen": intent.parameters["amount_fen"],
            },
        }

    def run(self):
        return self.service._run_refund(ROOT, self.context, self.trace)


def test_runtime_independently_evaluates_candidate_then_executes_50_under_70_ceiling(monkeypatch):
    harness = RefundHarness(monkeypatch)
    result = harness.run()
    assert result["refund"]["amount_fen"] == 5000
    assert harness.calls == [
        "plan",
        "/business-actions/refund/evaluate",
        "/business-actions/refund/resolve",
        "dispatch",
    ]
    checks = [event for event in harness.trace if event.action == "business_verification"]
    assert len(checks) == 1
    assert checks[0].details["status"] == "VERIFIED"
    assert checks[0].details["facts_hash"] == harness.context.ticket_context["facts_hash"]


@pytest.mark.parametrize("candidate", [{"customer_id": "ATTACKER"}, {"amount_fen": 7000}])
def test_incorrect_candidate_is_not_silently_repaired_or_dispatched(candidate, monkeypatch):
    harness = RefundHarness(monkeypatch, candidate=candidate)
    with pytest.raises(AgentRuntimeError):
        harness.run()
    assert "dispatch" not in harness.calls
    assert "/business-actions/refund/resolve" not in harness.calls
    plans = [event for event in harness.trace if event.action == "plan"]
    assert plans[0].details["intents"][0]["parameters"] == harness.intent.parameters


@pytest.mark.parametrize(
    "change",
    [
        {"task_id": "TASK-other"},
        {"ticket_id": "T-other"},
        {"facts_hash": "0" * 64},
    ],
)
def test_independent_verdict_must_bind_to_current_task_and_input_facts(change, monkeypatch):
    harness = RefundHarness(monkeypatch)
    harness.evaluation.update(change)
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == "BUSINESS_CONTEXT_MISMATCH"
    assert harness.calls == ["plan", "/business-actions/refund/evaluate"]
    assert not any(event.action == "business_verification" for event in harness.trace)


@pytest.mark.parametrize(
    "second,expected",
    [
        ("SUCCESS", "PLANNER_DECLINED"),
        ("FAILED", "BUSINESS_VERIFICATION_REJECTED"),
        ("PROCESSING", "BUSINESS_VERIFICATION_PENDING"),
    ],
)
def test_model_decline_still_records_independent_facts_reason_without_refund(
    second, expected, monkeypatch
):
    harness = RefundHarness(monkeypatch, facts=raw_facts(second), decline=True)
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == expected
    assert harness.calls == ["plan", "/business-actions/refund/evaluate"]
    checks = [event for event in harness.trace if event.action == "business_verification"]
    assert len(checks) == 1
    assert checks[0].details["status"] == harness.evaluation["status"]
    assert checks[0].details["reason"] == harness.evaluation["reason"]
    assert [event.action for event in harness.trace] == ["plan", "business_verification"]
