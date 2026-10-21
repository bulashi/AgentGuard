from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Event

import pytest

from backend.agent_runtime.contracts import AgentContext, PlanDecision, ToolIntent
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.config.settings import Settings

ROOT = [{"payload": {"task_id": "TASK-dependency-test", "tenant_id": "tenant-A"}}]
TICKET = {"ticket_id": "T10086", "customer_id": "C9527", "tenant_id": "tenant-A", "status": "OPEN"}
REFUND = {"refund_id": "REFUND-test", "amount_fen": 7000, "status": "COMMITTED"}


class CaseHarness:
    """Unit-only RPC/tool spies; these are not live model or database evidence."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.service = object.__new__(AgentRuntimeService)
        self.service.agent_id = "agent-case"
        self.service.settings = Settings()
        self.calls: list[str] = []
        self.ticket = deepcopy(TICKET)
        self.refund = deepcopy(REFUND)
        self.notification = {
            "notification_id": "NOTIFY-test",
            "status": "SENT",
            "template_id": "REFUND_SUCCESS",
            "related_business_effect_id": "REFUND-test",
        }
        self.refund_started = Event()
        self.refund_release = Event()
        self.refund_release.set()
        monkeypatch.setattr(self.service, "_plan", self.plan)
        monkeypatch.setattr(self.service, "_call_tool", self.call_tool)
        monkeypatch.setattr(self.service, "_delegate", self.delegate)
        monkeypatch.setattr(self.service, "_run_child", self.run_child)
        monkeypatch.setattr(self.service, "_post_json", self.post)

    def plan(self, _role, context, _trace, *, stage, **_kwargs):
        self.calls.append(stage)
        if stage == "case_read":
            intent = ToolIntent(
                service="ticket-service",
                name="ticket.read",
                parameters={"ticket_id": context.ticket_id},
            )
        else:
            assert stage == "case_notify"
            assert context.refund_context == self.refund
            intent = ToolIntent(
                service="notification-service",
                name="notification.send_template",
                parameters={
                    "customer_id": context.customer_id,
                    "template_id": "REFUND_SUCCESS",
                },
            )
        return PlanDecision(planner="deterministic", intents=(intent,))

    def call_tool(self, _chain, intent, **_kwargs):
        self.calls.append(intent.name)
        output = self.ticket if intent.name == "ticket.read" else self.notification
        return {"execution_id": "EXEC-test", "result": output}

    def delegate(self, _chain, **_kwargs):
        self.calls.append("delegate_refund")
        return {"payload": {"credential_id": "CRED-refund"}}

    def run_child(self, _url, _chain, context, _trace):
        self.calls.append("refund_started")
        assert context.ticket_context == self.ticket
        self.refund_started.set()
        assert self.refund_release.wait(3), "refund test barrier was not released"
        self.calls.append("refund_returned")
        return {"refund": self.refund}

    def post(self, _url, path, body, **_kwargs):
        assert path == "/business-actions/notification/resolve"
        assert body["related_business_effect_id"] == self.refund["refund_id"]
        self.calls.append("resolve_notification")
        return {"business_action_id": "ACTION-notification"}

    def run(self):
        return self.service._run_case(
            ROOT,
            AgentContext(
                ticket_id="T10086",
                customer_id="C9527",
                refund_amount_fen=7000,
                runtime_mode="deterministic",
                knowledge_context={"summary": "unit rules"},
            ),
            [],
        )


@pytest.mark.parametrize(
    "change",
    [
        {"status": "UNKNOWN"},
        {"status": "RESERVED"},
        {"refund_id": ""},
        {"amount_fen": 7},
        {"amount_fen": True},
        {"customer_id": "ATTACKER"},
        {"ticket_id": "OTHER"},
        {"task_id": "TASK-other"},
        {"tenant_id": "tenant-B"},
    ],
)
def test_case_does_not_plan_success_notice_from_an_unconfirmed_refund(change, monkeypatch):
    harness = CaseHarness(monkeypatch)
    harness.refund.update(change)
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == "BUSINESS_RESULT_MISMATCH"
    assert "case_notify" not in harness.calls
    assert "notification.send_template" not in harness.calls


@pytest.mark.parametrize(
    "change",
    [
        {"ticket_id": "OTHER"},
        {"customer_id": "ATTACKER"},
        {"tenant_id": "tenant-B"},
        {"ticket_id": None},
        {"customer_id": None},
    ],
)
def test_case_does_not_delegate_refund_from_an_unbound_ticket(change, monkeypatch):
    harness = CaseHarness(monkeypatch)
    harness.ticket.update(change)
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == "BUSINESS_CONTEXT_MISMATCH"
    assert "delegate_refund" not in harness.calls
    assert "case_notify" not in harness.calls


@pytest.mark.parametrize("status", ["CLOSED", "RESOLVED", "UNKNOWN", None])
def test_case_stops_before_refund_delegation_when_ticket_is_ineligible(status, monkeypatch):
    harness = CaseHarness(monkeypatch)
    harness.ticket["status"] = status
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == "BUSINESS_PRECONDITION_FAILED"
    assert "delegate_refund" not in harness.calls
    assert "case_notify" not in harness.calls


@pytest.mark.parametrize(
    "change",
    [
        {"status": "PENDING"},
        {"notification_id": ""},
        {"template_id": "OTHER"},
        {"related_business_effect_id": "REFUND-other"},
        {"customer_id": "ATTACKER"},
    ],
)
def test_case_does_not_report_completion_from_a_mismatched_notice(change, monkeypatch):
    harness = CaseHarness(monkeypatch)
    harness.notification.update(change)
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == "BUSINESS_RESULT_MISMATCH"


def test_notification_cannot_overtake_the_refund_response(monkeypatch):
    harness = CaseHarness(monkeypatch)
    harness.refund_release.clear()
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(harness.run)
        try:
            assert harness.refund_started.wait(2)
            assert "case_notify" not in harness.calls
            assert "notification.send_template" not in harness.calls
        finally:
            harness.refund_release.set()
        assert result.result(timeout=3)["notification"]["status"] == "SENT"
    assert harness.calls == [
        "case_read",
        "ticket.read",
        "delegate_refund",
        "refund_started",
        "refund_returned",
        "case_notify",
        "resolve_notification",
        "notification.send_template",
    ]


def test_case_stops_when_refund_is_declined(monkeypatch):
    harness = CaseHarness(monkeypatch)

    def decline(*_args, **_kwargs):
        raise AgentRuntimeError("PLANNER_DECLINED", "unit explicit decline", status_code=409)

    monkeypatch.setattr(harness.service, "_run_child", decline)
    with pytest.raises(AgentRuntimeError, match="unit explicit decline"):
        harness.run()
    assert "case_notify" not in harness.calls
    assert "notification.send_template" not in harness.calls


def test_case_stops_when_refund_result_is_unknown(monkeypatch):
    harness = CaseHarness(monkeypatch)

    def unknown(*_args, **_kwargs):
        raise AgentRuntimeError("RESULT_NOT_AVAILABLE", "unit unknown effect", status_code=409)

    monkeypatch.setattr(harness.service, "_run_child", unknown)
    with pytest.raises(AgentRuntimeError, match="unit unknown effect"):
        harness.run()
    assert "case_notify" not in harness.calls


def test_coordinator_waits_for_knowledge_before_dispatching_case(monkeypatch):
    service = object.__new__(AgentRuntimeService)
    service.agent_id = "agent-coordinator"
    service.settings = Settings()
    started, release = Event(), Event()
    calls = []
    context = AgentContext(
        ticket_id="T10086",
        customer_id="C9527",
        refund_amount_fen=7000,
        runtime_mode="deterministic",
    )
    monkeypatch.setattr(
        service,
        "_plan",
        lambda *_args, **_kwargs: PlanDecision(planner="deterministic", intents=()),
    )
    monkeypatch.setattr(
        service,
        "_delegate",
        lambda _chain, **kwargs: {"payload": {"credential_id": kwargs["child_role"]}},
    )

    def child(_url, chain, child_context, _trace):
        role = chain[-1]["payload"]["credential_id"]
        calls.append(role)
        if role == "knowledge":
            started.set()
            assert release.wait(3)
            return {"summary": "actual unit knowledge"}
        assert child_context.knowledge_context == {"summary": "actual unit knowledge"}
        return {"refund": REFUND}

    monkeypatch.setattr(service, "_run_child", child)
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(service._run_coordinator, ROOT, context, [])
        try:
            assert started.wait(2)
            assert calls == ["knowledge"]
        finally:
            release.set()
        assert result.result(timeout=3)["case"]["refund"] == REFUND
    assert calls == ["knowledge", "case"]
