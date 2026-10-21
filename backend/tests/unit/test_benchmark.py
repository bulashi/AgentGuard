from __future__ import annotations

import pytest

from backend.benchmark.agentguard_client import HttpObservation
from backend.benchmark.baseline_client import BaselineBenchmarkClient
from backend.benchmark.baseline_service import baseline_action_scope, baseline_policy_decision
from backend.benchmark.contracts import BaselineToolRequest
from backend.benchmark.runner import ModeMeasurement, evaluate_acceptance
from backend.benchmark.statistics import latency_summary, percentile
from backend.business_action.policy import TrustedTaskContext, notification_scope, refund_scope


def principal(*, status: str = "ACTIVE") -> dict[str, object]:
    return {
        "status": status,
        "token_hash": "token-hash",
        "tenant_scope": "tenant-A",
        "service_permissions": ["refund-service"],
    }


def test_static_baseline_checks_only_shared_credential_lifecycle() -> None:
    assert (
        baseline_policy_decision(
            "shared_static_credential",
            supplied_token_hash="token-hash",
            principal=principal(),
            tenant_id="tenant-B",
            tool_service="notification-service",
        )
        is None
    )
    assert (
        baseline_policy_decision(
            "shared_static_credential",
            supplied_token_hash="wrong",
            principal=principal(),
            tenant_id="tenant-A",
            tool_service="refund-service",
        )
        == "INVALID_CREDENTIAL"
    )


def test_rbac_baseline_has_role_tenant_and_service_scope_without_task_scope() -> None:
    assert (
        baseline_policy_decision(
            "conventional_rbac",
            supplied_token_hash="token-hash",
            principal=principal(),
            tenant_id="tenant-A",
            tool_service="refund-service",
        )
        is None
    )
    assert (
        baseline_policy_decision(
            "conventional_rbac",
            supplied_token_hash="token-hash",
            principal=principal(),
            tenant_id="tenant-B",
            tool_service="refund-service",
        )
        == "CROSS_TENANT"
    )
    assert (
        baseline_policy_decision(
            "conventional_rbac",
            supplied_token_hash="token-hash",
            principal=principal(),
            tenant_id="tenant-A",
            tool_service="notification-service",
        )
        == "TOOL_NOT_ALLOWED"
    )


def test_revoked_baseline_principal_is_rejected_before_scope_checks() -> None:
    assert (
        baseline_policy_decision(
            "conventional_rbac",
            supplied_token_hash="token-hash",
            principal=principal(status="REVOKED"),
            tenant_id="tenant-A",
            tool_service="refund-service",
        )
        == "CREDENTIAL_REVOKED"
    )


@pytest.mark.parametrize("tool", ["refund.create", "notification.send_template"])
@pytest.mark.parametrize("tenant", ["tenant-A", "tenant-B"])
def test_baseline_business_action_uses_the_same_tool_scope_contract(tool: str, tenant: str) -> None:
    notification = tool == "notification.send_template"
    parameters = (
        {
            "customer_id": "customer-1",
            "template_id": "REFUND_SUCCESS",
            "related_business_effect_id": "REFUND-1",
        }
        if notification
        else {"ticket_id": "ticket-1", "customer_id": "customer-1", "amount_fen": 7000}
    )
    request = BaselineToolRequest(
        run_id="bench-unit",
        workload_id="workload-1",
        request_id="request-1",
        operation_id="operation-1",
        task_id="task-1",
        tenant_id=tenant,
        tool_service="notification-service" if notification else "refund-service",
        tool_name=tool,
        canonical_parameters=parameters,
        trusted_action_slot="refund-success-notification" if notification else "primary-refund",
    )
    context = TrustedTaskContext(tenant, "task-1", "ticket-1", "customer-1")
    expected = (
        notification_scope(
            context, template_id="REFUND_SUCCESS", related_business_effect_id="REFUND-1"
        )
        if notification
        else refund_scope(context)
    )
    actual = baseline_action_scope(
        request, task_ticket_id="ticket-1", task_customer_id="customer-1"
    )
    assert actual == expected
    retried = request.model_copy(update={"request_id": "request-2", "operation_id": "operation-2"})
    assert (
        baseline_action_scope(retried, task_ticket_id="ticket-1", task_customer_id="customer-1")
        == actual
    )


def test_percentiles_use_linear_interpolation_and_reject_empty_samples() -> None:
    assert percentile([1, 2, 3, 4], 0.5) == 2.5
    summary = latency_summary([1, 2, 3, 4])
    assert summary == {
        "count": 4,
        "min_ms": 1.0,
        "p50_ms": 2.5,
        "p95_ms": 3.85,
        "p99_ms": 3.97,
        "max_ms": 4.0,
        "mean_ms": 2.5,
    }
    with pytest.raises(ValueError):
        percentile([], 0.5)


def test_baseline_acceptance_uses_decision_body_not_http_status() -> None:
    denied = HttpObservation(
        status_code=200,
        body={"decision": "DENY", "state": "DENIED", "reason_code": "CROSS_TENANT"},
        elapsed_ms=1.0,
    )
    allowed = HttpObservation(
        status_code=200,
        body={"decision": "ALLOW", "state": "COMMITTED", "reason_code": "ALLOWED"},
        elapsed_ms=1.0,
    )
    assert BaselineBenchmarkClient.allowed(denied) is False
    assert BaselineBenchmarkClient.allowed(allowed) is True


def _measurement(name: str) -> ModeMeasurement:
    return ModeMeasurement(
        name=name,
        legitimate_attempts=2,
        legitimate_accepted=2,
        normal_task_attempts=1,
        normal_tasks_completed=1,
        latency_ms=[1.0, 2.0],
        throughput_rps=10.0,
        component_timings_ms={},
        task_ids=[],
        workload_ids=[],
    )


def test_acceptance_requires_security_checks_without_performance_threshold() -> None:
    measurements = {
        "shared_static_credential": _measurement("shared_static_credential"),
        "conventional_rbac": _measurement("conventional_rbac"),
        "agentguard": _measurement("agentguard"),
    }
    aec = {name: {"passed": True} for name in ("AEC-01", "AEC-02", "AEC-03", "AEC-04")}
    acceptance = evaluate_acceptance(
        measurements=measurements,
        attacks={"agentguard": {"unauthorized_side_effects": 0}},
        revocation={"agentguard": {"denied": True}},
        concurrency={"agentguard": {"budget_safe": True}},
        aec=aec,
        audit={"valid": True},
    )
    assert acceptance["passed"] is True
    assert "No numeric performance threshold" in acceptance["note"]

    attacks = {"agentguard": {"unauthorized_side_effects": 1}}
    failed = evaluate_acceptance(
        measurements=measurements,
        attacks=attacks,
        revocation={"agentguard": {"denied": True}},
        concurrency={"agentguard": {"budget_safe": True}},
        aec=aec,
        audit={"valid": True},
    )
    assert failed["passed"] is False
