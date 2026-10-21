from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from backend.authorization.policy import build_root_capabilities
from backend.delegation.attenuation import AttenuationError, assert_monotonic_attenuation
from backend.delegation.contracts import DelegateCredentialRequest


def _parent_payload() -> dict[str, object]:
    return {
        "tenant_id": "tenant-A",
        "task_id": "TASK-001",
        "verifier_audience": "secure-tool-gateway",
        "capabilities": build_root_capabilities(
            ticket_id="T10086", customer_id="C9527", refund_total_fen=50_000
        ),
        "quotas": {"refund_total_fen": 50_000, "max_tool_calls": 20},
        "not_before": 100,
        "expires_at": 1_000,
        "delegation_depth": 2,
    }


def _child_payload() -> dict[str, object]:
    parent = _parent_payload()
    refund = deepcopy(parent["capabilities"][2])  # type: ignore[index]
    refund["constraints"]["single_max_fen"] = 10_000
    return {
        "tenant_id": "tenant-A",
        "task_id": "TASK-001",
        "verifier_audience": "secure-tool-gateway",
        "capabilities": [refund],
        "quotas": {"refund_total_fen": 20_000, "max_tool_calls": 5},
        "not_before": 200,
        "expires_at": 900,
        "delegation_depth": 1,
    }


def test_valid_child_is_monotonically_attenuated() -> None:
    assert_monotonic_attenuation(_parent_payload(), _child_payload())


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("tenant_id",), "tenant-B"),
        (("task_id",), "TASK-OTHER"),
        (("verifier_audience",), "other-gateway"),
        (("capabilities", 0, "version"), "v2"),
        (("capabilities", 0, "resources", "customer_ids"), ["attacker"]),
        (("capabilities", 0, "constraints", "single_max_fen"), 30_000),
        (("quotas", "refund_total_fen"), 60_000),
        (("quotas", "max_tool_calls"), 21),
        (("not_before",), 99),
        (("expires_at",), 1_001),
        (("delegation_depth",), 0),
    ],
)
def test_every_escalation_dimension_is_rejected(
    path: tuple[object, ...], value: object
) -> None:
    child = _child_payload()
    target: object = child
    for part in path[:-1]:
        target = target[part]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]
    with pytest.raises(AttenuationError):
        assert_monotonic_attenuation(_parent_payload(), child)


def test_unknown_service_and_template_are_rejected() -> None:
    child = _child_payload()
    child["capabilities"][0]["service"] = "admin-service"  # type: ignore[index]
    with pytest.raises(AttenuationError):
        assert_monotonic_attenuation(_parent_payload(), child)

    notification = deepcopy(_parent_payload()["capabilities"][3])  # type: ignore[index]
    notification["constraints"]["template_ids"] = ["PASSWORD_RESET"]
    child = _child_payload()
    child["capabilities"] = [notification]
    with pytest.raises(AttenuationError):
        assert_monotonic_attenuation(_parent_payload(), child)


@pytest.mark.parametrize("field", ["ticket_ids", "customer_ids"])
def test_child_cannot_remove_parent_resource_restriction(field: str) -> None:
    child = _child_payload()
    del child["capabilities"][0]["resources"][field]  # type: ignore[index]
    with pytest.raises(AttenuationError):
        assert_monotonic_attenuation(_parent_payload(), child)


def test_child_cannot_remove_parent_single_amount_limit() -> None:
    child = _child_payload()
    child["capabilities"][0]["constraints"] = {}  # type: ignore[index]
    with pytest.raises(AttenuationError):
        assert_monotonic_attenuation(_parent_payload(), child)


def test_child_cannot_remove_parent_template_limit() -> None:
    parent = _parent_payload()
    child = _child_payload()
    child["capabilities"] = [deepcopy(parent["capabilities"][3])]  # type: ignore[index]
    child["capabilities"][0]["constraints"] = {}  # type: ignore[index]
    with pytest.raises(AttenuationError):
        assert_monotonic_attenuation(parent, child)


def test_frozen_delegate_request_rejects_unknown_and_duplicate_content() -> None:
    payload = {
        "holder_agent_id": "agent-refund",
        "holder_key_id": "agent-refund-key-01",
        "capabilities": [_child_payload()["capabilities"][0]],
        "quotas": {"refund_total_fen": 20_000, "max_tool_calls": 5},
        "not_before": 200,
        "expires_at": 900,
    }
    request = DelegateCredentialRequest.model_validate(payload)
    assert request.holder_agent_id == "agent-refund"
    with pytest.raises(ValidationError):
        DelegateCredentialRequest.model_validate({**payload, "issuer_override": "attacker"})
    with pytest.raises(ValidationError):
        DelegateCredentialRequest.model_validate(
            {**payload, "capabilities": payload["capabilities"] * 2}
        )
