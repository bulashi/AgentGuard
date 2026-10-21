from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.authorization.app import parse_trusted_confirmers
from backend.authorization.contracts import AuthorizeTaskRequest, CreateTaskRequest
from backend.authorization.policy import build_root_capabilities


def test_root_policy_is_fixed_and_task_scoped() -> None:
    capabilities = build_root_capabilities(
        ticket_id="T10086", customer_id="C9527", refund_total_fen=50_000
    )
    assert [(item["service"], item["tool"]) for item in capabilities] == [
        ("ticket-service", "ticket.read"),
        ("knowledge-service", "knowledge.read_associated"),
        ("refund-service", "refund.create"),
        ("notification-service", "notification.send_template"),
    ]
    assert capabilities[2]["resources"] == {
        "ticket_ids": ["T10086"],
        "customer_ids": ["C9527"],
    }
    assert capabilities[2]["constraints"] == {"single_max_fen": 20_000}
    assert capabilities[3]["constraints"] == {"template_ids": ["REFUND_SUCCESS"]}


def test_single_refund_limit_never_exceeds_total_budget() -> None:
    capabilities = build_root_capabilities(
        ticket_id="T10086", customer_id="C9527", refund_total_fen=5_000
    )
    assert capabilities[2]["constraints"]["single_max_fen"] == 5_000


def test_frozen_requests_reject_implicit_confirmation_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        AuthorizeTaskRequest.model_validate(
            {
                "confirmed": False,
                "confirmer_id": "user-admin-01",
                "holder_agent_id": "agent-coordinator",
                "holder_key_id": "agent-coordinator-key-01",
                "delegation_depth": 2,
            }
        )
    with pytest.raises(ValidationError):
        CreateTaskRequest.model_validate(
            {
                "tenant_id": "tenant-A",
                "ticket_id": "T10086",
                "customer_id": "C9527",
                "refund_total_fen": 50_000,
                "max_tool_calls": 20,
                "expires_in_seconds": 1_800,
                "extra_permission": "refund.unbounded",
            }
        )


def test_trusted_confirmer_configuration_is_explicit() -> None:
    assert parse_trusted_confirmers("user-admin-01:USER,policy-refund-v1:POLICY") == {
        "user-admin-01": "USER",
        "policy-refund-v1": "POLICY",
    }
    with pytest.raises(ValueError):
        parse_trusted_confirmers("model-output:LLM")
