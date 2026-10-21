from __future__ import annotations

from typing import Any

import pytest

from backend.agent_runtime.contracts import ToolIntent
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService, RecordedTrace
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import derive_public_key, sm3_hex


def test_request_observation_binds_exact_envelope_without_saving_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = object.__new__(AgentRuntimeService)
    service.agent_id = "agent-refund"
    service.key_id = "agent-refund-key-01"
    service.private_key = "2" * 64  # Public test fixture, never a deployed key.
    service.public_key = derive_public_key(service.private_key)
    service.settings = type("TestSettings", (), {"gateway_url": "http://test-only"})()
    envelopes: list[dict[str, Any]] = []
    recorded = []
    trace = RecordedTrace(recorded.append)

    def deny(_base: str, _path: str, body: dict[str, Any]) -> dict[str, Any]:
        envelopes.append(body)
        error = AgentRuntimeError("PARAMETER_CONSTRAINT_VIOLATION", "test denial")
        error.execution_id = "EXEC-test-denied"
        raise error

    monkeypatch.setattr(service, "_post_json", deny)
    chain = [{"payload": {"credential_id": "ROOT-test", "task_id": "TASK-test"}}]
    intent = ToolIntent(
        service="refund-service",
        name="refund.create",
        version="v1",
        parameters={"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": 999999},
    )
    with pytest.raises(AgentRuntimeError):
        service._call_tool(chain, intent, business_action_id="ACTION-test", trace=trace)
    envelope = envelopes[0]
    request, decision = recorded
    assert request.details["request_hash"] == sm3_hex(canonicalize(envelope))
    assert request.details["parameter_hash"] == sm3_hex(canonicalize(intent.parameters))
    assert request.details["credential_chain_hash"] == sm3_hex(canonicalize(chain))
    assert request.details["request_id"] == envelope["request_id"]
    assert request.details["tool_service"] == envelope["tool_service"]
    assert request.details["tool_version"] == envelope["tool_version"]
    assert request.details["holder_key_id"] == envelope["holder_key_id"]
    assert decision.details["request_id"] == request.details["request_id"]
    assert decision.details["request_hash"] == request.details["request_hash"]
    assert decision.details["execution_id"] == "EXEC-test-denied"
    assert not {"credential_chain", "holder_proof", "signature", "private_key"} & request.details.keys()
