"""Local HTTP/authentication and normal-run queue checks for business facts.

The registry database and workflow engine are stubs; HMAC request verification
and strict HTTP contracts use the real handlers. No external model is called.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.business_action.app import make_app as registry_app
from backend.business_action.contracts import CreateBusinessCaseRequest
from backend.business_action.service import BusinessActionRegistryService
from backend.common.internal_auth import InternalAuthenticator, SqliteNonceStore
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.ui_api.app import make_app as ui_app
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore

KEYS = {"ui-api->business-action-registry": "55" * 32}
CREATE = {
    "tenant_id": "tenant-facts",
    "customer_id": "customer-facts",
    "ticket_id": "T-facts-ui",
    "order_id": "ORDER-facts-ui",
    "order_amount_fen": 7000,
    "claim_text": "客户申报可能重复扣款。请核对交易记录。",
    "cloud_shareable": False,
    "payments": [
        {
            "transaction_id": "PAY-facts-1",
            "amount_fen": 7000,
            "status": "SUCCESS",
            "refunded_amount_fen": 0,
        },
        {
            "transaction_id": "PAY-facts-2",
            "amount_fen": 7000,
            "status": "FAILED",
            "refunded_amount_fen": 0,
        },
    ],
}


def saved_case():
    request = CreateBusinessCaseRequest.model_validate(CREATE)
    facts = request.raw_facts()
    return {
        "ticket_id": request.ticket_id,
        "tenant_id": request.tenant_id,
        "customer_id": request.customer_id,
        "title": "退款申请",
        "description": request.claim_text,
        "status": "OPEN",
        "cloud_shareable": request.cloud_shareable,
        "business_facts": facts,
        "facts_hash": sm3_hex(canonicalize(facts)),
        "created_at": 1800000000,
    }


def receiver(tmp_path: Path):
    return InternalAuthenticator(
        service_id="business-action-registry",
        keys_json=json.dumps(KEYS),
        required=True,
        nonce_store=SqliteNonceStore(tmp_path / "registry-nonces.sqlite3"),
    )


def test_business_creation_rpc_is_authenticated_as_ui_and_exact_facts_are_written(
    monkeypatch, tmp_path
):
    registry = Mock(spec=BusinessActionRegistryService)
    registry.create_business_case.return_value = saved_case()
    server = TestClient(
        registry_app(settings=Settings(), service=registry, internal_auth=receiver(tmp_path))
    )
    requests = []
    real_client = httpx.Client

    def handler(request):
        requests.append(request)
        assert request.url.path == "/business-cases"
        assert json.loads(request.content) == CREATE
        response = server.post(
            request.url.path, content=request.content, headers=dict(request.headers)
        )
        return httpx.Response(response.status_code, content=response.content)

    def client(*args, **kwargs):
        assert kwargs["trust_env"] is False
        return real_client(*args, **kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr("backend.ui_api.service.httpx.Client", client)
    subject = UiService(
        Settings(
            business_action_registry_url="http://registry.test",
            internal_auth_required=True,
            internal_auth_service_id="ui-api",
            internal_auth_keys=json.dumps(KEYS),
        ),
        Mock(spec=UiReadStore),
    )
    assert (
        subject.create_business_case(CreateBusinessCaseRequest.model_validate(CREATE))
        == saved_case()
    )
    assert len(requests) == 1
    proof = json.loads(requests[0].headers["X-AgentGuard-Internal-Proof"])
    assert proof["caller"] == "ui-api"
    assert proof["recipient"] == "business-action-registry"
    assert proof["path"] == "/business-cases"
    assert proof["method"] == "POST"
    assert proof["body_sm3"] == sm3_hex(requests[0].content)
    registry.create_business_case.assert_called_once()
    assert registry.create_business_case.call_args.args[0].model_dump() == CREATE


def test_missing_registry_auth_edge_stops_before_transport(monkeypatch):
    client = Mock(side_effect=AssertionError("must not send an unauthenticated fact write"))
    monkeypatch.setattr("backend.ui_api.service.httpx.Client", client)
    subject = UiService(
        Settings(
            business_action_registry_url="http://registry.test",
            internal_auth_required=True,
            internal_auth_service_id="ui-api",
            internal_auth_keys="{}",
        ),
        Mock(spec=UiReadStore),
    )
    with pytest.raises(UiApiError) as caught:
        subject.create_business_case(CreateBusinessCaseRequest.model_validate(CREATE))
    assert caught.value.reason_code == "INTERNAL_AUTH_UNAVAILABLE"
    client.assert_not_called()


def test_registry_does_not_accept_unsigned_fact_creation_or_model_supplied_judgment(tmp_path):
    registry = Mock(spec=BusinessActionRegistryService)
    server = TestClient(
        registry_app(
            settings=Settings(internal_auth_required=False),
            service=registry,
            internal_auth=receiver(tmp_path),
        )
    )
    response = server.post("/business-cases", json=CREATE)
    assert response.status_code == 403
    registry.create_business_case.assert_not_called()
    sender = InternalAuthenticator(service_id="ui-api", keys_json=json.dumps(KEYS), required=True)
    body = canonicalize(CREATE | {"verification_status": "VERIFIED", "refundable_amount_fen": 7000})
    response = server.post(
        "/business-cases",
        content=body,
        headers=sender.request_headers(
            recipient="business-action-registry", method="POST", path="/business-cases", body=body
        ),
    )
    assert response.status_code == 400
    registry.create_business_case.assert_not_called()


def test_business_case_browser_write_requires_operator_session():
    service = Mock(spec=UiService)
    app = ui_app(
        settings=Settings(operator_auth_required=True, operator_session_secret="11" * 32),
        service=service,
    )
    response = TestClient(app, base_url="http://127.0.0.1").post("/api/business/cases", json=CREATE)
    assert response.status_code == 401
    assert response.json()["reason_code"] == "OPERATOR_SESSION_REQUIRED"
    service.create_business_case.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        {"ticket_id": "T-other"},
        {"customer_id": "customer-other"},
        {"facts_hash": "0" * 64},
        {"cloud_shareable": True},
    ],
)
def test_business_case_response_cannot_claim_different_identity_facts_or_privacy(
    change, monkeypatch
):
    body = saved_case() | change
    subject = UiService(Settings(), Mock(spec=UiReadStore))
    monkeypatch.setattr(subject, "_post", Mock(return_value=body))
    with pytest.raises(UiApiError) as caught:
        subject.create_business_case(CreateBusinessCaseRequest.model_validate(CREATE))
    assert caught.value.reason_code == "CONTROLLED_RESULT_INVALID"


def test_business_case_response_cannot_replace_raw_payments(monkeypatch):
    body = deepcopy(saved_case())
    body["business_facts"]["payments"][1]["status"] = "SUCCESS"
    body["facts_hash"] = sm3_hex(canonicalize(body["business_facts"]))
    subject = UiService(Settings(), Mock(spec=UiReadStore))
    monkeypatch.setattr(subject, "_post", Mock(return_value=body))
    with pytest.raises(UiApiError) as caught:
        subject.create_business_case(CreateBusinessCaseRequest.model_validate(CREATE))
    assert caught.value.reason_code == "CONTROLLED_RESULT_INVALID"


def test_normal_run_uses_persistent_queue_and_never_calls_synchronous_agent(monkeypatch):
    subject = UiService(Settings(), Mock(spec=UiReadStore))
    queued = {
        "run_id": "RUN-facts-ui",
        "task_id": "TASK-facts-ui",
        "state": "QUEUED",
        "runtime_mode": "deterministic",
    }
    start = Mock(return_value=queued)
    monkeypatch.setattr(subject, "start_authorized_workflow", start)
    transport = Mock(side_effect=AssertionError("normal run must not call /agents/run"))
    monkeypatch.setattr(subject, "_post", transport)
    result = subject.run_task("TASK-facts-ui")
    start.assert_called_once()
    assert start.call_args.args[0] == "TASK-facts-ui"
    request = start.call_args.args[1]
    assert request.runtime_mode == "deterministic" and request.scenario == "normal"
    assert result["status"] == "QUEUED"
    assert result["run_id"] == queued["run_id"]
    assert result["trace"] == []
    transport.assert_not_called()
