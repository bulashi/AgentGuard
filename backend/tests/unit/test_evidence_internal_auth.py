from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

import backend.common.internal_auth as auth_module
from backend.agent_runtime.service import AgentRuntimeService
from backend.audit.app import make_app as make_audit_app
from backend.audit.client import AuditClient
from backend.audit.service import AuditService
from backend.audit.worker_app import AuditAppendWorker
from backend.business_action.app import make_app as make_registry_app
from backend.business_action.service import BusinessActionRegistryService
from backend.checkpoint.app import make_app as make_checkpoint_app
from backend.checkpoint.service import CheckpointService
from backend.checkpoint.worker_app import CheckpointWorker
from backend.common.internal_auth import CALLER_HEADER, PROOF_HEADER
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.receipt.app import make_app as make_receipt_app
from backend.receipt.client import ReceiptClient
from backend.receipt.service import ReceiptService
from backend.tests.unit.test_internal_auth import authenticator

EVIDENCE_KEYS = {
    "secure-gateway->receipt-service": "11" * 32,
    "recovery-worker->receipt-service": "22" * 32,
    "secure-gateway->audit-append-authority": "33" * 32,
    "audit-worker->audit-append-authority": "44" * 32,
    "checkpoint-worker->checkpoint-service": "55" * 32,
    "agent-refund->business-action-registry": "66" * 32,
    "agent-case->business-action-registry": "77" * 32,
}
REJECTED_EVENT = {
    "schema_version": "1.0", "event_id": "EVENT-RAW-001", "raw_request_hash": "a" * 64,
    "parser_stage": "JSON", "reason_code": "MALFORMED_JSON",
    "source_context": {"route": "/execute"}, "received_at": 1000,
}
UNIT_RECEIPT = {"guard_test": "not_a_signature_result"}
ROUTES = [
    ("receipt-service", "secure-gateway", "POST", "/internal/receipts/issue",
     {"execution_id": "EXEC-001"}, "issue"),
    ("receipt-service", "secure-gateway", "GET", "/internal/receipts/EXEC-001", None, "get"),
    ("audit-append-authority", "audit-worker", "POST", "/internal/audit/append",
     {"max_events": 10}, "append_pending"),
    ("audit-append-authority", "secure-gateway", "POST", "/internal/audit/rejected",
     REJECTED_EVENT, "enqueue_rejected"),
    ("checkpoint-service", "checkpoint-worker", "POST", "/internal/checkpoint/run",
     None, "run_once"),
    ("business-action-registry", "agent-refund", "POST", "/business-actions/refund/resolve",
     {"task_id": "TASK-001"}, "resolve_refund"),
    ("business-action-registry", "agent-case", "POST", "/business-actions/notification/resolve",
     {"task_id": "TASK-001", "template_id": "REFUND_SUCCESS",
      "related_business_effect_id": "REFUND-001"}, "resolve_notification"),
]


def evidence_auth(tmp_path: Path, service_id: str, *, keys=None):
    return authenticator(
        tmp_path, service_id, keys=EVIDENCE_KEYS if keys is None else keys,
    )


def target_client(tmp_path: Path, recipient: str, *, keys=None):
    guard = evidence_auth(tmp_path, recipient, keys=keys)
    settings = Settings(internal_auth_required=True)
    if recipient == "receipt-service":
        service = Mock(spec=ReceiptService)
        service.issue.return_value = UNIT_RECEIPT
        service.get.return_value = UNIT_RECEIPT
        app = make_receipt_app(settings=settings, service=service, internal_auth=guard)
    elif recipient == "audit-append-authority":
        service = Mock(spec=AuditService)
        service.append_pending.return_value = {
            "appended_count": 1, "latest_event_sequence": 1, "latest_event_hash": "a" * 64,
        }
        app = make_audit_app(settings=settings, service=service, internal_auth=guard)
    elif recipient == "checkpoint-service":
        service = Mock(spec=CheckpointService)
        service.run_once.return_value = {"guard_test": "not_a_signature_result"}
        app = make_checkpoint_app(settings=settings, service=service, internal_auth=guard)
    else:
        service = Mock(spec=BusinessActionRegistryService)
        action = {
            "schema_version": "1.0", "business_action_id": "ACTION-001",
            "action_scope_key": "a" * 64, "tenant_id": "tenant-A", "task_id": "TASK-001",
            "tool_service": "refund-service", "tool_name": "refund.create",
            "trusted_action_slot": "primary-refund", "created_at": 1000, "status": "ACTIVE",
        }
        service.resolve_refund.return_value = action
        service.resolve_notification.return_value = {
            **action, "tool_service": "notification-service",
            "tool_name": "notification.send_template", "trusted_action_slot": "refund-notice",
        }
        app = make_registry_app(settings=settings, service=service, internal_auth=guard)
    return TestClient(app), service


@pytest.mark.parametrize(("recipient", "caller", "method", "path", "document", "operation"), ROUTES)
@pytest.mark.parametrize("text_identity", [None, "matching", "phase11-test"])
def test_high_trust_endpoints_reject_unsigned_text_without_business_call(
    tmp_path: Path, recipient, caller, method, path, document, operation, text_identity,
) -> None:
    client, service = target_client(tmp_path, recipient)
    headers = {} if text_identity is None else {
        CALLER_HEADER: caller if text_identity == "matching" else text_identity,
    }
    raw = b"" if document is None else canonicalize(document)
    response = client.request(method, path, content=raw, headers=headers)
    assert response.status_code == 403
    getattr(service, operation).assert_not_called()


@pytest.mark.parametrize(("recipient", "caller", "method", "path", "document", "operation"), ROUTES)
def test_authenticated_evidence_operation_cannot_be_replayed(
    tmp_path: Path, recipient, caller, method, path, document, operation,
) -> None:
    client, service = target_client(tmp_path, recipient)
    raw = b"" if document is None else canonicalize(document)
    headers = evidence_auth(tmp_path, caller).request_headers(
        recipient=recipient, method=method, path=path, body=raw,
    )
    assert client.request(method, path, content=raw, headers=headers).status_code == 200
    assert client.request(method, path, content=raw, headers=headers).status_code == 409
    getattr(service, operation).assert_called_once()


@pytest.mark.parametrize(("recipient", "caller", "method", "path", "document", "operation"), ROUTES)
def test_evidence_operation_binds_exact_body_and_does_not_consume_invalid_proof(
    tmp_path: Path, recipient, caller, method, path, document, operation,
) -> None:
    client, service = target_client(tmp_path, recipient)
    raw = b"" if document is None else canonicalize(document)
    headers = evidence_auth(tmp_path, caller).request_headers(
        recipient=recipient, method=method, path=path, body=raw,
    )
    response = client.request(method, path, content=raw + b" ", headers=headers)
    assert response.status_code == 403
    getattr(service, operation).assert_not_called()
    assert client.request(method, path, content=raw, headers=headers).status_code == 200
    getattr(service, operation).assert_called_once()


@pytest.mark.parametrize(("recipient", "caller", "method", "path", "document", "operation"), ROUTES)
def test_configured_agent_edge_is_not_permission_to_write_trusted_evidence(
    tmp_path: Path, recipient, caller, method, path, document, operation,
) -> None:
    del caller
    keys = {**EVIDENCE_KEYS, f"agent-knowledge->{recipient}": "aa" * 32}
    client, service = target_client(tmp_path, recipient, keys=keys)
    raw = b"" if document is None else canonicalize(document)
    headers = evidence_auth(tmp_path, "agent-knowledge", keys=keys).request_headers(
        recipient=recipient, method=method, path=path, body=raw,
    )
    assert client.request(method, path, content=raw, headers=headers).status_code == 403
    getattr(service, operation).assert_not_called()


@pytest.mark.parametrize(("path", "caller", "document", "operation"), [
    ("/business-actions/refund/resolve", "agent-case", {"task_id": "TASK-001"}, "resolve_refund"),
    ("/business-actions/notification/resolve", "agent-refund",
     {"task_id": "TASK-001", "template_id": "REFUND_SUCCESS",
      "related_business_effect_id": "REFUND-001"}, "resolve_notification"),
])
def test_registry_agent_cannot_use_the_other_roles_write_route(
    tmp_path: Path, path, caller, document, operation,
) -> None:
    client, service = target_client(tmp_path, "business-action-registry")
    raw = canonicalize(document)
    headers = evidence_auth(tmp_path, caller).request_headers(
        recipient="business-action-registry", method="POST", path=path, body=raw,
    )
    assert client.post(path, content=raw, headers=headers).status_code == 403
    getattr(service, operation).assert_not_called()


@pytest.mark.parametrize("kind", ["receipt", "audit"])
def test_gateway_evidence_client_signs_sent_bytes_with_fresh_retry_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    monkeypatch.setattr(auth_module, "now_unix", lambda: 1000)
    recipient = "receipt-service" if kind == "receipt" else "audit-append-authority"
    receiver = evidence_auth(tmp_path, recipient)
    requests = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={"secure-gateway"},
        )
        if kind == "receipt":
            assert json.loads(request.content) == {"execution_id": "EXEC-001"}
            return httpx.Response(200, json={"receipt": UNIT_RECEIPT})
        assert json.loads(request.content) == REJECTED_EVENT
        return httpx.Response(200, json={"status": "accepted"})

    real_client = httpx.Client

    def client_factory(**kwargs):
        assert kwargs["trust_env"] is False
        return real_client(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)
    guard = evidence_auth(tmp_path, "secure-gateway")
    if kind == "receipt":
        subject = ReceiptClient("http://receipt.invalid", internal_auth=guard)

        def invoke():
            return subject.issue("EXEC-001", current_time=1)

    else:
        subject = AuditClient("http://audit.invalid", internal_auth=guard)

        def invoke():
            return subject.enqueue_rejected(REJECTED_EVENT)

    assert invoke()
    assert invoke()
    assert len(requests) == 2
    assert requests[0].headers[PROOF_HEADER] != requests[1].headers[PROOF_HEADER]


@pytest.mark.parametrize("kind", ["receipt", "audit"])
def test_missing_gateway_edge_never_falls_back_to_constant_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    client_factory = Mock(side_effect=AssertionError("must not send unsigned request"))
    monkeypatch.setattr(httpx, "Client", client_factory)
    guard = evidence_auth(tmp_path, "secure-gateway", keys={})
    if kind == "receipt":
        subject = ReceiptClient("http://receipt.invalid", internal_auth=guard)
        assert subject.issue("EXEC-001") is None
    else:
        assert AuditClient("http://audit.invalid", internal_auth=guard).enqueue_rejected(
            REJECTED_EVENT,
        ) is False
    client_factory.assert_not_called()


@pytest.mark.parametrize("kind", ["audit", "checkpoint"])
def test_evidence_workers_sign_empty_or_canonical_body_and_refresh_proofs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    recipient = "audit-append-authority" if kind == "audit" else "checkpoint-service"
    caller = "audit-worker" if kind == "audit" else "checkpoint-worker"
    receiver = evidence_auth(tmp_path, recipient)
    requests = []
    stop = asyncio.Event()

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={caller},
        )
        stop.set()
        if kind == "audit":
            assert json.loads(request.content) == {"max_events": 1000}
            return httpx.Response(200, json={"appended_count": 1})
        assert request.content == b""
        return httpx.Response(200, json={"status": "CREATED"})

    real_client = httpx.AsyncClient

    def client_factory(**kwargs):
        assert kwargs["trust_env"] is False
        return real_client(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    worker_type = AuditAppendWorker if kind == "audit" else CheckpointWorker
    subject = worker_type(
        "http://worker.invalid", interval_seconds=1,
        internal_auth=evidence_auth(tmp_path, caller),
    )

    async def run_twice():
        nonlocal stop
        await subject.run(stop)
        stop = asyncio.Event()
        await subject.run(stop)

    asyncio.run(run_twice())
    assert subject.cycles == 2
    assert subject.last_error is None
    assert len(requests) == 2
    assert requests[0].headers[PROOF_HEADER] != requests[1].headers[PROOF_HEADER]


@pytest.mark.parametrize(("role", "path", "document"), [
    ("refund", "/business-actions/refund/resolve", {"task_id": "TASK-001"}),
    ("case", "/business-actions/notification/resolve",
     {"task_id": "TASK-001", "template_id": "REFUND_SUCCESS",
      "related_business_effect_id": "REFUND-001"}),
])
def test_runtime_registry_client_uses_corresponding_agent_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, path, document,
) -> None:
    monkeypatch.setattr(auth_module, "now_unix", lambda: 1000)
    receiver = evidence_auth(tmp_path, "business-action-registry")
    requests = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={f"agent-{role}"},
        )
        assert json.loads(request.content) == document
        return httpx.Response(200, json={"guard_test": "not_a_business_result"})

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: real_client(
            transport=httpx.MockTransport(handle), **kwargs,
        ),
    )
    subject = AgentRuntimeService.__new__(AgentRuntimeService)
    subject.role = role
    subject.agent_id = f"agent-{role}"
    subject.settings = Settings(
        internal_auth_required=True, internal_auth_service_id=f"agent-{role}",
        internal_auth_keys=json.dumps(EVIDENCE_KEYS),
        business_action_registry_url="http://registry.invalid",
    )
    assert subject._post_json("http://registry.invalid", path, document) == {
        "guard_test": "not_a_business_result",
    }
    assert len(requests) == 1
