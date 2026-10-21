from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import backend.recovery.app as recovery_app
from backend.business_action.policy import PRIMARY_REFUND_SLOT, TrustedTaskContext, refund_scope
from backend.common.internal_auth import CALLER_HEADER, PROOF_HEADER, InternalAuthenticator
from backend.common.time import now_unix
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.recovery.service import RecoveryService
from backend.tests.unit.test_internal_auth import authenticator
from backend.tests.unit.test_tools import PUBLIC_KEY, signed_envelope
from backend.tools.app import make_app as make_tool_app
from backend.tools.store import MemoryToolStore

RECONCILE_BODY = {
    "schema_version": "1.0", "execution_id": "EXEC-001", "tenant_id": "tenant-A",
    "task_id": "TASK-001", "business_action_id": "ACTION-001",
    "business_idempotency_key": "a" * 64, "parameter_hash": "b" * 64,
}


def tool_client(tmp_path: Path, kind: str = "refund") -> tuple[TestClient, Mock]:
    store = Mock(spec=MemoryToolStore)
    store.reconcile.return_value = {"status": "NOT_EXECUTED"}
    client = TestClient(make_tool_app(
        settings=Settings(storage="memory", tool_kind=kind), store=store,
        internal_auth=authenticator(tmp_path, f"{kind}-service"),
    ))
    return client, store


def post_signed(
    client: TestClient, sender: InternalAuthenticator, *, recipient: str, path: str,
    document: dict, headers: dict[str, str] | None = None,
):
    body = canonicalize(document)
    return client.post(
        path, content=body,
        headers=headers or sender.request_headers(
            recipient=recipient, method="POST", path=path, body=body,
        ),
    )


@pytest.mark.parametrize("kind", ["refund", "notification"])
@pytest.mark.parametrize("headers", [{}, {CALLER_HEADER: "recovery-worker"}])
def test_unauthenticated_reconcile_never_reads_business_state(
    tmp_path: Path, kind, headers,
) -> None:
    client, store = tool_client(tmp_path, kind)
    response = client.post("/internal/reconcile", json=RECONCILE_BODY, headers=headers)
    assert response.status_code == 403
    store.reconcile.assert_not_called()
    store.execute.assert_not_called()


@pytest.mark.parametrize("kind", ["refund", "notification"])
def test_authenticated_reconcile_is_read_only_and_replay_is_rejected(tmp_path: Path, kind) -> None:
    client, store = tool_client(tmp_path, kind)
    sender = authenticator(tmp_path, "recovery-worker")
    body = canonicalize(RECONCILE_BODY)
    headers = sender.request_headers(
        recipient=f"{kind}-service", method="POST", path="/internal/reconcile", body=body,
    )
    response = client.post("/internal/reconcile", content=body, headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "NOT_EXECUTED"
    store.reconcile.assert_called_once()
    store.execute.assert_not_called()
    replay = client.post("/internal/reconcile", content=body, headers=headers)
    assert replay.status_code == 409
    assert replay.json()["detail"]["reason_code"] == "REPLAY_DETECTED"
    assert store.reconcile.call_count == 1


@pytest.mark.parametrize("mutation", ["body", "recipient", "duplicate-header", "query"])
def test_reconcile_rejects_tampering_before_state_read(tmp_path: Path, mutation: str) -> None:
    client, store = tool_client(tmp_path)
    body = canonicalize(RECONCILE_BODY)
    headers = authenticator(tmp_path, "recovery-worker").request_headers(
        recipient="notification-service" if mutation == "recipient" else "refund-service",
        method="POST", path="/internal/reconcile", body=body,
    )
    path = "/internal/reconcile"
    if mutation == "body":
        body = canonicalize({**RECONCILE_BODY, "execution_id": "EXEC-OTHER"})
    elif mutation == "duplicate-header":
        headers = [*headers.items(), (PROOF_HEADER, headers[PROOF_HEADER])]
    elif mutation == "query":
        path += "?execution_id=EXEC-OTHER"
    response = client.post(path, content=body, headers=headers)
    assert response.status_code == 403
    store.reconcile.assert_not_called()
    store.execute.assert_not_called()


def test_reconcile_returns_existing_refund_without_creating_another(tmp_path: Path) -> None:
    store = MemoryToolStore()
    context = TrustedTaskContext(
        tenant_id="tenant-A", task_id="TASK-001", ticket_id="T10086", customer_id="C9527",
    )
    store.tasks[context.task_id] = {
        "tenant_id": context.tenant_id, "task_id": context.task_id,
        "ticket_id": context.ticket_id, "customer_id": context.customer_id,
        "status": "AUTHORIZED", "expires_at": now_unix() + 3600,
    }
    store.tickets[context.ticket_id] = {
        "tenant_id": context.tenant_id, "ticket_id": context.ticket_id,
        "customer_id": context.customer_id, "status": "OPEN",
    }
    store.business_actions["ACTION-AUTH-RECOVERY"] = {
        "tenant_id": context.tenant_id, "task_id": context.task_id,
        "tool_service": "refund-service", "tool_name": "refund.create", "status": "ACTIVE",
        "trusted_action_slot": PRIMARY_REFUND_SLOT, "action_scope_key": refund_scope(context)[0],
    }
    verified = {
        "tenant_id": context.tenant_id, "customer_id": context.customer_id,
        "original_transaction_id": "TXN-UNIT-001", "verification_status": "VERIFIED",
        "refundable_amount_fen": 7000, "verified_at": now_unix(),
        "evidence_reference": "UNIT-VERIFICATION-001",
    }
    store.payment_verifications[(context.tenant_id, "TXN-UNIT-001")] = dict(verified)
    store.refund_eligibility[(context.ticket_id, PRIMARY_REFUND_SLOT)] = {
        **verified, "ticket_id": context.ticket_id, "trusted_action_slot": PRIMARY_REFUND_SLOT,
        "refund_reason_code": "DUPLICATE_CHARGE",
    }
    client = TestClient(make_tool_app(
        settings=Settings(
            storage="memory", tool_kind="refund", gateway_public_key_hex=PUBLIC_KEY,
        ),
        store=store, internal_auth=authenticator(tmp_path, "refund-service"),
    ))
    envelope = signed_envelope(
        kind="refund", attempt="ATTEMPT-AUTH-RECOVERY",
        parameters={"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": 7000},
        business_action_id="ACTION-AUTH-RECOVERY", idempotency_key="c" * 64,
    )
    execution = client.post("/internal/execute", json=envelope)
    assert execution.status_code == 200
    payload = envelope["payload"]
    document = {"schema_version": "1.0"} | {
        name: payload[name] for name in RECONCILE_BODY if name != "schema_version"
    }
    sender = authenticator(tmp_path, "recovery-worker")
    for _ in range(2):
        response = post_signed(
            client, sender, recipient="refund-service", path="/internal/reconcile",
            document=document,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ALREADY_EXECUTED"
        assert response.json()["result"] == execution.json()["result"]
        assert response.json()["business_effect_id"] == execution.json()["business_effect_id"]
    assert len(store.refunds) == 1
    assert len(store.attempts) == 1


def recovery_client(tmp_path: Path, *, required: bool = True) -> tuple[TestClient, Mock]:
    service = Mock(spec=RecoveryService)
    service.recover_once.return_value = None
    service.scan_once.return_value = []
    client = TestClient(recovery_app.make_app(
        settings=Settings(recovery_autorun=False), recovery_service=service,
        internal_auth=authenticator(tmp_path, "recovery-worker", required=required),
    ))
    return client, service


@pytest.mark.parametrize("headers", [{}, {CALLER_HEADER: "recovery-trigger"}])
def test_unauthenticated_trigger_cannot_start_recovery(tmp_path: Path, headers) -> None:
    client, service = recovery_client(tmp_path)
    response = client.post("/internal/recovery/run", json={}, headers=headers)
    assert response.status_code == 403
    service.scan_once.assert_not_called()
    service.recover_once.assert_not_called()


@pytest.mark.parametrize("document", [{}, {"execution_id": "EXEC-001"}])
def test_valid_trigger_uses_only_server_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: dict,
) -> None:
    monkeypatch.setattr(recovery_app, "now_unix", lambda: 1000)
    client, service = recovery_client(tmp_path)
    response = post_signed(
        client, authenticator(tmp_path, "recovery-trigger"), recipient="recovery-worker",
        path="/internal/recovery/run", document=document,
    )
    assert response.status_code == 200
    if document:
        service.recover_once.assert_called_once_with(execution_id="EXEC-001", current_time=1000)
        service.scan_once.assert_not_called()
    else:
        service.scan_once.assert_called_once_with(current_time=1000)
        service.recover_once.assert_not_called()


@pytest.mark.parametrize("current_time", [0, 1000, 1001, 9_007_199_254_740_991])
def test_authenticated_trigger_cannot_override_recovery_time(tmp_path: Path, current_time) -> None:
    client, service = recovery_client(tmp_path)
    response = post_signed(
        client, authenticator(tmp_path, "recovery-trigger"), recipient="recovery-worker",
        path="/internal/recovery/run", document={"current_time": current_time},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["reason_code"] == "PARAMETER_CONSTRAINT_VIOLATION"
    service.scan_once.assert_not_called()
    service.recover_once.assert_not_called()


def test_trigger_replay_invokes_recovery_once(tmp_path: Path) -> None:
    client, service = recovery_client(tmp_path)
    body = canonicalize({"execution_id": "EXEC-001"})
    headers = authenticator(tmp_path, "recovery-trigger").request_headers(
        recipient="recovery-worker", method="POST", path="/internal/recovery/run", body=body,
    )
    assert client.post("/internal/recovery/run", content=body, headers=headers).status_code == 200
    response = client.post("/internal/recovery/run", content=body, headers=headers)
    assert response.status_code == 409
    service.recover_once.assert_called_once()


def test_explicit_test_mode_retains_virtual_clock_without_claiming_authentication(
    tmp_path: Path,
) -> None:
    client, service = recovery_client(tmp_path, required=False)
    response = client.post(
        "/internal/recovery/run", json={"execution_id": "EXEC-001", "current_time": 100},
        headers={CALLER_HEADER: "recovery-trigger"},
    )
    assert response.status_code == 200
    service.recover_once.assert_called_once_with(execution_id="EXEC-001", current_time=100)


def test_agent_with_an_unrelated_edge_key_cannot_act_as_trigger(tmp_path: Path) -> None:
    client, service = recovery_client(tmp_path)
    document = {}
    body = canonicalize(document)
    sender = authenticator(
        tmp_path, "agent-refund", keys={"agent-refund->recovery-worker": "77" * 32},
    )
    response = client.post(
        "/internal/recovery/run", content=body,
        headers=sender.request_headers(
            recipient="recovery-worker", method="POST", path="/internal/recovery/run", body=body,
        ),
    )
    assert response.status_code == 403
    service.scan_once.assert_not_called()
    service.recover_once.assert_not_called()


def test_strict_body_fields_are_not_bypassed_by_valid_authentication(tmp_path: Path) -> None:
    client, service = recovery_client(tmp_path)
    body = b'{"execution_id":"EXEC-001","execution_id":"EXEC-OTHER"}'
    headers = authenticator(tmp_path, "recovery-trigger").request_headers(
        recipient="recovery-worker", method="POST", path="/internal/recovery/run", body=body,
    )
    response = client.post("/internal/recovery/run", content=body, headers=headers)
    assert response.status_code == 422
    service.recover_once.assert_not_called()
