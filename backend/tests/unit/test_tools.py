from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from backend.business_action.policy import (
    REFUND_SUCCESS_NOTIFICATION_SLOT,
    TrustedTaskContext,
    notification_scope,
)
from backend.common.enums import KeyPurpose
from backend.common.time import now_unix
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import GATEWAY_EXECUTION_ENVELOPE
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex
from backend.tests.business_fixtures import memory_refund_store
from backend.tools.app import make_app
from backend.tools.store import MemoryToolStore

PRIVATE_KEY = "0" * 63 + "1"
PUBLIC_KEY = derive_public_key(PRIVATE_KEY)


def signed_envelope(
    *,
    kind: str,
    attempt: str,
    parameters: dict,
    business_action_id: str | None,
    idempotency_key: str | None,
    parameter_hash: str | None = None,
    execution_id: str | None = None,
) -> dict:
    service_and_tool = {
        "ticket": ("ticket-service", "ticket.read"),
        "knowledge": ("knowledge-service", "knowledge.read_associated"),
        "refund": ("refund-service", "refund.create"),
        "notification": ("notification-service", "notification.send_template"),
    }
    service, tool = service_and_tool[kind]
    current = now_unix()
    payload = {
        "schema_version": "1.0",
        "execution_id": execution_id or f"EXEC-{attempt}",
        "execution_attempt_id": attempt,
        "request_hash": "1" * 64,
        "tenant_id": "tenant-A",
        "task_id": "TASK-001",
        "tool_service": service,
        "tool_name": tool,
        "tool_version": "v1",
        "canonical_validated_parameters": parameters,
        "business_action_id": business_action_id,
        "business_idempotency_key": idempotency_key,
        "parameter_hash": parameter_hash or sm3_hex(canonicalize(parameters)),
        "issued_at": current,
        "expires_at": current + 30,
        "gateway_key_id": "gateway-key-01",
    }
    signature = sign_payload(
        payload,
        domain_separator=GATEWAY_EXECUTION_ENVELOPE,
        key_id="gateway-key-01",
        key_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
        private_key_hex=PRIVATE_KEY,
        public_key_hex=PUBLIC_KEY,
        signed_at=current,
        random_hex="0" * 63 + "2",
    )
    return {"payload": payload, "signature": signature}


def client(kind: str, store: MemoryToolStore) -> TestClient:
    settings = Settings(
        storage="memory",
        tool_kind=kind,
        gateway_public_key_hex=PUBLIC_KEY,
    )
    return TestClient(make_app(settings=settings, store=store))


def resign(envelope: dict, *, signed_at: int | None = None) -> None:
    envelope["signature"] = sign_payload(
        envelope["payload"],
        domain_separator=GATEWAY_EXECUTION_ENVELOPE,
        key_id="gateway-key-01",
        key_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
        private_key_hex=PRIVATE_KEY,
        public_key_hex=PUBLIC_KEY,
        signed_at=(envelope["payload"]["issued_at"] if signed_at is None else signed_at),
        random_hex="0" * 63 + "3",
    )


def test_ticket_and_knowledge_tools_read_real_state() -> None:
    store = MemoryToolStore(
        tickets={
            "T10086": {
                "ticket_id": "T10086",
                "tenant_id": "tenant-A",
                "customer_id": "C9527",
                "title": "Duplicate charge",
                "description": "Customer reports duplicate charge.",
                "status": "OPEN",
            }
        },
        documents={
            "DOC-001": {
                "document_id": "DOC-001",
                "title": "Refund policy",
                "content": "Verified duplicate charges may be refunded.",
                "sensitivity": "INTERNAL",
            }
        },
        ticket_documents={"T10086": ["DOC-001"]},
    )
    ticket_response = client("ticket", store).post(
        "/internal/execute",
        json=signed_envelope(
            kind="ticket",
            attempt="ATTEMPT-TICKET-1",
            parameters={"ticket_id": "T10086"},
            business_action_id=None,
            idempotency_key=None,
        ),
    )
    assert ticket_response.status_code == 200
    assert ticket_response.json()["result"]["ticket_id"] == "T10086"

    knowledge_response = client("knowledge", store).post(
        "/internal/execute",
        json=signed_envelope(
            kind="knowledge",
            attempt="ATTEMPT-KNOWLEDGE-1",
            parameters={"ticket_id": "T10086"},
            business_action_id=None,
            idempotency_key=None,
        ),
    )
    assert knowledge_response.status_code == 200
    assert knowledge_response.json()["result"]["documents"][0]["document_id"] == "DOC-001"


def test_refund_is_idempotent_and_attempt_replay_is_rejected() -> None:
    store = memory_refund_store()
    api = client("refund", store)
    parameters = {"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": 10_000}
    first = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-REFUND-1",
        parameters=parameters,
        business_action_id="ACTION-REFUND-1",
        idempotency_key="a" * 64,
    )
    response = api.post("/internal/execute", json=first)
    assert response.status_code == 200
    assert len(store.refunds) == 1

    replay = api.post("/internal/execute", json=first)
    assert replay.status_code == 409
    assert replay.json()["detail"]["reason_code"] == "EXECUTION_ENVELOPE_REPLAY"
    assert len(store.refunds) == 1

    retry = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-REFUND-2",
        parameters=parameters,
        business_action_id="ACTION-REFUND-1",
        idempotency_key="a" * 64,
        execution_id=first["payload"]["execution_id"],
    )
    retry_response = api.post("/internal/execute", json=retry)
    assert retry_response.status_code == 200
    assert retry_response.json()["business_effect_id"] == response.json()["business_effect_id"]
    assert len(store.refunds) == 1


def test_changed_parameters_under_same_business_key_conflict() -> None:
    store = memory_refund_store()
    api = client("refund", store)
    first_parameters = {"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": 10_000}
    second_parameters = {"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": 20_000}
    first = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-CONFLICT-1",
        parameters=first_parameters,
        business_action_id="ACTION-REFUND-1",
        idempotency_key="b" * 64,
    )
    assert api.post("/internal/execute", json=first).status_code == 200
    second = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-CONFLICT-2",
        parameters=second_parameters,
        business_action_id="ACTION-REFUND-1",
        idempotency_key="b" * 64,
    )
    response = api.post("/internal/execute", json=second)
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == "IDEMPOTENCY_CONFLICT"
    assert len(store.refunds) == 1


def test_tampered_signature_and_parameter_hash_are_rejected_before_effect() -> None:
    store = MemoryToolStore()
    api = client("refund", store)
    parameters = {"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": 10_000}
    envelope = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-TAMPER-1",
        parameters=parameters,
        business_action_id="ACTION-REFUND-1",
        idempotency_key="c" * 64,
    )
    envelope["payload"]["canonical_validated_parameters"]["amount_fen"] = 20_000
    response = api.post("/internal/execute", json=envelope)
    assert response.status_code == 403
    assert response.json()["detail"]["reason_code"] == "INVALID_SIGNATURE"
    assert store.refunds == {}


def test_tool_rejects_oversized_ttl_and_signature_time_mismatch() -> None:
    store = MemoryToolStore()
    api = client("refund", store)
    parameters = {"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": 10_000}

    oversized = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-TTL-OVERSIZED",
        parameters=parameters,
        business_action_id="ACTION-REFUND-TTL",
        idempotency_key="1" * 64,
    )
    oversized["payload"]["expires_at"] = oversized["payload"]["issued_at"] + 31
    resign(oversized)
    response = api.post("/internal/execute", json=oversized)
    assert response.status_code == 403
    assert response.json()["detail"]["reason_code"] == "EXECUTION_ENVELOPE_EXPIRED"

    mismatched_time = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-SIGNED-AT-MISMATCH",
        parameters=parameters,
        business_action_id="ACTION-REFUND-SIGNED-AT",
        idempotency_key="2" * 64,
    )
    resign(mismatched_time, signed_at=mismatched_time["payload"]["issued_at"] + 1)
    response = api.post("/internal/execute", json=mismatched_time)
    assert response.status_code == 403
    assert response.json()["detail"]["reason_code"] == "EXECUTION_ENVELOPE_EXPIRED"
    assert store.refunds == {}

    invalid_parameter_hash = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-TAMPER-HASH",
        parameters=parameters,
        business_action_id="ACTION-REFUND-1",
        idempotency_key="d" * 64,
        parameter_hash="0" * 64,
    )
    response = api.post("/internal/execute", json=invalid_parameter_hash)
    assert response.status_code == 403
    assert response.json()["detail"]["reason_code"] == "PARAMETER_CONSTRAINT_VIOLATION"
    assert store.refunds == {}

    invalid_signature = signed_envelope(
        kind="refund",
        attempt="ATTEMPT-TAMPER-2",
        parameters=parameters,
        business_action_id="ACTION-REFUND-1",
        idempotency_key="e" * 64,
    )
    invalid_signature["signature"]["value"] = "0" * 128
    response = api.post("/internal/execute", json=invalid_signature)
    assert response.status_code == 403
    assert response.json()["detail"]["reason_code"] == "INVALID_SIGNATURE"
    assert store.refunds == {}


def test_notification_uses_fixed_template_and_is_idempotent() -> None:
    store = memory_refund_store(action_id="ACTION-REFUND-NOTICE")
    refund_api = client("refund", store)
    refund = refund_api.post(
        "/internal/execute",
        json=signed_envelope(
            kind="refund",
            attempt="ATTEMPT-REFUND-NOTICE",
            parameters={"ticket_id": "T10086", "customer_id": "C9527", "amount_fen": 7000},
            business_action_id="ACTION-REFUND-NOTICE",
            idempotency_key="c" * 64,
        ),
    )
    assert refund.status_code == 200
    refund_id = refund.json()["business_effect_id"]
    scope_key, _ = notification_scope(
        TrustedTaskContext("tenant-A", "TASK-001", "T10086", "C9527"),
        template_id="REFUND_SUCCESS",
        related_business_effect_id=refund_id,
    )
    store.business_actions["ACTION-NOTIFY-1"] = {
        "tenant_id": "tenant-A",
        "task_id": "TASK-001",
        "tool_service": "notification-service",
        "tool_name": "notification.send_template",
        "trusted_action_slot": REFUND_SUCCESS_NOTIFICATION_SLOT,
        "action_scope_key": scope_key,
        "status": "ACTIVE",
    }
    api = client("notification", store)
    parameters = {
        "customer_id": "C9527",
        "template_id": "REFUND_SUCCESS",
        "related_business_effect_id": refund_id,
    }
    envelope = signed_envelope(
        kind="notification",
        attempt="ATTEMPT-NOTIFY-1",
        parameters=parameters,
        business_action_id="ACTION-NOTIFY-1",
        idempotency_key="e" * 64,
    )
    response = api.post("/internal/execute", json=envelope)
    assert response.status_code == 200
    assert response.json()["result"]["template_id"] == "REFUND_SUCCESS"
    result = response.json()["result"]
    assert result["template_version"] == "v1"
    assert "C9527" in result["content"] and "T10086" in result["content"]
    assert "70.00元" in result["content"] and refund_id in result["content"]
    assert len(store.notifications) == 1

    retry = api.post(
        "/internal/execute",
        json=signed_envelope(
            kind="notification",
            attempt="ATTEMPT-NOTIFY-RETRY",
            parameters=parameters,
            business_action_id="ACTION-NOTIFY-1",
            idempotency_key="e" * 64,
            execution_id=envelope["payload"]["execution_id"],
        ),
    )
    assert retry.status_code == 200
    assert retry.json()["result"] == result
    assert len(store.notifications) == 1

    forbidden = deepcopy(parameters)
    forbidden["template_id"] = "FREE_FORM"
    response = api.post(
        "/internal/execute",
        json=signed_envelope(
            kind="notification",
            attempt="ATTEMPT-NOTIFY-2",
            parameters=forbidden,
            business_action_id="ACTION-NOTIFY-2",
            idempotency_key="f" * 64,
        ),
    )
    assert response.status_code == 403
    assert response.json()["detail"]["reason_code"] == "PARAMETER_CONSTRAINT_VIOLATION"
    assert len(store.notifications) == 1


@pytest.mark.parametrize(
    "change",
    [
        None,
        {"status": "UNKNOWN"},
        {"tenant_id": "tenant-B"},
        {"task_id": "TASK-other"},
        {"ticket_id": "T-other"},
        {"customer_id": "C7812"},
    ],
)
def test_notification_rejects_missing_or_unbound_committed_refund(change) -> None:
    store = memory_refund_store()
    scope_key, _ = notification_scope(
        TrustedTaskContext("tenant-A", "TASK-001", "T10086", "C9527"),
        template_id="REFUND_SUCCESS",
        related_business_effect_id="REFUND-001",
    )
    store.business_actions["ACTION-NOTIFY"] = {
        "tenant_id": "tenant-A",
        "task_id": "TASK-001",
        "tool_service": "notification-service",
        "tool_name": "notification.send_template",
        "trusted_action_slot": REFUND_SUCCESS_NOTIFICATION_SLOT,
        "action_scope_key": scope_key,
        "status": "ACTIVE",
    }
    if change is not None:
        store.refunds["b" * 64] = {
            "refund_id": "REFUND-001",
            "tenant_id": "tenant-A",
            "task_id": "TASK-001",
            "ticket_id": "T10086",
            "customer_id": "C9527",
            "amount_fen": 7000,
            "status": "COMMITTED",
            **change,
        }
    response = client("notification", store).post(
        "/internal/execute",
        json=signed_envelope(
            kind="notification",
            attempt="ATTEMPT-NOTIFY-INVALID",
            parameters={
                "customer_id": "C9527",
                "template_id": "REFUND_SUCCESS",
                "related_business_effect_id": "REFUND-001",
            },
            business_action_id="ACTION-NOTIFY",
            idempotency_key="e" * 64,
        ),
    )
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == "BUSINESS_ACTION_INVALID"
    assert store.notifications == {}
