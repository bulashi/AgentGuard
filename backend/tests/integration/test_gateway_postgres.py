from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex
from backend.gateway.service import SecureGatewayService
from backend.tests.business_fixtures import business_test_case

pytestmark = [pytest.mark.integration]

DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")
REGISTRY_URL = os.getenv("AGENTGUARD_BUSINESS_ACTION_REGISTRY_URL")
GATEWAY_URL = os.getenv("AGENTGUARD_GATEWAY_URL")
HOLDER_PRIVATE_KEY_FILE = os.getenv("AGENTGUARD_HOLDER_PRIVATE_KEY_FILE")
REFUND_TOOL_URL = os.getenv("AGENTGUARD_REFUND_TOOL_URL")
if not all((DATABASE_URL, AUTHORITY_URL, REGISTRY_URL, GATEWAY_URL, HOLDER_PRIVATE_KEY_FILE)):
    pytest.skip("PostgreSQL gateway test environment is not active", allow_module_level=True)

HOLDER_KEY_ID = "agent-coordinator-key-01"
HOLDER_PRIVATE_KEY = Path(HOLDER_PRIVATE_KEY_FILE).read_text(encoding="ascii").strip()
HOLDER_PUBLIC_KEY = derive_public_key(HOLDER_PRIVATE_KEY)


def _create_root() -> dict[str, object]:
    assert AUTHORITY_URL is not None
    with httpx.Client(base_url=AUTHORITY_URL, timeout=10) as client:
        created = client.post(
            "/tasks",
            json={
                "tenant_id": "tenant-A",
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "refund_total_fen": 50_000,
                "max_tool_calls": 20,
                "expires_in_seconds": 1_800,
            },
        )
        assert created.status_code == 201, created.text
        task_id = created.json()["task_id"]
        authorized = client.post(
            f"/tasks/{task_id}/authorize",
            json={
                "confirmed": True,
                "confirmer_id": "policy-refund-v1",
                "holder_agent_id": "agent-coordinator",
                "holder_key_id": HOLDER_KEY_ID,
                "delegation_depth": 2,
            },
        )
    assert authorized.status_code == 201, authorized.text
    return authorized.json()


def _request(
    credential: dict[str, object],
    *,
    tool_service: str,
    tool_name: str,
    parameters: dict[str, object],
    business_action_id: str | None,
    request_id: str,
    issued_at: int | None = None,
) -> dict[str, object]:
    timestamp = now_unix() if issued_at is None else issued_at
    chain = [credential]
    chain_hash = sm3_hex(canonicalize(chain))
    parameter_hash = sm3_hex(canonicalize(parameters))
    holder_payload = {
        "schema_version": "1.0",
        "credential_chain_hash": chain_hash,
        "task_id": credential["payload"]["task_id"],
        "tool_service": tool_service,
        "tool_name": tool_name,
        "tool_version": "v1",
        "canonical_parameter_hash": parameter_hash,
        "request_id": request_id,
        "issued_at": timestamp,
        "business_action_id": business_action_id,
    }
    holder_signature = sign_payload(
        holder_payload,
        domain_separator=HOLDER_PROOF,
        key_id=HOLDER_KEY_ID,
        key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        private_key_hex=HOLDER_PRIVATE_KEY,
        public_key_hex=HOLDER_PUBLIC_KEY,
        signed_at=timestamp,
    )
    return {
        "schema_version": "1.0",
        "credential_chain": chain,
        "task_id": credential["payload"]["task_id"],
        "tool_service": tool_service,
        "tool_name": tool_name,
        "tool_version": "v1",
        "canonical_parameters": parameters,
        "request_id": request_id,
        "issued_at": timestamp,
        "holder_key_id": HOLDER_KEY_ID,
        "business_action_id": business_action_id,
        "holder_proof": {"payload": holder_payload, "signature": holder_signature},
    }


def test_gateway_accepts_bound_read_and_side_effect_commands() -> None:
    assert GATEWAY_URL is not None
    assert REGISTRY_URL is not None
    root = _create_root()
    task_id = root["payload"]["task_id"]

    with httpx.Client(base_url=GATEWAY_URL, timeout=10) as gateway:
        ticket_request = _request(
            root,
            tool_service="ticket-service",
            tool_name="ticket.read",
            parameters={"ticket_id": business_test_case()["ticket_id"]},
            business_action_id=None,
            request_id="REQ-TICKET-001",
        )
        ticket = gateway.post("/gateway/execute", json=ticket_request)
        assert ticket.status_code == 200, ticket.text
        ticket_body = ticket.json()
        assert ticket_body["decision"] == "ALLOW"
        assert ticket_body["state"] == "RECEIVED"
        assert len(ticket_body["request_hash"]) == 64
        assert len(ticket_body["credential_chain_hash"]) == 64
        assert ticket_body["validated_command"]["business_idempotency_key"] is None
        assert ticket_body["validated_command"]["validated_parameters"] == {
            "ticket_id": business_test_case()["ticket_id"]
        }

        with httpx.Client(base_url=REGISTRY_URL, timeout=10) as registry:
            resolved = registry.post("/business-actions/refund/resolve", json={"task_id": task_id})
        assert resolved.status_code == 200, resolved.text
        action = resolved.json()
        refund_request = _request(
            root,
            tool_service="refund-service",
            tool_name="refund.create",
            parameters={
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "amount_fen": 10_000,
            },
            business_action_id=action["business_action_id"],
            request_id="REQ-REFUND-001",
        )
        refund = gateway.post("/gateway/execute", json=refund_request)
        assert refund.status_code == 200, refund.text
        refund_body = refund.json()
        assert refund_body["decision"] == "ALLOW"
        expected_idempotency = SecureGatewayService._business_idempotency_key(
            "tenant-A",
            task_id,
            "refund-service",
            "refund.create",
            action["business_action_id"],
        )
        assert refund_body["validated_command"]["business_idempotency_key"] == expected_idempotency
        assert refund_body["validated_command"]["parameter_hash"] == sm3_hex(
            canonicalize(refund_request["canonical_parameters"])
        )


def test_gateway_rejects_holder_parameter_and_freshness_attacks() -> None:
    assert GATEWAY_URL is not None
    root = _create_root()
    task_id = root["payload"]["task_id"]
    with httpx.Client(base_url=REGISTRY_URL, timeout=10) as registry:
        resolved = registry.post("/business-actions/refund/resolve", json={"task_id": task_id})
    assert resolved.status_code == 200, resolved.text
    action_id = resolved.json()["business_action_id"]

    base = _request(
        root,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 10_000,
        },
        business_action_id=action_id,
        request_id="REQ-ATTACK-001",
    )
    tampered = deepcopy(base)
    tampered["canonical_parameters"]["amount_fen"] = 10_001
    with httpx.Client(base_url=GATEWAY_URL, timeout=10) as gateway:
        response = gateway.post("/gateway/execute", json=tampered)
        assert response.status_code == 403
        assert response.json()["reason_code"] == "INVALID_SIGNATURE"

        outside_resource = _request(
            root,
            tool_service="refund-service",
            tool_name="refund.create",
            parameters={
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "attacker",
                "amount_fen": 10_000,
            },
            business_action_id=action_id,
            request_id="REQ-ATTACK-002",
        )
        response = gateway.post("/gateway/execute", json=outside_resource)
        assert response.status_code == 403
        assert response.json()["reason_code"] == "RESOURCE_NOT_ALLOWED"

        stale = _request(
            root,
            tool_service="refund-service",
            tool_name="refund.create",
            parameters={
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "amount_fen": 10_000,
            },
            business_action_id=action_id,
            request_id="REQ-ATTACK-003",
            issued_at=now_unix() - 61,
        )
        response = gateway.post("/gateway/execute", json=stale)
        assert response.status_code == 403
        assert response.json()["reason_code"] == "REQUEST_STALE"
