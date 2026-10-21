from __future__ import annotations

import os
from uuid import uuid4

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import GATEWAY_EXECUTION_ENVELOPE
from backend.crypto.sm import generate_keypair, sign_payload, sm3_hex
from backend.gateway.service import SecureGatewayService
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case
from backend.tests.integration.test_admission_postgres import (
    DATABASE_URL,
    _budget_snapshot,
    _leaf_chain,
    _refund_action,
)

pytestmark = [pytest.mark.integration, pytest.mark.security]

REFUND_TOOL_URL = os.getenv("AGENTGUARD_REFUND_TOOL_URL")


def _lifecycle_counts(task_id: str) -> tuple[int, ...]:
    with connect(DATABASE_URL) as connection:
        row = connection.execute(
            """
            WITH task_executions AS (
                SELECT execution_id FROM execution_records WHERE task_id = %s
            )
            SELECT
              (SELECT count(*) FROM refunds WHERE task_id = %s),
              (SELECT count(*) FROM notifications WHERE task_id = %s),
              (SELECT count(*) FROM task_executions),
              (SELECT count(*) FROM execution_requests
               WHERE execution_id IN (SELECT execution_id FROM task_executions)),
              (SELECT count(*) FROM tool_execution_attempts
               WHERE execution_id IN (SELECT execution_id FROM task_executions)),
              (SELECT count(*) FROM execution_budget_reservations
               WHERE execution_id IN (SELECT execution_id FROM task_executions)),
              (SELECT count(*) FROM execution_receipts
               WHERE execution_id IN (SELECT execution_id FROM task_executions))
            """,
            (task_id,) * 3,
        ).fetchone()
    assert row is not None
    return tuple(int(value) for value in row)


@pytest.mark.parametrize("attack", ["raw-business", "missing-signature", "forged-signature"])
def test_native_same_host_rejects_direct_untrusted_tool_execution_without_effects(
    attack: str,
) -> None:
    assert os.getenv("AGENTGUARD_TEST_DEPLOYMENT") == "native"
    assert REFUND_TOOL_URL is not None and DATABASE_URL is not None
    _leaf, _chain, task_id, credential_ids = _leaf_chain()
    action = _refund_action(task_id)
    parameters = {
        "ticket_id": business_test_case()["ticket_id"],
        "customer_id": "C9527",
        "amount_fen": 1000,
    }
    now = now_unix()
    payload = {
        "schema_version": "1.0",
        "execution_id": f"NATIVE-EXEC-{uuid4().hex}",
        "execution_attempt_id": f"NATIVE-ATTEMPT-{uuid4().hex}",
        "request_hash": sm3_hex(uuid4().hex.encode()),
        "tenant_id": "tenant-A",
        "task_id": task_id,
        "tool_service": "refund-service",
        "tool_name": "refund.create",
        "tool_version": "v1",
        "canonical_validated_parameters": parameters,
        "business_action_id": str(action["business_action_id"]),
        "business_idempotency_key": SecureGatewayService._business_idempotency_key(
            "tenant-A",
            task_id,
            "refund-service",
            "refund.create",
            str(action["business_action_id"]),
        ),
        "parameter_hash": sm3_hex(canonicalize(parameters)),
        "issued_at": now,
        "expires_at": now + 30,
        "gateway_key_id": "gateway-key-01",
    }
    pair = generate_keypair()
    forged = {
        "payload": payload,
        "signature": sign_payload(
            payload,
            domain_separator=GATEWAY_EXECUTION_ENVELOPE,
            key_id="gateway-key-01",
            key_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
            private_key_hex=pair.private_key_hex,
            public_key_hex=pair.public_key_hex,
            signed_at=now,
        ),
    }
    SchemaStore().validate("gateway-execution-envelope.schema.json", forged)
    body = {
        "raw-business": parameters,
        "missing-signature": {"payload": payload},
        "forged-signature": forged,
    }[attack]
    before_budget = _budget_snapshot(credential_ids)
    assert len(before_budget) == 6
    before_counts = _lifecycle_counts(task_id)
    assert before_counts == (0,) * 7
    with httpx.Client(base_url=REFUND_TOOL_URL, timeout=20) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["tool_service"] == "refund-service"
        response = client.post("/internal/execute", json=body)
    if attack == "forged-signature":
        assert response.status_code == 403, response.text
        assert response.json() == {"detail": {"reason_code": "INVALID_SIGNATURE"}}
    else:
        assert response.status_code == 422, response.text
        errors = response.json()["detail"]
        assert any(
            error["type"] == "missing" and error["loc"] == ["body", "signature"] for error in errors
        )
    assert "receipt" not in response.json()
    assert _budget_snapshot(credential_ids) == before_budget
    assert _lifecycle_counts(task_id) == before_counts
