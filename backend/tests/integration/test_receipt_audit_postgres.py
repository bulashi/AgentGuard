from __future__ import annotations

import os
from copy import deepcopy

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_CHECKPOINT, EXECUTION_RECEIPT
from backend.crypto.sm import sm3_hex, verify_payload
from backend.identity.key_registry import PostgresKeyRegistry
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case
from backend.tests.integration.test_admission_postgres import (
    DATABASE_URL,
    GATEWAY_URL,
    _leaf_chain,
    _refund_action,
    _request,
)
from backend.tests.integration.test_dispatch_postgres import _dispatch, _resign_request

pytestmark = [pytest.mark.integration]

AUDIT_DATABASE_URL = os.getenv("AGENTGUARD_AUDIT_DATABASE_URL")
RECEIPT_URL = os.getenv("AGENTGUARD_RECEIPT_SERVICE_URL")
AUDIT_URL = os.getenv("AGENTGUARD_AUDIT_SERVICE_URL")
CHECKPOINT_URL = os.getenv("AGENTGUARD_CHECKPOINT_SERVICE_URL")

if not all(
    (
        DATABASE_URL,
        AUDIT_DATABASE_URL,
        GATEWAY_URL,
        RECEIPT_URL,
        AUDIT_URL,
        CHECKPOINT_URL,
    )
):
    pytest.skip(
        "PostgreSQL receipt and audit test environment is not active", allow_module_level=True
    )


SCHEMAS = SchemaStore()


def _admit(request: dict[str, object]) -> httpx.Response:
    assert GATEWAY_URL is not None
    with httpx.Client(base_url=GATEWAY_URL, timeout=20) as client:
        return client.post("/gateway/admit", json=request)


def _verify_receipt(receipt: dict[str, object]) -> None:
    SCHEMAS.validate("execution-receipt.schema.json", receipt)
    payload = receipt["payload"]
    signature = receipt["signature"]
    assert isinstance(payload, dict)
    assert isinstance(signature, dict)
    assert DATABASE_URL is not None
    key = PostgresKeyRegistry(DATABASE_URL).get(str(signature["key_id"]))
    assert signature["key_purpose"] == KeyPurpose.EXECUTION_RECEIPT_SIGNING.value
    assert verify_payload(
        payload,
        signature,
        domain_separator=EXECUTION_RECEIPT,
        expected_key_id=key.key_id,
        expected_key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
        public_key_hex=key.public_key_hex,
    )


def _append_audit() -> dict[str, object]:
    assert AUDIT_URL is not None
    with httpx.Client(base_url=AUDIT_URL, timeout=20) as client:
        response = client.post(
            "/internal/audit/append",
            headers={"X-AgentGuard-Internal": "phase11-test"},
            json={"max_events": 10_000},
        )
    assert response.status_code == 200, response.text
    return response.json()


def _verify_audit() -> httpx.Response:
    assert AUDIT_URL is not None
    with httpx.Client(base_url=AUDIT_URL, timeout=20) as client:
        return client.post(
            "/audit/verify",
            json={"from_sequence": 1, "include_independent_checkpoint": True},
        )


def test_allow_receipt_is_signed_bound_and_idempotently_retrieved() -> None:
    leaf, chain, task_id, _ = _leaf_chain()
    action = _refund_action(task_id)
    request = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 7_000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-RECEIPT-ALLOW",
        credential_chain=chain,
    )
    response = _dispatch(request)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "COMMITTED"
    assert isinstance(body["receipt"], dict)
    receipt = body["receipt"]
    _verify_receipt(receipt)
    assert receipt["payload"]["decision"] == "ALLOW"
    assert receipt["payload"]["business_effect_id"] is not None

    execution_id = body["execution_id"]
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        stored = connection.execute(
            """
            SELECT receipt_status, count(*) OVER ()
            FROM execution_receipts WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        effect = connection.execute(
            """
            SELECT business_effect_id, business_result_hash, result, terminal_at,
                   terminal_state::text, decision_at, decision_value::text
            FROM execution_records WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        refund = connection.execute(
            """
            SELECT refund_id, execution_id, business_action_id, tenant_id, task_id,
                   amount_fen, status, ticket_id, customer_id, business_idempotency_key,
                   parameter_hash, created_at
            FROM refunds WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        totals = connection.execute(
            """
            SELECT COALESCE(SUM(amount) FILTER (WHERE status = 'RESERVED'), 0),
                   COALESCE(SUM(amount) FILTER (WHERE status = 'COMMITTED'), 0)
            FROM execution_budget_reservations WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
    assert stored == ("SIGNED", 1)
    assert effect is not None and effect[0] is not None and effect[1] is not None
    assert receipt["payload"]["business_effect_id"] == effect[0]
    assert receipt["payload"]["business_result_hash"] == effect[1]
    assert isinstance(effect[2], dict)
    assert effect[1] == sm3_hex(canonicalize(effect[2]))
    assert type(effect[3]) is int and effect[4] == "COMMITTED"
    assert type(effect[5]) is int and effect[6] == "ALLOW"
    assert receipt["payload"]["started_at"] <= effect[5] <= effect[3]
    assert receipt["payload"]["decision_at"] == effect[5]
    assert receipt["payload"]["finished_at"] == effect[3]
    assert receipt["payload"]["business_effect_finalized_at"] == effect[3]
    assert receipt["payload"]["receipt_issued_at"] >= effect[3]
    assert refund is not None
    assert refund[:5] == (
        effect[0],
        execution_id,
        action["business_action_id"],
        receipt["payload"]["tenant_id"],
        task_id,
    )
    assert effect[2] == {
        "refund_id": refund[0],
        "execution_id": refund[1],
        "business_action_id": refund[2],
        "tenant_id": refund[3],
        "task_id": refund[4],
        "amount_fen": refund[5],
        "status": refund[6],
        "ticket_id": refund[7],
        "customer_id": refund[8],
        "business_idempotency_key": refund[9],
        "parameter_hash": refund[10],
        "created_at": refund[11],
    }
    assert refund[7] == business_test_case()["ticket_id"] and refund[8] == "C9527"
    assert refund[10] == sm3_hex(canonicalize(request["canonical_parameters"]))
    assert type(refund[11]) is int and refund[11] <= effect[3]
    assert totals is not None and totals[0] == 0
    assert receipt["payload"]["budget_reserved"] == int(totals[0])
    assert receipt["payload"]["budget_committed"] == int(totals[1])

    retry = deepcopy(request)
    retry["request_id"] = f"{task_id}-RECEIPT-ALLOW-RETRY"
    retry_proof = retry["holder_proof"]
    assert isinstance(retry_proof, dict)
    retry_payload = retry_proof["payload"]
    assert isinstance(retry_payload, dict)
    retry_payload["request_id"] = retry["request_id"]
    _resign_request(retry)
    repeated = _dispatch(retry)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["receipt"] == receipt

    assert RECEIPT_URL is not None
    with httpx.Client(base_url=RECEIPT_URL, timeout=20) as client:
        retrieved = client.get(
            f"/internal/receipts/{execution_id}",
            headers={"X-AgentGuard-Internal": "phase11-test"},
        )
    assert retrieved.status_code == 200
    assert retrieved.json()["receipt"] == receipt
    with connect(DATABASE_URL) as connection:
        terminal_after_retrieval = connection.execute(
            "SELECT terminal_at, terminal_state::text, decision_at, decision_value::text "
            "FROM execution_records WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
    assert terminal_after_retrieval == effect[3:7]


def test_deny_receipt_has_no_effect_and_retryable_receipt_status_recovers() -> None:
    leaf, chain, task_id, _ = _leaf_chain()
    action = _refund_action(task_id)
    request = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 20_000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-RECEIPT-DENY",
        credential_chain=chain,
    )
    response = _admit(request)
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["state"] == "DENIED"
    assert body["reason_code"] == "BUDGET_EXCEEDED"
    receipt = body["receipt"]
    assert isinstance(receipt, dict)
    _verify_receipt(receipt)
    payload = receipt["payload"]
    assert payload["decision"] == "DENY"
    assert payload["receipt_type"] == "AUTHORIZATION_DENIAL"
    assert payload["business_effect_id"] is None
    assert payload["business_result_hash"] is None
    assert payload["budget_reserved"] == 0
    assert payload["budget_committed"] == 0

    execution_id = body["execution_id"]
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        effect_count = connection.execute(
            "SELECT count(*) FROM refunds WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        connection.execute(
            """
            UPDATE execution_records SET receipt_status = 'FAILED_RETRYABLE'
            WHERE execution_id = %s
            """,
            (execution_id,),
        )
    assert effect_count == (0,)

    assert RECEIPT_URL is not None
    with httpx.Client(base_url=RECEIPT_URL, timeout=20) as client:
        recovered = client.post(
            "/internal/receipts/issue",
            headers={"X-AgentGuard-Internal": "phase11-test"},
            json={"execution_id": execution_id},
        )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["receipt"] == receipt
    with connect(DATABASE_URL) as connection:
        status = connection.execute(
            "SELECT receipt_status FROM execution_records WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
    assert status == ("SIGNED",)


def test_rejected_event_hash_chain_checkpoint_and_tamper_rollback_detection() -> None:
    assert AUDIT_URL is not None
    raw = b'{"schema_version":"1.0","duplicate":true}'
    rejected = {
        "schema_version": "1.0",
        "event_id": f"EVENT-RAW-PHASE11-{sm3_hex(raw)[:16]}",
        "raw_request_hash": sm3_hex(raw),
        "parser_stage": "DUPLICATE_KEY",
        "reason_code": "DUPLICATE_FIELD",
        "source_context": {"transport": "INTERNAL_TEST", "source_label": "phase11"},
        "received_at": now_unix(),
    }
    with httpx.Client(base_url=AUDIT_URL, timeout=20) as client:
        accepted = client.post(
            "/internal/audit/rejected",
            headers={"X-AgentGuard-Internal": "phase11-test"},
            json=rejected,
        )
    assert accepted.status_code == 200, accepted.text
    SCHEMAS.validate("rejected-audit-event.schema.json", rejected)

    appended = _append_audit()
    assert appended["appended_count"] >= 0
    # The worker may win the append race; require this exact event in the chain.
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        recorded = connection.execute(
            "SELECT payload_hash FROM audit_events WHERE event_type = 'RAW_REQUEST_REJECTED' "
            "AND evidence_reference = %s",
            (rejected["event_id"],),
        ).fetchall()
    assert recorded == [(sm3_hex(canonicalize(rejected)),)]

    assert CHECKPOINT_URL is not None
    with httpx.Client(base_url=CHECKPOINT_URL, timeout=20) as client:
        checkpoint_response = client.post(
            "/internal/checkpoint/run",
            headers={"X-AgentGuard-Internal": "phase11-test"},
        )
    assert checkpoint_response.status_code == 200, checkpoint_response.text
    checkpoint = checkpoint_response.json()["checkpoint"]
    assert isinstance(checkpoint, dict)
    SCHEMAS.validate("audit-checkpoint.schema.json", checkpoint)
    cp_payload = checkpoint["payload"]
    cp_signature = checkpoint["signature"]
    assert DATABASE_URL is not None
    cp_key = PostgresKeyRegistry(DATABASE_URL).get(str(cp_signature["key_id"]))
    assert verify_payload(
        cp_payload,
        cp_signature,
        domain_separator=AUDIT_CHECKPOINT,
        expected_key_id=cp_key.key_id,
        expected_key_purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
        public_key_hex=cp_key.public_key_hex,
    )

    valid = _verify_audit()
    assert valid.status_code == 200, valid.text
    assert valid.json()["valid"] is True
    assert valid.json()["rollback_detected"] is False

    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        raw_count = connection.execute(
            "SELECT count(*) FROM audit_events WHERE event_type = 'RAW_REQUEST_REJECTED'"
        ).fetchone()
        latest = connection.execute(
            """
            SELECT latest_event_sequence, latest_event_hash
            FROM audit_chain_head WHERE singleton = TRUE
            """
        ).fetchone()
        event = connection.execute(
            """
            SELECT event_sequence, payload_hash
            FROM audit_events ORDER BY event_sequence LIMIT 1
            """
        ).fetchone()
    assert raw_count is not None and raw_count[0] >= 1
    assert latest is not None and event is not None

    original_payload_hash = str(event[1])
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            "UPDATE audit_events SET payload_hash = repeat('f', 64) WHERE event_sequence = %s",
            (int(event[0]),),
        )
    tampered = _verify_audit()
    assert tampered.json()["valid"] is False
    assert tampered.json()["first_invalid_sequence"] == int(event[0])
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            "UPDATE audit_events SET payload_hash = %s WHERE event_sequence = %s",
            (original_payload_hash, int(event[0])),
        )

    original_head = (int(latest[0]), str(latest[1]))
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            """
            UPDATE audit_chain_head
            SET latest_event_sequence = %s, latest_event_hash = repeat('0', 64)
            WHERE singleton = TRUE
            """,
            (max(0, original_head[0] - 1),),
        )
    rolled_back = _verify_audit()
    assert rolled_back.json()["valid"] is False
    assert rolled_back.json()["rollback_detected"] is True
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            """
            UPDATE audit_chain_head
            SET latest_event_sequence = %s, latest_event_hash = %s
            WHERE singleton = TRUE
            """,
            original_head,
        )

    with connect(AUDIT_DATABASE_URL) as connection:
        stored_checkpoint = connection.execute(
            "SELECT count(*) FROM audit_checkpoints WHERE latest_event_sequence = %s",
            (original_head[0],),
        ).fetchone()
    assert stored_checkpoint == (1,)
