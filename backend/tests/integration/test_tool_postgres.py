from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from backend.business_action.policy import (
    PRIMARY_REFUND_SLOT,
    REFUND_SUCCESS_NOTIFICATION_SLOT,
    TrustedTaskContext,
    notification_scope,
    refund_scope,
)
from backend.common.enums import KeyPurpose
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import GATEWAY_EXECUTION_ENVELOPE
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case

pytestmark = [pytest.mark.integration]

REQUIRED_ENVIRONMENT = (
    "AGENTGUARD_DATABASE_URL",
    "AGENTGUARD_AUTHORITY_URL",
    "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE",
    "AGENTGUARD_TICKET_TOOL_URL",
    "AGENTGUARD_KNOWLEDGE_TOOL_URL",
    "AGENTGUARD_REFUND_TOOL_URL",
    "AGENTGUARD_NOTIFICATION_TOOL_URL",
)
if any(not os.getenv(name) for name in REQUIRED_ENVIRONMENT):
    pytest.skip("PostgreSQL tool test environment is not active", allow_module_level=True)

DATABASE_URL = os.environ["AGENTGUARD_DATABASE_URL"]
AUTHORITY_URL = os.environ["AGENTGUARD_AUTHORITY_URL"]
PRIVATE_KEY = (
    Path(os.environ["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"]).read_text(encoding="ascii").strip()
)
PUBLIC_KEY = derive_public_key(PRIVATE_KEY)
TOOL_URLS = {
    "ticket": os.environ["AGENTGUARD_TICKET_TOOL_URL"],
    "knowledge": os.environ["AGENTGUARD_KNOWLEDGE_TOOL_URL"],
    "refund": os.environ["AGENTGUARD_REFUND_TOOL_URL"],
    "notification": os.environ["AGENTGUARD_NOTIFICATION_TOOL_URL"],
}
TOOL_IDENTITIES = {
    "ticket": ("ticket-service", "ticket.read"),
    "knowledge": ("knowledge-service", "knowledge.read_associated"),
    "refund": ("refund-service", "refund.create"),
    "notification": ("notification-service", "notification.send_template"),
}


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def authorized_task() -> TrustedTaskContext:
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
                "holder_key_id": "agent-coordinator-key-01",
                "delegation_depth": 2,
            },
        )
        assert authorized.status_code == 201, authorized.text
    return TrustedTaskContext(
        tenant_id="tenant-A",
        task_id=task_id,
        ticket_id=business_test_case()["ticket_id"],
        customer_id="C9527",
    )


def cleanup_synthetic_task(task_context: TrustedTaskContext) -> None:
    with connect(DATABASE_URL) as connection, connection.transaction():
        row = connection.execute(
            """
            WITH task_executions AS (
                SELECT execution_id FROM execution_records WHERE task_id = %s
            )
            SELECT
                (SELECT count(*) FROM audit_outbox
                 WHERE execution_id IN (SELECT execution_id FROM task_executions)),
                (SELECT count(*) FROM execution_receipts
                 WHERE execution_id IN (SELECT execution_id FROM task_executions)),
                (SELECT count(*) FROM execution_budget_reservations
                 WHERE execution_id IN (SELECT execution_id FROM task_executions)),
                (SELECT count(*) FROM execution_requests
                 WHERE execution_id IN (SELECT execution_id FROM task_executions)),
                (SELECT count(*) FROM idempotency_records
                 WHERE execution_id IN (SELECT execution_id FROM task_executions)),
                (SELECT count(*) FROM execution_recovery_records
                 WHERE execution_id IN (SELECT execution_id FROM task_executions)),
                (SELECT count(*) FROM result_retrieval_requests
                 WHERE execution_id IN (SELECT execution_id FROM task_executions)),
                (SELECT count(*) FROM replay_denial_attempts
                 WHERE original_execution_id IN (SELECT execution_id FROM task_executions)
                    OR denial_execution_id IN (SELECT execution_id FROM task_executions))
            """,
            (task_context.task_id,),
        ).fetchone()
        assert row is not None
        labels = (
            "audit_outbox",
            "execution_receipts",
            "execution_budget_reservations",
            "execution_requests",
            "idempotency_records",
            "execution_recovery_records",
            "result_retrieval_requests",
            "replay_denial_attempts",
        )
        unexpected = {label: int(value) for label, value in zip(labels, row, strict=True) if value}
        assert not unexpected, (
            f"isolated Tool test unexpectedly entered the Gateway lifecycle: {unexpected}"
        )

        connection.execute(
            """
            DELETE FROM tool_execution_attempts
            WHERE execution_id IN (
                SELECT execution_id FROM execution_records WHERE task_id = %s
            )
            """,
            (task_context.task_id,),
        )
        connection.execute("DELETE FROM refunds WHERE task_id = %s", (task_context.task_id,))
        connection.execute("DELETE FROM notifications WHERE task_id = %s", (task_context.task_id,))
        connection.execute(
            "DELETE FROM execution_records WHERE task_id = %s", (task_context.task_id,)
        )
        connection.execute(
            "DELETE FROM business_actions WHERE task_id = %s", (task_context.task_id,)
        )


@pytest.fixture
def isolated_authorized_task() -> Iterator[TrustedTaskContext]:
    task_context = authorized_task()
    try:
        yield task_context
    finally:
        cleanup_synthetic_task(task_context)


def register_execution(
    *,
    task_context: TrustedTaskContext,
    kind: str,
    execution_id: str,
    parameters: dict,
    business_action_id: str | None,
    request_hash: str,
) -> str | None:
    service, tool = TOOL_IDENTITIES[kind]
    current = now_unix()
    with connect(DATABASE_URL) as connection, connection.transaction():
        if business_action_id is not None:
            if kind == "refund":
                action_scope_key, _ = refund_scope(task_context)
                trusted_action_slot = PRIMARY_REFUND_SLOT
            elif kind == "notification":
                action_scope_key, _ = notification_scope(
                    task_context,
                    template_id=str(parameters["template_id"]),
                    related_business_effect_id=str(parameters["related_business_effect_id"]),
                )
                trusted_action_slot = REFUND_SUCCESS_NOTIFICATION_SLOT
            else:
                raise AssertionError(f"unexpected side-effect tool kind: {kind}")

            existing = connection.execute(
                """
                SELECT business_action_id, tenant_id, task_id, tool_service,
                       tool_name, trusted_action_slot, status
                FROM business_actions WHERE action_scope_key = %s
                """,
                (action_scope_key,),
            ).fetchone()
            if existing is not None:
                assert tuple(existing[1:6]) == (
                    task_context.tenant_id,
                    task_context.task_id,
                    service,
                    tool,
                    trusted_action_slot,
                )
                assert str(existing[6]) in {"ACTIVE", "COMMITTED"}
                business_action_id = str(existing[0])
            else:
                connection.execute(
                    """
                    INSERT INTO business_actions (
                        business_action_id,
                        action_scope_key,
                        trusted_action_slot,
                        tenant_id,
                        task_id,
                        tool_service,
                        tool_name,
                        status,
                        created_at,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'ACTIVE', %s, %s)
                    """,
                    (
                        business_action_id,
                        action_scope_key,
                        trusted_action_slot,
                        task_context.tenant_id,
                        task_context.task_id,
                        service,
                        tool,
                        current,
                        current,
                    ),
                )
        previous = connection.execute(
            "SELECT tenant_id, task_id, tool_service, tool_name, parameter_hash, "
            "business_action_id, request_hash FROM execution_records WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        if previous is not None:
            assert tuple(previous[:6]) == (
                task_context.tenant_id,
                task_context.task_id,
                service,
                tool,
                sm3_hex(canonicalize(parameters)),
                business_action_id,
            )
            return business_action_id
        connection.execute(
            """
            INSERT INTO execution_records (
                execution_id,
                initial_request_id,
                request_hash,
                credential_chain_hash,
                tenant_id,
                task_id,
                tool_service,
                tool_name,
                tool_version,
                parameter_hash,
                state,
                decision,
                reason_code,
                receipt_status,
                business_action_id,
                created_at,
                updated_at
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, 'v1', %s,
                'DISPATCHED', 'ALLOW', 'AUTHORIZED', 'NOT_REQUIRED', %s, %s, %s
            )
            """,
            (
                execution_id,
                unique("REQUEST"),
                request_hash,
                sm3_hex(b"phase-1-test-chain"),
                task_context.tenant_id,
                task_context.task_id,
                service,
                tool,
                sm3_hex(canonicalize(parameters)),
                business_action_id,
                current,
                current,
            ),
        )
    return business_action_id


def signed_envelope(
    *,
    task_context: TrustedTaskContext,
    kind: str,
    parameters: dict,
    business_action_id: str | None = None,
    idempotency_key: str | None = None,
    execution_id: str | None = None,
) -> dict:
    service, tool = TOOL_IDENTITIES[kind]
    current = now_unix()
    resolved_execution_id = execution_id or unique("EXEC")
    request_hash = sm3_hex(unique("request").encode("utf-8"))
    if execution_id is not None:
        with connect(DATABASE_URL) as connection:
            previous = connection.execute(
                "SELECT request_hash FROM execution_records WHERE execution_id = %s",
                (execution_id,),
            ).fetchone()
        if previous is not None:
            request_hash = str(previous[0])
    resolved_business_action_id = register_execution(
        task_context=task_context,
        kind=kind,
        execution_id=resolved_execution_id,
        parameters=parameters,
        business_action_id=business_action_id,
        request_hash=request_hash,
    )
    payload = {
        "schema_version": "1.0",
        "execution_id": resolved_execution_id,
        "execution_attempt_id": unique("ATTEMPT"),
        "request_hash": request_hash,
        "tenant_id": task_context.tenant_id,
        "task_id": task_context.task_id,
        "tool_service": service,
        "tool_name": tool,
        "tool_version": "v1",
        "canonical_validated_parameters": parameters,
        "business_action_id": resolved_business_action_id,
        "business_idempotency_key": idempotency_key,
        "parameter_hash": sm3_hex(canonicalize(parameters)),
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
    )
    return {"payload": payload, "signature": signature}


def post(kind: str, envelope: dict) -> httpx.Response:
    return httpx.post(
        f"{TOOL_URLS[kind]}/internal/execute",
        json=envelope,
        timeout=10,
    )


def test_four_tools_use_postgres_and_enforce_replay_and_idempotency(
    isolated_authorized_task: TrustedTaskContext,
) -> None:
    task_context = isolated_authorized_task
    ticket = signed_envelope(
        task_context=task_context,
        kind="ticket",
        parameters={"ticket_id": business_test_case()["ticket_id"]},
    )
    ticket_response = post("ticket", ticket)
    assert ticket_response.status_code == 200
    assert ticket_response.json()["result"]["customer_id"] == "C9527"

    knowledge = signed_envelope(
        task_context=task_context,
        kind="knowledge",
        parameters={"ticket_id": business_test_case()["ticket_id"]},
    )
    knowledge_response = post("knowledge", knowledge)
    assert knowledge_response.status_code == 200
    assert (
        knowledge_response.json()["result"]["documents"][0]["document_id"]
        == business_test_case()["document_id"]
    )

    action_id = unique("ACTION-REFUND")
    idempotency_key = sm3_hex(unique("refund-key").encode("utf-8"))
    refund_parameters = {
        "ticket_id": business_test_case()["ticket_id"],
        "customer_id": "C9527",
        "amount_fen": 10000,
    }
    refund = signed_envelope(
        task_context=task_context,
        kind="refund",
        parameters=refund_parameters,
        business_action_id=action_id,
        idempotency_key=idempotency_key,
    )
    refund_response = post("refund", refund)
    assert refund_response.status_code == 200
    refund_id = refund_response.json()["business_effect_id"]

    replay_response = post("refund", refund)
    assert replay_response.status_code == 409
    assert replay_response.json()["detail"]["reason_code"] == "EXECUTION_ENVELOPE_REPLAY"

    retry = signed_envelope(
        task_context=task_context,
        kind="refund",
        parameters=refund_parameters,
        business_action_id=action_id,
        idempotency_key=idempotency_key,
        execution_id=refund["payload"]["execution_id"],
    )
    retry_response = post("refund", retry)
    assert retry_response.status_code == 200
    assert retry_response.json()["business_effect_id"] == refund_id

    changed = signed_envelope(
        task_context=task_context,
        kind="refund",
        parameters={**refund_parameters, "amount_fen": 20000},
        business_action_id=unique("ACTION-REFUND"),
        idempotency_key=idempotency_key,
    )
    changed_response = post("refund", changed)
    assert changed_response.status_code == 409
    assert changed_response.json()["detail"]["reason_code"] == "IDEMPOTENCY_CONFLICT"

    notification = signed_envelope(
        task_context=task_context,
        kind="notification",
        parameters={
            "customer_id": "C9527",
            "template_id": "REFUND_SUCCESS",
            "related_business_effect_id": refund_id,
        },
        business_action_id=unique("ACTION-NOTIFY"),
        idempotency_key=sm3_hex(unique("notification-key").encode("utf-8")),
    )
    notification_response = post("notification", notification)
    assert notification_response.status_code == 200
    assert notification_response.json()["result"]["status"] == "SENT"
    notice = notification_response.json()["result"]
    assert notice["template_version"] == "v1"
    assert "100.00元" in notice["content"] and refund_id in notice["content"]
    with connect(DATABASE_URL) as connection:
        stored = connection.execute(
            "SELECT template_version, content FROM notifications WHERE notification_id = %s",
            (notice["notification_id"],),
        ).fetchone()
    assert stored == (notice["template_version"], notice["content"])

    with connect(DATABASE_URL) as connection:
        refund_count = connection.execute(
            "SELECT count(*) FROM refunds WHERE business_idempotency_key = %s",
            (idempotency_key,),
        ).fetchone()[0]
    assert refund_count == 1
