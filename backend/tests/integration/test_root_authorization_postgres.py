from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.crypto.domains import CAPABILITY_CREDENTIAL
from backend.crypto.sm import verify_payload
from backend.identity.key_registry import PostgresKeyRegistry
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case

pytestmark = [pytest.mark.integration]

DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")
if not DATABASE_URL or not AUTHORITY_URL:
    pytest.skip(
        "PostgreSQL root authorization test environment is not active", allow_module_level=True
    )


def _create_task(client: httpx.Client) -> str:
    response = client.post(
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
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "PENDING_AUTHORIZATION"
    return body["task_id"]


def _authorization_request(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "confirmed": True,
        "confirmer_id": "policy-refund-v1",
        "holder_agent_id": "agent-coordinator",
        "holder_key_id": "agent-coordinator-key-01",
        "delegation_depth": 2,
    }
    value.update(changes)
    return value


def test_root_authorization_is_trusted_signed_atomic_and_idempotent() -> None:
    assert DATABASE_URL is not None
    assert AUTHORITY_URL is not None
    registry = PostgresKeyRegistry(DATABASE_URL)
    with httpx.Client(base_url=AUTHORITY_URL, timeout=10) as client:
        task_id = _create_task(client)

        implicit = client.post(
            f"/tasks/{task_id}/authorize",
            json=_authorization_request(confirmed=False),
        )
        assert implicit.status_code == 400
        assert implicit.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"

        untrusted = client.post(
            f"/tasks/{task_id}/authorize",
            json=_authorization_request(confirmer_id="agent-coordinator"),
        )
        assert untrusted.status_code == 403
        assert untrusted.json()["reason_code"] == "INVALID_SIGNATURE"

        wrong_holder = client.post(
            f"/tasks/{task_id}/authorize",
            json=_authorization_request(holder_key_id="agent-case-key-01"),
        )
        assert wrong_holder.status_code == 403
        assert wrong_holder.json()["reason_code"] == "INVALID_SIGNATURE"

        with connect(DATABASE_URL) as connection:
            before = connection.execute(
                """
                SELECT task.status,
                       (SELECT count(*) FROM credentials WHERE task_id = task.task_id),
                       (SELECT count(*) FROM authorization_confirmations
                        WHERE task_id = task.task_id)
                FROM tasks AS task WHERE task.task_id = %s
                """,
                (task_id,),
            ).fetchone()
        assert before == ("PENDING_AUTHORIZATION", 0, 0)

        authorized = client.post(f"/tasks/{task_id}/authorize", json=_authorization_request())
        assert authorized.status_code == 201, authorized.text
        credential = authorized.json()
        payload = credential["payload"]
        assert payload["task_id"] == task_id
        assert payload["tenant_id"] == "tenant-A"
        assert payload["holder"] == {
            "agent_id": "agent-coordinator",
            "key_id": "agent-coordinator-key-01",
        }
        assert payload["quotas"] == {
            "refund_total_fen": 50_000,
            "max_tool_calls": 20,
        }
        assert payload["parent_credential_id"] is None
        assert payload["parent_credential_hash"] is None
        assert len(payload["capabilities"]) == 4

        authority_key = registry.get("auth-key-01")
        assert verify_payload(
            payload,
            credential["signature"],
            domain_separator=CAPABILITY_CREDENTIAL,
            expected_key_id="auth-key-01",
            expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            public_key_hex=authority_key.public_key_hex,
        )

        repeated = client.post(f"/tasks/{task_id}/authorize", json=_authorization_request())
        assert repeated.status_code == 201
        assert repeated.json() == credential

        conflict = client.post(
            f"/tasks/{task_id}/authorize",
            json=_authorization_request(delegation_depth=1),
        )
        assert conflict.status_code == 400
        assert conflict.json()["reason_code"] == "IDEMPOTENCY_CONFLICT"

    with connect(DATABASE_URL) as connection:
        persisted = connection.execute(
            """
            SELECT task.status, confirmation.confirmer_id,
                   confirmation.confirmation_source, credential.credential_type,
                   credential.signed_object, count(budget.quota_type)
            FROM tasks AS task
            JOIN authorization_confirmations AS confirmation
              ON confirmation.task_id = task.task_id
            JOIN credentials AS credential
              ON credential.credential_id = confirmation.credential_id
            JOIN credential_budget_state AS budget
              ON budget.credential_id = credential.credential_id
            WHERE task.task_id = %s
            GROUP BY task.status, confirmation.confirmer_id,
                     confirmation.confirmation_source, credential.credential_type,
                     credential.signed_object
            """,
            (task_id,),
        ).fetchone()
    assert persisted is not None
    assert persisted[0:4] == ("AUTHORIZED", "policy-refund-v1", "POLICY", "ROOT")
    assert dict(persisted[4]) == credential
    assert persisted[5] == 2


def test_expired_task_cannot_be_authorized() -> None:
    assert DATABASE_URL is not None
    assert AUTHORITY_URL is not None
    with httpx.Client(base_url=AUTHORITY_URL, timeout=10) as client:
        task_id = _create_task(client)
        with connect(DATABASE_URL) as connection, connection.transaction():
            connection.execute("UPDATE tasks SET expires_at = 0 WHERE task_id = %s", (task_id,))
        response = client.post(f"/tasks/{task_id}/authorize", json=_authorization_request())
    assert response.status_code == 403
    assert response.json()["reason_code"] == "CREDENTIAL_EXPIRED"


def test_concurrent_identical_authorization_creates_one_root_credential() -> None:
    assert DATABASE_URL is not None
    assert AUTHORITY_URL is not None
    with httpx.Client(base_url=AUTHORITY_URL, timeout=10) as client:
        task_id = _create_task(client)

    def authorize() -> httpx.Response:
        with httpx.Client(base_url=AUTHORITY_URL, timeout=10) as client:
            return client.post(f"/tasks/{task_id}/authorize", json=_authorization_request())

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: authorize(), range(2)))
    assert [response.status_code for response in responses] == [201, 201]
    assert responses[0].json() == responses[1].json()

    with connect(DATABASE_URL) as connection:
        counts = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM credentials
                 WHERE task_id = %s AND credential_type = 'ROOT'),
                (SELECT count(*) FROM authorization_confirmations WHERE task_id = %s)
            """,
            (task_id, task_id),
        ).fetchone()
    assert counts == (1, 1)
