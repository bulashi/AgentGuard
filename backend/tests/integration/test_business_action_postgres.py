from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from backend.business_action.policy import APPROVED_SECOND_REFUND_SLOT
from backend.business_action.service import (
    BusinessActionError,
    BusinessActionRegistryService,
)
from backend.common.error_codes import ReasonCode
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case

pytestmark = [pytest.mark.integration]

DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")
REGISTRY_URL = os.getenv("AGENTGUARD_BUSINESS_ACTION_REGISTRY_URL")
if not DATABASE_URL or not AUTHORITY_URL or not REGISTRY_URL:
    pytest.skip(
        "PostgreSQL business action test environment is not active", allow_module_level=True
    )


def _authorized_task() -> str:
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
        return task_id


def test_registry_resolves_retries_and_rejects_identity_override() -> None:
    assert DATABASE_URL and REGISTRY_URL
    task_id = _authorized_task()
    with httpx.Client(base_url=REGISTRY_URL, timeout=10) as client:
        first = client.post("/business-actions/refund/resolve", json={"task_id": task_id})
        assert first.status_code == 200, first.text
        action = first.json()
        SchemaStore().validate("business-action.schema.json", action)
        assert action["tenant_id"] == "tenant-A"
        assert action["tool_service"] == "refund-service"
        assert action["tool_name"] == "refund.create"
        assert action["trusted_action_slot"] == "primary-refund"

        repeated = client.post("/business-actions/refund/resolve", json={"task_id": task_id})
        assert repeated.status_code == 200
        assert repeated.json() == action

        overridden = client.post(
            "/business-actions/refund/resolve",
            json={"task_id": task_id, "business_action_id": "ACTION-attacker"},
        )
        assert overridden.status_code == 400
        assert overridden.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"

        notification = client.post(
            "/business-actions/notification/resolve",
            json={
                "task_id": task_id,
                "template_id": "REFUND_SUCCESS",
                "related_business_effect_id": "REFUND-TRUSTED-001",
            },
        )
        assert notification.status_code == 403, notification.text
        assert notification.json()["reason_code"] == "BUSINESS_ACTION_INVALID"

        missing = client.post("/business-actions/refund/resolve", json={"task_id": "TASK-missing"})
        assert missing.status_code == 403
        assert missing.json()["reason_code"] == "BUSINESS_ACTION_INVALID"

    service = BusinessActionRegistryService(DATABASE_URL)
    second_slot = service.resolve_refund_for_trusted_slot(
        task_id,
        trusted_action_slot=APPROVED_SECOND_REFUND_SLOT,
        current_time=now_unix(),
    )
    assert second_slot["business_action_id"] != action["business_action_id"]
    assert second_slot["action_scope_key"] != action["action_scope_key"]

    with pytest.raises(BusinessActionError) as exc_info:
        service.resolve_refund_for_trusted_slot(
            task_id,
            trusted_action_slot="attacker-selected-third-refund",
            current_time=now_unix(),
        )
    assert exc_info.value.reason_code is ReasonCode.BUSINESS_ACTION_INVALID


def test_concurrent_scope_resolution_creates_exactly_one_action() -> None:
    assert DATABASE_URL and REGISTRY_URL
    task_id = _authorized_task()

    def resolve() -> httpx.Response:
        with httpx.Client(base_url=REGISTRY_URL, timeout=10) as client:
            return client.post("/business-actions/refund/resolve", json={"task_id": task_id})

    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(executor.map(lambda _: resolve(), range(8)))
    assert {response.status_code for response in responses} == {200}
    action_ids = {response.json()["business_action_id"] for response in responses}
    assert len(action_ids) == 1

    with connect(DATABASE_URL) as connection:
        persisted = connection.execute(
            """
            SELECT count(*), count(DISTINCT action_scope_key), min(tenant_id),
                   min(task_id), min(tool_service), min(tool_name)
            FROM business_actions WHERE task_id = %s
            """,
            (task_id,),
        ).fetchone()
    assert persisted == (1, 1, "tenant-A", task_id, "refund-service", "refund.create")
