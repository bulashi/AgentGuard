"""Runtime preflight uses saved credentials without business or budget mutations."""

from __future__ import annotations

import re
from copy import deepcopy
from unittest.mock import Mock
from urllib.parse import urlsplit

import httpx
import pytest

from backend.common.internal_auth import CALLER_HEADER, InternalAuthenticator
from backend.common.time import now_unix
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.revocation.contracts import RevokeCredentialRequest
from backend.revocation.service import RevocationService
from backend.state.database import connect
from backend.tests import business_fixtures
from backend.tests.integration.test_admission_postgres import (
    DATABASE_URL,
    GATEWAY_URL,
    _create_root,
    _leaf_chain,
)

pytestmark = [pytest.mark.integration]
AUTH_PATH = "/gateway/runtime/authorize"


@pytest.fixture(autouse=True)
def independent_business_case(monkeypatch):
    assert DATABASE_URL is not None
    target = urlsplit(DATABASE_URL)
    if target.hostname not in {"localhost", "127.0.0.1", "::1"} or not re.fullmatch(
        r"/agentguard_test_backend_[a-f0-9]+", target.path,
    ):
        pytest.fail("runtime preflight tests require a parent-owned disposable database")
    monkeypatch.setattr(
        business_fixtures, "POSTGRES_BUSINESS_TEST_CASE",
        business_fixtures.verified_postgres_case(DATABASE_URL),
    )


def request_document(chain, **context_changes):
    business = business_fixtures.business_test_case()
    return {
        "credential_chain": deepcopy(chain),
        "context": {
            "ticket_id": business["ticket_id"], "customer_id": business["customer_id"],
            "refund_amount_fen": 7000, "runtime_mode": "deterministic", **context_changes,
        },
    }


def post_preflight(document, *, caller, omit_caller=False):
    settings = Settings()
    body = canonicalize(document)
    sender = InternalAuthenticator(
        service_id=caller, keys_json=settings.internal_auth_keys,
        required=settings.internal_auth_required, nonce_store=Mock(),
        freshness_window_seconds=settings.freshness_window_seconds,
        allowed_clock_skew_seconds=settings.allowed_clock_skew_seconds,
    )
    # Even unsigned test stacks must carry caller identity to bind it to the leaf holder.
    headers = sender.request_headers(
        recipient="secure-gateway", method="POST", path=AUTH_PATH, body=body,
    )
    assert headers[CALLER_HEADER] == caller
    if omit_caller:
        headers.pop(CALLER_HEADER)
    with httpx.Client(base_url=GATEWAY_URL, timeout=15, trust_env=False) as client:
        return client.post(AUTH_PATH, content=body, headers=headers)


def business_snapshot(task_id):
    with connect(DATABASE_URL) as connection:
        budgets = connection.execute(
            "SELECT budget.credential_id, budget.quota_type, budget.limit_value, "
            "budget.reserved_value, budget.committed_value, budget.version, budget.updated_at "
            "FROM credential_budget_state budget JOIN credentials credential USING (credential_id) "
            "WHERE credential.task_id = %s ORDER BY budget.credential_id, budget.quota_type",
            (task_id,),
        ).fetchall()
        counts = connection.execute(
            "SELECT (SELECT count(*) FROM execution_records WHERE task_id = %s), "
            "(SELECT count(*) FROM business_actions WHERE task_id = %s), "
            "(SELECT count(*) FROM refunds WHERE task_id = %s), "
            "(SELECT count(*) FROM notifications WHERE task_id = %s)",
            (task_id, task_id, task_id, task_id),
        ).fetchone()
        task = connection.execute(
            "SELECT tenant_id, ticket_id, customer_id, status, expires_at "
            "FROM tasks WHERE task_id = %s",
            (task_id,),
        ).fetchone()
    return budgets, counts, task


@pytest.mark.parametrize("role", ["coordinator", "refund"])
def test_saved_root_or_two_level_leaf_authorizes_without_reserving_or_executing(role):
    if role == "coordinator":
        chain = [_create_root()]
    else:
        _leaf, chain, _task_id, _ids = _leaf_chain()
    task_id = chain[0]["payload"]["task_id"]
    document = request_document(chain)
    before = business_snapshot(task_id)
    response = post_preflight(document, caller=f"agent-{role}")
    assert response.status_code == 200, response.text
    assert response.json() == {
        "authorized": True, "task_id": task_id, "agent_id": f"agent-{role}",
        "credential_chain_hash": sm3_hex(canonicalize(chain)),
    }
    assert business_snapshot(task_id) == before
    assert before[1] == (0, 0, 0, 0)


@pytest.mark.parametrize("mutation,reason", [
    ("missing_caller", None),
    ("another_authenticated_agent", "WRONG_HOLDER"),
    ("unregistered_chain", "INVALID_SIGNATURE"),
    ("forged_chain", "INVALID_SIGNATURE"),
    ("other_ticket", "RESOURCE_NOT_ALLOWED"),
    ("other_customer", "RESOURCE_NOT_ALLOWED"),
    ("tenant_mismatch", "CROSS_TASK"),
    ("expired_task", "CREDENTIAL_EXPIRED"),
    ("revoked_root", "KEY_REVOKED"),
    ("amount_above_root", "BUDGET_EXCEEDED"),
])
def test_preflight_denials_do_not_enter_business_admission(mutation, reason):
    root = _create_root()
    task_id = root["payload"]["task_id"]
    document = request_document([root])
    caller = "agent-coordinator"
    original_task = business_snapshot(task_id)[2]
    if mutation == "another_authenticated_agent":
        caller = "agent-refund"
    elif mutation == "unregistered_chain":
        document["credential_chain"][0]["payload"]["credential_id"] = "CRED-unregistered"
    elif mutation == "forged_chain":
        document["credential_chain"][0]["signature"]["value"] = "0" * 128
    elif mutation in {"other_ticket", "other_customer"}:
        document["context"]["ticket_id" if mutation == "other_ticket" else "customer_id"] = (
            "outside-this-task"
        )
    elif mutation == "tenant_mismatch":
        with connect(DATABASE_URL) as connection:
            connection.execute("UPDATE tasks SET tenant_id = 'tenant-B' WHERE task_id = %s",
                               (task_id,))
    elif mutation == "expired_task":
        with connect(DATABASE_URL) as connection:
            connection.execute("UPDATE tasks SET expires_at = %s WHERE task_id = %s",
                               (now_unix() - 1, task_id))
    elif mutation == "revoked_root":
        RevocationService(DATABASE_URL).revoke(
            root["payload"]["credential_id"],
            RevokeCredentialRequest(reason="preflight regression", revoked_by="test-controller"),
        )
    elif mutation == "amount_above_root":
        document["context"]["refund_amount_fen"] = 30_001
    try:
        before = business_snapshot(task_id)
        response = post_preflight(document, caller=caller, omit_caller=mutation == "missing_caller")
        assert response.status_code == 403, response.text
        if reason:
            assert response.json()["reason_code"] == reason
        assert business_snapshot(task_id) == before
    finally:
        if mutation in {"tenant_mismatch", "expired_task"}:
            with connect(DATABASE_URL) as connection:
                connection.execute(
                    "UPDATE tasks SET tenant_id = %s, expires_at = %s WHERE task_id = %s",
                    (original_task[0], original_task[4], task_id),
                )


@pytest.mark.parametrize("shareable,confirmed,status", [
    (True, True, 200), (True, False, 403), (False, True, 403),
])
def test_cloud_preflight_uses_trusted_ticket_flag_without_contacting_model(
    shareable, confirmed, status,
):
    root = _create_root()
    task_id = root["payload"]["task_id"]
    ticket_id = business_fixtures.business_test_case()["ticket_id"]
    with connect(DATABASE_URL) as connection:
        original = connection.execute(
            "SELECT cloud_shareable FROM tickets WHERE ticket_id = %s", (ticket_id,),
        ).fetchone()[0]
        connection.execute("UPDATE tickets SET cloud_shareable = %s WHERE ticket_id = %s",
                           (shareable, ticket_id))
    document = request_document(
        [root], runtime_mode="cloud", cloud_data_confirmed=confirmed,
        ticket_context={"cloud_shareable": True},
    )
    try:
        before = business_snapshot(task_id)
        response = post_preflight(document, caller="agent-coordinator")
        assert response.status_code == status, response.text
        assert business_snapshot(task_id) == before
    finally:
        with connect(DATABASE_URL) as connection:
            connection.execute("UPDATE tickets SET cloud_shareable = %s WHERE ticket_id = %s",
                               (original, ticket_id))
