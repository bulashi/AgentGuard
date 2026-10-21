"""Real database and SM2 regressions; only run in the parent's disposable harness."""

from __future__ import annotations

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from urllib.parse import urlsplit

import psycopg
import pytest
from fastapi.testclient import TestClient

import backend.admission.service as admission_module
import backend.tools.store as tool_store_module
from backend.admission.service import AdmissionService
from backend.business_action.contracts import ResolveNotificationActionRequest
from backend.business_action.policy import notification_scope
from backend.business_action.service import BusinessActionError, BusinessActionRegistryService
from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.time import now_unix
from backend.config.settings import Settings
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex
from backend.gateway.contracts import RequestEnvelopeModel, ValidatedToolCommandModel
from backend.gateway.dispatch import GatewayDispatchService
from backend.gateway.service import SecureGatewayService
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case
from backend.tests.integration import test_tool_postgres as tool_helpers
from backend.tests.integration.test_admission_postgres import (
    COORDINATOR_URL,
    DATABASE_URL,
    _budget_snapshot,
    _capability,
    _create_root,
    _delegate,
    _leaf_chain,
    _refund_action,
    _request,
)
from backend.tests.integration.test_dispatch_postgres import _dispatch
from backend.tools.app import make_app as make_tool_app
from backend.tools.contracts import GatewayExecutionEnvelopeModel, ToolExecutionResponse
from backend.tools.store import PostgresToolStore

pytestmark = [pytest.mark.integration]
assert DATABASE_URL is not None
_target = urlsplit(DATABASE_URL)
if _target.hostname not in {"127.0.0.1", "localhost", "::1"} or not re.fullmatch(
    r"/agentguard_test_backend_[a-f0-9]+", _target.path
):
    pytest.fail("notification/locking regressions require the parent's disposable database")


def _case_chain():
    root = _create_root(refund_total_fen=30_000, max_tool_calls=8)
    case = _delegate(
        COORDINATOR_URL,
        root,
        holder_agent_id="agent-case",
        holder_key_id="agent-case-key-01",
        capabilities=[
            _capability(root, "refund.create"),
            _capability(root, "notification.send_template"),
        ],
        refund_total_fen=20_000,
        max_tool_calls=6,
    )
    return case, [root, case], str(root["payload"]["task_id"])


def _case_request(leaf, chain, *, tool, parameters, action_id, suffix):
    service = "refund-service" if tool == "refund.create" else "notification-service"
    body = _request(
        leaf,
        tool_service=service,
        tool_name=tool,
        parameters=parameters,
        business_action_id=action_id,
        request_id=str(leaf["payload"]["task_id"]) + suffix,
        credential_chain=chain,
    )
    private_file = Path(os.environ["AGENTGUARD_HOLDER_PRIVATE_KEY_FILE"]).with_name(
        "agent-case.private"
    )
    private = private_file.read_text(encoding="ascii").strip()
    body["holder_key_id"] = "agent-case-key-01"
    body["holder_proof"]["signature"] = sign_payload(
        body["holder_proof"]["payload"],
        domain_separator=HOLDER_PROOF,
        key_id=body["holder_key_id"],
        key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        private_key_hex=private,
        public_key_hex=derive_public_key(private),
        signed_at=body["issued_at"],
    )
    return body


def _case_refund(leaf, chain, task_id, *, second=False):
    action = _refund_action(task_id, second_slot=second)
    response = _dispatch(
        _case_request(
            leaf,
            chain,
            tool="refund.create",
            parameters={
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "amount_fen": 7000,
            },
            action_id=action["business_action_id"],
            suffix="-REFUND-SECOND" if second else "-REFUND-FIRST",
        )
    )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "COMMITTED"
    refund_id = response.json()["receipt"]["payload"]["business_effect_id"]
    with connect(DATABASE_URL) as connection:
        assert connection.execute(
            "SELECT task_id, amount_fen, status FROM refunds WHERE refund_id = %s", (refund_id,)
        ).fetchone() == (task_id, 7000, "COMMITTED")
    return refund_id


def _notice(registry, task_id, refund_id):
    return registry.resolve_notification(
        ResolveNotificationActionRequest(
            task_id=task_id,
            template_id="REFUND_SUCCESS",
            related_business_effect_id=refund_id,
        ),
        current_time=now_unix(),
    )


def test_registry_rejects_nonexistent_and_foreign_task_refund_without_new_scope():
    leaf, chain, task_id = _case_chain()
    refund_id = _case_refund(leaf, chain, task_id)
    registry = BusinessActionRegistryService(DATABASE_URL)
    with connect(DATABASE_URL) as connection:
        before = connection.execute(
            "SELECT count(*) FROM business_actions WHERE task_id = %s", (task_id,)
        ).fetchone()[0]
    for number in (1, 2):
        with pytest.raises(BusinessActionError) as captured:
            _notice(registry, task_id, f"REFUND-NOT-REGISTERED-{number}")
        assert captured.value.reason_code is ReasonCode.BUSINESS_ACTION_INVALID
    other_task = str(_create_root()["payload"]["task_id"])
    with pytest.raises(BusinessActionError) as captured:
        _notice(registry, other_task, refund_id)
    assert captured.value.reason_code is ReasonCode.BUSINESS_ACTION_INVALID
    with connect(DATABASE_URL) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM business_actions WHERE task_id = %s", (task_id,)
            ).fetchone()[0]
            == before
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM notifications WHERE task_id IN (%s, %s)",
                (task_id, other_task),
            ).fetchone()[0]
            == 0
        )


def test_gateway_binds_scope_and_keeps_retry_and_distinct_refunds():
    leaf, chain, task_id = _case_chain()
    first_refund = _case_refund(leaf, chain, task_id)
    second_refund = _case_refund(leaf, chain, task_id, second=True)
    registry = BusinessActionRegistryService(DATABASE_URL)
    first_action = _notice(registry, task_id, first_refund)
    second_action = _notice(registry, task_id, second_refund)
    assert _notice(registry, task_id, first_refund) == first_action
    assert first_action["business_action_id"] != second_action["business_action_id"]
    credential_ids = [str(item["payload"]["credential_id"]) for item in chain]
    budgets_before = _budget_snapshot(credential_ids)
    wrong = _dispatch(
        _case_request(
            leaf,
            chain,
            tool="notification.send_template",
            parameters={
                "customer_id": "C9527",
                "template_id": "REFUND_SUCCESS",
                "related_business_effect_id": first_refund,
            },
            action_id=second_action["business_action_id"],
            suffix="-NOTICE-WRONG-SCOPE",
        )
    )
    assert wrong.status_code == 409, wrong.text
    assert wrong.json()["reason_code"] == "BUSINESS_ACTION_CONFLICT"
    assert _budget_snapshot(credential_ids) == budgets_before
    with connect(DATABASE_URL) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM notifications WHERE task_id = %s", (task_id,)
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM tool_execution_attempts a "
                "JOIN execution_records e USING (execution_id) "
                "WHERE e.task_id = %s AND e.tool_name = 'notification.send_template'",
                (task_id,),
            ).fetchone()[0]
            == 0
        )
    effects = []
    for number, (refund_id, action) in enumerate(
        ((first_refund, first_action), (second_refund, second_action)), 1
    ):
        parameters = {
            "customer_id": "C9527",
            "template_id": "REFUND_SUCCESS",
            "related_business_effect_id": refund_id,
        }
        sent = _dispatch(
            _case_request(
                leaf,
                chain,
                tool="notification.send_template",
                parameters=parameters,
                action_id=action["business_action_id"],
                suffix=f"-NOTICE-{number}",
            )
        )
        assert sent.status_code == 200, sent.text
        effects.append(sent.json()["receipt"]["payload"]["business_effect_id"])
        budgets_after = _budget_snapshot(credential_ids)
        retry = _dispatch(
            _case_request(
                leaf,
                chain,
                tool="notification.send_template",
                parameters=parameters,
                action_id=action["business_action_id"],
                suffix=f"-NOTICE-{number}-RETRY",
            )
        )
        assert retry.status_code == 200, retry.text
        assert retry.json()["admission_outcome"] == "IDEMPOTENT_RETURN"
        assert retry.json()["receipt"]["payload"]["business_effect_id"] == effects[-1]
        assert _budget_snapshot(credential_ids) == budgets_after
    with connect(DATABASE_URL) as connection:
        notices = connection.execute(
            "SELECT notification_id, related_business_effect_id FROM notifications "
            "WHERE task_id = %s",
            (task_id,),
        ).fetchall()
    assert len(notices) == len(set(effects)) == 2
    assert dict(notices) == dict(zip(effects, (first_refund, second_refund), strict=True))


def test_tool_rechecks_signed_dispatch_scope_before_effect_and_preserves_retry():
    # This fixture intentionally alters a trusted action index after signing.
    # It tests the tool boundary, not an attacker's ability to modify the database.
    context = tool_helpers.authorized_task()
    refund_key = sm3_hex(tool_helpers.unique("refund-binding-key").encode("utf-8"))
    notice_key = sm3_hex(tool_helpers.unique("notification-binding-key").encode("utf-8"))
    try:
        refund = tool_helpers.signed_envelope(
            task_context=context,
            kind="refund",
            parameters={
                "ticket_id": context.ticket_id,
                "customer_id": context.customer_id,
                "amount_fen": 7000,
            },
            business_action_id=tool_helpers.unique("ACTION-REFUND-SCOPE"),
            idempotency_key=refund_key,
        )
        refunded = tool_helpers.post("refund", refund)
        assert refunded.status_code == 200, refunded.text
        refund_id = refunded.json()["business_effect_id"]
        parameters = {
            "customer_id": context.customer_id,
            "template_id": "REFUND_SUCCESS",
            "related_business_effect_id": refund_id,
        }
        notice = tool_helpers.signed_envelope(
            task_context=context,
            kind="notification",
            parameters=parameters,
            business_action_id=tool_helpers.unique("ACTION-NOTIFY-SCOPE"),
            idempotency_key=notice_key,
        )
        action_id = notice["payload"]["business_action_id"]
        wrong_scope, _ = notification_scope(
            context,
            template_id="REFUND_SUCCESS",
            related_business_effect_id="REFUND-NOT-REGISTERED",
        )
        with connect(DATABASE_URL) as connection, connection.transaction():
            original_scope = connection.execute(
                "SELECT action_scope_key FROM business_actions WHERE business_action_id = %s",
                (action_id,),
            ).fetchone()[0]
            connection.execute(
                "UPDATE business_actions SET action_scope_key = %s WHERE business_action_id = %s",
                (wrong_scope, action_id),
            )
        denied = tool_helpers.post("notification", notice)
        assert denied.status_code == 409, denied.text
        assert denied.json()["detail"]["reason_code"] == "BUSINESS_ACTION_CONFLICT"
        with connect(DATABASE_URL) as connection, connection.transaction():
            assert (
                connection.execute(
                    "SELECT count(*) FROM notifications WHERE task_id = %s", (context.task_id,)
                ).fetchone()[0]
                == 0
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM tool_execution_attempts WHERE execution_id = %s",
                    (notice["payload"]["execution_id"],),
                ).fetchone()[0]
                == 0
            )
            connection.execute(
                "UPDATE business_actions SET action_scope_key = %s WHERE business_action_id = %s",
                (original_scope, action_id),
            )
        sent = tool_helpers.post("notification", notice)
        assert sent.status_code == 200, sent.text
        retry = tool_helpers.signed_envelope(
            task_context=context,
            kind="notification",
            parameters=parameters,
            business_action_id=action_id,
            idempotency_key=notice_key,
            execution_id=notice["payload"]["execution_id"],
        )
        repeated = tool_helpers.post("notification", retry)
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["business_effect_id"] == sent.json()["business_effect_id"]
        with connect(DATABASE_URL) as connection:
            assert (
                connection.execute(
                    "SELECT count(*) FROM notifications WHERE task_id = %s", (context.task_id,)
                ).fetchone()[0]
                == 1
            )
    finally:
        tool_helpers.cleanup_synthetic_task(context)


def test_admission_retry_and_tool_fixed_interleaving_share_one_lock_order(monkeypatch):
    leaf, chain, task_id, credential_ids = _leaf_chain()
    action = _refund_action(task_id)
    parameters = {
        "ticket_id": business_test_case()["ticket_id"],
        "customer_id": "C9527",
        "amount_fen": 7000,
    }
    first = RequestEnvelopeModel.model_validate(
        _request(
            leaf,
            tool_service="refund-service",
            tool_name="refund.create",
            parameters=parameters,
            business_action_id=action["business_action_id"],
            request_id=task_id + "-LOCK-FIRST",
            credential_chain=chain,
        )
    )
    gateway = SecureGatewayService(database_url=DATABASE_URL)
    admission = AdmissionService(gateway)
    admitted = admission.admit_request(first, current_time=now_unix())
    command = ValidatedToolCommandModel.model_validate(admitted.body["validated_command"])
    dispatch = GatewayDispatchService(
        gateway,
        admission,
        tool_urls={},
        gateway_key_id="gateway-key-01",
        gateway_private_key_file=os.environ["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"],
    )
    envelope = dispatch._mark_dispatched(command, request_hash=admitted.body["request_hash"])
    assert isinstance(envelope, GatewayExecutionEnvelopeModel)
    retry = RequestEnvelopeModel.model_validate(
        _request(
            leaf,
            tool_service="refund-service",
            tool_name="refund.create",
            parameters=parameters,
            business_action_id=action["business_action_id"],
            request_id=task_id + "-LOCK-RETRY",
            credential_chain=chain,
        )
    )
    budgets_before = _budget_snapshot(credential_ids)
    task_locked, release_admission, tool_connected, tool_execution_locked = (
        Event() for _ in range(4)
    )
    pids = {}
    sqlstates = []

    class ObservedConnection:
        def __init__(self, connection, role):
            self.raw = connection
            self.role = role

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def execute(self, query, parameters=()):
            sql = " ".join(query.split())
            try:
                cursor = self.raw.execute(query, parameters)
            except psycopg.Error as error:
                sqlstates.append((self.role, error.sqlstate))
                raise
            if (
                self.role == "admission"
                and "FROM tasks" in sql
                and "FOR UPDATE" in sql
                and not task_locked.is_set()
            ):
                task_locked.set()
                assert release_admission.wait(10), "coordinator did not release admission"
            if self.role == "tool" and "FROM execution_records" in sql and "FOR UPDATE" in sql:
                tool_execution_locked.set()
            return cursor

    @contextmanager
    def observed_connection(url, *, role):
        with connect(url) as connection:
            connection.execute("SET statement_timeout = '15000ms'")
            connection.execute("SET lock_timeout = '10000ms'")
            pids[role] = connection.info.backend_pid
            if role == "tool":
                tool_connected.set()
            yield ObservedConnection(connection, role)

    monkeypatch.setattr(
        admission_module, "connect", lambda url: observed_connection(url, role="admission")
    )
    monkeypatch.setattr(
        tool_store_module, "connect", lambda url: observed_connection(url, role="tool")
    )
    api = TestClient(
        make_tool_app(
            settings=Settings(
                storage="postgres",
                database_url=DATABASE_URL,
                tool_kind="refund",
                gateway_public_key_hex=tool_helpers.PUBLIC_KEY,
            ),
            store=PostgresToolStore(DATABASE_URL),
        )
    )
    results = {}
    errors = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        admission_future = executor.submit(admission.admit_request, retry, current_time=now_unix())
        try:
            assert task_locked.wait(8), "admission did not reach the real task row lock"
            tool_future = executor.submit(
                api.post, "/internal/execute", json=envelope.model_dump(mode="json")
            )
            assert tool_connected.wait(8), "tool did not open its execution transaction"
            deadline = time.monotonic() + 5
            blockers = []
            with connect(DATABASE_URL) as observer:
                while time.monotonic() < deadline:
                    blockers = observer.execute(
                        "SELECT pg_blocking_pids(%s)", (pids["tool"],)
                    ).fetchone()[0]
                    if pids["admission"] in blockers:
                        break
                    time.sleep(0.02)
            assert pids["admission"] in blockers, (
                "fixed interleaving did not reach an observed PG lock wait"
            )
            execution_before_release = tool_execution_locked.is_set()
        finally:
            release_admission.set()
        for role, future in (("admission", admission_future), ("tool", tool_future)):
            try:
                results[role] = future.result(timeout=20)
            except Exception as error:
                errors.append(error)
    api.close()
    print(
        "PG_FIXED_INTERLEAVING "
        f"tool_execution_before_task_release={execution_before_release} SQLSTATE={sqlstates}"
    )
    if errors:
        raise errors[0]
    retried, executed = results["admission"], results["tool"]
    assert not execution_before_release, (
        "tool acquired the execution lock before waiting for the task"
    )
    assert not sqlstates
    assert retried.body["execution_id"] == command.execution_id
    assert retried.body["admission_outcome"] == "EXISTING_EXECUTION"
    assert executed.status_code == 200, executed.text
    assert _budget_snapshot(credential_ids) == budgets_before
    with connect(DATABASE_URL) as connection:
        assert connection.execute(
            "SELECT count(*), sum(amount_fen) FROM refunds WHERE task_id = %s", (task_id,)
        ).fetchone() == (1, 7000)
    dispatch._settle_success(
        command,
        body=admitted.body,
        tool_response=ToolExecutionResponse.model_validate(executed.json()),
    )
