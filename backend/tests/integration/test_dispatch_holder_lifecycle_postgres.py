"""Parent-owned disposable PostgreSQL regressions for the dispatch Holder Proof key."""

from __future__ import annotations

import re
from contextlib import contextmanager
from urllib.parse import urlsplit

import pytest

from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.ids import new_id
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import generate_keypair, sm3_hex
from backend.gateway.contracts import RequestEnvelopeModel
from backend.gateway.dispatch import DispatchResult
from backend.identity.key_registry import KeyRecord, PostgresKeyRegistry
from backend.state.database import connect
from backend.tests import business_fixtures
from backend.tests.integration.test_admission_postgres import (
    DATABASE_URL,
    _budget_snapshot,
    _request,
)
from backend.tests.integration.test_dispatch_postgres import _dispatch
from backend.tests.integration.test_dispatch_revocation_postgres import (
    assert_cancelled,
    dispatcher,
    pending_refund,
)

pytestmark = [pytest.mark.integration]


@pytest.fixture(autouse=True)
def independent_business_case(monkeypatch):
    assert DATABASE_URL is not None
    target = urlsplit(DATABASE_URL)
    if target.hostname not in {"localhost", "127.0.0.1", "::1"} or not re.fullmatch(
        r"/agentguard_test_backend_[a-f0-9]+", target.path,
    ):
        pytest.fail("dispatch lifecycle tests require a parent-owned disposable database")
    case = business_fixtures.verified_postgres_case(DATABASE_URL)
    monkeypatch.setattr(business_fixtures, "POSTGRES_BUSINESS_TEST_CASE", case)


@contextmanager
def changed_key_state(key_id, state):
    registry = PostgresKeyRegistry(DATABASE_URL)
    original = registry.get(key_id)
    assert original.status is KeyState.ACTIVE
    timestamp = now_unix()
    try:
        if state == "REVOKED":
            registry.revoke(key_id, revoked_at=timestamp)
        elif state == "COMPROMISED":
            registry.compromise(key_id, compromised_at=timestamp)
        elif state == "RETIRED":
            pair = generate_keypair()
            replacement = registry.register(KeyRecord(
                key_id=new_id("LIFECYCLE-REPLACEMENT"), subject_id=original.subject_id,
                subject_type="AGENT", purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
                public_key_hex=pair.public_key_hex, status=KeyState.ACTIVE,
                material_state=KeyMaterialState.PRESENT, private_key_reference=None,
                activated_at=timestamp, created_at=timestamp,
            ))
            registry.retire(key_id, replacement.key_id, retired_at=timestamp)
        else:
            raise AssertionError(f"unhandled fixture state: {state}")
        yield
    finally:
        # These shared harness signing keys must be restored before another test creates a chain.
        with connect(DATABASE_URL) as connection, connection.transaction():
            connection.execute(
                "UPDATE key_registry SET status = %s, retired_at = %s, revoked_at = %s, "
                "compromised_at = %s, replaced_by = %s WHERE key_id = %s",
                (
                    original.status.value, original.retired_at, original.revoked_at,
                    original.compromised_at, original.replaced_by, key_id,
                ),
            )


@pytest.mark.parametrize("state,reason", [
    ("REVOKED", "KEY_REVOKED"),
    ("COMPROMISED", "KEY_COMPROMISED"),
    ("RETIRED", "KEY_RETIRED_FOR_SIGNING"),
])
def test_leaf_holder_transition_after_admission_cancels_without_any_tool_effect(
    state, reason, record_testsuite_property,
):
    request, chain, ids, admitted = pending_refund(f"HOLDER-{state}")
    holder_key_id = chain[-1]["payload"]["holder"]["key_id"]
    assert holder_key_id not in {item["payload"]["issuer"]["key_id"] for item in chain}
    service = dispatcher()
    command = service._command_for_admitted_request(
        RequestEnvelopeModel.model_validate(request), admitted,
    )
    assert command is not None
    with changed_key_state(holder_key_id, state):
        result = service._mark_dispatched(command, request_hash=sm3_hex(canonicalize(request)))
        assert isinstance(result, DispatchResult), "inactive leaf proof cannot produce an envelope"
        assert result.status_code == 403
        assert result.body["decision"] == "DENY" and result.body["reason_code"] == reason
        cancellation = assert_cancelled(request, ids, admitted, reason)
        retry = service._mark_dispatched(command, request_hash=sm3_hex(canonicalize(request)))
        assert isinstance(retry, DispatchResult) and retry.body == result.body
        repeated = assert_cancelled(request, ids, admitted, reason)
        assert repeated == cancellation
    record_testsuite_property("inactive_leaf_holder_state", state)
    record_testsuite_property("dispatch_reason_code", reason)
    record_testsuite_property("tool_attempts_and_refund_rows", "0/0")
    record_testsuite_property("released_reservations", "6/6")


def assert_committed_refund(request, ids, admitted):
    # /gateway/dispatch performs admission again. Retry the same business action
    # with a new request ID and a freshly signed Holder Proof.
    chain = request["credential_chain"]
    retry = _request(
        chain[-1],
        tool_service=request["tool_service"],
        tool_name=request["tool_name"],
        parameters=request["canonical_parameters"],
        business_action_id=request["business_action_id"],
        request_id=new_id("HOLDER-DISPATCH"),
        credential_chain=chain,
    )
    assert retry["request_id"] != request["request_id"]
    response = _dispatch(retry)
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "COMMITTED"
    assert response.json()["execution_id"] == admitted["execution_id"]
    with connect(DATABASE_URL) as connection:
        assert connection.execute(
            "SELECT amount_fen, status::text FROM refunds WHERE execution_id = %s",
            (admitted["execution_id"],),
        ).fetchall() == [(7_000, "COMMITTED")]
        assert connection.execute(
            "SELECT count(*) FROM dispatch_cancellations WHERE execution_id = %s",
            (admitted["execution_id"],),
        ).fetchone() == (0,)
    budgets = _budget_snapshot(ids)
    assert len(budgets) == 6
    assert all(
        row[3] == 0 and row[4] == (7_000 if row[1] == "refund_total_fen" else 1)
        for row in budgets
    )


def test_active_leaf_proof_dispatch_still_commits_once():
    request, _chain, ids, admitted = pending_refund("HOLDER-ACTIVE")
    assert_committed_refund(request, ids, admitted)


def test_historical_retired_issuer_stays_valid_with_active_leaf_holder():
    request, chain, ids, admitted = pending_refund("HOLDER-HISTORICAL-ISSUER")
    issuer_key_id = chain[-1]["payload"]["issuer"]["key_id"]
    assert issuer_key_id != chain[-1]["payload"]["holder"]["key_id"]
    with changed_key_state(issuer_key_id, "RETIRED"):
        assert_committed_refund(request, ids, admitted)
