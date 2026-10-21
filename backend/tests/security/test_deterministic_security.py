from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import EXECUTION_RECEIPT
from backend.crypto.sm import sm3_hex, verify_payload
from backend.identity.key_registry import PostgresKeyRegistry
from backend.state.database import connect
from backend.tests import business_fixtures
from backend.tests.business_fixtures import business_test_case, verified_postgres_case
from backend.tests.integration.test_admission_postgres import (
    DATABASE_URL,
    GATEWAY_URL,
    _admit,
    _budget_snapshot,
    _create_root,
    _leaf_chain,
    _refund_action,
    _request,
)
from backend.tests.integration.test_dispatch_postgres import _dispatch, _resign_request

pytestmark = [pytest.mark.integration, pytest.mark.security]

AUDIT_URL = os.getenv("AGENTGUARD_AUDIT_SERVICE_URL")
CHECKPOINT_URL = os.getenv("AGENTGUARD_CHECKPOINT_SERVICE_URL")
REVOCATION_URL = os.getenv("AGENTGUARD_REVOCATION_URL")
REFUND_TOOL_URL = os.getenv("AGENTGUARD_REFUND_TOOL_URL")
AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")

if not all((DATABASE_URL, GATEWAY_URL, AUDIT_URL, CHECKPOINT_URL)):
    pytest.skip(
        "PostgreSQL deterministic security test environment is not active", allow_module_level=True
    )

SCHEMAS = SchemaStore()


def _append_audit() -> None:
    assert AUDIT_URL is not None
    with httpx.Client(base_url=AUDIT_URL, timeout=20) as client:
        response = client.post(
            "/internal/audit/append",
            headers={"X-AgentGuard-Internal": "phase13-test"},
            json={"max_events": 10_000},
        )
    assert response.status_code == 200, response.text


def _checkpoint() -> None:
    assert CHECKPOINT_URL is not None
    with httpx.Client(base_url=CHECKPOINT_URL, timeout=20) as client:
        response = client.post(
            "/internal/checkpoint/run",
            headers={"X-AgentGuard-Internal": "phase13-test"},
        )
    assert response.status_code == 200, response.text


def _verify_audit() -> None:
    assert AUDIT_URL is not None
    with httpx.Client(base_url=AUDIT_URL, timeout=20) as client:
        response = client.post(
            "/audit/verify",
            json={"from_sequence": 1, "include_independent_checkpoint": True},
        )
    assert response.status_code == 200, response.text
    assert response.json()["valid"] is True, response.text
    assert response.json()["rollback_detected"] is False, response.text


def _verify_signed_receipt(receipt: dict[str, object]) -> None:
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


def _effect_count(task_id: str) -> tuple[int, int]:
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        row = connection.execute(
            """
            SELECT
              (SELECT count(*) FROM refunds WHERE task_id = %s),
              (SELECT count(*) FROM notifications WHERE task_id = %s)
            """,
            (task_id, task_id),
        ).fetchone()
    assert row is not None
    return int(row[0]), int(row[1])


def _deny_request(
    request: dict[str, object],
    *,
    expected: set[str],
    credential_ids: list[str],
    before_effects: tuple[int, int],
) -> dict[str, object]:
    assert GATEWAY_URL is not None
    before_budget = _budget_snapshot(credential_ids)
    with httpx.Client(base_url=GATEWAY_URL, timeout=20) as client:
        response = client.post("/gateway/admit", json=request)
    assert response.status_code in {400, 403, 409}, response.text
    body = response.json()
    assert body["decision"] == "DENY", body
    assert body["state"] == "DENIED", body
    assert body["reason_code"] in expected, body
    receipt = body.get("receipt")
    assert isinstance(receipt, dict), body
    _verify_signed_receipt(receipt)
    payload = receipt["payload"]
    assert isinstance(payload, dict)
    assert payload["request_id"] == request["request_id"]
    assert payload["decision"] == "DENY"
    assert payload["business_effect_id"] is None
    assert payload["business_result_hash"] is None
    assert payload["budget_committed"] == 0
    assert _budget_snapshot(credential_ids) == before_budget
    assert _effect_count(str(request["task_id"])) == before_effects
    return body


def _resign_for_request(request: dict[str, object]) -> None:
    _resign_request(request)


def _reject_request_at_parse(
    request: dict[str, object],
    *,
    credential_ids: list[str],
    before_effects: tuple[int, int],
) -> None:
    assert GATEWAY_URL is not None and DATABASE_URL is not None
    before_budget = _budget_snapshot(credential_ids)
    raw = json.dumps(request, separators=(",", ":"), allow_nan=False).encode("utf-8")
    with httpx.Client(base_url=GATEWAY_URL, timeout=20) as client:
        response = client.post(
            "/gateway/admit", content=raw, headers={"content-type": "application/json"}
        )
    assert response.status_code == 400, response.text
    assert response.json() == {
        "status": "rejected_at_parse",
        "reason_code": "REQUEST_SCHEMA_INVALID",
    }
    with connect(DATABASE_URL) as connection:
        audit = connection.execute(
            """
            SELECT payload->>'reason_code', payload->>'raw_request_hash',
                   payload->>'parser_stage', event_type, execution_id
            FROM audit_outbox WHERE payload->>'raw_request_hash' = %s
            ORDER BY created_at DESC LIMIT 1
            """,
            (sm3_hex(raw),),
        ).fetchone()
        records = connection.execute(
            """
            SELECT
              (SELECT count(*) FROM execution_records WHERE initial_request_id = %s),
              (SELECT count(*) FROM execution_requests WHERE request_id = %s),
              (SELECT count(*) FROM execution_receipts AS receipt
               JOIN execution_records AS execution ON execution.execution_id = receipt.execution_id
               WHERE execution.initial_request_id = %s)
            """,
            (request["request_id"],) * 3,
        ).fetchone()
    assert audit == ("REQUEST_SCHEMA_INVALID", sm3_hex(raw), "SCHEMA", "RAW_REQUEST_REJECTED", None)
    assert records == (0, 0, 0)
    assert _budget_snapshot(credential_ids) == before_budget
    assert _effect_count(str(request["task_id"])) == before_effects


def test_raw_parse_and_schema_rejection_have_only_rejected_audit_evidence() -> None:
    assert GATEWAY_URL is not None and AUDIT_URL is not None
    raw_cases = [
        (b"{", "MALFORMED_JSON"),
        (b"\xff\xfe", "INVALID_UTF8"),
        (b'{"schema_version":"1.0","schema_version":"1.0"}', "DUPLICATE_FIELD"),
    ]
    raw_hashes: list[str] = []
    for raw, expected_reason in raw_cases:
        with httpx.Client(base_url=GATEWAY_URL, timeout=20) as client:
            response = client.post(
                "/gateway/execute",
                content=raw,
                headers={"content-type": "application/json"},
            )
        assert response.status_code == 400, response.text
        assert response.json()["status"] == "rejected_at_parse"
        raw_hashes.append(sm3_hex(raw))
        with connect(DATABASE_URL) as connection:
            row = connection.execute(
                """
                SELECT payload->>'reason_code', payload->>'raw_request_hash',
                       event_type, execution_id
                FROM audit_outbox
                WHERE payload->>'raw_request_hash' = %s
                ORDER BY created_at DESC LIMIT 1
                """,
                (raw_hashes[-1],),
            ).fetchone()
        assert row is not None
        assert str(row[0]) == expected_reason
        assert str(row[1]) == raw_hashes[-1]
        assert row[2] == "RAW_REQUEST_REJECTED"
        assert row[3] is None

    leaf, chain, task_id, _ = _leaf_chain()
    action = _refund_action(task_id)
    valid = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 1000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-RAW-UNKNOWN-{uuid4().hex}",
        credential_chain=chain,
    )
    valid["unexpected_security_field"] = "attacker-controlled"
    raw = json.dumps(valid, separators=(",", ":")).encode("utf-8")
    with httpx.Client(base_url=GATEWAY_URL, timeout=20) as client:
        response = client.post(
            "/gateway/execute",
            content=raw,
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 400, response.text
    assert response.json()["status"] == "rejected_at_parse"
    raw_hash = sm3_hex(raw)
    with connect(DATABASE_URL) as connection:
        row = connection.execute(
            """
            SELECT payload->>'reason_code', event_type, execution_id
            FROM audit_outbox WHERE payload->>'raw_request_hash' = %s
            ORDER BY created_at DESC LIMIT 1
            """,
            (raw_hash,),
        ).fetchone()
    assert row is not None
    assert row[0] in {"UNKNOWN_FIELD", "REQUEST_SCHEMA_INVALID"}
    assert row[1] == "RAW_REQUEST_REJECTED"
    assert row[2] is None

    _append_audit()
    _checkpoint()
    _verify_audit()


def test_parseable_deny_matrix_preserves_receipt_budget_and_business_state() -> None:
    leaf, chain, task_id, credential_ids = _leaf_chain()
    action = _refund_action(task_id)
    base = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 1000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-MATRIX-BASE-{uuid4().hex}",
        credential_chain=chain,
    )
    before_effects = _effect_count(task_id)

    tampered = deepcopy(base)
    tampered["canonical_parameters"]["amount_fen"] = 1001
    _deny_request(
        tampered,
        expected={"INVALID_SIGNATURE"},
        credential_ids=credential_ids,
        before_effects=before_effects,
    )

    wrong_holder = deepcopy(base)
    wrong_holder["request_id"] = f"{task_id}-MATRIX-WRONG-HOLDER-{uuid4().hex}"
    wrong_holder["holder_key_id"] = "agent-case-key-01"
    wrong_holder["holder_proof"]["payload"]["request_id"] = wrong_holder["request_id"]
    _resign_for_request(wrong_holder)
    _deny_request(
        wrong_holder,
        expected={"WRONG_HOLDER", "INVALID_SIGNATURE"},
        credential_ids=credential_ids,
        before_effects=before_effects,
    )

    cross_task = deepcopy(base)
    other_root = _create_root()
    other_task = str(other_root["payload"]["task_id"])
    cross_task["request_id"] = f"{task_id}-MATRIX-CROSS-TASK-{uuid4().hex}"
    cross_task["task_id"] = other_task
    cross_task["holder_proof"]["payload"]["task_id"] = other_task
    cross_task["holder_proof"]["payload"]["request_id"] = cross_task["request_id"]
    _resign_for_request(cross_task)
    _deny_request(
        cross_task,
        expected={"CROSS_TASK"},
        credential_ids=credential_ids,
        before_effects=_effect_count(other_task),
    )

    wrong_service = deepcopy(base)
    wrong_service["request_id"] = f"{task_id}-MATRIX-WRONG-SERVICE-{uuid4().hex}"
    wrong_service["tool_service"] = "admin-service"
    wrong_service["tool_name"] = "refund.create"
    wrong_service["canonical_parameters"] = {
        "ticket_id": business_test_case()["ticket_id"],
        "customer_id": "C9527",
        "amount_fen": 1000,
    }
    proof_payload = wrong_service["holder_proof"]["payload"]
    proof_payload.update(
        {
            "tool_service": wrong_service["tool_service"],
            "tool_name": wrong_service["tool_name"],
            "canonical_parameter_hash": sm3_hex(
                canonicalize(wrong_service["canonical_parameters"])
            ),
            "request_id": wrong_service["request_id"],
            "business_action_id": wrong_service["business_action_id"],
        }
    )
    _resign_for_request(wrong_service)
    _deny_request(
        wrong_service,
        expected={"TOOL_NOT_ALLOWED", "SERVICE_NOT_ALLOWED"},
        credential_ids=credential_ids,
        before_effects=before_effects,
    )

    negative = deepcopy(base)
    negative["request_id"] = f"{task_id}-MATRIX-NEGATIVE-{uuid4().hex}"
    negative["canonical_parameters"]["amount_fen"] = -1
    negative["holder_proof"]["payload"]["request_id"] = negative["request_id"]
    negative["holder_proof"]["payload"]["canonical_parameter_hash"] = sm3_hex(
        canonicalize(negative["canonical_parameters"])
    )
    _resign_for_request(negative)
    _deny_request(
        negative,
        expected={"REQUEST_SCHEMA_INVALID"},
        credential_ids=credential_ids,
        before_effects=before_effects,
    )

    overflow = deepcopy(base)
    overflow["request_id"] = f"{task_id}-MATRIX-OVERFLOW-{uuid4().hex}"
    overflow["canonical_parameters"]["amount_fen"] = 9_007_199_254_740_992
    overflow["holder_proof"]["payload"]["request_id"] = overflow["request_id"]
    _resign_for_request(overflow)
    _reject_request_at_parse(
        overflow,
        credential_ids=credential_ids,
        before_effects=before_effects,
    )

    stale = deepcopy(base)
    stale["request_id"] = f"{task_id}-MATRIX-STALE-{uuid4().hex}"
    stale["issued_at"] = now_unix() - 600
    stale["holder_proof"]["payload"]["request_id"] = stale["request_id"]
    stale["holder_proof"]["payload"]["issued_at"] = stale["issued_at"]
    _resign_for_request(stale)
    _deny_request(
        stale,
        expected={"REQUEST_STALE"},
        credential_ids=credential_ids,
        before_effects=before_effects,
    )

    _append_audit()
    _checkpoint()
    _verify_audit()


def test_cross_tenant_replay_budget_and_idempotency_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    leaf, chain, task_id, credential_ids = _leaf_chain()
    action = _refund_action(task_id)
    base = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 1000,
        },
        business_action_id=str(action["business_action_id"]),
        request_id=f"{task_id}-MATRIX-REPLAY-{uuid4().hex}",
        credential_chain=chain,
    )
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute("UPDATE tasks SET tenant_id = 'tenant-B' WHERE task_id = %s", (task_id,))
    try:
        tenant_attack = deepcopy(base)
        tenant_attack["holder_proof"]["payload"]["request_id"] = tenant_attack["request_id"]
        _resign_for_request(tenant_attack)
        _deny_request(
            tenant_attack,
            expected={"CROSS_TENANT"},
            credential_ids=credential_ids,
            before_effects=_effect_count(task_id),
        )
    finally:
        with connect(DATABASE_URL) as connection, connection.transaction():
            connection.execute(
                "UPDATE tasks SET tenant_id = 'tenant-A' WHERE task_id = %s",
                (task_id,),
            )

    replay = deepcopy(base)
    replay["request_id"] = f"{task_id}-MATRIX-REPLAY-FIRST-{uuid4().hex}"
    replay["holder_proof"]["payload"]["request_id"] = replay["request_id"]
    _resign_for_request(replay)
    first = _dispatch(replay)
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["state"] == "COMMITTED", first_body
    assert first_body["decision"] == "ALLOW", first_body
    assert isinstance(first_body.get("receipt"), dict), first_body
    _verify_signed_receipt(first_body["receipt"])

    repeated = _dispatch(replay)
    assert repeated.status_code == 403, repeated.text
    repeated_body = repeated.json()
    assert repeated_body["reason_code"] == "REPLAY_DETECTED"
    assert isinstance(repeated_body.get("receipt"), dict), repeated_body
    _verify_signed_receipt(repeated_body["receipt"])

    conflict = deepcopy(replay)
    conflict["request_id"] = f"{task_id}-MATRIX-CONFLICT-{uuid4().hex}"
    conflict["canonical_parameters"]["amount_fen"] = 1001
    conflict["holder_proof"]["payload"]["request_id"] = conflict["request_id"]
    conflict["holder_proof"]["payload"]["canonical_parameter_hash"] = sm3_hex(
        canonicalize(conflict["canonical_parameters"])
    )
    _resign_for_request(conflict)
    conflict_response = _dispatch(conflict)
    assert conflict_response.status_code == 409, conflict_response.text
    conflict_body = conflict_response.json()
    assert conflict_body["reason_code"] == "IDEMPOTENCY_CONFLICT"
    assert isinstance(conflict_body.get("receipt"), dict), conflict_body
    _verify_signed_receipt(conflict_body["receipt"])

    assert _effect_count(task_id) == (1, 0)
    assert DATABASE_URL is not None
    monkeypatch.setattr(
        business_fixtures, "POSTGRES_BUSINESS_TEST_CASE", verified_postgres_case(DATABASE_URL)
    )
    budget_leaf, budget_chain, budget_task, budget_ids = _leaf_chain()
    budget_action = _refund_action(budget_task)
    oversized = _request(
        budget_leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 10_001,
        },
        business_action_id=str(budget_action["business_action_id"]),
        request_id=f"{budget_task}-MATRIX-BUDGET-{uuid4().hex}",
        credential_chain=budget_chain,
    )
    _deny_request(
        oversized,
        expected={"BUDGET_EXCEEDED"},
        credential_ids=budget_ids,
        before_effects=_effect_count(budget_task),
    )
    assert _effect_count(task_id) == (1, 0)
    assert _effect_count(budget_task) == (0, 0)

    _append_audit()
    _checkpoint()
    _verify_audit()


def test_protected_tool_envelope_replay_and_expiry_have_no_second_effect(
    request: pytest.FixtureRequest,
) -> None:
    assert REFUND_TOOL_URL is not None
    from backend.tests.integration.test_tool_postgres import (
        TOOL_URLS,
        authorized_task,
        cleanup_synthetic_task,
        signed_envelope,
    )

    task_context = authorized_task()
    request.addfinalizer(lambda: cleanup_synthetic_task(task_context))
    parameters = {
        "ticket_id": business_test_case()["ticket_id"],
        "customer_id": "C9527",
        "amount_fen": 1000,
    }
    envelope = signed_envelope(
        task_context=task_context,
        kind="refund",
        parameters=parameters,
        business_action_id=f"MATRIX-ACTION-{uuid4().hex}",
        idempotency_key=sm3_hex(f"MATRIX-IDEM-{uuid4().hex}".encode()),
    )
    first = httpx.post(f"{TOOL_URLS['refund']}/internal/execute", json=envelope, timeout=20)
    assert first.status_code == 200, first.text
    effect_id = first.json()["business_effect_id"]
    replay = httpx.post(f"{TOOL_URLS['refund']}/internal/execute", json=envelope, timeout=20)
    assert replay.status_code == 409, replay.text
    assert replay.json()["detail"]["reason_code"] == "EXECUTION_ENVELOPE_REPLAY"

    expired = deepcopy(envelope)
    expired["payload"]["execution_attempt_id"] = f"MATRIX-EXPIRED-{uuid4().hex}"
    expired["payload"]["issued_at"] = now_unix() - 100
    expired["payload"]["expires_at"] = now_unix() - 1
    response = httpx.post(f"{TOOL_URLS['refund']}/internal/execute", json=expired, timeout=20)
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["reason_code"] == "EXECUTION_ENVELOPE_EXPIRED"

    with connect(DATABASE_URL) as connection:
        effect_count = connection.execute(
            "SELECT count(*) FROM refunds WHERE business_idempotency_key = %s",
            (envelope["payload"]["business_idempotency_key"],),
        ).fetchone()
    assert effect_count == (1,)
    assert effect_id is not None


def test_compromised_holder_key_is_rejected_before_new_admission(tmp_path: Path) -> None:
    from backend.tests.integration.test_revocation_postgres import (
        _dynamic_root,
        _dynamic_ticket_request,
    )

    if not AUTHORITY_URL:
        pytest.skip("authority URL is not configured")
    credential, _agent_id, key_id, private_key, _task_id = _dynamic_root(
        tmp_path,
        agent_suffix=f"phase13-{uuid4().hex[:8]}",
        key_suffix=f"phase13-{uuid4().hex[:8]}",
    )
    assert DATABASE_URL is not None
    PostgresKeyRegistry(DATABASE_URL).compromise(key_id, compromised_at=now_unix())
    blocked = _admit(
        _dynamic_ticket_request(
            credential,
            agent_key_id=key_id,
            private_key=private_key,
            request_id=f"PHASE13-COMPROMISED-{uuid4().hex}",
        )
    )
    assert blocked.status_code == 403, blocked.text
    assert blocked.json()["reason_code"] == "KEY_COMPROMISED"
