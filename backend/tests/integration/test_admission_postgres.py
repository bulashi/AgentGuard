from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import httpx
import pytest

from backend.business_action.policy import APPROVED_SECOND_REFUND_SLOT
from backend.business_action.service import BusinessActionRegistryService
from backend.common.enums import KeyPurpose
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case

pytestmark = [pytest.mark.integration]

DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")
COORDINATOR_URL = os.getenv("AGENTGUARD_COORDINATOR_DELEGATION_URL")
CASE_URL = os.getenv("AGENTGUARD_CASE_DELEGATION_URL")
REFUND_URL = os.getenv("AGENTGUARD_REFUND_DELEGATION_URL")
GATEWAY_URL = os.getenv("AGENTGUARD_GATEWAY_URL")
HOLDER_PRIVATE_KEY_FILE = os.getenv("AGENTGUARD_HOLDER_PRIVATE_KEY_FILE")
if not all(
    (
        DATABASE_URL,
        AUTHORITY_URL,
        COORDINATOR_URL,
        CASE_URL,
        REFUND_URL,
        GATEWAY_URL,
        HOLDER_PRIVATE_KEY_FILE,
    )
):
    pytest.skip("PostgreSQL admission test environment is not active", allow_module_level=True)

HOLDER_KEY_ID = "agent-refund-key-01"
HOLDER_PRIVATE_KEY = Path(HOLDER_PRIVATE_KEY_FILE).read_text(encoding="ascii").strip()
HOLDER_PUBLIC_KEY = derive_public_key(HOLDER_PRIVATE_KEY)


def _create_root(*, refund_total_fen: int = 30_000, max_tool_calls: int = 4) -> dict[str, object]:
    assert AUTHORITY_URL is not None
    with httpx.Client(base_url=AUTHORITY_URL, timeout=10) as client:
        created = client.post(
            "/tasks",
            json={
                "tenant_id": "tenant-A",
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "refund_total_fen": refund_total_fen,
                "max_tool_calls": max_tool_calls,
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
    return authorized.json()


def _capability(credential: dict[str, object], tool: str) -> dict[str, object]:
    payload = credential["payload"]
    assert isinstance(payload, dict)
    return deepcopy(next(item for item in payload["capabilities"] if item["tool"] == tool))


def _delegate(
    base_url: str,
    parent: dict[str, object],
    *,
    holder_agent_id: str,
    holder_key_id: str,
    capabilities: list[dict[str, object]],
    refund_total_fen: int,
    max_tool_calls: int,
) -> dict[str, object]:
    payload = parent["payload"]
    assert isinstance(payload, dict)
    with httpx.Client(base_url=base_url, timeout=10) as client:
        response = client.post(
            f"/credentials/{payload['credential_id']}/delegate",
            json={
                "holder_agent_id": holder_agent_id,
                "holder_key_id": holder_key_id,
                "capabilities": capabilities,
                "quotas": {
                    "refund_total_fen": refund_total_fen,
                    "max_tool_calls": max_tool_calls,
                },
                "not_before": payload["not_before"],
                "expires_at": payload["expires_at"] - 60,
            },
        )
    assert response.status_code == 201, response.text
    return response.json()


def _leaf_chain() -> tuple[dict[str, object], list[dict[str, object]], str, list[str]]:
    root = _create_root()
    root_payload = root["payload"]
    assert isinstance(root_payload, dict)
    case = _delegate(
        COORDINATOR_URL,
        root,
        holder_agent_id="agent-case",
        holder_key_id="agent-case-key-01",
        capabilities=[_capability(root, "ticket.read"), _capability(root, "refund.create")],
        refund_total_fen=15_000,
        max_tool_calls=3,
    )
    leaf = _delegate(
        CASE_URL,
        case,
        holder_agent_id="agent-refund",
        holder_key_id=HOLDER_KEY_ID,
        capabilities=[_capability(case, "ticket.read"), _capability(case, "refund.create")],
        refund_total_fen=10_000,
        max_tool_calls=2,
    )
    credential_ids = [str(item["payload"]["credential_id"]) for item in (root, case, leaf)]
    return leaf, [root, case, leaf], str(root_payload["task_id"]), credential_ids


def _request(
    credential: dict[str, object],
    *,
    tool_service: str,
    tool_name: str,
    parameters: dict[str, object],
    business_action_id: str | None,
    request_id: str,
    credential_chain: list[dict[str, object]] | None = None,
    issued_at: int | None = None,
) -> dict[str, object]:
    timestamp = now_unix() if issued_at is None else issued_at
    chain = credential_chain or [credential]
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


def _refund_action(task_id: str, *, second_slot: bool = False) -> dict[str, object]:
    assert DATABASE_URL is not None
    return BusinessActionRegistryService(DATABASE_URL).resolve_refund_for_trusted_slot(
        task_id,
        trusted_action_slot=(APPROVED_SECOND_REFUND_SLOT if second_slot else "primary-refund"),
        current_time=now_unix(),
    )


def _admit(request: dict[str, object]) -> httpx.Response:
    assert GATEWAY_URL is not None
    with httpx.Client(base_url=GATEWAY_URL, timeout=15) as client:
        return client.post("/gateway/admit", json=request)


def _budget_snapshot(credential_ids: list[str]) -> list[tuple[object, ...]]:
    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        rows = connection.execute(
            """
            SELECT credential_id, quota_type, limit_value, reserved_value,
                   committed_value, version
            FROM credential_budget_state
            WHERE credential_id = ANY(%s)
            ORDER BY credential_id, quota_type
            """,
            (credential_ids,),
        ).fetchall()
    return [tuple(row) for row in rows]


def test_atomic_admission_retries_and_three_level_budget_accounting() -> None:
    leaf, chain, task_id, credential_ids = _leaf_chain()
    primary = _refund_action(task_id)
    first = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 7_000,
        },
        business_action_id=str(primary["business_action_id"]),
        request_id=f"{task_id}-ADMIT-FIRST",
        credential_chain=chain,
    )
    admitted = _admit(first)
    assert admitted.status_code == 200, admitted.text
    admitted_body = admitted.json()
    assert admitted_body["state"] == "ADMITTED"
    assert admitted_body["decision"] == "ALLOW"
    assert admitted_body["admission_outcome"] == "NEW_EXECUTION"
    execution_id = admitted_body["execution_id"]

    after_first = _budget_snapshot(credential_ids)
    assert all(row[3:5] == (7_000, 0) or row[1] == "max_tool_calls" for row in after_first)
    assert sum(1 for row in after_first if row[1] == "max_tool_calls" and row[3] == 1) == 3

    retry = deepcopy(first)
    retry["request_id"] = f"{task_id}-ADMIT-RETRY"
    retry["holder_proof"]["payload"]["request_id"] = f"{task_id}-ADMIT-RETRY"
    retry["holder_proof"]["signature"] = sign_payload(
        retry["holder_proof"]["payload"],
        domain_separator=HOLDER_PROOF,
        key_id=HOLDER_KEY_ID,
        key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        private_key_hex=HOLDER_PRIVATE_KEY,
        public_key_hex=HOLDER_PUBLIC_KEY,
        signed_at=retry["issued_at"],
    )
    repeated = _admit(retry)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["execution_id"] == execution_id
    assert repeated.json()["admission_outcome"] == "EXISTING_EXECUTION"
    assert _budget_snapshot(credential_ids) == after_first

    conflict = _request(
        leaf,
        tool_service="refund-service",
        tool_name="refund.create",
        parameters={
            "ticket_id": business_test_case()["ticket_id"],
            "customer_id": "C9527",
            "amount_fen": 7_001,
        },
        business_action_id=str(primary["business_action_id"]),
        request_id=f"{task_id}-ADMIT-CONFLICT",
        credential_chain=chain,
    )
    conflicted = _admit(conflict)
    assert conflicted.status_code == 409
    conflict_body = conflicted.json()
    assert conflict_body["reason_code"] == "IDEMPOTENCY_CONFLICT"
    assert conflict_body["state"] == "DENIED"
    assert conflict_body["decision"] == "DENY"
    assert conflict_body["execution_id"] != execution_id
    assert conflict_body["receipt"]["payload"]["decision"] == "DENY"
    assert conflict_body["receipt"]["payload"]["request_id"] == conflict["request_id"]
    assert conflict_body["receipt"]["payload"]["business_effect_id"] is None
    assert _budget_snapshot(credential_ids) == after_first

    replay = _admit(first)
    assert replay.status_code == 403
    assert replay.json()["reason_code"] == "REPLAY_DETECTED"
    assert _budget_snapshot(credential_ids) == after_first

    read_request = _request(
        leaf,
        tool_service="ticket-service",
        tool_name="ticket.read",
        parameters={"ticket_id": business_test_case()["ticket_id"]},
        business_action_id=None,
        request_id=f"{task_id}-ADMIT-READ-001",
        credential_chain=chain,
    )
    read = _admit(read_request)
    assert read.status_code == 200, read.text
    assert read.json()["admission_outcome"] == "NEW_EXECUTION"
    after_read = _budget_snapshot(credential_ids)
    denied_call = _admit(
        _request(
            leaf,
            tool_service="ticket-service",
            tool_name="ticket.read",
            parameters={"ticket_id": business_test_case()["ticket_id"]},
            business_action_id=None,
            request_id=f"{task_id}-ADMIT-READ-002",
            credential_chain=chain,
        )
    )
    assert denied_call.status_code == 403
    assert denied_call.json()["reason_code"] == "BUDGET_EXCEEDED"
    assert _budget_snapshot(credential_ids) == after_read


def test_concurrent_distinct_business_actions_reserve_once_across_all_levels() -> None:
    leaf, chain, task_id, credential_ids = _leaf_chain()
    primary = _refund_action(task_id)
    second = _refund_action(task_id, second_slot=True)

    requests = [
        _request(
            leaf,
            tool_service="refund-service",
            tool_name="refund.create",
            parameters={
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "amount_fen": 6_000,
            },
            business_action_id=str(primary["business_action_id"]),
            request_id=f"{task_id}-ADMIT-CONCURRENT-001",
            credential_chain=chain,
        ),
        _request(
            leaf,
            tool_service="refund-service",
            tool_name="refund.create",
            parameters={
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "amount_fen": 6_000,
            },
            business_action_id=str(second["business_action_id"]),
            request_id=f"{task_id}-ADMIT-CONCURRENT-002",
            credential_chain=chain,
        ),
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(_admit, requests))
    assert sorted(response.status_code for response in responses) == [200, 403]
    allowed = [response for response in responses if response.status_code == 200]
    denied = [response for response in responses if response.status_code == 403]
    assert len(allowed) == 1
    assert denied[0].json()["reason_code"] == "BUDGET_EXCEEDED"

    snapshot = _budget_snapshot(credential_ids)
    assert sum(1 for row in snapshot if row[1] == "max_tool_calls" and row[3] == 1) == 3
    assert sum(1 for row in snapshot if row[1] == "refund_total_fen" and row[3] == 6_000) == 3
    assert all(row[3] + row[4] <= row[2] for row in snapshot)

    assert DATABASE_URL is not None
    with connect(DATABASE_URL) as connection:
        invariant = connection.execute(
            """
            SELECT count(*)
            FROM credential_budget_state
            WHERE reserved_value + committed_value > limit_value
            """
        ).fetchone()
    assert invariant == (0,)
