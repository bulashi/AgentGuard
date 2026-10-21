from __future__ import annotations

import os
import time
from copy import deepcopy

import httpx
import pytest
from psycopg.types.json import Jsonb

from backend.common.enums import KeyPurpose
from backend.crypto.domains import DELEGATION_CREDENTIAL
from backend.crypto.sm import signed_object_hash, verify_payload
from backend.delegation.verifier import ChainVerificationError, CredentialChainVerifier
from backend.identity.key_registry import PostgresKeyRegistry
from backend.state.database import connect
from backend.tests.business_fixtures import business_test_case

pytestmark = [pytest.mark.integration]

DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")
COORDINATOR_URL = os.getenv("AGENTGUARD_COORDINATOR_DELEGATION_URL")
CASE_URL = os.getenv("AGENTGUARD_CASE_DELEGATION_URL")
REFUND_URL = os.getenv("AGENTGUARD_REFUND_DELEGATION_URL")
if not all((DATABASE_URL, AUTHORITY_URL, COORDINATOR_URL, CASE_URL, REFUND_URL)):
    pytest.skip("PostgreSQL delegation test environment is not active", allow_module_level=True)


def _create_root() -> dict[str, object]:
    assert AUTHORITY_URL is not None
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
        authorized = client.post(
            f"/tasks/{created.json()['task_id']}/authorize",
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
    expires_before_parent: int,
) -> httpx.Response:
    payload = parent["payload"]
    assert isinstance(payload, dict)
    with httpx.Client(base_url=base_url, timeout=10) as client:
        return client.post(
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
                "expires_at": payload["expires_at"] - expires_before_parent,
            },
        )


def test_two_level_delegation_is_signed_attenuated_bound_and_persisted() -> None:
    assert DATABASE_URL is not None
    assert COORDINATOR_URL is not None
    assert CASE_URL is not None
    assert REFUND_URL is not None
    root = _create_root()
    root_payload = root["payload"]
    assert isinstance(root_payload, dict)

    knowledge_response = _delegate(
        COORDINATOR_URL,
        root,
        holder_agent_id="agent-knowledge",
        holder_key_id="agent-knowledge-key-01",
        capabilities=[_capability(root, "knowledge.read_associated")],
        refund_total_fen=0,
        max_tool_calls=5,
        expires_before_parent=600,
    )
    assert knowledge_response.status_code == 201, knowledge_response.text
    knowledge = knowledge_response.json()

    refund_capability = _capability(root, "refund.create")
    refund_capability["constraints"]["single_max_fen"] = 15_000
    case_response = _delegate(
        COORDINATOR_URL,
        root,
        holder_agent_id="agent-case",
        holder_key_id="agent-case-key-01",
        capabilities=[
            _capability(root, "ticket.read"),
            refund_capability,
            _capability(root, "notification.send_template"),
        ],
        refund_total_fen=30_000,
        max_tool_calls=10,
        expires_before_parent=300,
    )
    assert case_response.status_code == 201, case_response.text
    case = case_response.json()

    grandchild_capability = _capability(case, "refund.create")
    grandchild_capability["constraints"]["single_max_fen"] = 10_000
    refund_response = _delegate(
        CASE_URL,
        case,
        holder_agent_id="agent-refund",
        holder_key_id="agent-refund-key-01",
        capabilities=[grandchild_capability],
        refund_total_fen=20_000,
        max_tool_calls=3,
        expires_before_parent=100,
    )
    assert refund_response.status_code == 201, refund_response.text
    refund = refund_response.json()

    assert [
        root_payload["delegation_depth"],
        case["payload"]["delegation_depth"],
        refund["payload"]["delegation_depth"],
    ] == [2, 1, 0]
    assert knowledge["payload"]["issuer"] == {
        "subject_id": root_payload["holder"]["agent_id"],
        "key_id": root_payload["holder"]["key_id"],
    }
    assert case["payload"]["issuer"] == {
        "subject_id": root_payload["holder"]["agent_id"],
        "key_id": root_payload["holder"]["key_id"],
    }
    assert refund["payload"]["issuer"] == {
        "subject_id": case["payload"]["holder"]["agent_id"],
        "key_id": case["payload"]["holder"]["key_id"],
    }
    assert case["payload"]["parent_credential_id"] == root_payload["credential_id"]
    assert case["payload"]["parent_credential_hash"] == signed_object_hash(root)
    assert refund["payload"]["parent_credential_hash"] == signed_object_hash(case)

    registry = PostgresKeyRegistry(DATABASE_URL)
    coordinator_key = registry.get("agent-coordinator-key-01")
    case_key = registry.get("agent-case-key-01")
    assert verify_payload(
        case["payload"],
        case["signature"],
        domain_separator=DELEGATION_CREDENTIAL,
        expected_key_id=coordinator_key.key_id,
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=coordinator_key.public_key_hex,
    )
    assert verify_payload(
        refund["payload"],
        refund["signature"],
        domain_separator=DELEGATION_CREDENTIAL,
        expected_key_id=case_key.key_id,
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=case_key.public_key_hex,
    )

    verifier = CredentialChainVerifier(DATABASE_URL)
    chain = verifier.verify_chain(refund["payload"]["credential_id"], current_time=int(time.time()))
    assert [item["payload"]["credential_id"] for item in chain] == [
        root_payload["credential_id"],
        case["payload"]["credential_id"],
        refund["payload"]["credential_id"],
    ]

    wrong_holder = _delegate(
        CASE_URL,
        root,
        holder_agent_id="agent-refund",
        holder_key_id="agent-refund-key-01",
        capabilities=[_capability(root, "refund.create")],
        refund_total_fen=10_000,
        max_tool_calls=1,
        expires_before_parent=700,
    )
    assert wrong_holder.status_code == 403
    assert wrong_holder.json()["reason_code"] == "WRONG_HOLDER"

    depth_zero = _delegate(
        REFUND_URL,
        refund,
        holder_agent_id="agent-knowledge",
        holder_key_id="agent-knowledge-key-01",
        capabilities=[_capability(refund, "refund.create")],
        refund_total_fen=1_000,
        max_tool_calls=1,
        expires_before_parent=1,
    )
    assert depth_zero.status_code == 403
    assert depth_zero.json()["reason_code"] == "DELEGATION_ESCALATION"

    with connect(DATABASE_URL) as connection:
        rows = connection.execute(
            """
            SELECT credential_id, parent_credential_id, parent_credential_hash,
                   signed_object_hash,
                   (SELECT count(*) FROM credential_budget_state AS budget
                    WHERE budget.credential_id = credential.credential_id)
            FROM credentials AS credential
            WHERE credential_id = ANY(%s)
            ORDER BY delegation_depth DESC
            """,
            (
                [
                    knowledge["payload"]["credential_id"],
                    case["payload"]["credential_id"],
                    refund["payload"]["credential_id"],
                ],
            ),
        ).fetchall()
    assert len(rows) == 3
    assert all(row[4] == 2 for row in rows)
    assert all(row[2] is not None and row[3] is not None for row in rows)


def test_escalation_and_parent_substitution_are_rejected_without_partial_state() -> None:
    assert DATABASE_URL is not None
    assert COORDINATOR_URL is not None
    assert CASE_URL is not None
    root = _create_root()
    root_payload = root["payload"]
    assert isinstance(root_payload, dict)
    base_refund = _capability(root, "refund.create")

    attacks: list[dict[str, object]] = []
    added_service = deepcopy(base_refund)
    added_service["service"] = "admin-service"
    attacks.append({"capabilities": [added_service]})
    outside_resource = deepcopy(base_refund)
    outside_resource["resources"]["customer_ids"] = ["attacker"]
    attacks.append({"capabilities": [outside_resource]})
    raised_amount = deepcopy(base_refund)
    raised_amount["constraints"]["single_max_fen"] = 20_001
    attacks.append({"capabilities": [raised_amount]})
    attacks.append({"refund_total_fen": 50_001})
    attacks.append({"max_tool_calls": 21})
    attacks.append({"expires_at": root_payload["expires_at"] + 1})

    with connect(DATABASE_URL) as connection:
        before = connection.execute(
            "SELECT count(*) FROM credentials WHERE task_id = %s",
            (root_payload["task_id"],),
        ).fetchone()[0]
    for attack in attacks:
        body = {
            "holder_agent_id": "agent-case",
            "holder_key_id": "agent-case-key-01",
            "capabilities": [base_refund],
            "quotas": {"refund_total_fen": 30_000, "max_tool_calls": 10},
            "not_before": root_payload["not_before"],
            "expires_at": root_payload["expires_at"] - 100,
        }
        if "refund_total_fen" in attack:
            body["quotas"]["refund_total_fen"] = attack["refund_total_fen"]
        elif "max_tool_calls" in attack:
            body["quotas"]["max_tool_calls"] = attack["max_tool_calls"]
        else:
            body.update(attack)
        with httpx.Client(base_url=COORDINATOR_URL, timeout=10) as client:
            response = client.post(
                f"/credentials/{root_payload['credential_id']}/delegate", json=body
            )
        assert response.status_code == 403, response.text
        assert response.json()["reason_code"] == "DELEGATION_ESCALATION"
    with connect(DATABASE_URL) as connection:
        after = connection.execute(
            "SELECT count(*) FROM credentials WHERE task_id = %s",
            (root_payload["task_id"],),
        ).fetchone()[0]
    assert after == before

    case_response = _delegate(
        COORDINATOR_URL,
        root,
        holder_agent_id="agent-case",
        holder_key_id="agent-case-key-01",
        capabilities=[base_refund],
        refund_total_fen=30_000,
        max_tool_calls=10,
        expires_before_parent=100,
    )
    assert case_response.status_code == 201
    case = case_response.json()
    refund_capability = _capability(case, "refund.create")
    refund_response = _delegate(
        CASE_URL,
        case,
        holder_agent_id="agent-refund",
        holder_key_id="agent-refund-key-01",
        capabilities=[refund_capability],
        refund_total_fen=20_000,
        max_tool_calls=3,
        expires_before_parent=10,
    )
    assert refund_response.status_code == 201
    refund = refund_response.json()

    original_hash = signed_object_hash(case)
    substituted = deepcopy(case)
    value = substituted["signature"]["value"]
    substituted["signature"]["value"] = ("0" if value[0] != "0" else "1") + value[1:]
    substituted_hash = signed_object_hash(substituted)
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            "UPDATE credentials SET signed_object = %s, signed_object_hash = %s "
            "WHERE credential_id = %s",
            (Jsonb(substituted), substituted_hash, case["payload"]["credential_id"]),
        )
    verifier = CredentialChainVerifier(DATABASE_URL)
    with pytest.raises(ChainVerificationError, match="parent signed-object hash"):
        verifier.verify_chain(refund["payload"]["credential_id"], current_time=int(time.time()))
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            "UPDATE credentials SET signed_object = %s, signed_object_hash = %s "
            "WHERE credential_id = %s",
            (Jsonb(case), original_hash, case["payload"]["credential_id"]),
        )
    assert (
        len(
            verifier.verify_chain(refund["payload"]["credential_id"], current_time=int(time.time()))
        )
        == 3
    )
