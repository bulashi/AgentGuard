from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from uuid import uuid4

import httpx
import psycopg
import pytest

from backend.common.enums import KeyPurpose
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex
from backend.identity.key_lifecycle import FilePrivateKeyStore, KeyManager
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect, psycopg_url
from backend.tests.business_fixtures import business_test_case
from backend.tests.integration.test_admission_postgres import (
    _admit,
    _leaf_chain,
    _request,
)

pytestmark = [pytest.mark.integration]

DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
AUTHORITY_URL = os.getenv("AGENTGUARD_AUTHORITY_URL")
REVOCATION_URL = os.getenv("AGENTGUARD_REVOCATION_URL")
HOLDER_PRIVATE_KEY_FILE = os.getenv("AGENTGUARD_HOLDER_PRIVATE_KEY_FILE")
if not all((DATABASE_URL, AUTHORITY_URL, REVOCATION_URL, HOLDER_PRIVATE_KEY_FILE)):
    pytest.skip("PostgreSQL revocation test environment is not active", allow_module_level=True)

HOLDER_KEY_ID = "agent-refund-key-01"
HOLDER_PRIVATE_KEY = Path(HOLDER_PRIVATE_KEY_FILE).read_text(encoding="ascii").strip()
HOLDER_PUBLIC_KEY = derive_public_key(HOLDER_PRIVATE_KEY)


def _revoke(credential_id: str, *, reason: str = "phase10-test") -> httpx.Response:
    assert REVOCATION_URL is not None
    with httpx.Client(base_url=REVOCATION_URL, timeout=15) as client:
        return client.post(
            f"/credentials/{credential_id}/revoke",
            headers={"X-AgentGuard-Internal": "revocation-authority"},
            json={"reason": reason, "revoked_by": "phase10-test-authority"},
        )


def test_root_intermediate_and_leaf_revocation_block_new_admission() -> None:
    for target_index in (0, 1, 2):
        leaf, chain, _task_id, _credential_ids = _leaf_chain()
        baseline = _admit(
            _request(
                leaf,
                tool_service="ticket-service",
                tool_name="ticket.read",
                parameters={"ticket_id": business_test_case()["ticket_id"]},
                business_action_id=None,
                request_id=f"REVOCATION-BASE-{uuid4().hex}",
                credential_chain=chain,
            )
        )
        assert baseline.status_code == 200, baseline.text

        target_id = str(chain[target_index]["payload"]["credential_id"])
        revoked = _revoke(target_id, reason=f"phase10-target-{target_index}")
        assert revoked.status_code == 200, revoked.text
        repeated = _revoke(target_id, reason=f"phase10-target-{target_index}")
        assert repeated.status_code == 200, repeated.text
        assert repeated.json() == revoked.json()

        blocked = _admit(
            _request(
                leaf,
                tool_service="ticket-service",
                tool_name="ticket.read",
                parameters={"ticket_id": business_test_case()["ticket_id"]},
                business_action_id=None,
                request_id=f"REVOCATION-BLOCKED-{uuid4().hex}",
                credential_chain=chain,
            )
        )
        assert blocked.status_code == 403, blocked.text
        expected_reason = "KEY_REVOKED" if target_index == 2 else "ANCESTOR_REVOKED"
        assert blocked.json()["reason_code"] == expected_reason


def _lock_credential(credential_id: str) -> psycopg.Connection:
    assert DATABASE_URL is not None
    connection = psycopg.connect(psycopg_url(DATABASE_URL))
    connection.execute("BEGIN")
    connection.execute(
        "SELECT credential_id FROM credentials WHERE credential_id = %s FOR UPDATE",
        (credential_id,),
    )
    return connection


def _start_admission(request: dict[str, object]) -> tuple[threading.Thread, list[httpx.Response]]:
    result: list[httpx.Response] = []
    thread = threading.Thread(target=lambda: result.append(_admit(request)), daemon=True)
    thread.start()
    time.sleep(0.25)
    return thread, result


def test_revocation_commit_before_admission_commit_denies_request() -> None:
    leaf, chain, _task_id, _credential_ids = _leaf_chain()
    request = _request(
        leaf,
        tool_service="ticket-service",
        tool_name="ticket.read",
        parameters={"ticket_id": business_test_case()["ticket_id"]},
        business_action_id=None,
        request_id=f"REVOCATION-RACE-DENY-{uuid4().hex}",
        credential_chain=chain,
    )
    root_id = str(chain[0]["payload"]["credential_id"])
    holder = _lock_credential(root_id)
    thread, result = _start_admission(request)
    holder.execute(
        """
        INSERT INTO credential_revocations (
            credential_id, revoked_at, revocation_reason, revoked_by
        )
        VALUES (%s, %s, %s, %s)
        """,
        (root_id, now_unix(), "phase10-race-before-admission", "phase10-race"),
    )
    holder.commit()
    holder.close()
    thread.join(timeout=15)
    assert not thread.is_alive()
    assert len(result) == 1
    assert result[0].status_code == 403, result[0].text
    assert result[0].json()["reason_code"] == "ANCESTOR_REVOKED"


def test_admission_commit_before_revocation_commit_is_allowed_then_future_request_denied() -> None:
    leaf, chain, _task_id, _credential_ids = _leaf_chain()
    request = _request(
        leaf,
        tool_service="ticket-service",
        tool_name="ticket.read",
        parameters={"ticket_id": business_test_case()["ticket_id"]},
        business_action_id=None,
        request_id=f"REVOCATION-RACE-ALLOW-{uuid4().hex}",
        credential_chain=chain,
    )
    root_id = str(chain[0]["payload"]["credential_id"])
    holder = _lock_credential(root_id)
    thread, result = _start_admission(request)
    holder.commit()
    holder.close()
    thread.join(timeout=15)
    assert not thread.is_alive()
    assert len(result) == 1
    assert result[0].status_code == 200, result[0].text
    assert result[0].json()["state"] == "ADMITTED"

    revoked = _revoke(root_id, reason="phase10-race-after-admission")
    assert revoked.status_code == 200, revoked.text
    future = _admit(
        _request(
            leaf,
            tool_service="ticket-service",
            tool_name="ticket.read",
            parameters={"ticket_id": business_test_case()["ticket_id"]},
            business_action_id=None,
            request_id=f"REVOCATION-RACE-FUTURE-{uuid4().hex}",
            credential_chain=chain,
        )
    )
    assert future.status_code == 403, future.text
    assert future.json()["reason_code"] == "ANCESTOR_REVOKED"


def _dynamic_root(
    tmp_path: Path,
    *,
    agent_suffix: str,
    key_suffix: str,
) -> tuple[dict[str, object], str, str, str, str]:
    assert DATABASE_URL is not None and AUTHORITY_URL is not None
    agent_id = f"phase10-agent-{agent_suffix}"
    key_id = f"phase10-key-{key_suffix}"
    private_store = FilePrivateKeyStore(tmp_path / agent_suffix)
    manager = KeyManager(PostgresKeyRegistry(DATABASE_URL), private_store)
    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            """
            INSERT INTO agent_identities (agent_id, display_name, agent_type, created_at)
            VALUES (%s, %s, 'PHASE10', %s)
            ON CONFLICT (agent_id) DO NOTHING
            """,
            (agent_id, agent_id, now_unix()),
        )
    record = manager.generate_and_register(
        key_id=key_id,
        subject_id=agent_id,
        subject_type="AGENT",
        purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        now=now_unix(),
    )
    with httpx.Client(base_url=AUTHORITY_URL, timeout=15) as client:
        created = client.post(
            "/tasks",
            json={
                "tenant_id": "tenant-A",
                "ticket_id": business_test_case()["ticket_id"],
                "customer_id": "C9527",
                "refund_total_fen": 10_000,
                "max_tool_calls": 3,
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
                "holder_agent_id": agent_id,
                "holder_key_id": key_id,
                "delegation_depth": 0,
            },
        )
    assert authorized.status_code == 201, authorized.text
    private_key = private_store.load(record.private_key_reference or f"{key_id}.private")
    return authorized.json(), agent_id, key_id, private_key, task_id


def _dynamic_ticket_request(
    credential: dict[str, object],
    *,
    agent_key_id: str,
    private_key: str,
    request_id: str,
) -> dict[str, object]:
    timestamp = now_unix()
    chain = [credential]
    chain_hash = sm3_hex(canonicalize(chain))
    parameters = {"ticket_id": business_test_case()["ticket_id"]}
    holder_payload = {
        "schema_version": "1.0",
        "credential_chain_hash": chain_hash,
        "task_id": credential["payload"]["task_id"],
        "tool_service": "ticket-service",
        "tool_name": "ticket.read",
        "tool_version": "v1",
        "canonical_parameter_hash": sm3_hex(canonicalize(parameters)),
        "request_id": request_id,
        "issued_at": timestamp,
        "business_action_id": None,
    }
    public_key = derive_public_key(private_key)
    signature = sign_payload(
        holder_payload,
        domain_separator=HOLDER_PROOF,
        key_id=agent_key_id,
        key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        private_key_hex=private_key,
        public_key_hex=public_key,
        signed_at=timestamp,
    )
    return {
        "schema_version": "1.0",
        "credential_chain": chain,
        "task_id": credential["payload"]["task_id"],
        "tool_service": "ticket-service",
        "tool_name": "ticket.read",
        "tool_version": "v1",
        "canonical_parameters": parameters,
        "request_id": request_id,
        "issued_at": timestamp,
        "holder_key_id": agent_key_id,
        "business_action_id": None,
        "holder_proof": {"payload": holder_payload, "signature": signature},
    }


@pytest.mark.parametrize(
    ("transition", "expected_reason"),
    (("revoke", "KEY_REVOKED"), ("compromise", "KEY_COMPROMISED")),
)
def test_holder_key_revoked_or_compromised_denies_new_admission(
    tmp_path: Path, transition: str, expected_reason: str
) -> None:
    credential, _agent_id, key_id, private_key, _task_id = _dynamic_root(
        tmp_path,
        agent_suffix=f"{transition}-{uuid4().hex[:8]}",
        key_suffix=f"{transition}-{uuid4().hex[:8]}",
    )
    assert DATABASE_URL is not None
    registry = PostgresKeyRegistry(DATABASE_URL)
    if transition == "revoke":
        registry.revoke(key_id, revoked_at=now_unix())
    else:
        registry.compromise(key_id, compromised_at=now_unix())
    blocked = _admit(
        _dynamic_ticket_request(
            credential,
            agent_key_id=key_id,
            private_key=private_key,
            request_id=f"KEY-STATUS-{transition}-{uuid4().hex}",
        )
    )
    assert blocked.status_code == 403, blocked.text
    assert blocked.json()["reason_code"] == expected_reason


def test_key_rotation_retires_old_signing_key_and_preserves_history(tmp_path: Path) -> None:
    assert DATABASE_URL is not None
    prefix = f"phase10-rotation-{uuid4().hex[:12]}"
    store = FilePrivateKeyStore(tmp_path / "rotation")
    registry = PostgresKeyRegistry(DATABASE_URL)
    manager = KeyManager(registry, store)
    base = 1_760_000_000
    old = manager.generate_and_register(
        key_id=f"{prefix}-old",
        subject_id=f"{prefix}-agent",
        subject_type="AGENT",
        purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        now=base,
    )
    payload = {"schema_version": "1.0", "request_id": prefix, "issued_at": base + 1}
    old_signature = manager.sign(
        payload,
        domain_separator=HOLDER_PROOF,
        key_id=old.key_id,
        expected_subject_id=old.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        signed_at=base + 1,
    )
    replacement = manager.rotate(
        old_key_id=old.key_id,
        new_key_id=f"{prefix}-replacement",
        now=base + 10,
    )
    with pytest.raises(KeyRegistryError):
        manager.sign(
            payload,
            domain_separator=HOLDER_PROOF,
            key_id=old.key_id,
            expected_subject_id=old.subject_id,
            expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            signed_at=base + 11,
        )
    manager.verify(
        payload,
        old_signature,
        domain_separator=HOLDER_PROOF,
        expected_subject_id=old.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        trusted_registered_at=base + 1,
    )
    replacement_signature = manager.sign(
        payload,
        domain_separator=HOLDER_PROOF,
        key_id=replacement.key_id,
        expected_subject_id=replacement.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        signed_at=base + 11,
    )
    manager.verify(
        payload,
        replacement_signature,
        domain_separator=HOLDER_PROOF,
        expected_subject_id=replacement.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
    )
    old_path = store.root / f"{old.key_id}.private"
    manager.destroy_private_material(old.key_id, destroyed_at=base + 20)
    assert not old_path.exists()
    manager.verify(
        payload,
        old_signature,
        domain_separator=HOLDER_PROOF,
        expected_subject_id=old.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        trusted_registered_at=base + 1,
    )

    with connect(DATABASE_URL) as connection, connection.transaction():
        connection.execute(
            "DELETE FROM key_registry WHERE key_id IN (%s, %s)",
            (old.key_id, replacement.key_id),
        )
