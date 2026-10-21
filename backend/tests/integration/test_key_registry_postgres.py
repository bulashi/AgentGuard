from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest

from backend.common.enums import KeyPurpose, KeyState
from backend.common.error_codes import ReasonCode
from backend.crypto.domains import HOLDER_PROOF
from backend.identity.key_lifecycle import FilePrivateKeyStore, KeyManager
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect

pytestmark = [pytest.mark.integration]

if not os.getenv("AGENTGUARD_DATABASE_URL"):
    pytest.skip("PostgreSQL key registry test environment is not active", allow_module_level=True)


def test_postgres_key_registry_enforces_lifecycle_and_purpose(tmp_path: Path) -> None:
    database_url = os.environ["AGENTGUARD_DATABASE_URL"]
    prefix = f"phase2-{uuid4().hex[:12]}"
    registry = PostgresKeyRegistry(database_url)
    private_store = FilePrivateKeyStore(tmp_path / "private")
    manager = KeyManager(registry, private_store)
    now = 1_760_000_000
    payload = {"schema_version": "1.0", "request_id": prefix, "issued_at": now + 1}

    old = manager.generate_and_register(
        key_id=f"{prefix}-old",
        subject_id=f"{prefix}-agent",
        subject_type="AGENT",
        purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        now=now,
    )
    old_signature = manager.sign(
        payload,
        domain_separator=HOLDER_PROOF,
        key_id=old.key_id,
        expected_subject_id=old.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        signed_at=now + 1,
    )
    manager.verify(
        payload,
        old_signature,
        domain_separator=HOLDER_PROOF,
        expected_subject_id=old.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
    )

    with pytest.raises(KeyRegistryError) as wrong_purpose:
        manager.verify(
            payload,
            old_signature,
            domain_separator=HOLDER_PROOF,
            expected_subject_id=old.subject_id,
            expected_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
        )
    assert wrong_purpose.value.reason_code is ReasonCode.INVALID_SIGNATURE

    replacement = manager.generate_and_register(
        key_id=f"{prefix}-replacement",
        subject_id=old.subject_id,
        subject_type="AGENT",
        purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        now=now + 10,
    )
    retired = registry.retire(old.key_id, replacement.key_id, retired_at=now + 20)
    assert retired.status is KeyState.RETIRED
    assert retired.replaced_by == replacement.key_id

    with pytest.raises(KeyRegistryError) as retired_signing:
        manager.sign(
            payload,
            domain_separator=HOLDER_PROOF,
            key_id=old.key_id,
            expected_subject_id=old.subject_id,
            expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            signed_at=now + 21,
        )
    assert retired_signing.value.reason_code is ReasonCode.KEY_RETIRED_FOR_SIGNING

    with pytest.raises(KeyRegistryError) as unregistered_history:
        manager.verify(
            payload,
            old_signature,
            domain_separator=HOLDER_PROOF,
            expected_subject_id=old.subject_id,
            expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        )
    assert unregistered_history.value.reason_code is ReasonCode.KEY_RETIRED_FOR_SIGNING

    manager.verify(
        payload,
        old_signature,
        domain_separator=HOLDER_PROOF,
        expected_subject_id=old.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        trusted_registered_at=now + 2,
    )

    old_private_path = private_store.root / f"{old.key_id}.private"
    assert old_private_path.is_file()
    destroyed = manager.destroy_private_material(old.key_id, destroyed_at=now + 30)
    assert not old_private_path.exists()
    assert destroyed.private_key_reference is None
    assert destroyed.material_state.value == "DESTROYED"
    manager.verify(
        payload,
        old_signature,
        domain_separator=HOLDER_PROOF,
        expected_subject_id=old.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        trusted_registered_at=now + 2,
    )

    replacement_signature = manager.sign(
        payload,
        domain_separator=HOLDER_PROOF,
        key_id=replacement.key_id,
        expected_subject_id=replacement.subject_id,
        expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        signed_at=now + 21,
    )
    registry.revoke(replacement.key_id, revoked_at=now + 22)
    with pytest.raises(KeyRegistryError) as revoked:
        manager.verify(
            payload,
            replacement_signature,
            domain_separator=HOLDER_PROOF,
            expected_subject_id=replacement.subject_id,
            expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        )
    assert revoked.value.reason_code is ReasonCode.KEY_REVOKED

    compromised = manager.generate_and_register(
        key_id=f"{prefix}-compromised",
        subject_id=old.subject_id,
        subject_type="AGENT",
        purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        now=now,
    )
    registry.compromise(compromised.key_id, compromised_at=now + 5)
    with pytest.raises(KeyRegistryError) as compromised_signing:
        manager.sign(
            payload,
            domain_separator=HOLDER_PROOF,
            key_id=compromised.key_id,
            expected_subject_id=compromised.subject_id,
            expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            signed_at=now + 6,
        )
    assert compromised_signing.value.reason_code is ReasonCode.KEY_COMPROMISED

    with pytest.raises(KeyRegistryError) as unknown:
        registry.get(f"{prefix}-missing")
    assert unknown.value.reason_code is ReasonCode.UNKNOWN_KEY

    with connect(database_url) as connection, connection.transaction():
        columns = {
            row[0]
            for row in connection.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'key_registry'
                """
            ).fetchall()
        }
        assert "private_key_hex" not in columns
        assert "private_key" not in columns
        connection.execute("DELETE FROM key_registry WHERE key_id LIKE %s", (f"{prefix}%",))
