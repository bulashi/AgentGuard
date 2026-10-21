from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from backend.audit.service import AuditService
from backend.common.enums import KeyPurpose
from backend.crypto.domains import AUDIT_CHECKPOINT
from backend.crypto.sm import generate_keypair, sign_payload
from backend.identity.key_registry import PostgresKeyRegistry


@pytest.fixture
def signed_anchors(monkeypatch: pytest.MonkeyPatch):
    pair = generate_keypair()
    key = SimpleNamespace(
        key_id="audit-key-test",
        purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
        public_key_hex=pair.public_key_hex,
    )

    @contextmanager
    def fake_connect(url: str):
        del url
        yield object()

    monkeypatch.setattr("backend.audit.service.connect", fake_connect)
    monkeypatch.setattr(
        PostgresKeyRegistry,
        "resolve_for_verification_with_connection",
        lambda connection, key_id, **kwargs: key,
    )

    def make_anchor(checkpoint_sequence: int, event_sequence: int, event_hash: str):
        payload = {
            "schema_version": "1.0",
            "checkpoint_sequence": checkpoint_sequence,
            "latest_event_sequence": event_sequence,
            "latest_event_hash": event_hash,
            "timestamp": 100,
        }
        signature = sign_payload(
            payload,
            domain_separator=AUDIT_CHECKPOINT,
            key_id=key.key_id,
            key_purpose=key.purpose,
            private_key_hex=pair.private_key_hex,
            public_key_hex=pair.public_key_hex,
            signed_at=100,
        )
        return (checkpoint_sequence, event_sequence, event_hash, {"payload": payload, "signature": signature})

    return make_anchor


def test_checkpoint_binds_prefix_after_chain_growth(signed_anchors) -> None:
    anchor = signed_anchors(1, 1, "1" * 64)
    service = AuditService("unused", audit_database_url="unused")
    assert service._verify_checkpoint(
        2, "2" * 64,
        event_hashes={1: "1" * 64, 2: "2" * 64}, checkpoints=[anchor],
    ) == (True, False)


@pytest.mark.parametrize("covered", [{}, {1: "3" * 64}])
def test_missing_or_changed_covered_event_is_rejected(signed_anchors, covered) -> None:
    anchor = signed_anchors(1, 1, "1" * 64)
    service = AuditService("unused", audit_database_url="unused")
    assert service._verify_checkpoint(
        2, "2" * 64, event_hashes=covered, checkpoints=[anchor],
    ) == (False, True)


def test_new_anchor_does_not_erase_old_independent_anchor(signed_anchors) -> None:
    anchors = [signed_anchors(1, 1, "1" * 64), signed_anchors(2, 2, "2" * 64)]
    service = AuditService("unused", audit_database_url="unused")
    assert service._verify_checkpoint(
        2, "2" * 64,
        event_hashes={1: "3" * 64, 2: "2" * 64}, checkpoints=anchors,
    ) == (False, True)
