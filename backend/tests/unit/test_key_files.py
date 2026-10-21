from __future__ import annotations

from pathlib import Path

import pytest

from backend.crypto.sm import derive_public_key, generate_keypair, sign_message, verify_message
from backend.identity.key_lifecycle import FilePrivateKeyStore


def test_sm2_key_file_round_trip_and_signature(tmp_path: Path) -> None:
    store = FilePrivateKeyStore(tmp_path / "private")
    pair = generate_keypair()
    reference = store.write("round-trip-key", pair.private_key_hex)
    reloaded_private = store.load(reference)
    assert reloaded_private == pair.private_key_hex
    assert derive_public_key(reloaded_private) == pair.public_key_hex
    message = b"AgentGuard Phase 2 serialization test"
    signature = sign_message(
        message,
        private_key_hex=reloaded_private,
        public_key_hex=pair.public_key_hex,
    )
    assert verify_message(message, signature, public_key_hex=pair.public_key_hex)


def test_private_key_store_rejects_path_escape_and_overwrite(tmp_path: Path) -> None:
    store = FilePrivateKeyStore(tmp_path / "private")
    pair = generate_keypair()
    store.write("key-1", pair.private_key_hex)
    with pytest.raises(FileExistsError):
        store.write("key-1", pair.private_key_hex)
    with pytest.raises(ValueError):
        store.load("../outside.private")
