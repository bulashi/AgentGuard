from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.error_codes import ReasonCode
from backend.crypto.sm import (
    derive_public_key,
    generate_keypair,
    sign_payload,
    verify_payload,
)
from backend.identity.key_registry import KeyRecord, KeyRegistryError, PostgresKeyRegistry


class FilePrivateKeyStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, reference: str) -> Path:
        path = (self.root / reference).resolve()
        if path.parent != self.root:
            raise ValueError("private key reference escapes the configured key directory")
        return path

    def write(self, key_id: str, private_key_hex: str) -> str:
        reference = f"{key_id}.private"
        path = self._path(reference)
        if path.exists():
            raise FileExistsError(path)
        temporary = path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
                handle.write(private_key_hex)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return reference

    def load(self, reference: str) -> str:
        value = self._path(reference).read_text(encoding="ascii").strip()
        if len(value) != 64 or value.lower() != value:
            raise ValueError("stored SM2 private key has invalid encoding")
        return value

    def destroy(self, reference: str) -> None:
        self._path(reference).unlink(missing_ok=False)


class KeyManager:
    def __init__(self, registry: PostgresKeyRegistry, private_keys: FilePrivateKeyStore) -> None:
        self.registry = registry
        self.private_keys = private_keys

    def generate_and_register(
        self,
        *,
        key_id: str,
        subject_id: str,
        subject_type: str,
        purpose: KeyPurpose,
        now: int,
    ) -> KeyRecord:
        pair = generate_keypair()
        reference = self.private_keys.write(key_id, pair.private_key_hex)
        try:
            return self.registry.register(
                KeyRecord(
                    key_id=key_id,
                    subject_id=subject_id,
                    subject_type=subject_type,
                    purpose=purpose,
                    public_key_hex=pair.public_key_hex,
                    status=KeyState.ACTIVE,
                    material_state=KeyMaterialState.PRESENT,
                    private_key_reference=reference,
                    activated_at=now,
                    created_at=now,
                )
            )
        except Exception:
            self.private_keys.destroy(reference)
            raise

    def sign(
        self,
        payload: Any,
        *,
        domain_separator: str,
        key_id: str,
        expected_subject_id: str,
        expected_purpose: KeyPurpose,
        signed_at: int,
        random_hex: str | None = None,
    ) -> dict[str, Any]:
        record = self.registry.resolve_for_signing(
            key_id,
            expected_subject_id=expected_subject_id,
            expected_purpose=expected_purpose,
        )
        if record.private_key_reference is None:
            raise KeyRegistryError(ReasonCode.UNKNOWN_KEY, "private key reference is absent")
        private_key = self.private_keys.load(record.private_key_reference)
        if derive_public_key(private_key) != record.public_key_hex:
            raise KeyRegistryError(ReasonCode.INVALID_SIGNATURE, "private/public key mismatch")
        return sign_payload(
            payload,
            domain_separator=domain_separator,
            key_id=record.key_id,
            key_purpose=record.purpose,
            private_key_hex=private_key,
            public_key_hex=record.public_key_hex,
            signed_at=signed_at,
            random_hex=random_hex,
        )

    def rotate(
        self,
        *,
        old_key_id: str,
        new_key_id: str,
        now: int,
    ) -> KeyRecord:
        """Create a same-purpose replacement and retire the old signing key."""
        old = self.registry.get(old_key_id)
        replacement = self.generate_and_register(
            key_id=new_key_id,
            subject_id=old.subject_id,
            subject_type=old.subject_type,
            purpose=old.purpose,
            now=now,
        )
        try:
            self.registry.retire(old_key_id, replacement.key_id, retired_at=now)
        except Exception:
            self.private_keys.destroy(replacement.private_key_reference or f"{new_key_id}.private")
            raise
        return replacement

    def verify(
        self,
        payload: Any,
        signature: dict[str, Any],
        *,
        domain_separator: str,
        expected_subject_id: str,
        expected_purpose: KeyPurpose,
        trusted_registered_at: int | None = None,
    ) -> KeyRecord:
        key_id = signature.get("key_id")
        signed_at = signature.get("signed_at")
        if not isinstance(key_id, str) or not isinstance(signed_at, int):
            raise KeyRegistryError(ReasonCode.INVALID_SIGNATURE, "signature metadata is invalid")
        record = self.registry.resolve_for_verification(
            key_id,
            expected_subject_id=expected_subject_id,
            expected_purpose=expected_purpose,
            signed_at=signed_at,
            trusted_registered_at=trusted_registered_at,
        )
        if not verify_payload(
            payload,
            signature,
            domain_separator=domain_separator,
            expected_key_id=record.key_id,
            expected_key_purpose=record.purpose,
            public_key_hex=record.public_key_hex,
        ):
            raise KeyRegistryError(
                ReasonCode.INVALID_SIGNATURE,
                "SM2 signature verification failed",
            )
        return record

    def destroy_private_material(self, key_id: str, *, destroyed_at: int) -> KeyRecord:
        record = self.registry.get(key_id)
        if record.status is KeyState.ACTIVE:
            raise ValueError("ACTIVE key material cannot be destroyed")
        if record.material_state is KeyMaterialState.DESTROYED:
            return record
        if record.private_key_reference is None:
            raise RuntimeError("PRESENT private material is missing its reference")
        self.private_keys.destroy(record.private_key_reference)
        return self.registry.mark_private_material_destroyed(key_id, destroyed_at=destroyed_at)
