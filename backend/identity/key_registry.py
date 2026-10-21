from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import psycopg

from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.error_codes import ReasonCode
from backend.state.database import connect


class KeyRegistryError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    subject_id: str
    subject_type: str
    purpose: KeyPurpose
    public_key_hex: str
    status: KeyState
    material_state: KeyMaterialState
    private_key_reference: str | None
    activated_at: int
    created_at: int
    retired_at: int | None = None
    revoked_at: int | None = None
    compromised_at: int | None = None
    destroyed_at: int | None = None
    replaced_by: str | None = None
    algorithm: str = "SM2"


_SELECT_COLUMNS = """
    key_id,
    subject_id,
    subject_type,
    purpose,
    algorithm,
    public_key_hex,
    status,
    material_state,
    private_key_reference,
    activated_at,
    retired_at,
    revoked_at,
    compromised_at,
    destroyed_at,
    replaced_by,
    created_at
"""


def lock_key_identities(
    connection: psycopg.Connection,
    identities: Iterable[tuple[str, str]],
) -> None:
    # Both registries lock the entire ID/public-key set before checking or inserting.
    names = {
        name
        for key_id, public_key_hex in identities
        for name in (
            "agentguard:key-id:" + key_id,
            "agentguard:key-public:" + public_key_hex,
        )
    }
    for name in sorted(names):
        connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (name,))


def _record_from_row(row: tuple[object, ...]) -> KeyRecord:
    return KeyRecord(
        key_id=str(row[0]),
        subject_id=str(row[1]),
        subject_type=str(row[2]),
        purpose=KeyPurpose(str(row[3])),
        algorithm=str(row[4]),
        public_key_hex=str(row[5]),
        status=KeyState(str(row[6])),
        material_state=KeyMaterialState(str(row[7])),
        private_key_reference=None if row[8] is None else str(row[8]),
        activated_at=int(row[9]),
        retired_at=None if row[10] is None else int(row[10]),
        revoked_at=None if row[11] is None else int(row[11]),
        compromised_at=None if row[12] is None else int(row[12]),
        destroyed_at=None if row[13] is None else int(row[13]),
        replaced_by=None if row[14] is None else str(row[14]),
        created_at=int(row[15]),
    )


class PostgresKeyRegistry:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    @staticmethod
    def _fetch(connection: psycopg.Connection, key_id: str, *, lock: bool = False) -> KeyRecord:
        suffix = " FOR UPDATE" if lock else ""
        row = connection.execute(
            f"SELECT {_SELECT_COLUMNS} FROM key_registry WHERE key_id = %s{suffix}",
            (key_id,),
        ).fetchone()
        if row is None:
            raise KeyRegistryError(ReasonCode.UNKNOWN_KEY, f"unknown key: {key_id}")
        return _record_from_row(row)

    def get(self, key_id: str) -> KeyRecord:
        with connect(self.database_url) as connection:
            return self._fetch(connection, key_id)

    @classmethod
    def get_with_connection(
        cls,
        connection: psycopg.Connection,
        key_id: str,
        *,
        lock: bool = False,
    ) -> KeyRecord:
        """Read a key inside a caller-owned transaction, optionally locking its row."""
        return cls._fetch(connection, key_id, lock=lock)

    def register(self, record: KeyRecord) -> KeyRecord:
        invalid_public_key = (
            len(record.public_key_hex) != 128
            or record.public_key_hex.lower() != record.public_key_hex
        )
        if invalid_public_key:
            raise ValueError("SM2 public key must be 128 lowercase hexadecimal characters")
        if record.status is not KeyState.ACTIVE:
            raise ValueError("newly registered keys must be ACTIVE")
        if record.material_state is not KeyMaterialState.PRESENT:
            raise ValueError("newly registered keys must have PRESENT private material")
        with connect(self.database_url) as connection, connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            lock_key_identities(connection, ((record.key_id, record.public_key_hex),))
            if connection.execute("SELECT to_regclass('public.coauthorization_keys')").fetchone()[0] is not None:
                if connection.execute(
                    "SELECT 1 FROM public.coauthorization_keys WHERE key_id = %s OR public_key_hex = %s LIMIT 1",
                    (record.key_id, record.public_key_hex),
                ).fetchone() is not None:
                    raise ValueError("runtime key overlaps a coauthorization key")
            connection.execute(
                """
                INSERT INTO key_registry (
                    key_id,
                    subject_id,
                    subject_type,
                    purpose,
                    algorithm,
                    public_key_hex,
                    status,
                    material_state,
                    private_key_reference,
                    activated_at,
                    created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (key_id) DO NOTHING
                """,
                (
                    record.key_id,
                    record.subject_id,
                    record.subject_type,
                    record.purpose.value,
                    record.algorithm,
                    record.public_key_hex,
                    record.status.value,
                    record.material_state.value,
                    record.private_key_reference,
                    record.activated_at,
                    record.created_at,
                ),
            )
            stored = self._fetch(connection, record.key_id, lock=True)
            immutable_fields = (
                "subject_id",
                "subject_type",
                "purpose",
                "algorithm",
                "public_key_hex",
                "private_key_reference",
            )
            if any(getattr(stored, field) != getattr(record, field) for field in immutable_fields):
                raise ValueError(f"key_id already exists with different metadata: {record.key_id}")
            return stored

    def retire(self, key_id: str, replacement_key_id: str, *, retired_at: int) -> KeyRecord:
        if key_id == replacement_key_id:
            raise ValueError("a key cannot replace itself")
        with connect(self.database_url) as connection, connection.transaction():
            current = self._fetch(connection, key_id, lock=True)
            replacement = self._fetch(connection, replacement_key_id, lock=True)
            if current.status is not KeyState.ACTIVE:
                raise KeyRegistryError(
                    ReasonCode.KEY_RETIRED_FOR_SIGNING,
                    f"only ACTIVE keys can be retired: {key_id}",
                )
            if replacement.status is not KeyState.ACTIVE:
                raise ValueError("replacement key must be ACTIVE")
            if (current.subject_id, current.purpose) != (
                replacement.subject_id,
                replacement.purpose,
            ):
                raise ValueError("replacement key must have the same subject and purpose")
            if retired_at < current.activated_at or retired_at < replacement.activated_at:
                raise ValueError("retirement time precedes key activation")
            connection.execute(
                """
                UPDATE key_registry
                SET status = 'RETIRED', retired_at = %s, replaced_by = %s
                WHERE key_id = %s
                """,
                (retired_at, replacement_key_id, key_id),
            )
            return self._fetch(connection, key_id)

    def revoke(self, key_id: str, *, revoked_at: int) -> KeyRecord:
        with connect(self.database_url) as connection, connection.transaction():
            current = self._fetch(connection, key_id, lock=True)
            if current.status is KeyState.COMPROMISED:
                raise KeyRegistryError(
                    ReasonCode.KEY_COMPROMISED,
                    f"compromised key cannot transition to revoked: {key_id}",
                )
            if current.status is KeyState.REVOKED:
                return current
            if revoked_at < current.activated_at:
                raise ValueError("revocation time precedes key activation")
            connection.execute(
                """
                UPDATE key_registry
                SET status = 'REVOKED', revoked_at = %s
                WHERE key_id = %s
                """,
                (revoked_at, key_id),
            )
            return self._fetch(connection, key_id)

    def compromise(self, key_id: str, *, compromised_at: int) -> KeyRecord:
        with connect(self.database_url) as connection, connection.transaction():
            current = self._fetch(connection, key_id, lock=True)
            if current.status is KeyState.COMPROMISED:
                return current
            if compromised_at < current.activated_at:
                raise ValueError("compromise time precedes key activation")
            connection.execute(
                """
                UPDATE key_registry
                SET status = 'COMPROMISED', compromised_at = %s
                WHERE key_id = %s
                """,
                (compromised_at, key_id),
            )
            return self._fetch(connection, key_id)

    def mark_private_material_destroyed(self, key_id: str, *, destroyed_at: int) -> KeyRecord:
        with connect(self.database_url) as connection, connection.transaction():
            current = self._fetch(connection, key_id, lock=True)
            if current.status is KeyState.ACTIVE:
                raise ValueError("ACTIVE key material cannot be destroyed")
            if current.material_state is KeyMaterialState.DESTROYED:
                return current
            if destroyed_at < current.activated_at:
                raise ValueError("destruction time precedes key activation")
            connection.execute(
                """
                UPDATE key_registry
                SET material_state = 'DESTROYED', destroyed_at = %s,
                    private_key_reference = NULL
                WHERE key_id = %s
                """,
                (destroyed_at, key_id),
            )
            return self._fetch(connection, key_id)

    def resolve_for_signing(
        self,
        key_id: str,
        *,
        expected_subject_id: str,
        expected_purpose: KeyPurpose,
    ) -> KeyRecord:
        record = self.get(key_id)
        self._assert_identity(record, expected_subject_id, expected_purpose)
        self._assert_signing_allowed(record)
        return record

    @classmethod
    def resolve_for_signing_with_connection(
        cls,
        connection: psycopg.Connection,
        key_id: str,
        *,
        expected_subject_id: str,
        expected_purpose: KeyPurpose,
        lock: bool = False,
    ) -> KeyRecord:
        record = cls._fetch(connection, key_id, lock=lock)
        cls._assert_identity(record, expected_subject_id, expected_purpose)
        cls._assert_signing_allowed(record)
        return record

    @staticmethod
    def _assert_signing_allowed(record: KeyRecord) -> None:
        if record.status is KeyState.RETIRED:
            raise KeyRegistryError(ReasonCode.KEY_RETIRED_FOR_SIGNING, "retired key cannot sign")
        if record.status is KeyState.REVOKED:
            raise KeyRegistryError(ReasonCode.KEY_REVOKED, "revoked key cannot sign")
        if record.status is KeyState.COMPROMISED:
            raise KeyRegistryError(ReasonCode.KEY_COMPROMISED, "compromised key cannot sign")
        if record.material_state is not KeyMaterialState.PRESENT:
            raise KeyRegistryError(ReasonCode.UNKNOWN_KEY, "private key material is destroyed")

    def resolve_for_verification(
        self,
        key_id: str,
        *,
        expected_subject_id: str,
        expected_purpose: KeyPurpose,
        signed_at: int,
        trusted_registered_at: int | None = None,
    ) -> KeyRecord:
        record = self.get(key_id)
        self._assert_identity(record, expected_subject_id, expected_purpose)
        self._assert_verification_allowed(
            record,
            signed_at=signed_at,
            trusted_registered_at=trusted_registered_at,
        )
        return record

    @classmethod
    def resolve_for_verification_with_connection(
        cls,
        connection: psycopg.Connection,
        key_id: str,
        *,
        expected_subject_id: str,
        expected_purpose: KeyPurpose,
        signed_at: int,
        trusted_registered_at: int | None = None,
        lock: bool = False,
    ) -> KeyRecord:
        record = cls._fetch(connection, key_id, lock=lock)
        cls._assert_identity(record, expected_subject_id, expected_purpose)
        cls._assert_verification_allowed(
            record,
            signed_at=signed_at,
            trusted_registered_at=trusted_registered_at,
        )
        return record

    @staticmethod
    def _assert_verification_allowed(
        record: KeyRecord,
        *,
        signed_at: int,
        trusted_registered_at: int | None,
    ) -> None:
        if signed_at < record.activated_at:
            raise KeyRegistryError(ReasonCode.INVALID_SIGNATURE, "signature predates activation")
        if record.status is KeyState.REVOKED:
            raise KeyRegistryError(ReasonCode.KEY_REVOKED, "revoked key is not trusted")
        if record.status is KeyState.COMPROMISED:
            raise KeyRegistryError(ReasonCode.KEY_COMPROMISED, "compromised key is not trusted")
        if record.status is KeyState.RETIRED:
            if record.retired_at is None:
                raise RuntimeError("retired key is missing retired_at")
            if signed_at > record.retired_at:
                raise KeyRegistryError(
                    ReasonCode.KEY_RETIRED_FOR_SIGNING,
                    "signature claims to postdate retirement",
                )
            if trusted_registered_at is None or trusted_registered_at > record.retired_at:
                raise KeyRegistryError(
                    ReasonCode.KEY_RETIRED_FOR_SIGNING,
                    "retired-key verification requires trusted pre-retirement registration",
                )

    @staticmethod
    def _assert_identity(
        record: KeyRecord,
        expected_subject_id: str,
        expected_purpose: KeyPurpose,
    ) -> None:
        if record.subject_id != expected_subject_id:
            raise KeyRegistryError(ReasonCode.INVALID_SIGNATURE, "key subject mismatch")
        if record.purpose is not expected_purpose:
            raise KeyRegistryError(ReasonCode.INVALID_SIGNATURE, "key purpose mismatch")
        if record.algorithm != "SM2":
            raise KeyRegistryError(ReasonCode.INVALID_SIGNATURE, "key algorithm mismatch")
