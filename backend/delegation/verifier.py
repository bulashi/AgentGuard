from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import psycopg
from jsonschema import ValidationError

from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.schema import SchemaStore
from backend.crypto.domains import CAPABILITY_CREDENTIAL, DELEGATION_CREDENTIAL
from backend.crypto.sm import signed_object_hash, verify_payload
from backend.delegation.attenuation import AttenuationError, assert_monotonic_attenuation
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect


class ChainVerificationError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class StoredCredential:
    credential_id: str
    credential_type: str
    parent_credential_id: str | None
    parent_credential_hash: str | None
    stored_hash: str
    signed_object: dict[str, Any]
    issuer_subject_id: str
    issuer_key_id: str
    holder_agent_id: str
    holder_key_id: str
    tenant_id: str
    task_id: str
    verifier_audience: str
    not_before: int
    expires_at: int
    delegation_depth: int
    issued_at: int
    created_at: int


_CREDENTIAL_COLUMNS = """
    credential_id, credential_type, parent_credential_id, parent_credential_hash,
    signed_object_hash, signed_object, issuer_subject_id, issuer_key_id,
    holder_agent_id, holder_key_id, tenant_id, task_id, verifier_audience,
    not_before, expires_at, delegation_depth, issued_at, created_at
"""


def _from_row(row: tuple[object, ...]) -> StoredCredential:
    return StoredCredential(
        credential_id=str(row[0]),
        credential_type=str(row[1]),
        parent_credential_id=None if row[2] is None else str(row[2]),
        parent_credential_hash=None if row[3] is None else str(row[3]),
        stored_hash=str(row[4]),
        signed_object=dict(row[5]),
        issuer_subject_id=str(row[6]),
        issuer_key_id=str(row[7]),
        holder_agent_id=str(row[8]),
        holder_key_id=str(row[9]),
        tenant_id=str(row[10]),
        task_id=str(row[11]),
        verifier_audience=str(row[12]),
        not_before=int(row[13]),
        expires_at=int(row[14]),
        delegation_depth=int(row[15]),
        issued_at=int(row[16]),
        created_at=int(row[17]),
    )


class CredentialChainVerifier:
    def __init__(
        self, database_url: str, schema_store: SchemaStore | None = None
    ) -> None:
        self.database_url = database_url
        self.schemas = schema_store or SchemaStore()

    def verify_chain(self, leaf_credential_id: str, *, current_time: int) -> list[dict[str, Any]]:
        with connect(self.database_url) as connection:
            return self.verify_chain_with_connection(
                connection,
                leaf_credential_id,
                current_time=current_time,
                lock=False,
            )

    def verify_chain_with_connection(
        self,
        connection: psycopg.Connection,
        leaf_credential_id: str,
        *,
        current_time: int,
        lock: bool,
    ) -> list[dict[str, Any]]:
        chain = self._load_chain(connection, leaf_credential_id, lock=lock)
        if lock:
            # Keep the verified key lifecycle stable through the caller's transaction.
            for key_id in sorted({
                key_id for item in chain for key_id in (item.issuer_key_id, item.holder_key_id)
            }):
                try:
                    PostgresKeyRegistry.get_with_connection(connection, key_id, lock=True)
                except KeyRegistryError as exc:
                    raise ChainVerificationError(exc.reason_code, str(exc)) from exc
        self._verify_structure_and_links(connection, chain, current_time=current_time)
        self._verify_signatures(connection, chain)
        return [item.signed_object for item in chain]

    @staticmethod
    def _load_chain(
        connection: psycopg.Connection, leaf_credential_id: str, *, lock: bool
    ) -> list[StoredCredential]:
        reversed_chain: list[StoredCredential] = []
        seen: set[str] = set()
        current_id: str | None = leaf_credential_id
        suffix = " FOR UPDATE" if lock else ""
        while current_id is not None:
            if current_id in seen or len(reversed_chain) >= 17:
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE, "credential chain is cyclic or too deep"
                )
            seen.add(current_id)
            row = connection.execute(
                f"SELECT {_CREDENTIAL_COLUMNS} FROM credentials "
                f"WHERE credential_id = %s{suffix}",
                (current_id,),
            ).fetchone()
            if row is None:
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE, "credential chain references a missing parent"
                )
            item = _from_row(row)
            reversed_chain.append(item)
            current_id = item.parent_credential_id
        chain = list(reversed(reversed_chain))
        if not chain or chain[0].credential_type != "ROOT":
            raise ChainVerificationError(
                ReasonCode.INVALID_SIGNATURE, "credential chain does not terminate at a root"
            )
        return chain

    def _verify_structure_and_links(
        self,
        connection: psycopg.Connection,
        chain: list[StoredCredential],
        *,
        current_time: int,
    ) -> None:
        for index, item in enumerate(chain):
            schema = (
                "capability-credential.schema.json"
                if item.credential_type == "ROOT"
                else "delegation-credential.schema.json"
            )
            try:
                self.schemas.validate(schema, item.signed_object)
            except ValidationError as exc:
                raise ChainVerificationError(
                    ReasonCode.REQUEST_SCHEMA_INVALID,
                    "stored credential violates its frozen schema",
                ) from exc
            payload = item.signed_object["payload"]
            signature = item.signed_object["signature"]
            expected_columns = {
                "credential_id": item.credential_id,
                "credential_type": item.credential_type,
                "parent_credential_id": item.parent_credential_id,
                "parent_credential_hash": item.parent_credential_hash,
                "tenant_id": item.tenant_id,
                "task_id": item.task_id,
                "verifier_audience": item.verifier_audience,
                "not_before": item.not_before,
                "expires_at": item.expires_at,
                "delegation_depth": item.delegation_depth,
                "issued_at": item.issued_at,
            }
            if any(payload[field] != value for field, value in expected_columns.items()):
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE,
                    "credential payload and trusted index columns disagree",
                )
            if payload["issuer"] != {
                "subject_id": item.issuer_subject_id,
                "key_id": item.issuer_key_id,
            } or payload["holder"] != {
                "agent_id": item.holder_agent_id,
                "key_id": item.holder_key_id,
            }:
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE, "credential identity index mismatch"
                )
            if signature["signed_at"] != payload["issued_at"]:
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE,
                    "signature time must equal credential issued_at",
                )
            if signed_object_hash(item.signed_object) != item.stored_hash:
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE, "stored signed-object hash mismatch"
                )
            revoked = connection.execute(
                "SELECT 1 FROM credential_revocations WHERE credential_id = %s",
                (item.credential_id,),
            ).fetchone()
            if revoked is not None:
                reason = (
                    ReasonCode.ANCESTOR_REVOKED
                    if index < len(chain) - 1
                    else ReasonCode.KEY_REVOKED
                )
                raise ChainVerificationError(reason, "credential chain contains a revocation")
            if not item.not_before <= current_time <= item.expires_at:
                raise ChainVerificationError(
                    ReasonCode.CREDENTIAL_EXPIRED,
                    "credential is not valid at the verifier time",
                )

            holder_key = PostgresKeyRegistry.get_with_connection(
                connection, item.holder_key_id, lock=False
            )
            if (
                holder_key.subject_id != item.holder_agent_id
                or holder_key.subject_type != "AGENT"
                or holder_key.purpose is not KeyPurpose.AGENT_HOLDER_SIGNING
                or holder_key.algorithm != "SM2"
            ):
                raise ChainVerificationError(
                    ReasonCode.WRONG_HOLDER, "credential holder key binding is invalid"
                )

            if index == 0:
                if item.parent_credential_id is not None or item.parent_credential_hash is not None:
                    raise ChainVerificationError(
                        ReasonCode.INVALID_SIGNATURE, "root credential has a parent"
                    )
                continue
            parent = chain[index - 1]
            if item.parent_credential_id != parent.credential_id:
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE, "parent credential ID binding mismatch"
                )
            if item.parent_credential_hash != parent.stored_hash:
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE,
                    "parent signed-object hash binding mismatch",
                )
            if payload["issuer"] != {
                "subject_id": parent.holder_agent_id,
                "key_id": parent.holder_key_id,
            }:
                raise ChainVerificationError(
                    ReasonCode.WRONG_HOLDER, "child issuer is not the parent holder"
                )
            try:
                assert_monotonic_attenuation(parent.signed_object["payload"], payload)
            except AttenuationError as exc:
                raise ChainVerificationError(exc.reason_code, str(exc)) from exc

    @staticmethod
    def _verify_signatures(
        connection: psycopg.Connection, chain: list[StoredCredential]
    ) -> None:
        for item in chain:
            payload = item.signed_object["payload"]
            signature = item.signed_object["signature"]
            if item.credential_type == "ROOT":
                purpose = KeyPurpose.AUTHORIZATION_ROOT_SIGNING
                domain = CAPABILITY_CREDENTIAL
            else:
                purpose = KeyPurpose.AGENT_HOLDER_SIGNING
                domain = DELEGATION_CREDENTIAL
            try:
                key = PostgresKeyRegistry.resolve_for_verification_with_connection(
                    connection,
                    item.issuer_key_id,
                    expected_subject_id=item.issuer_subject_id,
                    expected_purpose=purpose,
                    signed_at=signature["signed_at"],
                    trusted_registered_at=item.created_at,
                    lock=False,
                )
            except KeyRegistryError as exc:
                raise ChainVerificationError(exc.reason_code, str(exc)) from exc
            if not verify_payload(
                payload,
                signature,
                domain_separator=domain,
                expected_key_id=key.key_id,
                expected_key_purpose=purpose,
                public_key_hex=key.public_key_hex,
            ):
                raise ChainVerificationError(
                    ReasonCode.INVALID_SIGNATURE, "credential signature verification failed"
                )
