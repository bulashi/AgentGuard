from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import ValidationError

from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.crypto.domains import DELEGATION_CREDENTIAL
from backend.crypto.sm import derive_public_key, sign_payload, signed_object_hash, verify_payload
from backend.delegation.attenuation import assert_monotonic_attenuation
from backend.delegation.contracts import DelegateCredentialRequest
from backend.identity.key_lifecycle import FilePrivateKeyStore
from backend.identity.key_registry import KeyRecord


class DelegationBuildError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def build_signed_delegation_credential(
    *,
    parent_credential: dict[str, Any],
    request: DelegateCredentialRequest,
    issuer_agent_id: str,
    issuer_key: KeyRecord,
    private_key_root: Path,
    current_time: int,
    schemas: SchemaStore,
) -> dict[str, Any]:
    parent_payload = parent_credential["payload"]
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "credential_id": new_id("cred-delegation"),
        "credential_type": "DELEGATION",
        "issuer": {"subject_id": issuer_agent_id, "key_id": issuer_key.key_id},
        "holder": {
            "agent_id": request.holder_agent_id,
            "key_id": request.holder_key_id,
        },
        "tenant_id": parent_payload["tenant_id"],
        "task_id": parent_payload["task_id"],
        "verifier_audience": "secure-tool-gateway",
        "capabilities": [
            capability.model_dump(mode="json", exclude_none=True)
            for capability in request.capabilities
        ],
        "quotas": request.quotas.model_dump(mode="json"),
        "not_before": request.not_before,
        "expires_at": request.expires_at,
        "delegation_depth": parent_payload["delegation_depth"] - 1,
        "parent_credential_id": parent_payload["credential_id"],
        "parent_credential_hash": signed_object_hash(parent_credential),
        "issued_at": current_time,
    }
    assert_monotonic_attenuation(parent_payload, payload)
    if issuer_key.private_key_reference is None:
        raise DelegationBuildError(ReasonCode.UNKNOWN_KEY, "issuer key reference is absent")
    private_key = FilePrivateKeyStore(private_key_root).load(
        issuer_key.private_key_reference
    )
    if derive_public_key(private_key) != issuer_key.public_key_hex:
        raise DelegationBuildError(
            ReasonCode.INVALID_SIGNATURE, "issuer private/public key mismatch"
        )
    signature = sign_payload(
        payload,
        domain_separator=DELEGATION_CREDENTIAL,
        key_id=issuer_key.key_id,
        key_purpose=issuer_key.purpose,
        private_key_hex=private_key,
        public_key_hex=issuer_key.public_key_hex,
        signed_at=current_time,
    )
    credential = {"payload": payload, "signature": signature}
    try:
        schemas.validate("delegation-credential.schema.json", credential)
    except ValidationError as exc:
        raise DelegationBuildError(
            ReasonCode.REQUEST_SCHEMA_INVALID,
            "signed delegation credential violates the frozen schema",
        ) from exc
    if not verify_payload(
        payload,
        signature,
        domain_separator=DELEGATION_CREDENTIAL,
        expected_key_id=issuer_key.key_id,
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=issuer_key.public_key_hex,
    ):
        raise DelegationBuildError(
            ReasonCode.INVALID_SIGNATURE,
            "delegation credential self-verification failed",
        )
    return credential

