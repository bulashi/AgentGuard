from __future__ import annotations

from typing import Any

from jsonschema import ValidationError

from backend.authorization.contracts import AuthorizeTaskRequest
from backend.authorization.policy import build_root_capabilities
from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.crypto.domains import CAPABILITY_CREDENTIAL
from backend.crypto.sm import derive_public_key, sign_payload, verify_payload
from backend.identity.key_lifecycle import FilePrivateKeyStore
from backend.identity.key_registry import KeyRecord


class CredentialBuildError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def build_signed_root_credential(
    *,
    task: dict[str, Any],
    request: AuthorizeTaskRequest,
    authority_subject_id: str,
    authority_key: KeyRecord,
    private_keys: FilePrivateKeyStore,
    current_time: int,
    schemas: SchemaStore,
    credential_not_before: int | None = None,
) -> dict[str, Any]:
    not_before = current_time if credential_not_before is None else credential_not_before
    if not not_before <= current_time < task["expires_at"]:
        raise CredentialBuildError(ReasonCode.CREDENTIAL_EXPIRED, "root validity window is invalid")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "credential_id": new_id("cred-root"),
        "credential_type": "ROOT",
        "issuer": {
            "subject_id": authority_subject_id,
            "key_id": authority_key.key_id,
        },
        "holder": {
            "agent_id": request.holder_agent_id,
            "key_id": request.holder_key_id,
        },
        "tenant_id": task["tenant_id"],
        "task_id": task["task_id"],
        "verifier_audience": "secure-tool-gateway",
        "capabilities": build_root_capabilities(
            ticket_id=task["ticket_id"],
            customer_id=task["customer_id"],
            refund_total_fen=task["refund_total_fen"],
        ),
        "quotas": {
            "refund_total_fen": task["refund_total_fen"],
            "max_tool_calls": task["max_tool_calls"],
        },
        "not_before": not_before,
        "expires_at": task["expires_at"],
        "delegation_depth": request.delegation_depth,
        "parent_credential_id": None,
        "parent_credential_hash": None,
        "issued_at": current_time,
    }
    if authority_key.private_key_reference is None:
        raise CredentialBuildError(ReasonCode.UNKNOWN_KEY, "authority key reference is absent")
    private_key = private_keys.load(authority_key.private_key_reference)
    if derive_public_key(private_key) != authority_key.public_key_hex:
        raise CredentialBuildError(
            ReasonCode.INVALID_SIGNATURE, "authority private/public key mismatch"
        )
    signature = sign_payload(
        payload,
        domain_separator=CAPABILITY_CREDENTIAL,
        key_id=authority_key.key_id,
        key_purpose=authority_key.purpose,
        private_key_hex=private_key,
        public_key_hex=authority_key.public_key_hex,
        signed_at=current_time,
    )
    credential = {"payload": payload, "signature": signature}
    try:
        schemas.validate("capability-credential.schema.json", credential)
    except ValidationError as exc:
        raise CredentialBuildError(
            ReasonCode.REQUEST_SCHEMA_INVALID,
            "signed root credential violates the frozen schema",
        ) from exc
    if not verify_payload(
        payload,
        signature,
        domain_separator=CAPABILITY_CREDENTIAL,
        expected_key_id=authority_key.key_id,
        expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=authority_key.public_key_hex,
    ):
        raise CredentialBuildError(
            ReasonCode.INVALID_SIGNATURE, "root credential self-verification failed"
        )
    return credential
