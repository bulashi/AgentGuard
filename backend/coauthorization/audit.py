from __future__ import annotations

import re
from functools import lru_cache

from jsonschema import ValidationError as SchemaValidationError
from referencing import Resource

from backend.authorization.contracts import BUSINESS_IDENTIFIER_PATTERN, IDENTIFIER_PATTERN
from backend.coauthorization.contracts import (
    MAX_BUNDLE_BYTES,
    ApprovalSignature,
    CoauthorizationBundle,
    TrustedTask,
)
from backend.common.schema import PROJECT_ROOT, SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.crypto.strict_json import parse_strict_json

COAUTHORIZATION_AUDIT_EVENT_TYPE = "COAUTH_ROOT_AUTHORIZED"
COAUTHORIZATION_AUDIT_SCHEMA_VERSION = "2.0"
MAX_EVIDENCE_BYTES = 65_536

_INVALID_EVIDENCE_MESSAGE = "invalid coauthorization audit evidence"
_EXTENSION_SCHEMA_ROOT = PROJECT_ROOT / "protocol" / "extensions" / "coauthorization-v1"


@lru_cache(maxsize=1)
def load_authorization_audit_schemas() -> SchemaStore:
    """Load local extension and frozen root resources without settings or live state."""
    schemas = SchemaStore(_EXTENSION_SCHEMA_ROOT)
    root_schemas = SchemaStore()
    # Both directories contain common.schema.json with different absolute IDs.
    # Register root resources without replacing the extension documents by name.
    schemas.registry = schemas.registry.with_resources(
        (document["$id"], Resource.from_contents(document))
        for document in root_schemas.documents.values()
    )
    return schemas


def _strict_document(document: dict, *, max_bytes: int) -> dict:
    if type(document) is not dict:
        raise ValueError(_INVALID_EVIDENCE_MESSAGE)
    encoded = canonicalize(document, normalize_sets=False)
    if len(encoded) > max_bytes:
        raise ValueError(_INVALID_EVIDENCE_MESSAGE)
    return parse_strict_json(encoded)


def _validate_identifier(value: str, *, business: bool = False) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or re.fullmatch(BUSINESS_IDENTIFIER_PATTERN if business else IDENTIFIER_PATTERN, value) is None
    ):
        raise ValueError(_INVALID_EVIDENCE_MESSAGE)


def authorization_audit_outbox_id(root_credential_id: str) -> str:
    """Return a stable 78-character identifier for one root authorization."""
    _validate_identifier(root_credential_id)
    return "OUTBOX-COAUTH-" + sm3_hex(root_credential_id.encode("utf-8"))


def validate_authorization_audit_evidence(document: dict) -> None:
    """Check stored evidence shape, hashes, metadata and scope self-consistency.

    Actual SM2 verification with trusted registry keys belongs to the Authority
    production entry point before this helper. This does not verify signatures,
    signature domains, real principals, current key state or challenge state.
    The frozen signature objects contain no domain or payload-hash metadata.
    """
    try:
        document = _strict_document(document, max_bytes=MAX_EVIDENCE_BYTES)
        load_authorization_audit_schemas().validate(
            "authorization-audit-evidence.schema.json", document
        )
        bundle_document = _strict_document(document["signed_bundle"], max_bytes=MAX_BUNDLE_BYTES)
        bundle = CoauthorizationBundle.model_validate(bundle_document)
        payload = bundle.payload
        digest = sm3_hex(canonicalize(bundle_document["payload"]))
        credential = document["credential"]
        root = credential["payload"]
        root_signature = ApprovalSignature.model_validate(credential["signature"])
        authorized_at = document["authorized_at"]

        for field in ("tenant_id", "task_id", "challenge_id", "policy_revision"):
            _validate_identifier(document[field], business=field == "tenant_id")
            if document[field] != getattr(payload, field):
                raise ValueError(_INVALID_EVIDENCE_MESSAGE)
        for value in (
            root["credential_id"], root["issuer"]["subject_id"], root["issuer"]["key_id"],
            payload.ticket_id, payload.holder.agent_id, payload.holder.key_id,
            payload.required_signers.enterprise_approver.subject_id,
            payload.required_signers.enterprise_approver.key_id,
            payload.required_signers.finance_approver.subject_id,
            payload.required_signers.finance_approver.key_id,
        ):
            _validate_identifier(value)
        _validate_identifier(payload.customer_id, business=True)
        if (
            document["approval_payload_hash"] != digest
            or document["bundle_hash"] != sm3_hex(canonicalize(bundle_document))
            or document["root_credential_id"] != root["credential_id"]
            or document["root_credential_hash"] != signed_object_hash(credential)
        ):
            raise ValueError(_INVALID_EVIDENCE_MESSAGE)

        scope_matches = all(root[field] == expected for field, expected in (
            ("tenant_id", payload.tenant_id),
            ("task_id", payload.task_id),
            ("holder", payload.holder.model_dump(mode="json")),
            ("quotas", payload.quotas.model_dump(mode="json")),
            ("not_before", payload.not_before),
            ("expires_at", payload.expires_at),
            ("delegation_depth", payload.delegation_depth),
        ))
        capabilities_digest = sm3_hex(canonicalize({"capabilities": root["capabilities"]}))
        if not scope_matches or capabilities_digest != payload.capabilities_hash:
            raise ValueError(_INVALID_EVIDENCE_MESSAGE)

        # The frozen root schema is broader than the four-tool approval profile.
        # Reuse its task contract to bind ticket/customer scope and refund limits.
        TrustedTask.model_validate({
            "tenant_id": root["tenant_id"], "task_id": root["task_id"],
            "ticket_id": payload.ticket_id, "customer_id": payload.customer_id,
            "holder": root["holder"], "capabilities": root["capabilities"],
            "quotas": root["quotas"], "not_before": root["not_before"],
            "expires_at": root["expires_at"], "delegation_depth": root["delegation_depth"],
            "status": "AUTHORIZED",
        })
        if (
            root_signature.key_id != root["issuer"]["key_id"]
            or root_signature.signed_at != root["issued_at"]
            or not (
                payload.approval_not_before <= root_signature.signed_at
                <= authorized_at < payload.approval_expires_at
            )
        ):
            raise ValueError(_INVALID_EVIDENCE_MESSAGE)

        signers = payload.required_signers
        if (
            signers.enterprise_approver.subject_id == signers.finance_approver.subject_id
            or signers.enterprise_approver.key_id == signers.finance_approver.key_id
        ):
            raise ValueError(_INVALID_EVIDENCE_MESSAGE)
        for evidence in bundle.approvals:
            statement = evidence.statement
            signature = evidence.signature
            required = signers.for_role(statement.role)
            if (
                statement.approval_payload_hash != digest
                or statement.subject_id != required.subject_id
                or statement.key_id != required.key_id
                or signature.key_id != statement.key_id
                or signature.signed_at != statement.approved_at
                or not (
                    payload.approval_not_before <= statement.approved_at
                    <= root_signature.signed_at < payload.approval_expires_at
                )
            ):
                raise ValueError(_INVALID_EVIDENCE_MESSAGE)
    except (ValueError, TypeError, KeyError, RecursionError, SchemaValidationError):
        raise ValueError(_INVALID_EVIDENCE_MESSAGE) from None


def make_authorization_audit_evidence(
    *, signed_bundle: dict, credential: dict, authorized_at: int
) -> dict:
    """Snapshot previously verified approvals and their root without signing or I/O writes."""
    try:
        signed_bundle = _strict_document(signed_bundle, max_bytes=MAX_BUNDLE_BYTES)
        credential = _strict_document(credential, max_bytes=MAX_EVIDENCE_BYTES)
        payload = signed_bundle["payload"]
        document = {
            "schema_version": "1.0",
            "record_type": "COAUTH_ROOT_AUTHORIZED_V1",
            "tenant_id": payload["tenant_id"],
            "task_id": payload["task_id"],
            "challenge_id": payload["challenge_id"],
            "policy_revision": payload["policy_revision"],
            "approval_payload_hash": sm3_hex(canonicalize(payload)),
            "bundle_hash": sm3_hex(canonicalize(signed_bundle)),
            "signed_bundle": signed_bundle,
            "root_credential_id": credential["payload"]["credential_id"],
            "root_credential_hash": signed_object_hash(credential),
            "credential": credential,
            "authorized_at": authorized_at,
        }
        validate_authorization_audit_evidence(document)
        return document
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ValueError(_INVALID_EVIDENCE_MESSAGE) from None
