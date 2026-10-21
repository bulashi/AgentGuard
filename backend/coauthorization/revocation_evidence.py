from __future__ import annotations

import hashlib
import re

from jsonschema import ValidationError

from backend.authorization.contracts import IDENTIFIER_PATTERN
from backend.coauthorization.evidence_verifier import (
    MAX_PACKAGE_BYTES, EvidenceVerificationError, evidence_schemas, verify_evidence_package,
)
from backend.coauthorization.revocation_audit import (
    REVOCATION_AUDIT_EVENT_TYPE, REVOCATION_AUDIT_SCHEMA_VERSION,
    revocation_audit_reference, validate_revocation_audit_evidence, validate_revocation_audit_outbox,
)
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER, parse_strict_json

SOURCE_KINDS = {
    "APPROVAL_KEY_REVOKED", "APPROVAL_KEY_COMPROMISED", "APPROVAL_POLICY_REVOKED", "AUTHORIZATION_WITHDRAWN",
}


def _expect_revocation(event_id: int, source_kind: str, source_identifier: str) -> None:
    if (
        type(event_id) is not int or not 1 <= event_id <= MAX_SAFE_INTEGER
        or type(source_kind) is not str or source_kind not in SOURCE_KINDS
        or type(source_identifier) is not str or not 1 <= len(source_identifier) <= 128
        or re.fullmatch(IDENTIFIER_PATTERN, source_identifier) is None
    ):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_EXPECTATION_INVALID")


def verify_revocation_evidence_package(
    raw_package: bytes, *, expected_revocation_event_id: int,
    expected_source_kind: str, expected_source_identifier: str, **authorization_inputs,
) -> dict:
    """Verify recorded pages and the selected signed root, without querying current state."""
    _expect_revocation(expected_revocation_event_id, expected_source_kind, expected_source_identifier)
    try:
        if type(raw_package) is not bytes or not 0 < len(raw_package) <= MAX_PACKAGE_BYTES:
            raise ValueError("invalid revocation package size")
        package = parse_strict_json(raw_package)
        evidence_schemas().validate("revocation-package.schema.json", package)
    except (ValueError, TypeError, RecursionError, ValidationError):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_INPUT_INVALID") from None
    authorization_package = package["authorization_package"]
    authorization_result = verify_evidence_package(
        canonicalize(authorization_package, normalize_sets=False), **authorization_inputs,
    )
    pages = package["revocation_pages"]
    try:
        for page in pages:
            validate_revocation_audit_evidence(page)
        first = pages[0]
        header = {field: value for field, value in first.items() if field not in {"page_number", "roots"}}
        if (
            first["revocation_event_id"] != expected_revocation_event_id
            or first["source_kind"] != expected_source_kind or first["source_identifier"] != expected_source_identifier
            or first["tenant_id"] != authorization_package["authorization_evidence"]["tenant_id"]
        ):
            raise EvidenceVerificationError("COAUTH_EVIDENCE_EXPECTATION_MISMATCH")
        if len(pages) != first["page_count"] or [page["page_number"] for page in pages] != list(range(1, len(pages) + 1)):
            raise ValueError("revocation pages are missing, duplicated or out of order")
        if any({field: value for field, value in page.items() if field not in {"page_number", "roots"}} != header for page in pages):
            raise ValueError("revocation page headers differ")
        roots = [root for page in pages for root in page["roots"]]
        identifiers = [root["root_credential_id"] for root in roots]
        if (
            len(roots) != first["matched_root_count"] or identifiers != sorted(set(identifiers))
            or sum(root["root_revocation_created"] for root in roots) != first["created_root_revocation_count"]
        ):
            raise ValueError("revocation pages do not contain the complete recorded roots")
        selected = next((root for root in roots if root["root_credential_id"] == authorization_result["root_credential_id"]), None)
        evidence = authorization_package["authorization_evidence"]
        signers = evidence["signed_bundle"]["payload"]["required_signers"]
        if selected is None or any(selected[field] != expected for field, expected in (
            ("root_credential_hash", evidence["root_credential_hash"]),
            ("task_id", evidence["task_id"]), ("challenge_id", evidence["challenge_id"]),
            ("policy_revision", evidence["policy_revision"]), ("approval_payload_hash", evidence["approval_payload_hash"]),
            ("bundle_hash", evidence["bundle_hash"]),
            ("enterprise_key_id", signers["enterprise_approver"]["key_id"]),
            ("finance_key_id", signers["finance_approver"]["key_id"]),
        )):
            raise ValueError("revocation observation does not bind the selected signed root")
        if selected["revoked_at"] < evidence["authorized_at"]:
            raise ValueError("root revocation predates its authorization observation")
    except EvidenceVerificationError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_BINDING_INVALID") from None
    sequences: list[int] = []
    for page in pages:
        reference = revocation_audit_reference(expected_revocation_event_id, page["page_number"])
        matches = [event for event in authorization_package["audit_events"] if event["evidence_reference"] == reference]
        if len(matches) != 1:
            raise EvidenceVerificationError("COAUTH_EVIDENCE_AUDIT_BINDING_INVALID")
        event = matches[0]
        if (
            event["schema_version"] != REVOCATION_AUDIT_SCHEMA_VERSION
            or event["event_type"] != REVOCATION_AUDIT_EVENT_TYPE or event["execution_id"] is not None
            or event["payload_hash"] != sm3_hex(canonicalize(page))
            or event["timestamp"] < page["captured_at"]
        ):
            raise EvidenceVerificationError("COAUTH_EVIDENCE_AUDIT_BINDING_INVALID")
        sequences.append(event["event_sequence"])
    result = {
        "schema_version": "1.0", "verification_scope": "SELECTED_ROOT_REVOCATION_AND_COMPLETE_PINNED_OBSERVATION",
        "verified": True, "authorization_verification": authorization_result,
        "revocation_event_id": expected_revocation_event_id, "source_kind": expected_source_kind,
        "source_identifier": expected_source_identifier, "capture_kind": first["capture_kind"],
        "observed_at_claim": first["observed_at"], "captured_at_claim": first["captured_at"],
        "page_count": len(pages), "matched_root_count": first["matched_root_count"],
        "created_root_revocation_count": first["created_root_revocation_count"],
        "selected_root_revocation_created": selected["root_revocation_created"],
        "selected_root_revoked_at_claim": selected["revoked_at"], "audit_event_sequences": sorted(sequences),
        "package_sha256": hashlib.sha256(raw_package).hexdigest(),
        "proves_complete_recorded_pages": True, "authorizes_execution": False,
        "proves_current_revocation": False, "proves_atomic_state_change": False,
        "proves_other_root_signatures": False, "proves_real_principal_independence": False,
        "proves_business_side_effects": False,
    }
    try:
        evidence_schemas().validate("revocation-verified-result.schema.json", result)
    except ValidationError:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_RESULT_INVALID") from None
    return result


def export_revocation_evidence_package(
    database_url: str, *, expected_revocation_event_id: int,
    expected_source_kind: str, expected_source_identifier: str, **authorization_inputs,
) -> tuple[bytes, dict]:
    """Read immutable evidence and reverify its pinned anchor; never create a checkpoint."""
    from backend.coauthorization.evidence_export import export_evidence_package
    from backend.state.database import connect

    _expect_revocation(expected_revocation_event_id, expected_source_kind, expected_source_identifier)
    raw_authorization, _ = export_evidence_package(database_url, **authorization_inputs)
    with connect(database_url) as connection, connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        rows = connection.execute(
            """
            SELECT outbox_event_id, execution_id, event_type, evidence_reference, payload_hash, payload, created_at, status
            FROM audit_outbox WHERE outbox_event_id LIKE %s
            """, (f"OUTBOX-COAUTH-REV-{expected_revocation_event_id}-%",),
        ).fetchall()
    if not rows:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_EXPORT_UNAVAILABLE")
    try:
        for row in rows:
            if row[7] != "APPENDED":
                raise ValueError("revocation evidence is not appended")
            validate_revocation_audit_outbox(
                outbox_id=row[0], execution_id=row[1], event_type=row[2], evidence_reference=row[3],
                payload_hash=row[4], payload=row[5], created_at=row[6],
            )
        pages = sorted((row[5] for row in rows), key=lambda page: page["page_number"])
    except (ValueError, TypeError, KeyError, RecursionError):
        raise EvidenceVerificationError("COAUTH_EVIDENCE_BINDING_INVALID") from None
    raw_package = canonicalize({
        "schema_version": "1.0", "record_type": "COAUTH_REVOCATION_EVIDENCE_PACKAGE_V1",
        "authorization_package": parse_strict_json(raw_authorization), "revocation_pages": pages,
    }, normalize_sets=False)
    result = verify_revocation_evidence_package(
        raw_package, expected_revocation_event_id=expected_revocation_event_id,
        expected_source_kind=expected_source_kind, expected_source_identifier=expected_source_identifier,
        **authorization_inputs,
    )
    return raw_package, result
