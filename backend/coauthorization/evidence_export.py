from __future__ import annotations

from psycopg.rows import dict_row

from backend.audit.service import AuditError, AuditService
from backend.coauthorization.audit import authorization_audit_outbox_id
from backend.coauthorization.evidence_verifier import (
    MAX_EVENTS,
    MAX_PACKAGE_BYTES,
    EvidenceVerificationError,
    load_pinned_checkpoint,
    load_pinned_trust_context,
    validate_verification_expectations,
    verify_evidence_package,
)
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash
from backend.state.database import connect


def export_evidence_package(
    database_url: str,
    *,
    raw_trust_context: bytes,
    trusted_context_sha256: str,
    raw_checkpoint: bytes,
    trusted_checkpoint_sha256: str,
    expected_task_id: str,
    expected_root_credential_id: str,
    expected_approval_payload_hash: str,
    observed_at: int,
) -> tuple[bytes, dict]:
    """Read an existing prefix and verify before returning it; never generate evidence."""
    validate_verification_expectations(
        expected_task_id, expected_root_credential_id, expected_approval_payload_hash, observed_at
    )
    load_pinned_trust_context(raw_trust_context, trusted_context_sha256)
    anchor = load_pinned_checkpoint(raw_checkpoint, trusted_checkpoint_sha256)["payload"]
    if not 1 <= anchor["latest_event_sequence"] <= MAX_EVENTS:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_PREFIX_INVALID")
    outbox_id = authorization_audit_outbox_id(expected_root_credential_id)
    with connect(database_url) as connection, connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        with connection.cursor(row_factory=dict_row) as cursor:
            row = cursor.execute("""
                SELECT outbox.outbox_event_id, outbox.execution_id, outbox.event_type,
                       outbox.evidence_reference, outbox.payload_hash, outbox.payload,
                       outbox.created_at, outbox.status,
                       root.signed_object, root.signed_object_hash, root.task_id,
                       root.tenant_id, root.credential_type::text AS credential_type
                FROM audit_outbox AS outbox
                JOIN credentials AS root ON root.credential_id = %s
                WHERE outbox.outbox_event_id = %s
            """, (expected_root_credential_id, outbox_id)).fetchone()
            if row is None or row["status"] != "APPENDED":
                raise EvidenceVerificationError("COAUTH_EVIDENCE_EXPORT_UNAVAILABLE")
            try:
                evidence = row["payload"]
                AuditService._validate_coauthorization_outbox(
                    outbox_id=row["outbox_event_id"], execution_id=row["execution_id"],
                    event_type=row["event_type"], evidence_reference=row["evidence_reference"],
                    payload_hash=row["payload_hash"], payload=evidence, created_at=row["created_at"],
                )
                if (
                    row["credential_type"] != "ROOT" or row["task_id"] != expected_task_id
                    or row["tenant_id"] != evidence["tenant_id"]
                    or signed_object_hash(row["signed_object"]) != row["signed_object_hash"]
                    or row["signed_object_hash"] != evidence["root_credential_hash"]
                    or canonicalize(row["signed_object"]) != canonicalize(evidence["credential"])
                ):
                    raise ValueError("stored root differs from authorization evidence")
            except (AuditError, ValueError, TypeError, KeyError, RecursionError):
                raise EvidenceVerificationError("COAUTH_EVIDENCE_BINDING_INVALID") from None
            events = cursor.execute("""
                SELECT schema_version, event_sequence, event_id, execution_id, event_type,
                       event_timestamp AS timestamp, payload_hash, evidence_reference,
                       previous_event_hash, event_hash
                FROM audit_events
                WHERE event_sequence >= 1 AND event_sequence <= %s
                ORDER BY event_sequence
                LIMIT %s
            """, (anchor["latest_event_sequence"], MAX_EVENTS + 1)).fetchall()
    raw_package = canonicalize({
        "schema_version": "1.0", "record_type": "COAUTHORIZATION_EVIDENCE_PACKAGE_V1",
        "authorization_evidence": evidence, "audit_events": events,
    }, normalize_sets=False)
    if len(raw_package) > MAX_PACKAGE_BYTES:
        raise EvidenceVerificationError("COAUTH_EVIDENCE_INPUT_INVALID")
    result = verify_evidence_package(
        raw_package, raw_trust_context=raw_trust_context,
        trusted_context_sha256=trusted_context_sha256,
        raw_checkpoint=raw_checkpoint, trusted_checkpoint_sha256=trusted_checkpoint_sha256,
        expected_task_id=expected_task_id, expected_root_credential_id=expected_root_credential_id,
        expected_approval_payload_hash=expected_approval_payload_hash, observed_at=observed_at,
    )
    return raw_package, result
