from __future__ import annotations

from typing import Any

from jsonschema import ValidationError
from psycopg.types.json import Jsonb

from backend.coauthorization.audit import load_authorization_audit_schemas
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER, parse_strict_json

REVOCATION_AUDIT_EVENT_TYPE = "COAUTH_REVOCATION_APPLIED"
REVOCATION_AUDIT_SCHEMA_VERSION = "3.0"
REVOCATION_AUDIT_RECORD_TYPE = "COAUTH_REVOCATION_APPLIED_V1"
REVOCATION_ROOTS_PER_PAGE = 32
MAX_REVOCATION_PAGE_BYTES = 262_144
ROOT_FIELDS = (
    "root_credential_id", "root_credential_hash", "task_id", "challenge_id", "policy_revision",
    "approval_payload_hash", "bundle_hash", "enterprise_key_id", "finance_key_id",
    "root_revocation_created", "revoked_at", "revoked_by", "revocation_reason",
)


def _positive_integer(value: Any) -> None:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise ValueError("invalid revocation audit identifier")


def revocation_audit_outbox_id(event_id: int, page_number: int) -> str:
    _positive_integer(event_id)
    _positive_integer(page_number)
    return f"OUTBOX-COAUTH-REV-{event_id}-{page_number}"


def revocation_audit_reference(event_id: int, page_number: int) -> str:
    _positive_integer(event_id)
    _positive_integer(page_number)
    return f"COAUTH-REV-{event_id}-P-{page_number}"


def validate_revocation_audit_evidence(document: Any) -> None:
    """Validate an observation page, not signatures, live permissions or all other pages."""
    try:
        if type(document) is not dict:
            raise ValueError("revocation audit evidence must be an object")
        encoded = canonicalize(document, normalize_sets=False)
        if len(encoded) > MAX_REVOCATION_PAGE_BYTES:
            raise ValueError("revocation audit page exceeds its limit")
        document = parse_strict_json(encoded)
        load_authorization_audit_schemas().validate("revocation-audit-evidence.schema.json", document)
        total, number, pages = document["matched_root_count"], document["page_number"], document["page_count"]
        expected_pages = max(1, (total + REVOCATION_ROOTS_PER_PAGE - 1) // REVOCATION_ROOTS_PER_PAGE)
        expected_size = min(REVOCATION_ROOTS_PER_PAGE, max(0, total - (number - 1) * REVOCATION_ROOTS_PER_PAGE))
        roots = document["roots"]
        identifiers = [root["root_credential_id"] for root in roots]
        if (
            pages != expected_pages or number > pages or len(roots) != expected_size
            or identifiers != sorted(set(identifiers))
            or document["created_root_revocation_count"] > total
            or sum(root["root_revocation_created"] for root in roots) > document["created_root_revocation_count"]
            or document["captured_at"] < document["observed_at"]
            or (document["source_kind"] == "AUTHORIZATION_WITHDRAWN")
            != (document["observation_context"] == "EXPLICIT_WITHDRAWAL")
        ):
            raise ValueError("revocation audit pagination or observation differs")
        if document["source_kind"] == "AUTHORIZATION_WITHDRAWN" and total != 1:
            raise ValueError("withdrawal must contain exactly one root")
        for root in roots:
            if root["revoked_at"] > document["observed_at"] or root["enterprise_key_id"] == root["finance_key_id"]:
                raise ValueError("revocation audit root observation differs")
            source_kind, target = document["source_kind"], document["source_identifier"]
            if (
                source_kind in {"APPROVAL_KEY_REVOKED", "APPROVAL_KEY_COMPROMISED"}
                and target not in {root["enterprise_key_id"], root["finance_key_id"]}
            ) or (source_kind == "APPROVAL_POLICY_REVOKED" and target != root["policy_revision"]) or (
                source_kind == "AUTHORIZATION_WITHDRAWN" and target != root["root_credential_id"]
            ):
                raise ValueError("revocation audit source does not bind this root")
            if root["root_revocation_created"] and (
                root["revoked_at"] != document["observed_at"]
                or root["revoked_by"] != "COAUTH_REGISTRY:" + document["database_actor"]
                or root["revocation_reason"] != source_kind + ":" + target
            ):
                raise ValueError("new root revocation differs from its observation")
    except (ValidationError, KeyError, TypeError, ValueError, RecursionError):
        raise ValueError("invalid coauthorization revocation audit evidence") from None


def validate_revocation_audit_outbox(
    *, outbox_id: Any, execution_id: Any, event_type: Any, evidence_reference: Any,
    payload_hash: Any, payload: Any, created_at: Any,
) -> None:
    validate_revocation_audit_evidence(payload)
    if (
        event_type != REVOCATION_AUDIT_EVENT_TYPE or execution_id is not None
        or outbox_id != revocation_audit_outbox_id(payload["revocation_event_id"], payload["page_number"])
        or evidence_reference != revocation_audit_reference(payload["revocation_event_id"], payload["page_number"])
        or payload_hash != sm3_hex(canonicalize(payload))
        or type(created_at) is not int or created_at != payload["captured_at"]
    ):
        raise ValueError("revocation audit outbox metadata differs from its evidence")


def enqueue_revocation_audit(connection: Any, event_id: int) -> None:
    """Capture every root in the caller's transaction; never commit or overwrite evidence."""
    _positive_integer(event_id)
    event = connection.execute(
        """
        SELECT revocation_event_id, tenant_id, source_kind, source_identifier, observed_at,
               observation_context, database_actor, audit_required
        FROM coauthorization_revocation_events WHERE revocation_event_id = %s FOR UPDATE NOWAIT
        """, (event_id,),
    ).fetchone()
    if event is None or event[0] != event_id or type(event[7]) is not bool:
        raise ValueError("revocation observation is unavailable")
    root_rows = connection.execute(
        """
        SELECT mapping.root_credential_id, credential.signed_object_hash, credential.task_id,
               approval.challenge_id, challenge.policy_revision, approval.approval_payload_hash,
               approval.bundle_hash, approval.enterprise_key_id, approval.finance_key_id,
               mapping.root_revocation_created, revocation.revoked_at, revocation.revoked_by, revocation.revocation_reason
        FROM coauthorization_revocation_roots mapping
        LEFT JOIN credentials credential ON credential.credential_id = mapping.root_credential_id
        LEFT JOIN coauthorization_authorizations approval ON approval.root_credential_id = mapping.root_credential_id
        LEFT JOIN coauthorization_challenges challenge ON challenge.challenge_id = approval.challenge_id
        LEFT JOIN credential_revocations revocation ON revocation.credential_id = mapping.root_credential_id
        WHERE mapping.revocation_event_id = %s
        ORDER BY mapping.root_credential_id COLLATE "C"
        """, (event_id,),
    ).fetchall()
    roots = [dict(zip(ROOT_FIELDS, row, strict=True)) for row in root_rows]
    if any(type(root["root_revocation_created"]) is not bool for root in roots):
        raise ValueError("revocation root observation is inconsistent")
    total = len(roots)
    if total > MAX_SAFE_INTEGER:
        raise ValueError("revocation root count exceeds the safe integer range")
    page_count = max(1, (total + REVOCATION_ROOTS_PER_PAGE - 1) // REVOCATION_ROOTS_PER_PAGE)
    header = {
        "schema_version": "1.0", "record_type": REVOCATION_AUDIT_RECORD_TYPE,
        "revocation_event_id": event[0], "tenant_id": event[1], "source_kind": event[2],
        "source_identifier": event[3], "observed_at": event[4], "observation_context": event[5],
        "database_actor": event[6],
        "capture_kind": "TRANSACTIONAL_CAPTURE" if event[7] else "LEGACY_OBSERVATION_LINK",
        "page_count": page_count, "matched_root_count": total,
        "created_root_revocation_count": sum(root["root_revocation_created"] for root in roots),
    }
    prior = connection.execute(
        """
        SELECT outbox_event_id, execution_id, event_type, evidence_reference, payload_hash, payload, created_at, status
        FROM audit_outbox WHERE outbox_event_id LIKE %s FOR UPDATE NOWAIT
        """, (f"OUTBOX-COAUTH-REV-{event_id}-%",),
    ).fetchall()
    if prior:
        stored = {row[0]: row for row in prior}
        if len(stored) != page_count:
            raise ValueError("revocation audit pages are missing or duplicated")
        captured_times: set[int] = set()
        for number in range(1, page_count + 1):
            row = stored.get(revocation_audit_outbox_id(event_id, number))
            if row is None:
                raise ValueError("revocation audit page is missing")
            if row[7] not in {"PENDING", "APPENDED"}:
                raise ValueError("revocation audit page has an invalid lifecycle")
            validate_revocation_audit_outbox(
                outbox_id=row[0], execution_id=row[1], event_type=row[2], evidence_reference=row[3],
                payload_hash=row[4], payload=row[5], created_at=row[6],
            )
            expected = header | {
                "captured_at": row[6], "page_number": number,
                "roots": roots[(number - 1) * REVOCATION_ROOTS_PER_PAGE:number * REVOCATION_ROOTS_PER_PAGE],
            }
            if row[5] != expected:
                raise ValueError("recorded revocation audit binding changed")
            captured_times.add(row[6])
        if len(captured_times) != 1:
            raise ValueError("revocation audit pages have different capture times")
    else:
        clock = connection.execute("SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT").fetchone()
        if clock is None or type(clock[0]) is not int or not 0 <= clock[0] <= MAX_SAFE_INTEGER:
            raise ValueError("revocation audit capture clock is unavailable")
        for number in range(1, page_count + 1):
            payload = header | {
                "captured_at": clock[0], "page_number": number,
                "roots": roots[(number - 1) * REVOCATION_ROOTS_PER_PAGE:number * REVOCATION_ROOTS_PER_PAGE],
            }
            validate_revocation_audit_evidence(payload)
            connection.execute(
                """
                INSERT INTO audit_outbox (
                    outbox_event_id, execution_id, event_type, evidence_reference, payload_hash, payload, status, created_at
                ) VALUES (%s, NULL, %s, %s, %s, %s, 'PENDING', %s)
                """, (revocation_audit_outbox_id(event_id, number), REVOCATION_AUDIT_EVENT_TYPE,
                       revocation_audit_reference(event_id, number), sm3_hex(canonicalize(payload)), Jsonb(payload), clock[0]),
            )
    connection.execute("SELECT assert_coauthorization_revocation_journal(%s)", (event_id,))
