from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import ValidationError
from psycopg.types.json import Jsonb
from referencing import Resource

from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex

AUDIT_SCHEMA_VERSION = "4.0"
AUDIT_EVENT_TYPE = "CREDENTIAL_REVOKED"
AUDIT_RECORD_TYPE = "CREDENTIAL_REVOKED_V1"
SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "protocol/extensions/dispatch-revocation/v1"


@lru_cache(maxsize=1)
def audit_schemas():
    schemas = SchemaStore(SCHEMA_ROOT)
    core = SchemaStore()
    schemas.registry = schemas.registry.with_resources(
        (document["$id"], Resource.from_contents(document)) for document in core.documents.values()
    )
    return schemas


def revocation_outbox_id(credential_id: str) -> str:
    return "OUTBOX-CRED-REV-" + sm3_hex(canonicalize({"credential_id": credential_id}))


def _revocation_evidence(connection, credential_id: str):
    row = connection.execute(
        """
        SELECT c.credential_id, c.credential_type, c.parent_credential_id, c.task_id,
               r.revoked_at, r.revoked_by, r.revocation_reason
        FROM credentials c JOIN credential_revocations r USING (credential_id)
        WHERE c.credential_id = %s
        """,
        (credential_id,),
    ).fetchone()
    if row is None:
        raise ValueError("credential revocation evidence is missing")
    return {
        "schema_version": "1.0",
        "record_type": AUDIT_RECORD_TYPE,
        "credential_id": str(row[0]),
        "credential_type": str(row[1]),
        "parent_credential_id": None if row[2] is None else str(row[2]),
        "task_id": str(row[3]),
        "revoked_at": int(row[4]),
        "revoked_by": str(row[5]),
        "reason": str(row[6]),
    }


def enqueue_revocation(connection, credential_id: str) -> None:
    evidence = _revocation_evidence(connection, credential_id)
    audit_schemas().validate("credential-revocation-evidence.schema.json", evidence)
    connection.execute(
        """
        INSERT INTO audit_outbox (
            outbox_event_id, execution_id, event_type, evidence_reference,
            payload_hash, payload, status, created_at
        ) VALUES (%s, NULL, %s, %s, %s, %s, 'PENDING', %s)
        ON CONFLICT (outbox_event_id) DO NOTHING
        """,
        (
            revocation_outbox_id(credential_id),
            AUDIT_EVENT_TYPE,
            credential_id,
            sm3_hex(canonicalize(evidence)),
            Jsonb(evidence),
            evidence["revoked_at"],
        ),
    )


def validate_revocation_audit_outbox(
    *, outbox_id, execution_id, event_type, evidence_reference,
    payload_hash, payload, created_at,
) -> None:
    try:
        audit_schemas().validate("credential-revocation-evidence.schema.json", payload)
    except (ValidationError, TypeError) as exc:
        raise ValueError("credential revocation evidence violates its schema") from exc
    if (
        event_type != AUDIT_EVENT_TYPE
        or execution_id is not None
        or outbox_id != revocation_outbox_id(payload["credential_id"])
        or evidence_reference != payload["credential_id"]
        or payload_hash != sm3_hex(canonicalize(payload))
        or type(created_at) is not int
        or created_at != payload["revoked_at"]
    ):
        raise ValueError("credential revocation audit metadata differs")


def validate_control_outbox(
    connection,
    *,
    outbox_id,
    execution_id,
    event_type,
    evidence_reference,
    payload_hash,
    payload,
    created_at,
):
    if not isinstance(payload, dict) or payload_hash != sm3_hex(canonicalize(payload)):
        raise ValueError("control audit payload hash differs")
    if outbox_id.startswith("OUTBOX-CRED-REV-"):
        validate_revocation_audit_outbox(
            outbox_id=outbox_id, execution_id=execution_id, event_type=event_type,
            evidence_reference=evidence_reference, payload_hash=payload_hash,
            payload=payload, created_at=created_at,
        )
        if (
            payload != _revocation_evidence(connection, payload["credential_id"])
        ):
            raise ValueError("credential revocation audit binding differs")
    elif outbox_id.startswith("OUTBOX-DISPATCH-CANCEL-"):
        try:
            audit_schemas().validate("dispatch-cancellation-evidence.schema.json", payload)
        except (ValidationError, TypeError) as exc:
            raise ValueError("dispatch cancellation evidence violates its schema") from exc
        row = connection.execute(
            """
            SELECT cancellation_id, execution_id, denial_execution_id, evidence, cancelled_at
            FROM dispatch_cancellations WHERE cancellation_id = %s
            """,
            (evidence_reference,),
        ).fetchone()
        if (
            row is None
            or event_type != "EXECUTION_RELEASED"
            or execution_id != row[1]
            or evidence_reference != row[0]
            or outbox_id != "OUTBOX-DISPATCH-CANCEL-" + row[0]
            or payload != row[3]
            or created_at != row[4]
            or payload.get("record_type") != "DISPATCH_CANCELLED_V1"
        ):
            raise ValueError("dispatch cancellation audit binding differs")
        states = connection.execute(
            "SELECT execution_id, state, decision FROM execution_records "
            "WHERE execution_id = ANY(%s)",
            ([row[1], row[2]],),
        ).fetchall()
        if {str(item[0]): (str(item[1]), str(item[2])) for item in states} != {
            str(row[1]): ("RELEASED", "ALLOW"),
            str(row[2]): ("DENIED", "DENY"),
        }:
            raise ValueError("cancelled execution decisions were rewritten")
    else:
        raise ValueError("unknown control audit record")


def is_control_outbox(outbox_id: Any) -> bool:
    return isinstance(outbox_id, str) and outbox_id.startswith(
        ("OUTBOX-CRED-REV-", "OUTBOX-DISPATCH-CANCEL-"),
    )
