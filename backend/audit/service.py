from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from jsonschema import ValidationError
from psycopg.types.json import Jsonb
from referencing import Resource

from backend.audit.prefix_contracts import AuditPrefixRequest, AuditPrefixResponse
from backend.coauthorization.audit import (
    COAUTHORIZATION_AUDIT_EVENT_TYPE,
    COAUTHORIZATION_AUDIT_SCHEMA_VERSION,
    authorization_audit_outbox_id,
    validate_authorization_audit_evidence,
)
from backend.coauthorization.revocation_audit import (
    REVOCATION_AUDIT_EVENT_TYPE,
    REVOCATION_AUDIT_RECORD_TYPE,
    REVOCATION_AUDIT_SCHEMA_VERSION,
    validate_revocation_audit_outbox,
)
from backend.coauthorization.verifier import EXTENSION_SCHEMA_ROOT
from backend.common.enums import KeyPurpose
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_CHECKPOINT, AUDIT_EVENT_HASH
from backend.crypto.sm import signed_object_hash, sm3_hex, verify_payload
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.revocation.audit import (
    AUDIT_EVENT_TYPE as CREDENTIAL_REVOCATION_EVENT,
)
from backend.revocation.audit import (
    AUDIT_RECORD_TYPE as CREDENTIAL_REVOCATION_RECORD,
)
from backend.revocation.audit import (
    AUDIT_SCHEMA_VERSION as CREDENTIAL_REVOCATION_VERSION,
)
from backend.revocation.audit import (
    audit_schemas as credential_revocation_schemas,
)
from backend.revocation.audit import (
    is_control_outbox,
    validate_control_outbox,
)
from backend.state.database import connect

AUDIT_EVENT_TYPES = {
    "RAW_REQUEST_REJECTED",
    "AUTHORIZATION_DENIED",
    "EXECUTION_ADMITTED",
    "TOOL_DISPATCHED",
    "EXECUTION_COMMITTED",
    "EXECUTION_RELEASED",
    "EXECUTION_UNKNOWN",
    "RECEIPT_PENDING",
    "RECEIPT_SIGNED",
    "RESULT_RETRIEVAL_ALLOWED",
    "RESULT_RETRIEVAL_DENIED",
}


class AuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditVerificationSnapshot:
    response: dict[str, Any]
    latest_event_hash: str
    events: dict[int, dict[str, Any]]
    checkpoint: dict[str, Any] | None


class AuditService:
    """Append the main-database outbox into a row-locked SM3 hash chain."""

    def __init__(
        self,
        database_url: str,
        *,
        audit_database_url: str | None = None,
        schemas: SchemaStore | None = None,
    ) -> None:
        self.database_url = database_url
        self.audit_database_url = audit_database_url
        self.schemas = schemas or SchemaStore()
        self.coauthorization_schemas = SchemaStore(EXTENSION_SCHEMA_ROOT)
        self.coauthorization_schemas.registry = self.coauthorization_schemas.registry.with_resources(
            (document["$id"], Resource.from_contents(document))
            for document in self.schemas.documents.values()
        )

    def enqueue_rejected(self, event: dict[str, Any]) -> None:
        try:
            self.schemas.validate("rejected-audit-event.schema.json", event)
        except ValidationError as exc:
            raise AuditError("rejected audit event violates its frozen schema") from exc
        payload = dict(event)
        payload_hash = sm3_hex(canonicalize(payload))
        with connect(self.database_url) as connection, connection.transaction():
            connection.execute(
                """
                INSERT INTO audit_outbox (
                    outbox_event_id, execution_id, event_type, evidence_reference,
                    payload_hash, payload, status, created_at
                )
                VALUES (%s, NULL, 'RAW_REQUEST_REJECTED', %s, %s, %s, 'PENDING', %s)
                ON CONFLICT (outbox_event_id) DO UPDATE
                SET evidence_reference = EXCLUDED.evidence_reference,
                    payload_hash = EXCLUDED.payload_hash,
                    payload = EXCLUDED.payload,
                    created_at = EXCLUDED.created_at
                WHERE audit_outbox.status = 'PENDING'
                """,
                (
                    f"OUTBOX-{event['event_id']}",
                    str(event["event_id"]),
                    payload_hash,
                    Jsonb(payload),
                    int(event["received_at"]),
                ),
            )

    def append_pending(
        self, *, max_events: int = 100, current_time: int | None = None
    ) -> dict[str, Any]:
        timestamp = now_unix() if current_time is None else current_time
        appended = 0
        with connect(self.database_url) as connection, connection.transaction():
            head = connection.execute(
                """
                SELECT latest_event_sequence, latest_event_hash
                FROM audit_chain_head WHERE singleton = TRUE FOR UPDATE
                """
            ).fetchone()
            if head is None:
                raise AuditError("audit chain head is missing")
            sequence = int(head[0])
            previous_hash = str(head[1])
            rows = connection.execute(
                """
                SELECT outbox_event_id, execution_id, event_type, evidence_reference,
                       payload_hash, payload, created_at
                FROM audit_outbox
                WHERE status = 'PENDING' AND created_at <= %s
                ORDER BY created_at, outbox_event_id
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (timestamp, max_events),
            ).fetchall()
            for row in rows:
                self._validate_payload_hash(row[5], row[4])
                if self._is_control_payload(row[5]) and not is_control_outbox(row[0]):
                    raise AuditError("control evidence cannot use an unrelated audit outbox")
                if is_control_outbox(row[0]):
                    self._validate_control_record(connection, row)
                if self._is_coauthorization_outbox_id(row[0]) and row[2] != COAUTHORIZATION_AUDIT_EVENT_TYPE:
                    raise AuditError("coauthorization outbox cannot use a legacy event type")
                if self._is_revocation_outbox_id(row[0]) and row[2] != REVOCATION_AUDIT_EVENT_TYPE:
                    raise AuditError("revocation outbox cannot use a legacy event type")
                event_type = self._normalize_event_type(str(row[2]))
                version = "1.0"
                if event_type == CREDENTIAL_REVOCATION_EVENT:
                    if not is_control_outbox(row[0]):
                        raise AuditError("credential revocation evidence is not bound to its outbox")
                    version = CREDENTIAL_REVOCATION_VERSION
                elif event_type == COAUTHORIZATION_AUDIT_EVENT_TYPE:
                    self._validate_coauthorization_outbox(
                        outbox_id=row[0], execution_id=row[1], event_type=row[2],
                        evidence_reference=row[3], payload_hash=row[4], payload=row[5],
                        created_at=row[6],
                    )
                    version = COAUTHORIZATION_AUDIT_SCHEMA_VERSION
                    if type(timestamp) is not int or timestamp < row[6]:
                        raise AuditError("coauthorization append predates authorization")
                elif event_type == REVOCATION_AUDIT_EVENT_TYPE:
                    self._validate_revocation_outbox(
                        outbox_id=row[0], execution_id=row[1], event_type=row[2],
                        evidence_reference=row[3], payload_hash=row[4], payload=row[5], created_at=row[6],
                    )
                    version = REVOCATION_AUDIT_SCHEMA_VERSION
                    if type(timestamp) is not int or timestamp < row[6]:
                        raise AuditError("revocation append predates evidence capture")
                elif self._is_coauthorization_payload(row[5]):
                    raise AuditError("coauthorization evidence cannot use a legacy event type")
                if self._is_revocation_payload(row[5]) and event_type != REVOCATION_AUDIT_EVENT_TYPE:
                    raise AuditError("revocation evidence cannot use another event type")
                sequence += 1
                event_without_hash = {
                    "schema_version": version,
                    "event_sequence": sequence,
                    "event_id": new_id("EVENT"),
                    "execution_id": None if row[1] is None else str(row[1]),
                    "event_type": event_type,
                    "timestamp": timestamp,
                    "payload_hash": str(row[4]),
                    "evidence_reference": str(row[3]),
                    "previous_event_hash": previous_hash,
                }
                self._validate_event(event_without_hash | {"event_hash": "0" * 64})
                event_hash = self._event_hash(event_without_hash)
                connection.execute(
                    """
                    INSERT INTO audit_events (
                        event_sequence, event_id, outbox_event_id, execution_id,
                        event_type, event_timestamp, payload_hash, evidence_reference,
                        previous_event_hash, event_hash, schema_version
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        sequence,
                        event_without_hash["event_id"],
                        str(row[0]),
                        event_without_hash["execution_id"],
                        event_type,
                        timestamp,
                        event_without_hash["payload_hash"],
                        event_without_hash["evidence_reference"],
                        previous_hash,
                        event_hash,
                        version,
                    ),
                )
                connection.execute(
                    """
                    UPDATE audit_outbox
                    SET status = 'APPENDED', appended_at = %s
                    WHERE outbox_event_id = %s
                    """,
                    (timestamp, str(row[0])),
                )
                previous_hash = event_hash
                appended += 1
            if appended:
                connection.execute(
                    """
                    UPDATE audit_chain_head
                    SET latest_event_sequence = %s, latest_event_hash = %s, updated_at = %s
                    WHERE singleton = TRUE
                    """,
                    (sequence, previous_hash, timestamp),
                )
        return {
            "appended_count": appended,
            "latest_event_sequence": sequence,
            "latest_event_hash": previous_hash,
        }

    def verify(
        self,
        *,
        from_sequence: int = 1,
        include_independent_checkpoint: bool = True,
    ) -> dict[str, Any]:
        return self._verification_snapshot(
            from_sequence=from_sequence,
            include_independent_checkpoint=include_independent_checkpoint,
        ).response

    def verify_events(self, request: AuditPrefixRequest) -> dict[str, Any]:
        snapshot = self._verification_snapshot(from_sequence=1, include_independent_checkpoint=True)
        checkpoint = snapshot.checkpoint
        anchor_sequence = checkpoint["signed_checkpoint"]["payload"]["latest_event_sequence"] if checkpoint else 0
        bindings = []
        for selected in request.events:
            stored = snapshot.events.get(selected["event_sequence"])
            if stored is not None and stored["event_id"] != selected["event_id"]:
                stored = None
            matched = stored is not None and canonicalize(stored) == canonicalize(selected)
            bindings.append({
                "event_sequence": selected["event_sequence"],
                "event_id": selected["event_id"], "event_hash": selected["event_hash"],
                "matched": matched,
                "covered": bool(matched and snapshot.response["valid"] and checkpoint
                                and selected["event_sequence"] <= anchor_sequence),
                "verified_event": stored,
            })
        report = AuditPrefixResponse.model_validate({
            "schema_version": "1.0", "task_id": request.task_id,
            "verification": snapshot.response | {"latest_event_hash": snapshot.latest_event_hash},
            "checkpoint": checkpoint, "event_bindings": bindings,
        })
        report.require_request_binding(request)
        return report.model_dump(mode="json")

    def _verification_snapshot(
        self, *, from_sequence: int, include_independent_checkpoint: bool,
    ) -> AuditVerificationSnapshot:
        checkpoint_rows = self._load_checkpoints() if include_independent_checkpoint else []
        with connect(self.database_url) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            head = connection.execute(
                """
                SELECT latest_event_sequence, latest_event_hash
                FROM audit_chain_head WHERE singleton = TRUE
                """
            ).fetchone()
            if head is None:
                raise AuditError("audit chain head is missing")
            latest_sequence = int(head[0])
            latest_hash = str(head[1])
            all_rows = connection.execute(
                """
                SELECT event.event_sequence, event.event_id, event.execution_id, event.event_type,
                       event.event_timestamp, event.payload_hash, event.evidence_reference,
                       event.previous_event_hash, event.event_hash, event.schema_version,
                       event.outbox_event_id, outbox.payload, outbox.payload_hash,
                       outbox.execution_id, outbox.event_type, outbox.evidence_reference,
                       outbox.created_at, outbox.status
                FROM audit_events AS event
                LEFT JOIN audit_outbox AS outbox USING (outbox_event_id)
                ORDER BY event.event_sequence
                """
            ).fetchall()
            # Chain rows, head and checkpoint key trust are checked in this same main-DB snapshot.
            return self._verify_rows(
                connection, latest_sequence=latest_sequence, latest_hash=latest_hash,
                all_rows=all_rows, checkpoint_rows=checkpoint_rows,
                from_sequence=from_sequence, include_independent_checkpoint=include_independent_checkpoint,
            )

    def _verify_rows(
        self, connection: Any, *, latest_sequence: int, latest_hash: str,
        all_rows: list[tuple[Any, ...]], checkpoint_rows: list[tuple[Any, ...]],
        from_sequence: int, include_independent_checkpoint: bool,
    ) -> AuditVerificationSnapshot:
        rollback = bool(
            (all_rows and latest_sequence < int(all_rows[-1][0]))
            or (latest_sequence > 0 and (not all_rows or latest_hash != str(all_rows[-1][8])))
        )
        first_invalid: int | None = None
        expected_sequence = 1
        expected_previous = "0" * 64
        for row in all_rows:
            sequence = int(row[0])
            if sequence != expected_sequence:
                first_invalid = sequence
                break
            event_without_hash = {
                "schema_version": str(row[9]),
                "event_sequence": sequence,
                "event_id": str(row[1]),
                "execution_id": None if row[2] is None else str(row[2]),
                "event_type": str(row[3]),
                "timestamp": int(row[4]),
                "payload_hash": str(row[5]),
                "evidence_reference": str(row[6]),
                "previous_event_hash": str(row[7]),
            }
            try:
                self._validate_event(event_without_hash | {"event_hash": str(row[8])})
                self._validate_payload_hash(row[11], row[12])
                if self._is_control_payload(row[11]) and not is_control_outbox(row[10]):
                    raise AuditError("control evidence was downgraded to an unrelated event")
                if is_control_outbox(row[10]):
                    self._validate_control_record(connection, (
                        row[10], row[13], row[14], row[15], row[12], row[11], row[16],
                    ))
                if str(row[10]).startswith("OUTBOX-CRED-REV-") != (
                    row[9] == CREDENTIAL_REVOCATION_VERSION and row[3] == CREDENTIAL_REVOCATION_EVENT
                ):
                    raise AuditError("credential revocation audit version was downgraded")
                if (
                    row[12] != row[5] or row[13] != row[2] or row[15] != row[6]
                    or self._normalize_event_type(str(row[14])) != row[3]
                    or row[17] != "APPENDED" or type(row[16]) is not int
                    or int(row[4]) < row[16]
                ):
                    raise AuditError("audit chain and outbox bindings differ")
                coauthorization_outbox = self._is_coauthorization_outbox_id(row[10])
                if coauthorization_outbox != (
                    event_without_hash["schema_version"] == COAUTHORIZATION_AUDIT_SCHEMA_VERSION
                    and row[3] == COAUTHORIZATION_AUDIT_EVENT_TYPE
                ):
                    raise AuditError("coauthorization audit version was downgraded")
                if self._is_revocation_outbox_id(row[10]) != (
                    event_without_hash["schema_version"] == REVOCATION_AUDIT_SCHEMA_VERSION
                    and row[3] == REVOCATION_AUDIT_EVENT_TYPE
                ):
                    raise AuditError("revocation audit version was downgraded")
                if event_without_hash["schema_version"] == COAUTHORIZATION_AUDIT_SCHEMA_VERSION:
                    self._validate_coauthorization_outbox(
                        outbox_id=row[10], execution_id=row[13], event_type=row[14],
                        evidence_reference=row[15], payload_hash=row[12], payload=row[11],
                        created_at=row[16],
                    )
                    if (
                        row[12] != row[5] or row[14] != row[3] or row[15] != row[6]
                        or row[17] != "APPENDED" or int(row[4]) < row[11]["authorized_at"]
                    ):
                        raise AuditError("coauthorization chain and outbox bindings differ")
                elif event_without_hash["schema_version"] == REVOCATION_AUDIT_SCHEMA_VERSION:
                    self._validate_revocation_outbox(
                        outbox_id=row[10], execution_id=row[13], event_type=row[14],
                        evidence_reference=row[15], payload_hash=row[12], payload=row[11], created_at=row[16],
                    )
                elif self._is_coauthorization_payload(row[11]):
                    raise AuditError("coauthorization evidence was downgraded to a legacy event")
                if self._is_revocation_payload(row[11]) and row[3] != REVOCATION_AUDIT_EVENT_TYPE:
                    raise AuditError("revocation evidence was downgraded to another event")
            except (AuditError, TypeError, ValueError):
                first_invalid = sequence
                break
            if str(row[7]) != expected_previous or self._event_hash(
                event_without_hash
            ) != str(row[8]):
                first_invalid = sequence
                break
            expected_previous = str(row[8])
            expected_sequence += 1
        valid = first_invalid is None and not rollback and latest_sequence == len(all_rows)
        verified_checkpoint = None
        if include_independent_checkpoint:
            checkpoint_valid, checkpoint_rollback = self._verify_checkpoint(
                latest_sequence,
                latest_hash,
                event_hashes={int(row[0]): str(row[8]) for row in all_rows},
                checkpoints=checkpoint_rows,
                connection=connection,
            )
            valid = valid and checkpoint_valid
            rollback = rollback or checkpoint_rollback
            if valid:
                retained = max(checkpoint_rows, key=lambda row: (int(row[1]), int(row[0])))
                signed = dict(retained[3])
                verified_checkpoint = {"signed_checkpoint": signed, "signed_object_hash": signed_object_hash(signed)}
        response = {
            "valid": valid,
            "checked_events": max(0, len(all_rows) - from_sequence + 1)
            if all_rows and from_sequence <= len(all_rows)
            else 0,
            "latest_event_sequence": latest_sequence,
            "rollback_detected": rollback,
            "first_invalid_sequence": first_invalid,
        }
        return AuditVerificationSnapshot(
            response=response, latest_event_hash=latest_hash,
            events={int(row[0]): self._row_event_core(row) for row in all_rows},
            checkpoint=verified_checkpoint,
        )

    @staticmethod
    def _row_event_core(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "schema_version": str(row[9]), "event_sequence": int(row[0]),
            "event_id": str(row[1]), "execution_id": None if row[2] is None else str(row[2]),
            "event_type": str(row[3]), "timestamp": int(row[4]), "payload_hash": str(row[5]),
            "evidence_reference": str(row[6]), "previous_event_hash": str(row[7]), "event_hash": str(row[8]),
        }

    @staticmethod
    def _normalize_event_type(event_type: str) -> str:
        if event_type == CREDENTIAL_REVOCATION_EVENT:
            return event_type
        if event_type in {COAUTHORIZATION_AUDIT_EVENT_TYPE, REVOCATION_AUDIT_EVENT_TYPE}:
            return event_type
        if event_type.startswith("COAUTH_"):
            raise AuditError("unsupported coauthorization audit event type")
        if event_type in AUDIT_EVENT_TYPES:
            return event_type
        if event_type == "RECOVERY_FAILED_FINAL":
            return "EXECUTION_UNKNOWN"
        return "EXECUTION_UNKNOWN"

    @staticmethod
    def _is_coauthorization_payload(payload: Any) -> bool:
        return isinstance(payload, dict) and payload.get("record_type") == "COAUTH_ROOT_AUTHORIZED_V1"

    @staticmethod
    def _is_control_payload(payload: Any) -> bool:
        return isinstance(payload, dict) and payload.get("record_type") in {
            CREDENTIAL_REVOCATION_RECORD, "DISPATCH_CANCELLED_V1",
        }

    @staticmethod
    def _is_coauthorization_outbox_id(outbox_id: Any) -> bool:
        return isinstance(outbox_id, str) and re.fullmatch(
            r"OUTBOX-COAUTH-[0-9a-f]{64}", outbox_id
        ) is not None

    @staticmethod
    def _is_revocation_outbox_id(outbox_id: Any) -> bool:
        return isinstance(outbox_id, str) and outbox_id.startswith("OUTBOX-COAUTH-REV-")

    @staticmethod
    def _is_revocation_payload(payload: Any) -> bool:
        return isinstance(payload, dict) and payload.get("record_type") == REVOCATION_AUDIT_RECORD_TYPE

    @staticmethod
    def _validate_payload_hash(payload: Any, payload_hash: Any) -> None:
        try:
            if type(payload) is not dict or payload_hash != sm3_hex(canonicalize(payload)):
                raise ValueError("payload hash differs")
        except (ValueError, TypeError, RecursionError):
            raise AuditError("audit outbox payload hash is inconsistent") from None

    def _validate_event(self, event: dict[str, Any]) -> None:
        try:
            if event.get("schema_version") == "1.0":
                self.schemas.validate("audit-event.schema.json", event)
            elif event.get("schema_version") == COAUTHORIZATION_AUDIT_SCHEMA_VERSION:
                self.coauthorization_schemas.validate("audit-event-v2.schema.json", event)
            elif event.get("schema_version") == REVOCATION_AUDIT_SCHEMA_VERSION:
                self.coauthorization_schemas.validate("audit-event-v3.schema.json", event)
            elif event.get("schema_version") == CREDENTIAL_REVOCATION_VERSION:
                credential_revocation_schemas().validate("audit-event-v4.schema.json", event)
            else:
                raise AuditError("unsupported audit event schema version")
        except ValidationError:
            raise AuditError("audit event violates its versioned schema") from None

    @staticmethod
    def _validate_control_record(connection, row) -> None:
        try:
            validate_control_outbox(
                connection, outbox_id=row[0], execution_id=row[1], event_type=row[2],
                evidence_reference=row[3], payload_hash=row[4], payload=row[5], created_at=row[6],
            )
        except (ValidationError, ValueError, TypeError, KeyError):
            raise AuditError("credential/dispatch revocation audit binding differs") from None

    @staticmethod
    def _validate_coauthorization_outbox(
        *, outbox_id: Any, execution_id: Any, event_type: Any,
        evidence_reference: Any, payload_hash: Any, payload: Any, created_at: Any,
    ) -> None:
        try:
            validate_authorization_audit_evidence(payload)
            if (
                event_type != COAUTHORIZATION_AUDIT_EVENT_TYPE or execution_id is not None
                or outbox_id != authorization_audit_outbox_id(payload["root_credential_id"])
                or evidence_reference != payload["root_credential_id"]
                or payload_hash != sm3_hex(canonicalize(payload))
                or type(created_at) is not int or created_at != payload["authorized_at"]
            ):
                raise ValueError("outbox metadata differs from evidence")
        except (TypeError, ValueError):
            raise AuditError("coauthorization outbox evidence is inconsistent") from None

    @staticmethod
    def _validate_revocation_outbox(
        *, outbox_id: Any, execution_id: Any, event_type: Any,
        evidence_reference: Any, payload_hash: Any, payload: Any, created_at: Any,
    ) -> None:
        try:
            validate_revocation_audit_outbox(
                outbox_id=outbox_id, execution_id=execution_id, event_type=event_type,
                evidence_reference=evidence_reference, payload_hash=payload_hash, payload=payload, created_at=created_at,
            )
        except (TypeError, ValueError):
            raise AuditError("revocation outbox evidence is inconsistent") from None

    @staticmethod
    def _event_hash(event_without_hash: dict[str, Any]) -> str:
        previous = str(event_without_hash["previous_event_hash"])
        if len(previous) != 64:
            raise AuditError("previous event hash is malformed")
        message = (
            AUDIT_EVENT_HASH.encode("utf-8")
            + b"\x00"
            + bytes.fromhex(previous)
            + canonicalize(event_without_hash)
        )
        return sm3_hex(message)

    def _load_checkpoints(self) -> list[tuple[Any, ...]]:
        if not self.audit_database_url:
            return []
        with connect(self.audit_database_url) as audit_connection:
            audit_connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            return audit_connection.execute(
                """
                SELECT checkpoint_sequence, latest_event_sequence, latest_event_hash,
                       signed_checkpoint, received_at
                FROM audit_checkpoints ORDER BY checkpoint_sequence
                """
            ).fetchall()

    def _verify_checkpoint(
        self,
        latest_sequence: int,
        latest_hash: str,
        *,
        event_hashes: dict[int, str],
        checkpoints: list[tuple[Any, ...]],
        connection: Any | None = None,
    ) -> tuple[bool, bool]:
        if connection is not None:
            return self._verify_checkpoints_with_connection(
                connection, latest_sequence, latest_hash, event_hashes=event_hashes, checkpoints=checkpoints,
            )
        with connect(self.database_url) as standalone_connection:
            return self._verify_checkpoints_with_connection(
                standalone_connection, latest_sequence, latest_hash,
                event_hashes=event_hashes, checkpoints=checkpoints,
            )

    def _verify_checkpoints_with_connection(
        self, connection: Any, latest_sequence: int, latest_hash: str, *,
        event_hashes: dict[int, str], checkpoints: list[tuple[Any, ...]],
    ) -> tuple[bool, bool]:
        if not checkpoints:
            return False, False
        # Every independently retained anchor must still bind its covered prefix.
        for row in checkpoints:
            try:
                signed_checkpoint = dict(row[3])
                self.schemas.validate("audit-checkpoint.schema.json", signed_checkpoint)
                payload = signed_checkpoint["payload"]
                signature = signed_checkpoint["signature"]
                sequence = int(payload["latest_event_sequence"])
                anchor_hash = str(payload["latest_event_hash"])
                if (
                    int(row[0]) != int(payload["checkpoint_sequence"])
                    or int(row[1]) != sequence
                    or str(row[2]) != anchor_hash
                    or signature["signed_at"] != payload["timestamp"]
                ):
                    return False, False
            except (ValidationError, ValueError, TypeError, KeyError, IndexError):
                return False, False
            rollback = (
                sequence > latest_sequence
                or event_hashes.get(sequence) != anchor_hash
                or (sequence == latest_sequence and anchor_hash != latest_hash)
            )
            try:
                key = PostgresKeyRegistry.resolve_for_verification_with_connection(
                    connection,
                    str(signature["key_id"]),
                    expected_subject_id="audit-checkpoint-signer",
                    expected_purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
                    signed_at=int(signature["signed_at"]),
                    trusted_registered_at=(int(row[4]) if len(row) > 4 else None),
                )
            except (KeyRegistryError, ValueError, TypeError):
                return False, rollback
            if not verify_payload(
                payload,
                signature,
                domain_separator=AUDIT_CHECKPOINT,
                expected_key_id=key.key_id,
                expected_key_purpose=key.purpose,
                public_key_hex=key.public_key_hex,
            ):
                return False, rollback
            if rollback:
                return False, True
        return True, False
