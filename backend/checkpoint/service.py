from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import ValidationError
from psycopg.types.json import Jsonb

from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.crypto.domains import AUDIT_CHECKPOINT
from backend.crypto.sm import sign_payload
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.identity.key_registry import PostgresKeyRegistry
from backend.state.database import connect


class CheckpointError(RuntimeError):
    pass


class CheckpointService:
    def __init__(
        self,
        database_url: str,
        audit_database_url: str,
        *,
        private_key_file: str,
        key_id: str = "audit-key-01",
        schemas: SchemaStore | None = None,
    ) -> None:
        self.database_url = database_url
        self.audit_database_url = audit_database_url
        self.private_key_file = private_key_file
        self.key_id = key_id
        self.schemas = schemas or SchemaStore()

    def run_once(self, *, current_time: int | None = None) -> dict[str, Any] | None:
        with connect(self.database_url) as connection:
            head = connection.execute(
                """
                SELECT head.latest_event_sequence, head.latest_event_hash,
                       (SELECT MAX(event.event_timestamp) FROM audit_events event
                        WHERE event.event_sequence <= head.latest_event_sequence)
                FROM audit_chain_head head WHERE head.singleton = TRUE
                """
            ).fetchone()
            if head is None or int(head[0]) == 0:
                return None
            latest_sequence = int(head[0])
            latest_hash = str(head[1])
            prefix_timestamp = head[2]
            if type(prefix_timestamp) is not int or not 0 <= prefix_timestamp <= MAX_SAFE_INTEGER:
                raise CheckpointError("audit prefix has no valid event time")
            key = PostgresKeyRegistry.resolve_for_signing_with_connection(
                connection,
                self.key_id,
                expected_subject_id="audit-checkpoint-signer",
                expected_purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
            )
        with connect(self.audit_database_url) as audit_connection, audit_connection.transaction():
            existing = audit_connection.execute(
                """
                SELECT signed_checkpoint FROM audit_checkpoints
                WHERE latest_event_sequence = %s
                """,
                (latest_sequence,),
            ).fetchone()
            if existing is not None:
                signed = dict(existing[0])
                stored_time = signed["payload"]["timestamp"]
                if type(stored_time) is not int or stored_time < prefix_timestamp:
                    raise CheckpointError("stored checkpoint predates its covered audit events")
                return signed
            next_sequence = audit_connection.execute(
                "SELECT COALESCE(MAX(checkpoint_sequence), 0) + 1 FROM audit_checkpoints"
            ).fetchone()[0]
            # Observe the clock after the covered prefix and all database waits.
            timestamp = now_unix() if current_time is None else current_time
            if (
                type(timestamp) is not int
                or not prefix_timestamp <= timestamp <= MAX_SAFE_INTEGER
            ):
                raise CheckpointError("checkpoint clock precedes its covered audit events")
            payload = {
                "schema_version": "1.0",
                "checkpoint_sequence": int(next_sequence),
                "latest_event_sequence": latest_sequence,
                "latest_event_hash": latest_hash,
                "timestamp": timestamp,
            }
            private_key = Path(self.private_key_file).read_text(encoding="ascii").strip()
            signature = sign_payload(
                payload,
                domain_separator=AUDIT_CHECKPOINT,
                key_id=key.key_id,
                key_purpose=key.purpose,
                private_key_hex=private_key,
                public_key_hex=key.public_key_hex,
                signed_at=timestamp,
            )
            signed = {"payload": payload, "signature": signature}
            try:
                self.schemas.validate("audit-checkpoint.schema.json", signed)
            except ValidationError as exc:
                raise CheckpointError("checkpoint violates the frozen schema") from exc
            audit_connection.execute(
                """
                INSERT INTO audit_checkpoints (
                    checkpoint_sequence, latest_event_sequence, latest_event_hash,
                    checkpoint_timestamp, signer_key_id, signature_algorithm,
                    signature_encoding, signature_value, signed_checkpoint, received_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    int(next_sequence),
                    latest_sequence,
                    latest_hash,
                    timestamp,
                    key.key_id,
                    signature["algorithm"],
                    signature["encoding"],
                    signature["value"],
                    Jsonb(signed),
                    timestamp,
                ),
            )
            return signed

    def latest(self) -> dict[str, Any] | None:
        with connect(self.audit_database_url) as audit_connection:
            row = audit_connection.execute(
                """
                SELECT signed_checkpoint
                FROM audit_checkpoints
                ORDER BY checkpoint_sequence DESC
                LIMIT 1
                """
            ).fetchone()
        return None if row is None else dict(row[0])
