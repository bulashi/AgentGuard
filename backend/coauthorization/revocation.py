from __future__ import annotations

from typing import Any, Literal

from jsonschema import ValidationError
from psycopg import OperationalError, errors

from backend.coauthorization.revocation_audit import enqueue_revocation_audit
from backend.coauthorization.verifier import EXTENSION_SCHEMA_ROOT
from backend.common.schema import SchemaStore
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.state.database import connect

RevocationSource = Literal[
    "APPROVAL_KEY_REVOKED", "APPROVAL_KEY_COMPROMISED",
    "APPROVAL_POLICY_REVOKED", "AUTHORIZATION_WITHDRAWN",
]


class CoauthorizationRevocationError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _clock(connection: Any) -> int:
    row = connection.execute(
        "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
    ).fetchone()
    if row is None or type(row[0]) is not int or not 0 <= row[0] <= MAX_SAFE_INTEGER:
        raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "trusted clock is unavailable")
    return row[0]


def _recorded_response(connection: Any, event_id: int, schemas: SchemaStore) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT event.revocation_event_id, event.tenant_id, event.source_kind,
               event.source_identifier, event.observed_at, event.observation_context,
               event.database_actor, COUNT(root.root_credential_id),
               COUNT(root.root_credential_id) FILTER (WHERE root.root_revocation_created)
        FROM coauthorization_revocation_events AS event
        LEFT JOIN coauthorization_revocation_roots AS root USING (revocation_event_id)
        WHERE event.revocation_event_id = %s
        GROUP BY event.revocation_event_id, event.tenant_id, event.source_kind,
                 event.source_identifier, event.observed_at, event.observation_context, event.database_actor
        """,
        (event_id,),
    ).fetchone()
    if row is None or any(
        type(row[index]) is not int or not 0 <= row[index] <= MAX_SAFE_INTEGER
        for index in (0, 4, 7, 8)
    ) or row[0] != event_id or row[8] > row[7]:
        raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "revocation observation is inconsistent")
    response = {
        "schema_version": "1.0", "revocation_event_id": row[0], "tenant_id": row[1],
        "source_kind": row[2], "source_identifier": row[3], "observed_at": row[4],
        "observation_context": row[5], "database_actor": row[6],
        "matched_root_count": row[7], "created_root_revocation_count": row[8],
        "status": "RECORDED",
    }
    try:
        schemas.validate("revocation-response.schema.json", response)
    except ValidationError as exc:
        raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "revocation observation is inconsistent") from exc
    return response


def revoke_coauthorization_source(
    database_url: str, *, tenant_id: str, source_kind: RevocationSource, source_identifier: str,
) -> dict[str, Any]:
    """Administrative database operation; never load approver/Authority private keys."""
    schemas = SchemaStore(EXTENSION_SCHEMA_ROOT)
    document = {"tenant_id": tenant_id, "source_kind": source_kind, "source_identifier": source_identifier}
    try:
        schemas.validate("revocation-request.schema.json", document)
    except ValidationError as exc:
        raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_REQUEST", "invalid revocation target") from exc
    try:
        with connect(database_url) as connection, connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            if source_kind in {"APPROVAL_KEY_REVOKED", "APPROVAL_KEY_COMPROMISED"}:
                key = connection.execute(
                    """
                    SELECT status, activated_at FROM coauthorization_keys
                    WHERE tenant_id = %s AND key_id = %s FOR UPDATE NOWAIT
                    """, (tenant_id, source_identifier),
                ).fetchone()
                if key is None:
                    raise CoauthorizationRevocationError("COAUTH_REVOCATION_NOT_FOUND", "approval key does not exist for this tenant")
                requested_status = "REVOKED" if source_kind == "APPROVAL_KEY_REVOKED" else "COMPROMISED"
                if key[0] not in {"ACTIVE", "RETIRED", "REVOKED", "COMPROMISED"} or (
                    key[0] == "COMPROMISED" and requested_status != "COMPROMISED"
                ):
                    raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "approval key lifecycle cannot move backwards")
                if key[0] != requested_status:
                    observed_at = _clock(connection)
                    if type(key[1]) is not int or not 0 <= key[1] <= observed_at:
                        raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "approval key activation time is inconsistent")
                    if requested_status == "REVOKED":
                        connection.execute(
                            """
                            UPDATE coauthorization_keys SET status = 'REVOKED', revoked_at = COALESCE(revoked_at, %s)
                            WHERE tenant_id = %s AND key_id = %s
                            """, (observed_at, tenant_id, source_identifier),
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE coauthorization_keys SET status = 'COMPROMISED', compromised_at = COALESCE(compromised_at, %s)
                            WHERE tenant_id = %s AND key_id = %s
                            """, (observed_at, tenant_id, source_identifier),
                        )
            elif source_kind == "APPROVAL_POLICY_REVOKED":
                policy = connection.execute(
                    """
                    SELECT status FROM coauthorization_policies
                    WHERE tenant_id = %s AND revision = %s FOR UPDATE NOWAIT
                    """, (tenant_id, source_identifier),
                ).fetchone()
                if policy is None:
                    raise CoauthorizationRevocationError("COAUTH_REVOCATION_NOT_FOUND", "approval policy does not exist for this tenant")
                if policy[0] not in {"ACTIVE", "RETIRED", "REVOKED"}:
                    raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "approval policy lifecycle is inconsistent")
                if policy[0] != "REVOKED":
                    connection.execute(
                        "UPDATE coauthorization_policies SET status = 'REVOKED' WHERE tenant_id = %s AND revision = %s",
                        (tenant_id, source_identifier),
                    )
            context = "EXPLICIT_WITHDRAWAL" if source_kind == "AUTHORIZATION_WITHDRAWN" else "REGISTRY_STATUS_UPDATE"
            event = connection.execute(
                "SELECT apply_coauthorization_revocation(%s, %s, %s, %s)",
                (source_kind, tenant_id, source_identifier, context),
            ).fetchone()
            if event is None or type(event[0]) is not int or not 1 <= event[0] <= MAX_SAFE_INTEGER:
                raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "revocation event is unavailable")
            enqueue_revocation_audit(connection, event[0])
            response = _recorded_response(connection, event[0], schemas)
            if any(response[field] != document[field] for field in document):
                raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "revocation target binding is inconsistent")
            return response
    except (errors.LockNotAvailable, errors.DeadlockDetected, errors.SerializationFailure) as exc:
        raise CoauthorizationRevocationError("COAUTH_REVOCATION_BUSY", "revocation was rolled back; retry the same target") from exc
    except errors.InvalidParameterValue as exc:
        raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "revocation state or observation is inconsistent") from exc
    except (ValueError, TypeError) as exc:
        raise CoauthorizationRevocationError("COAUTH_REVOCATION_INVALID_STATE", "revocation audit evidence is inconsistent") from exc
    except (OperationalError, errors.UndefinedTable, errors.UndefinedColumn, errors.UndefinedFunction, errors.InsufficientPrivilege) as exc:
        raise CoauthorizationRevocationError("COAUTH_REVOCATION_UNAVAILABLE", "revocation storage unavailable; check migrations 0019/0020 and database permissions") from exc
