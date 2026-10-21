from __future__ import annotations

from psycopg import sql

from backend.coauthorization.contracts import PublicApprovalSetup, RegisteredApprovalKey
from backend.coauthorization.public_keys import valid_public_point
from backend.coauthorization.service import _one
from backend.coauthorization.verifier import EXTENSION_SCHEMA_ROOT, CoauthorizationError, CoauthorizationReason
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.identity.key_registry import lock_key_identities
from backend.state.database import connect


def register_public_approval_policy(database_url: str, setup: PublicApprovalSetup) -> None:
    """Administrative operation only; does not create keys or accept approvals."""
    document = setup.model_dump(mode="json")
    SchemaStore(EXTENSION_SCHEMA_ROOT).validate("public-approval-setup.schema.json", document)
    setup = PublicApprovalSetup.model_validate(document)
    for key in setup.keys:
        if not valid_public_point(key.public_key_hex):
            raise CoauthorizationError(CoauthorizationReason.UNTRUSTED_KEY, "public key is not on the SM2 curve")
    with connect(database_url) as connection, connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                           ("coauthorization-policy:" + setup.policy.tenant_id,))
        policy = setup.policy
        enterprise, finance = policy.required_signers.enterprise_approver, policy.required_signers.finance_approver
        expected = {
            "tenant_id": policy.tenant_id, "revision": policy.revision,
            "enterprise_subject_id": enterprise.subject_id, "enterprise_key_id": enterprise.key_id,
            "finance_subject_id": finance.subject_id, "finance_key_id": finance.key_id,
            "not_before": policy.not_before, "expires_at": policy.expires_at, "status": "ACTIVE",
        }
        existing = _one(connection, """
            SELECT tenant_id, revision, enterprise_subject_id, enterprise_key_id,
                   finance_subject_id, finance_key_id, not_before, expires_at, status
            FROM coauthorization_policies WHERE tenant_id = %s AND revision = %s FOR UPDATE
        """, (policy.tenant_id, policy.revision))
        if existing is not None and existing != expected:
            raise CoauthorizationError(CoauthorizationReason.POLICY_NOT_ACTIVE, "policy revision already differs or is inactive")
        if existing is None and connection.execute("""
            SELECT 1 FROM coauthorization_policies WHERE tenant_id = %s AND status = 'ACTIVE' FOR SHARE
        """, (policy.tenant_id,)).fetchone() is not None:
            raise CoauthorizationError(CoauthorizationReason.POLICY_NOT_ACTIVE, "retire the existing policy before registering a new revision")
        lock_key_identities(connection, ((key.key_id, key.public_key_hex) for key in setup.keys))
        for key in sorted(setup.keys, key=lambda item: item.key_id):
            if connection.execute("""
                SELECT 1 FROM key_registry WHERE key_id = %s OR public_key_hex = %s LIMIT 1
            """, (key.key_id, key.public_key_hex)).fetchone() is not None:
                raise CoauthorizationError(CoauthorizationReason.UNTRUSTED_KEY, "approval key overlaps a runtime key")
            if now_unix() >= key.expires_at:
                raise CoauthorizationError(CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID, "public key is expired")
            values = key.model_dump(mode="json")
            names = tuple(values)
            connection.execute(
                sql.SQL("INSERT INTO coauthorization_keys ({}) VALUES ({}) ON CONFLICT (key_id) DO NOTHING").format(
                    sql.SQL(", ").join(sql.Identifier(name) for name in names),
                    sql.SQL(", ").join(sql.Placeholder() for _ in names),
                ),
                tuple(values[name] for name in names),
            )
            stored = _one(connection, "SELECT * FROM coauthorization_keys WHERE key_id = %s FOR UPDATE", (key.key_id,))
            if stored is None or RegisteredApprovalKey.model_validate(stored) != key:
                raise CoauthorizationError(CoauthorizationReason.UNTRUSTED_KEY, "key id already has different metadata")
        if now_unix() >= policy.expires_at:
            raise CoauthorizationError(CoauthorizationReason.POLICY_EXPIRED_OR_NOT_YET_VALID, "policy is expired")
        if existing is not None:
            return
        connection.execute("""
            INSERT INTO coauthorization_policies (
                tenant_id, revision, enterprise_subject_id, enterprise_key_id, finance_subject_id,
                finance_key_id, not_before, expires_at, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'ACTIVE')
        """, (policy.tenant_id, policy.revision, enterprise.subject_id, enterprise.key_id,
              finance.subject_id, finance.key_id, policy.not_before, policy.expires_at))
