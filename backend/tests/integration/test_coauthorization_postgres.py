"""Opt-in PostgreSQL tests; no HTTP server or deployment keys are used.

The operator must create a disposable database named agentguard_coauth_test_*
and apply all current database/migrations/main migrations before running this module.
Only AGENTGUARD_COAUTHORIZATION_TEST_DATABASE_URL opts in. An unset variable
means SKIP, not a successful database verification. This module never applies
migrations, creates databases, or falls back to another database setting.

SM2 keys and signatures are real, but all private material stays in memory.
tmp_path supplies an already temporary constructor root, with no private files.
An operator requiring temporary files on F: must also place pytest's basetemp
under the project before running pytest.

Authorization evidence stays PENDING in audit_outbox. These tests never append
the database-wide outbox or alter audit history/head. Cleanup refuses any case
whose authorization evidence has already been appended.
"""

from __future__ import annotations

import ast
import json
import os
import re
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from threading import Barrier
from time import monotonic
from types import SimpleNamespace
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg import IsolationLevel, ProgrammingError, errors, sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row
from pydantic import ValidationError

from backend.authorization.contracts import AuthorizeTaskRequest
from backend.authorization.app import make_app as make_authority_app
from backend.authorization.policy import build_root_capabilities
from backend.authorization.service import AuthorizationError, RootAuthorizationService
from backend.coauthorization import provisioning as coauthorization_provisioning
from backend.coauthorization import service as coauthorization_service
from backend.coauthorization.audit import (
    COAUTHORIZATION_AUDIT_EVENT_TYPE,
    MAX_EVIDENCE_BYTES,
    validate_authorization_audit_evidence,
)
from backend.coauthorization.contracts import (
    APPROVAL_PURPOSE,
    COAUTHORIZATION_DOMAIN,
    ApprovalPayload,
    ApprovalRole,
    ChallengeResponse,
    CoauthorizationBundle,
    CoauthorizationResponse,
    CreateChallengeRequest,
    PublicApprovalSetup,
    RegisteredApprovalKey,
    TrustedApprovalPolicy,
)
from backend.coauthorization.provisioning import register_public_approval_policy
from backend.coauthorization.review import CoauthorizationReadService
from backend.coauthorization.revocation import revoke_coauthorization_source
from backend.coauthorization.service import CoauthorizationService
from backend.coauthorization.verifier import (
    CoauthorizationError,
    CoauthorizationReason,
    build_approval_statement,
)
from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.error_codes import ReasonCode
from backend.common.schema import PROJECT_ROOT
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import CAPABILITY_CREDENTIAL
from backend.crypto.sm import (
    Sm2KeyPair,
    derive_public_key,
    generate_keypair,
    sign_payload,
    signed_object_hash,
    sm3_hex,
    verify_payload,
)
from backend.crypto.strict_json import parse_strict_json
from backend.identity import key_registry as identity_key_registry
from backend.identity.key_registry import KeyRecord, PostgresKeyRegistry
from backend.state.database import connect, psycopg_url

pytestmark = pytest.mark.integration

TEST_DATABASE_ENV = "AGENTGUARD_COAUTHORIZATION_TEST_DATABASE_URL"
DATABASE_NAME = re.compile(r"agentguard_coauth_test_[A-Za-z0-9_]+", re.ASCII)
ROLES: tuple[ApprovalRole, ApprovalRole] = ("ENTERPRISE_APPROVER", "FINANCE_APPROVER")


def _validated_database_url(candidate: str) -> tuple[str, str]:
    """Validate explicit local targets without libpq query or service overrides."""
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
        parameters = conninfo_to_dict(psycopg_url(candidate))
    except (ValueError, ProgrammingError):
        pytest.fail(f"{TEST_DATABASE_ENV} must be an explicit PostgreSQL URI", pytrace=False)
    database_name = unquote(parsed.path.removeprefix("/"))
    if (
        parsed.scheme not in {"postgres", "postgresql", "postgresql+psycopg"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1", "postgres"}
        or port is None
        or not 1 <= port <= 65535
        or not parsed.username
        or not parsed.password
        or DATABASE_NAME.fullmatch(database_name) is None
        or parameters.get("dbname") != database_name
        or parameters.get("host") != parsed.hostname
        or parameters.get("port") != str(port)
        or "hostaddr" in parameters
        or "service" in parameters
        or "servicefile" in parameters
        or os.getenv("PGSERVICE")
        or os.getenv("PGSERVICEFILE")
    ):
        pytest.fail(
            "Refusing to connect: require an explicit local host, port, credentials, "
            "and agentguard_coauth_test_ database; query, fragment, and service overrides "
            "are forbidden",
            pytrace=False,
        )
    return make_conninfo(
        host=parsed.hostname,
        port=port,
        user=unquote(parsed.username),
        password=unquote(parsed.password),
        dbname=database_name,
        application_name="agentguard-coauthorization-test",
        connect_timeout=5,
        options="-c search_path=public -c statement_timeout=15000 -c lock_timeout=10000",
    ), database_name


@pytest.fixture(scope="module")
def coauthorization_database_url() -> str:
    candidate = os.getenv(TEST_DATABASE_ENV)
    if not candidate:
        pytest.skip(f"Set {TEST_DATABASE_ENV} explicitly; database behavior is unverified")
    database_url, expected_name = _validated_database_url(candidate)
    required_columns = {
        "agent_identities": {"agent_id", "display_name", "agent_type", "created_at"},
        "key_registry": {
            "key_id",
            "subject_id",
            "subject_type",
            "purpose",
            "public_key_hex",
            "status",
            "material_state",
            "private_key_reference",
            "activated_at",
            "replaced_by",
        },
        "tickets": {"ticket_id", "tenant_id", "customer_id", "created_at", "updated_at"},
        "tasks": {
            "task_id",
            "tenant_id",
            "ticket_id",
            "customer_id",
            "refund_total_fen",
            "max_tool_calls",
            "created_at",
            "updated_at",
            "expires_at",
            "status",
        },
        "credentials": {
            "credential_id",
            "credential_type",
            "task_id",
            "tenant_id",
            "signed_object",
            "signed_object_hash",
            "issuer_key_id",
            "holder_agent_id",
            "holder_key_id",
        },
        "credential_budget_state": {
            "credential_id",
            "quota_type",
            "limit_value",
            "reserved_value",
            "committed_value",
            "version",
            "updated_at",
        },
        "credential_revocations": {
            "credential_id",
            "revoked_at",
            "revoked_by",
            "revocation_reason",
        },
        "audit_outbox": {
            "outbox_event_id",
            "execution_id",
            "event_type",
            "evidence_reference",
            "payload",
            "payload_hash",
            "status",
            "created_at",
            "appended_at",
        },
        "audit_events": {
            "evidence_reference",
            "outbox_event_id",
            "event_type",
            "schema_version",
        },
        "authorization_confirmations": {"task_id", "credential_id", "request_hash"},
        "coauthorization_keys": set(RegisteredApprovalKey.model_fields),
        "coauthorization_policies": {
            "tenant_id",
            "revision",
            "enterprise_subject_id",
            "enterprise_key_id",
            "finance_subject_id",
            "finance_key_id",
            "not_before",
            "expires_at",
            "status",
        },
        "coauthorization_challenges": {
            "challenge_id",
            "tenant_id",
            "task_id",
            "policy_revision",
            "approval_payload",
            "approval_payload_hash",
            "issued_at",
            "expires_at",
            "status",
            "bundle_hash",
            "signed_bundle",
            "root_credential_id",
            "root_credential_hash",
            "consumed_at",
            "revoked_at",
        },
        "coauthorization_authorizations": {
            "task_id",
            "challenge_id",
            "root_credential_id",
            "approval_payload_hash",
            "bundle_hash",
            "enterprise_subject_id",
            "enterprise_key_id",
            "finance_subject_id",
            "finance_key_id",
            "authorized_at",
        },
    }
    required_indexes = {
        "uq_root_credential_per_task",
        "uq_coauthorization_active_policy",
        "uq_coauthorization_pending_task",
    }
    required_triggers = {
        "coauthorization_key_immutable",
        "coauthorization_policy_immutable",
        "coauthorization_challenge_immutable",
    }
    with connect(database_url) as connection:
        connection.execute("SET TRANSACTION READ ONLY")
        actual_name = connection.execute("SELECT current_database()").fetchone()
        if actual_name != (expected_name,):
            pytest.fail("Refusing writes: current_database() differs from the validated name")
        columns: dict[str, set[str]] = {}
        for table, column in connection.execute(
            """
            SELECT table_name, column_name FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = ANY(%s)
            """,
            (list(required_columns),),
        ).fetchall():
            columns.setdefault(table, set()).add(column)
        missing = {
            table: sorted(expected - columns.get(table, set()))
            for table, expected in required_columns.items()
            if not expected <= columns.get(table, set())
        }
        indexes = {
            row[0]
            for row in connection.execute(
                """
                SELECT relation.relname FROM pg_index AS index_info
                JOIN pg_class AS relation ON relation.oid = index_info.indexrelid
                JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname = 'public'
                  AND index_info.indisunique AND index_info.indisvalid
                  AND relation.relname = ANY(%s)
                """,
                (list(required_indexes),),
            ).fetchall()
        }
        triggers = {
            row[0]
            for row in connection.execute(
                """
                SELECT trigger_info.tgname FROM pg_trigger AS trigger_info
                JOIN pg_class AS relation ON relation.oid = trigger_info.tgrelid
                JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname = 'public' AND NOT trigger_info.tgisinternal
                  AND trigger_info.tgenabled IN ('O', 'A') AND trigger_info.tgname = ANY(%s)
                """,
                (list(required_triggers),),
            ).fetchall()
        }
    if missing or indexes != required_indexes or triggers != required_triggers:
        pytest.fail(
            "Apply main 0001..0016 migrations yourself to the disposable database first. "
            f"Missing columns: {missing}; indexes: {sorted(required_indexes - indexes)}; "
            f"triggers: {sorted(required_triggers - triggers)}",
            pytrace=False,
        )
    return database_url


class MemoryPrivateKeyStore:
    """Only the storage boundary is injected; signing and verification stay real."""

    def __init__(self) -> None:
        self._pairs: dict[str, Sm2KeyPair] = {}
        self.loaded_references: list[str] = []

    def add(self, key_id: str, pair: Sm2KeyPair) -> str:
        reference = f"memory:{key_id}"
        assert derive_public_key(pair.private_key_hex) == pair.public_key_hex
        self._pairs[reference] = pair
        return reference

    def load(self, reference: str) -> str:
        pair = self._pairs[reference]
        self.loaded_references.append(reference)
        return pair.private_key_hex

    def clear(self) -> None:
        self._pairs.clear()


@dataclass
class ApprovalClock:
    value: int

    def __call__(self) -> int:
        return self.value


def _read_state(connection: Any, task_id: str) -> dict[str, Any]:
    with connection.cursor(row_factory=dict_row) as cursor:
        task = cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (task_id,)).fetchone()
        assert task is not None
        roots = cursor.execute(
            "SELECT * FROM credentials WHERE task_id = %s ORDER BY credential_id", (task_id,)
        ).fetchall()
        budgets = cursor.execute(
            """
            SELECT budget.* FROM credential_budget_state AS budget
            JOIN credentials AS credential USING (credential_id)
            WHERE credential.task_id = %s ORDER BY budget.credential_id, budget.quota_type
            """,
            (task_id,),
        ).fetchall()
        confirmations = cursor.execute(
            "SELECT * FROM authorization_confirmations WHERE task_id = %s", (task_id,)
        ).fetchall()
        challenges = cursor.execute(
            """
            SELECT * FROM coauthorization_challenges WHERE task_id = %s ORDER BY challenge_id
            """,
            (task_id,),
        ).fetchall()
        authorizations = cursor.execute(
            "SELECT * FROM coauthorization_authorizations WHERE task_id = %s", (task_id,)
        ).fetchall()
        revocations = cursor.execute(
            """
            SELECT revocation.* FROM credential_revocations AS revocation
            JOIN credentials AS credential USING (credential_id)
            WHERE credential.task_id = %s ORDER BY credential_id
            """,
            (task_id,),
        ).fetchall()
        evidence_references = [
            task_id,
            *(row["credential_id"] for row in roots),
            *(row["challenge_id"] for row in challenges),
        ]
        audit_outbox = cursor.execute(
            """
            SELECT * FROM audit_outbox
            WHERE evidence_reference = ANY(%s) OR payload ->> 'task_id' = %s
            ORDER BY outbox_event_id
            """,
            (evidence_references, task_id),
        ).fetchall()
        audit_events = cursor.execute(
            """
            SELECT event.* FROM audit_events AS event
            JOIN audit_outbox AS outbox USING (outbox_event_id)
            WHERE event.evidence_reference = ANY(%s) OR outbox.payload ->> 'task_id' = %s
            ORDER BY event_sequence
            """,
            (evidence_references, task_id),
        ).fetchall()
    return {
        "task": task,
        "roots": roots,
        "budgets": budgets,
        "confirmations": confirmations,
        "challenges": challenges,
        "authorizations": authorizations,
        "revocations": revocations,
        "audit_outbox": audit_outbox,
        "audit_events": audit_events,
    }


class CoauthorizationCase:
    def __init__(self, database_url: str, tmp_path: Path) -> None:
        self.database_url = database_url
        self.prefix = f"coauth-test-{uuid4().hex}"
        self.clock = ApprovalClock(now_unix())
        self.namespace_claimed = False
        self.tenant_id = self.identifier("tenant")
        self.ticket_id = self.identifier("ticket")
        self.customer_id = self.identifier("customer")
        self.other_ticket_id = self.identifier("other-ticket")
        self.other_customer_id = self.identifier("other-customer")
        self.task_id = self.identifier("task")
        self.private_keys = MemoryPrivateKeyStore()
        self.approval_pairs: dict[str, Sm2KeyPair] = {}
        self.task_ids: set[str] = set()
        self.ticket_ids: set[str] = set()
        self.agent_ids: set[str] = set()
        self.runtime_key_ids: set[str] = set()
        self.approval_key_ids: set[str] = set()
        self.policy_ids: set[tuple[str, str]] = set()
        self.authority_pair = generate_keypair()
        self.authority = self._runtime_record(
            "authority", self.authority_pair, "AUTHORITY", KeyPurpose.AUTHORIZATION_ROOT_SIGNING
        )
        self.holder = self._runtime_record(
            "holder", generate_keypair(), "AGENT", KeyPurpose.AGENT_HOLDER_SIGNING
        )
        self.other_holder = self._runtime_record(
            "other-holder", generate_keypair(), "AGENT", KeyPurpose.AGENT_HOLDER_SIGNING
        )
        self.root = RootAuthorizationService(
            database_url=database_url,
            private_key_root=str(tmp_path),
            authority_subject_id=self.authority.subject_id,
            authority_key_id=self.authority.key_id,
            trusted_confirmers={self.identifier("legacy-confirmer"): "POLICY"},
            coauthorization_required=True,
        )
        self.root.private_keys = self.private_keys
        self.service = CoauthorizationService(
            root_service=self.root, challenge_ttl_seconds=300, clock=self.clock
        )
        self.request = CreateChallengeRequest(
            holder_agent_id=self.holder.subject_id,
            holder_key_id=self.holder.key_id,
            delegation_depth=2,
        )
        self.setup = self.public_setup("initial", tenant_id=self.tenant_id)

    def identifier(self, suffix: str) -> str:
        return f"{self.prefix}-{suffix}"

    def _runtime_record(
        self,
        label: str,
        pair: Sm2KeyPair,
        subject_type: str,
        purpose: KeyPurpose,
    ) -> KeyRecord:
        key_id = self.identifier(f"{label}-key")
        return KeyRecord(
            key_id=key_id,
            subject_id=self.identifier(label),
            subject_type=subject_type,
            purpose=purpose,
            public_key_hex=pair.public_key_hex,
            status=KeyState.ACTIVE,
            material_state=KeyMaterialState.PRESENT,
            private_key_reference=self.private_keys.add(key_id, pair),
            activated_at=self.clock.value - 120,
            created_at=self.clock.value - 120,
        )

    def public_setup(self, label: str, *, tenant_id: str | None = None) -> PublicApprovalSetup:
        tenant = tenant_id or self.identifier(f"{label}-tenant")
        records = []
        for role, short in zip(ROLES, ("enterprise", "finance"), strict=True):
            key_id = self.identifier(f"{label}-{short}-key")
            pair = generate_keypair()
            self.approval_pairs[key_id] = pair
            self.approval_key_ids.add(key_id)
            records.append(
                RegisteredApprovalKey(
                    tenant_id=tenant,
                    subject_id=self.identifier(f"{label}-{short}-subject"),
                    principal_id=self.identifier(f"{label}-{short}-principal"),
                    key_id=key_id,
                    role=role,
                    approval_purpose=APPROVAL_PURPOSE,
                    signing_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING.value,
                    algorithm="SM2",
                    public_key_hex=pair.public_key_hex,
                    status="ACTIVE",
                    activated_at=self.clock.value - 120,
                    expires_at=self.clock.value + 86_400,
                    retired_at=None,
                    revoked_at=None,
                    compromised_at=None,
                )
            )
        policy = TrustedApprovalPolicy(
            tenant_id=tenant,
            revision=self.identifier(f"{label}-policy"),
            required_signers={
                "enterprise_approver": {
                    "subject_id": records[0].subject_id,
                    "key_id": records[0].key_id,
                },
                "finance_approver": {
                    "subject_id": records[1].subject_id,
                    "key_id": records[1].key_id,
                },
            },
            not_before=self.clock.value - 120,
            expires_at=self.clock.value + 7_200,
        )
        self.policy_ids.add((policy.tenant_id, policy.revision))
        return PublicApprovalSetup(policy=policy, keys=records)

    def seed(self) -> None:
        # Refuse an occupied namespace before any fixture write or later cleanup.
        with connect(self.database_url) as connection, connection.transaction():
            for table, column in (
                ("tasks", "task_id"),
                ("tickets", "ticket_id"),
                ("agent_identities", "agent_id"),
                ("key_registry", "key_id"),
                ("coauthorization_keys", "key_id"),
                ("coauthorization_policies", "tenant_id"),
            ):
                query = sql.SQL("SELECT 1 FROM {} WHERE left({}, length(%s)) = %s LIMIT 1").format(
                    sql.Identifier(table), sql.Identifier(column)
                )
                assert connection.execute(query, (self.prefix, self.prefix)).fetchone() is None
            self.namespace_claimed = True
            for record in (self.holder, self.other_holder):
                connection.execute(
                    """
                    INSERT INTO agent_identities (agent_id, display_name, agent_type, created_at)
                    VALUES (%s, %s, 'coauthorization-test', %s)
                    """,
                    (record.subject_id, record.subject_id, self.clock.value - 60),
                )
            for ticket_id, customer_id in (
                (self.ticket_id, self.customer_id),
                (self.other_ticket_id, self.other_customer_id),
            ):
                connection.execute(
                    """
                    INSERT INTO tickets (
                        ticket_id, tenant_id, customer_id, title, description, status,
                        created_at, updated_at
                    ) VALUES (%s, %s, %s, 'Coauthorization test', 'Isolated fixture', 'OPEN', %s, %s)
                    """,
                    (
                        ticket_id,
                        self.tenant_id,
                        customer_id,
                        self.clock.value - 60,
                        self.clock.value - 60,
                    ),
                )
        self.agent_ids.update((self.holder.subject_id, self.other_holder.subject_id))
        self.ticket_ids.update((self.ticket_id, self.other_ticket_id))
        registry = PostgresKeyRegistry(self.database_url)
        for record in (self.authority, self.holder, self.other_holder):
            registry.register(record)
            self.runtime_key_ids.add(record.key_id)
        register_public_approval_policy(self.database_url, self.setup)
        self.create_task("task")

    def create_task(self, label: str) -> str:
        task_id = self.identifier(label)
        with connect(self.database_url) as connection, connection.transaction():
            connection.execute(
                """
                INSERT INTO tasks (
                    task_id, tenant_id, ticket_id, customer_id, refund_total_fen,
                    max_tool_calls, expires_at, status, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, 7000, 4, %s, 'PENDING_AUTHORIZATION', %s, %s)
                """,
                (
                    task_id,
                    self.tenant_id,
                    self.ticket_id,
                    self.customer_id,
                    self.clock.value + 3_600,
                    self.clock.value - 60,
                    self.clock.value - 60,
                ),
            )
        self.task_ids.add(task_id)
        return task_id

    def challenge(self) -> ChallengeResponse:
        return self.service.create_challenge(self.task_id, self.request)

    def signed_bundle(self, payload: ApprovalPayload) -> dict[str, Any]:
        approvals = []
        for role in ROLES:
            statement = build_approval_statement(
                payload=payload, role=role, approved_at=payload.approval_not_before
            ).model_dump(mode="json")
            pair = self.approval_pairs[statement["key_id"]]
            signature = sign_payload(
                statement,
                domain_separator=COAUTHORIZATION_DOMAIN,
                key_id=statement["key_id"],
                key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
                private_key_hex=pair.private_key_hex,
                public_key_hex=pair.public_key_hex,
                signed_at=statement["approved_at"],
            )
            assert verify_payload(
                statement,
                signature,
                domain_separator=COAUTHORIZATION_DOMAIN,
                expected_key_id=statement["key_id"],
                expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
                public_key_hex=pair.public_key_hex,
            )
            self.service.schemas.validate("approval-statement.schema.json", statement)
            approvals.append({"statement": statement, "signature": signature})
        bundle = CoauthorizationBundle.model_validate(
            {
                "payload": payload.model_dump(mode="json"),
                "approvals": approvals,
            }
        ).model_dump(mode="json")
        self.service.schemas.validate("approval-payload.schema.json", bundle["payload"])
        self.service.schemas.validate("coauthorization-bundle.schema.json", bundle)
        return bundle

    def state(self, task_id: str | None = None) -> dict[str, Any]:
        with connect(self.database_url) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            return _read_state(connection, task_id or self.task_id)

    def registration_state(self, setup: PublicApprovalSetup) -> tuple[list, list]:
        with connect(self.database_url) as connection, connection.cursor(row_factory=dict_row) as c:
            keys = c.execute(
                "SELECT * FROM coauthorization_keys WHERE key_id = ANY(%s) ORDER BY key_id",
                ([record.key_id for record in setup.keys],),
            ).fetchall()
            policies = c.execute(
                "SELECT * FROM coauthorization_policies WHERE tenant_id = %s AND revision = %s",
                (setup.policy.tenant_id, setup.policy.revision),
            ).fetchall()
        return keys, policies

    def cleanup(self) -> None:
        if not self.namespace_claimed:
            return
        with connect(self.database_url) as connection, connection.transaction():
            connection.execute("SET TRANSACTION READ ONLY")
            if (
                connection.execute(
                    "SELECT 1 FROM coauthorization_revocation_events WHERE tenant_id = %s LIMIT 1",
                    (self.tenant_id,),
                ).fetchone()
                is not None
            ):
                # V3 observations and journal pages are immutable; retain this isolated namespace.
                return
        task_ids = sorted(self.task_ids)
        for identifier in (
            *task_ids,
            *self.ticket_ids,
            *self.agent_ids,
            *self.runtime_key_ids,
            *self.approval_key_ids,
            *(identifier for pair in self.policy_ids for identifier in pair),
        ):
            assert identifier.startswith(f"{self.prefix}-")
        with connect(self.database_url) as connection, connection.transaction():
            root_ids = [
                row[0]
                for row in connection.execute(
                    """
                    SELECT credential_id FROM credentials
                    WHERE task_id = ANY(%s) AND tenant_id = %s AND credential_type = 'ROOT'
                    ORDER BY credential_id FOR UPDATE
                    """,
                    (task_ids, self.tenant_id),
                ).fetchall()
            ]
            expected_outbox_ids = [
                "OUTBOX-COAUTH-" + sm3_hex(root_id.encode("utf-8")) for root_id in root_ids
            ]
            outbox_rows = connection.execute(
                """
                SELECT outbox_event_id, execution_id, event_type, evidence_reference, status
                FROM audit_outbox
                WHERE evidence_reference = ANY(%s) OR outbox_event_id = ANY(%s)
                ORDER BY outbox_event_id FOR UPDATE
                """,
                (root_ids, expected_outbox_ids),
            ).fetchall()
            if (
                any(row[4] == "APPENDED" for row in outbox_rows)
                or connection.execute(
                    """
                SELECT 1 FROM audit_events
                WHERE evidence_reference = ANY(%s) OR outbox_event_id = ANY(%s) LIMIT 1
                """,
                    (root_ids, expected_outbox_ids),
                ).fetchone()
                is not None
            ):
                raise RuntimeError(
                    "Refusing cleanup: this case has APPENDED authorization evidence; "
                    "audit history, chain head and all case rows must remain intact"
                )
            if any(
                row[4] != "PENDING"
                or row[1] is not None
                or row[2] != COAUTHORIZATION_AUDIT_EVENT_TYPE
                or row[3] not in root_ids
                or row[0] != "OUTBOX-COAUTH-" + sm3_hex(row[3].encode("utf-8"))
                for row in outbox_rows
            ):
                raise RuntimeError("Refusing cleanup: unexpected authorization outbox binding")
            removed = connection.execute(
                """
                DELETE FROM audit_outbox AS outbox
                WHERE outbox.evidence_reference = ANY(%s)
                  AND outbox.outbox_event_id = ANY(%s) AND outbox.status = 'PENDING'
                  AND NOT EXISTS (
                      SELECT 1 FROM audit_events AS event
                      WHERE event.outbox_event_id = outbox.outbox_event_id
                  )
                """,
                (root_ids, expected_outbox_ids),
            )
            assert removed.rowcount == len(outbox_rows)
            # Derived root/challenge IDs belong to these exact, newly seeded tasks.
            connection.execute(
                "DELETE FROM coauthorization_authorizations WHERE task_id = ANY(%s)", (task_ids,)
            )
            connection.execute(
                "DELETE FROM coauthorization_challenges WHERE task_id = ANY(%s)", (task_ids,)
            )
            connection.execute(
                "DELETE FROM authorization_confirmations WHERE task_id = ANY(%s)", (task_ids,)
            )
            for table in ("credential_budget_state", "credential_revocations"):
                query = sql.SQL(
                    "DELETE FROM {} AS child USING credentials AS credential "
                    "WHERE child.credential_id = credential.credential_id "
                    "AND credential.task_id = ANY(%s) AND credential.tenant_id = %s"
                ).format(sql.Identifier(table))
                connection.execute(query, (task_ids, self.tenant_id))
            connection.execute(
                "DELETE FROM credentials WHERE task_id = ANY(%s) AND tenant_id = %s",
                (task_ids, self.tenant_id),
            )
            connection.execute(
                "DELETE FROM tasks WHERE task_id = ANY(%s) AND tenant_id = %s",
                (task_ids, self.tenant_id),
            )
            for tenant_id, revision in sorted(self.policy_ids):
                connection.execute(
                    "DELETE FROM coauthorization_policies WHERE tenant_id = %s AND revision = %s",
                    (tenant_id, revision),
                )
            connection.execute(
                "DELETE FROM coauthorization_keys WHERE key_id = ANY(%s)",
                (sorted(self.approval_key_ids),),
            )
            connection.execute(
                "DELETE FROM tickets WHERE ticket_id = ANY(%s) AND tenant_id = %s",
                (sorted(self.ticket_ids), self.tenant_id),
            )
            connection.execute(
                "DELETE FROM key_registry WHERE key_id = ANY(%s)",
                (sorted(self.runtime_key_ids),),
            )
            connection.execute(
                "DELETE FROM agent_identities WHERE agent_id = ANY(%s)",
                (sorted(self.agent_ids),),
            )


@pytest.fixture
def case(coauthorization_database_url: str, tmp_path: Path) -> Iterator[CoauthorizationCase]:
    value = CoauthorizationCase(coauthorization_database_url, tmp_path)
    try:
        value.seed()
        yield value
    finally:
        try:
            value.cleanup()
        finally:
            value.private_keys.clear()
            value.approval_pairs.clear()


def _assert_pending(state: dict[str, Any], *, challenge_count: int) -> None:
    assert state["task"]["status"] == "PENDING_AUTHORIZATION"
    assert state["roots"] == []
    assert state["budgets"] == []
    assert state["confirmations"] == []
    assert state["authorizations"] == []
    assert state["revocations"] == []
    assert state["audit_outbox"] == []
    assert state["audit_events"] == []
    assert len(state["challenges"]) == challenge_count
    for challenge in state["challenges"]:
        assert challenge["status"] == "PENDING"
        for name in (
            "bundle_hash",
            "signed_bundle",
            "root_credential_id",
            "root_credential_hash",
            "consumed_at",
            "revoked_at",
        ):
            assert challenge[name] is None


def _set_runtime_activation(
    case: CoauthorizationCase,
    record: KeyRecord,
    activated_at: int,
) -> None:
    assert record.key_id in case.runtime_key_ids
    assert record.key_id.startswith(f"{case.prefix}-")
    with connect(case.database_url) as connection, connection.transaction():
        assert (
            connection.execute(
                """
            UPDATE key_registry SET activated_at = %s
            WHERE key_id = %s AND subject_id = %s AND public_key_hex = %s
            """,
                (activated_at, record.key_id, record.subject_id, record.public_key_hex),
            ).rowcount
            == 1
        )
    assert PostgresKeyRegistry(case.database_url).get(record.key_id) == replace(
        record,
        activated_at=activated_at,
    )


def _rewind_after_locked_scope(
    case: CoauthorizationCase,
    monkeypatch: Any,
    timestamp: int,
) -> list[int]:
    original_scope = case.service._scope
    observed: list[int] = []

    def scope_then_rewind(connection: Any, task: dict[str, Any], holder: Any) -> Any:
        # The real service locks/reads runtime keys before entering this real scope check.
        task_scope = original_scope(connection, task, holder)
        observed.append(case.clock.value)
        case.clock.value = timestamp
        return task_scope

    monkeypatch.setattr(case.service, "_scope", scope_then_rewind)
    return observed


def _runtime_registration_candidate(
    case: CoauthorizationCase,
    approval: RegisteredApprovalKey,
    collision: str,
) -> KeyRecord:
    assert collision in {"key_id", "public_key"}
    pair = generate_keypair() if collision == "key_id" else case.approval_pairs[approval.key_id]
    candidate = case._runtime_record(
        f"runtime-{collision}-reuse",
        pair,
        "AUTHORITY",
        KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
    )
    if collision == "key_id":
        candidate = replace(
            candidate,
            key_id=approval.key_id,
            private_key_reference=case.private_keys.add(approval.key_id, pair),
        )
        assert candidate.public_key_hex != approval.public_key_hex
    else:
        assert candidate.key_id != approval.key_id
    assert (candidate.key_id == approval.key_id) == (collision == "key_id")
    assert (candidate.public_key_hex == approval.public_key_hex) == (collision == "public_key")
    # Track attempted identities as well, so an unexpected successful insert is still cleaned up.
    case.runtime_key_ids.add(candidate.key_id)
    return candidate


def _reject_unchanged(
    case: CoauthorizationCase,
    raw: bytes,
    reason: CoauthorizationReason,
    *,
    task_id: str | None = None,
) -> CoauthorizationError:
    target = task_id or case.task_id
    before = case.state(target)
    with pytest.raises(CoauthorizationError) as error:
        case.service.authorize_task(target, raw)
    assert error.value.reason_code == reason
    assert case.state(target) == before
    return error.value


def _assert_authorized(
    case: CoauthorizationCase,
    challenge: ChallengeResponse,
    bundle: dict[str, Any],
    response: CoauthorizationResponse,
) -> dict[str, Any]:
    state = case.state()
    task = state["task"]
    assert task["status"] == "AUTHORIZED"
    assert len(state["roots"]) == 1
    assert len(state["budgets"]) == 2
    assert len(state["challenges"]) == 1
    assert len(state["authorizations"]) == 1
    assert state["confirmations"] == []
    assert state["revocations"] == []
    root = state["roots"][0]
    assert root["credential_type"] == "ROOT"
    assert root["credential_id"] == response.root_credential_id
    assert root["signed_object"] == response.credential
    assert root["signed_object_hash"] == response.root_credential_hash
    assert signed_object_hash(response.credential) == response.root_credential_hash
    assert root["task_id"] == case.task_id
    assert root["tenant_id"] == case.tenant_id
    assert root["issuer_key_id"] == case.authority.key_id
    assert root["holder_agent_id"] == case.holder.subject_id
    assert root["holder_key_id"] == case.holder.key_id
    assert root["parent_credential_id"] is None
    assert root["parent_credential_hash"] is None
    payload = response.credential["payload"]
    assert challenge.payload.not_before == task["created_at"]
    assert payload["not_before"] == root["not_before"] == task["created_at"]
    assert payload["issued_at"] == root["issued_at"] == case.clock.value
    assert task["updated_at"] == case.clock.value
    assert payload["issuer"] == {
        "subject_id": case.authority.subject_id,
        "key_id": case.authority.key_id,
    }
    for name in (
        "tenant_id",
        "task_id",
        "holder",
        "quotas",
        "not_before",
        "expires_at",
        "delegation_depth",
    ):
        assert payload[name] == bundle["payload"][name]
    assert canonicalize({"capabilities": payload["capabilities"]}) == canonicalize(
        {
            "capabilities": [item.model_dump(mode="json") for item in challenge.task_capabilities],
        }
    )
    assert (
        sm3_hex(canonicalize({"capabilities": payload["capabilities"]}))
        == (bundle["payload"]["capabilities_hash"])
    )
    case.root.schemas.validate("capability-credential.schema.json", response.credential)
    case.service.schemas.validate(
        "challenge-response.schema.json", challenge.model_dump(mode="json")
    )
    case.service.schemas.validate(
        "coauthorization-response.schema.json", response.model_dump(mode="json")
    )
    assert verify_payload(
        payload,
        response.credential["signature"],
        domain_separator=CAPABILITY_CREDENTIAL,
        expected_key_id=case.authority.key_id,
        expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=case.authority.public_key_hex,
    )
    assert {row["quota_type"]: row["limit_value"] for row in state["budgets"]} == {
        "refund_total_fen": task["refund_total_fen"],
        "max_tool_calls": task["max_tool_calls"],
    }
    for row in state["budgets"]:
        assert row["credential_id"] == response.root_credential_id
        assert (row["reserved_value"], row["committed_value"], row["version"]) == (0, 0, 0)
    digest = sm3_hex(canonicalize(bundle["payload"]))
    bundle_hash = sm3_hex(canonicalize(bundle))
    assert response.challenge_id == challenge.payload.challenge_id
    assert response.approval_payload_hash == challenge.approval_payload_hash == digest
    assert response.bundle_hash == bundle_hash
    consumed = state["challenges"][0]
    assert consumed["status"] == "CONSUMED"
    assert consumed["challenge_id"] == response.challenge_id
    assert consumed["tenant_id"] == case.tenant_id
    assert consumed["task_id"] == case.task_id
    assert consumed["policy_revision"] == case.setup.policy.revision
    assert consumed["approval_payload"] == bundle["payload"]
    assert consumed["approval_payload_hash"] == digest
    assert consumed["bundle_hash"] == bundle_hash
    assert consumed["signed_bundle"] == bundle
    assert consumed["root_credential_id"] == response.root_credential_id
    assert consumed["root_credential_hash"] == response.root_credential_hash
    assert consumed["consumed_at"] == case.clock.value
    assert consumed["revoked_at"] is None
    enterprise, finance = case.setup.keys
    assert state["authorizations"][0] == {
        "task_id": case.task_id,
        "challenge_id": response.challenge_id,
        "root_credential_id": response.root_credential_id,
        "approval_payload_hash": digest,
        "bundle_hash": bundle_hash,
        "enterprise_subject_id": enterprise.subject_id,
        "enterprise_key_id": enterprise.key_id,
        "finance_subject_id": finance.subject_id,
        "finance_key_id": finance.key_id,
        "authorized_at": case.clock.value,
    }
    assert len(state["audit_outbox"]) == 1
    assert state["audit_events"] == []
    outbox = state["audit_outbox"][0]
    assert outbox["outbox_event_id"] == (
        "OUTBOX-COAUTH-" + sm3_hex(response.root_credential_id.encode("utf-8"))
    )
    assert outbox["execution_id"] is None
    assert outbox["event_type"] == COAUTHORIZATION_AUDIT_EVENT_TYPE
    assert outbox["evidence_reference"] == response.root_credential_id
    assert outbox["status"] == "PENDING"
    assert outbox["created_at"] == consumed["consumed_at"]
    assert outbox["appended_at"] is None
    evidence = outbox["payload"]
    assert evidence == {
        "schema_version": "1.0",
        "record_type": "COAUTH_ROOT_AUTHORIZED_V1",
        "tenant_id": case.tenant_id,
        "task_id": case.task_id,
        "challenge_id": response.challenge_id,
        "policy_revision": case.setup.policy.revision,
        "approval_payload_hash": digest,
        "bundle_hash": bundle_hash,
        "signed_bundle": bundle,
        "root_credential_id": response.root_credential_id,
        "root_credential_hash": response.root_credential_hash,
        "credential": response.credential,
        "authorized_at": consumed["consumed_at"],
    }
    assert len(canonicalize(evidence, normalize_sets=False)) <= MAX_EVIDENCE_BYTES
    assert outbox["payload_hash"] == sm3_hex(canonicalize(evidence))
    validate_authorization_audit_evidence(evidence)
    return state


def _assert_declared_http_conflict(error: CoauthorizationError) -> None:
    """Inspect the real handler's literal mapping without importing or running the app."""
    document = ast.parse(
        (PROJECT_ROOT / "backend" / "authorization" / "app.py").read_text(encoding="utf-8")
    )
    make_app = next(
        node
        for node in document.body
        if isinstance(node, ast.FunctionDef) and node.name == "make_app"
    )
    handler = next(
        node
        for node in make_app.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "coauthorization_error_handler"
    )
    codes = next(
        node.value
        for node in handler.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "codes" for target in node.targets)
    )
    assert isinstance(codes, ast.Dict)
    declared = {}
    for key, value in zip(codes.keys, codes.values, strict=True):
        assert isinstance(key, ast.Attribute) and isinstance(key.value, ast.Name)
        assert key.value.id == "CoauthorizationReason"
        assert isinstance(value, ast.Constant) and type(value.value) is int
        declared[getattr(CoauthorizationReason, key.attr)] = value.value
    assert declared[error.reason_code] == 409
    response = next(node.value for node in handler.body if isinstance(node, ast.Return))
    assert isinstance(response, ast.Call)
    status_code = next(item.value for item in response.keywords if item.arg == "status_code")
    assert isinstance(status_code, ast.Call)
    assert isinstance(status_code.func, ast.Attribute) and status_code.func.attr == "get"
    assert isinstance(status_code.func.value, ast.Name) and status_code.func.value.id == "codes"
    assert isinstance(status_code.args[0], ast.Attribute)
    assert status_code.args[0].attr == "reason_code"


def test_create_challenge_is_idempotent_and_conflicts_on_another_holder(case) -> None:
    _assert_pending(case.state(), challenge_count=0)
    challenge = case.challenge()
    first_state = case.state()
    assert challenge.payload.not_before == first_state["task"]["created_at"]
    assert challenge.approval_payload_hash == sm3_hex(
        canonicalize(challenge.payload.model_dump(mode="json"))
    )
    repeated = case.challenge()
    assert repeated.model_dump(mode="json") == challenge.model_dump(mode="json")
    assert case.state() == first_state
    _assert_pending(first_state, challenge_count=1)
    other = CreateChallengeRequest(
        holder_agent_id=case.other_holder.subject_id,
        holder_key_id=case.other_holder.key_id,
        delegation_depth=case.request.delegation_depth,
    )
    with pytest.raises(CoauthorizationError) as error:
        case.service.create_challenge(case.task_id, other)
    assert error.value.reason_code == CoauthorizationReason.CHALLENGE_CONFLICT
    _assert_declared_http_conflict(error.value)
    assert case.state() == first_state


def test_dual_approval_issues_one_real_signed_root_and_no_base_confirmation(case) -> None:
    registered_keys, policies = case.registration_state(case.setup)
    assert {
        row["key_id"]: RegisteredApprovalKey.model_validate(row) for row in registered_keys
    } == {record.key_id: record for record in case.setup.keys}
    assert len(policies) == 1 and policies[0]["status"] == "ACTIVE"
    assert len({record.principal_id for record in case.setup.keys}) == 2
    assert len({record.public_key_hex for record in case.setup.keys}) == 2
    registry = PostgresKeyRegistry(case.database_url)
    for record in (case.authority, case.holder, case.other_holder):
        assert registry.get(record.key_id) == record
        assert record.private_key_reference is not None
        assert record.private_key_reference.startswith("memory:")
    challenge = case.challenge()
    bundle = case.signed_bundle(challenge.payload)
    raw = canonicalize(bundle)
    response = case.service.authorize_task(case.task_id, raw)
    assert response.reused is False
    first_state = _assert_authorized(case, challenge, bundle, response)
    repeated = case.service.authorize_task(case.task_id, raw)
    assert repeated.reused is True
    assert repeated.model_dump(exclude={"reused"}) == response.model_dump(exclude={"reused"})
    assert _assert_authorized(case, challenge, bundle, repeated) == first_state


def test_two_threads_with_the_same_canonical_bundle_return_the_same_root(case) -> None:
    challenge = case.challenge()
    bundle = case.signed_bundle(challenge.payload)
    compact = canonicalize(bundle)
    formatted = json.dumps(bundle, sort_keys=True, indent=2, allow_nan=False).encode("utf-8")
    assert compact != formatted
    assert canonicalize(parse_strict_json(formatted)) == compact
    barrier = Barrier(2)

    def authorize(raw: bytes) -> CoauthorizationResponse:
        barrier.wait(timeout=10)
        return case.service.authorize_task(case.task_id, raw)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(authorize, raw) for raw in (compact, formatted)]
        responses = [future.result(timeout=30) for future in futures]
    assert sorted(response.reused for response in responses) == [False, True]
    assert responses[0].root_credential_id == responses[1].root_credential_id
    assert responses[0].model_dump(exclude={"reused"}) == responses[1].model_dump(
        exclude={"reused"}
    )
    _assert_authorized(case, challenge, bundle, responses[0])


def test_consumed_challenge_rejects_different_real_approval_signatures_as_conflict(case) -> None:
    challenge = case.challenge()
    original = case.signed_bundle(challenge.payload)
    response = case.service.authorize_task(case.task_id, canonicalize(original))
    assert response.reused is False
    before = _assert_authorized(case, challenge, original, response)
    resigned = case.signed_bundle(challenge.payload)
    assert resigned["payload"] == original["payload"]
    assert [item["statement"] for item in resigned["approvals"]] == [
        item["statement"] for item in original["approvals"]
    ]
    assert canonicalize(resigned) != canonicalize(original)
    error = _reject_unchanged(
        case, canonicalize(resigned), CoauthorizationReason.IDEMPOTENCY_CONFLICT
    )
    _assert_declared_http_conflict(error)
    assert case.state() == before


def test_consumed_retry_fails_fast_on_a_locked_root_and_reuses_it_after_release(case) -> None:
    challenge = case.challenge()
    bundle = case.signed_bundle(challenge.payload)
    raw = canonicalize(bundle)
    original = case.service.authorize_task(case.task_id, raw)
    assert original.reused is False
    before = _assert_authorized(case, challenge, bundle, original)

    # This independent transaction holds only the ROOT row, never the task row.
    with connect(case.database_url) as blocker, blocker.transaction():
        locked = blocker.execute(
            """
            SELECT credential_id FROM credentials
            WHERE credential_id = %s AND credential_type = 'ROOT' FOR UPDATE
            """,
            (original.root_credential_id,),
        ).fetchone()
        assert locked == (original.root_credential_id,)
        started_at = monotonic()
        with pytest.raises(CoauthorizationError) as error:
            case.service.authorize_task(case.task_id, raw)
        elapsed = monotonic() - started_at
        assert error.value.reason_code == CoauthorizationReason.CHALLENGE_CONFLICT
        assert isinstance(error.value.__cause__, errors.LockNotAvailable)
        # Less than the session's 10-second lock_timeout distinguishes NOWAIT.
        assert elapsed < 5.0, "same-bundle retry waited for the locked ROOT"
        _assert_declared_http_conflict(error.value)
        assert case.state() == before
        with connect(case.database_url) as probe, probe.transaction():
            assert probe.execute(
                "SELECT task_id FROM tasks WHERE task_id = %s FOR UPDATE NOWAIT",
                (case.task_id,),
            ).fetchone() == (case.task_id,)

    repeated = case.service.authorize_task(case.task_id, raw)
    assert repeated.reused is True
    assert repeated.root_credential_id == original.root_credential_id
    assert repeated.model_dump(exclude={"reused"}) == original.model_dump(exclude={"reused"})
    assert _assert_authorized(case, challenge, bundle, repeated) == before


@pytest.mark.parametrize("role", ROLES)
def test_invalid_signature_is_rejected_without_root_or_evidence(case, role) -> None:
    challenge = case.challenge()
    bundle = case.signed_bundle(challenge.payload)
    invalid = deepcopy(bundle)
    approval = next(item for item in invalid["approvals"] if item["statement"]["role"] == role)
    approval["signature"]["value"] = "0" * 128
    case.service.schemas.validate("coauthorization-bundle.schema.json", invalid)
    _reject_unchanged(case, canonicalize(invalid), CoauthorizationReason.INVALID_SIGNATURE)
    _assert_pending(case.state(), challenge_count=1)


@pytest.mark.parametrize(
    "binding",
    ("task_id", "tenant_id", "ticket_id", "customer_id", "refund_total_fen", "max_tool_calls"),
)
def test_even_valid_double_signatures_cannot_change_the_challenge_binding(case, binding) -> None:
    challenge = case.challenge()
    changed = challenge.payload.model_dump(mode="json")
    if binding in {"refund_total_fen", "max_tool_calls"}:
        changed["quotas"][binding] += 1
    else:
        changed[binding] = case.identifier(f"changed-{binding}")
    changed["capabilities_hash"] = sm3_hex(
        canonicalize(
            {
                "capabilities": build_root_capabilities(
                    ticket_id=changed["ticket_id"],
                    customer_id=changed["customer_id"],
                    refund_total_fen=changed["quotas"]["refund_total_fen"],
                ),
            }
        )
    )
    bundle = case.signed_bundle(ApprovalPayload.model_validate(changed))
    _reject_unchanged(case, canonicalize(bundle), CoauthorizationReason.TASK_OR_POLICY_MISMATCH)
    _assert_pending(case.state(), challenge_count=1)


def test_valid_bundle_cannot_be_submitted_for_another_existing_task(case) -> None:
    challenge = case.challenge()
    raw = canonicalize(case.signed_bundle(challenge.payload))
    other_task = case.create_task("other-task")
    original_state = case.state()
    _reject_unchanged(case, raw, CoauthorizationReason.TASK_OR_POLICY_MISMATCH, task_id=other_task)
    assert case.state() == original_state
    _assert_pending(case.state(), challenge_count=1)
    _assert_pending(case.state(other_task), challenge_count=0)


@pytest.mark.parametrize(
    "binding", ("refund_total_fen", "max_tool_calls", "customer_id", "ticket_customer")
)
def test_database_binding_changes_after_challenge_are_rejected_without_root(case, binding) -> None:
    challenge = case.challenge()
    raw = canonicalize(case.signed_bundle(challenge.payload))
    with connect(case.database_url) as connection, connection.transaction():
        if binding in {"refund_total_fen", "max_tool_calls"}:
            query = sql.SQL("UPDATE tasks SET {} = {} + 1 WHERE task_id = %s").format(
                sql.Identifier(binding), sql.Identifier(binding)
            )
            assert connection.execute(query, (case.task_id,)).rowcount == 1
        else:
            assert (
                connection.execute(
                    "UPDATE tickets SET customer_id = %s WHERE ticket_id = %s",
                    (case.other_customer_id, case.ticket_id),
                ).rowcount
                == 1
            )
            if binding == "customer_id":
                assert (
                    connection.execute(
                        "UPDATE tasks SET customer_id = %s WHERE task_id = %s",
                        (case.other_customer_id, case.task_id),
                    ).rowcount
                    == 1
                )
    reason = (
        CoauthorizationReason.TASK_OR_POLICY_MISMATCH
        if binding == "ticket_customer"
        else CoauthorizationReason.CHALLENGE_MISMATCH
    )
    _reject_unchanged(case, raw, reason)
    _assert_pending(case.state(), challenge_count=1)


@pytest.mark.parametrize("role", ROLES)
def test_revoked_approval_key_is_rejected_at_consumption(case, role) -> None:
    challenge = case.challenge()
    raw = canonicalize(case.signed_bundle(challenge.payload))
    record = next(record for record in case.setup.keys if record.role == role)
    recorded = revoke_coauthorization_source(
        case.database_url,
        tenant_id=case.tenant_id,
        source_kind="APPROVAL_KEY_REVOKED",
        source_identifier=record.key_id,
    )
    assert recorded["status"] == "RECORDED"
    with connect(case.database_url) as connection, connection.transaction():
        assert connection.execute(
            "SELECT status FROM coauthorization_keys WHERE key_id = %s",
            (record.key_id,),
        ).fetchone() == ("REVOKED",)
        audit_rows = connection.execute(
            "SELECT status, event_type FROM audit_outbox WHERE outbox_event_id LIKE %s",
            (f"OUTBOX-COAUTH-REV-{recorded['revocation_event_id']}-%",),
        ).fetchall()
        assert audit_rows and all(
            tuple(row) == ("PENDING", "COAUTH_REVOCATION_APPLIED") for row in audit_rows
        )
    _reject_unchanged(case, raw, CoauthorizationReason.KEY_NOT_ACTIVE)
    _assert_pending(case.state(), challenge_count=1)


@pytest.mark.parametrize("consumed", [False, True])
def test_joint_approval_history_reads_pending_and_consumed_evidence_without_writes(
    case, consumed
) -> None:
    challenge = case.challenge()
    if consumed:
        response = case.service.authorize_task(
            case.task_id, canonicalize(case.signed_bundle(challenge.payload))
        )
    before = case.state()
    reader = CoauthorizationReadService(case.database_url, clock=case.clock)
    history = reader.task_history(case.task_id)
    assert history.task_id == case.task_id
    assert len(history.items) == 1
    entry = history.items[0]
    assert entry.challenge_id == challenge.payload.challenge_id
    assert entry.challenge_status == ("CONSUMED" if consumed else "PENDING")
    if consumed:
        assert entry.root_credential_id == response.root_credential_id
    assert reader.task_history(case.task_id, offset=1).items == []
    client = TestClient(
        make_authority_app(
            settings=SimpleNamespace(coauthorization_required=True),
            service=case.root,
            coauthorization_service=case.service,
            coauthorization_read_service=reader,
        )
    )
    response = client.get(f"/extensions/coauthorization/v1/tasks/{case.task_id}")
    assert response.status_code == 200, response.text
    assert response.json() == history.model_dump(mode="json")
    assert case.state() == before


def test_replaced_policy_revision_invalidates_the_old_pending_challenge(case) -> None:
    challenge = case.challenge()
    raw = canonicalize(case.signed_bundle(challenge.payload))
    replacement = case.setup.policy.model_dump(mode="json")
    replacement["revision"] = case.identifier("replacement-policy")
    setup = PublicApprovalSetup(
        policy=TrustedApprovalPolicy.model_validate(replacement), keys=case.setup.keys
    )
    case.policy_ids.add((setup.policy.tenant_id, setup.policy.revision))
    with connect(case.database_url) as connection, connection.transaction():
        assert (
            connection.execute(
                """
            UPDATE coauthorization_policies SET status = 'RETIRED'
            WHERE tenant_id = %s AND revision = %s AND status = 'ACTIVE'
            """,
                (case.tenant_id, case.setup.policy.revision),
            ).rowcount
            == 1
        )
    register_public_approval_policy(case.database_url, setup)
    keys, policies = case.registration_state(setup)
    assert len(keys) == 2 and len(policies) == 1 and policies[0]["status"] == "ACTIVE"
    _reject_unchanged(case, raw, CoauthorizationReason.CHALLENGE_MISMATCH)
    _assert_pending(case.state(), challenge_count=1)


def test_challenge_is_expired_at_its_exact_deadline(case) -> None:
    challenge = case.challenge()
    raw = canonicalize(case.signed_bundle(challenge.payload))
    case.clock.value = challenge.payload.approval_expires_at
    _reject_unchanged(case, raw, CoauthorizationReason.CHALLENGE_EXPIRED_OR_NOT_YET_VALID)
    _assert_pending(case.state(), challenge_count=1)


@pytest.mark.parametrize("runtime_key", ("authority", "holder"))
@pytest.mark.parametrize("stage", ("challenge", "authorize"))
def test_final_timestamp_before_runtime_activation_is_rejected_after_key_lock(
    case,
    monkeypatch,
    runtime_key,
    stage,
) -> None:
    raw = None
    if stage == "authorize":
        challenge = case.challenge()
        raw = canonicalize(case.signed_bundle(challenge.payload))
    activated_at = case.clock.value + 2
    _set_runtime_activation(case, getattr(case, runtime_key), activated_at)
    case.clock.value = activated_at + 1
    before = case.state()
    final_timestamp = activated_at - 1
    assert before["task"]["created_at"] <= final_timestamp < before["task"]["expires_at"]
    assert case.setup.policy.not_before <= final_timestamp < case.setup.policy.expires_at
    assert all(key.activated_at <= final_timestamp < key.expires_at for key in case.setup.keys)
    if stage == "authorize":
        assert (
            challenge.payload.approval_not_before
            <= final_timestamp
            < (challenge.payload.approval_expires_at)
        )
    observed = _rewind_after_locked_scope(case, monkeypatch, final_timestamp)
    if stage == "challenge":
        with pytest.raises(CoauthorizationError) as error:
            case.challenge()
        assert error.value.reason_code == CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID
    else:
        assert raw is not None
        _reject_unchanged(case, raw, CoauthorizationReason.KEY_EXPIRED_OR_NOT_YET_VALID)
    assert observed == [activated_at + 1]
    assert case.clock.value == final_timestamp
    assert case.private_keys.loaded_references == []
    assert case.state() == before
    _assert_pending(case.state(), challenge_count=int(stage == "authorize"))


@pytest.mark.parametrize("runtime_key", ("authority", "holder"))
@pytest.mark.parametrize("stage", ("challenge", "authorize"))
def test_final_timestamp_at_exact_runtime_activation_is_accepted_after_key_lock(
    case,
    monkeypatch,
    runtime_key,
    stage,
) -> None:
    bundle = None
    if stage == "authorize":
        challenge = case.challenge()
        bundle = case.signed_bundle(challenge.payload)
    activated_at = case.clock.value + 2
    _set_runtime_activation(case, getattr(case, runtime_key), activated_at)
    case.clock.value = activated_at + 1
    observed = _rewind_after_locked_scope(case, monkeypatch, activated_at)
    if stage == "challenge":
        response = case.challenge()
        state = case.state()
        assert response.payload.approval_not_before == activated_at
        assert state["challenges"][0]["issued_at"] == activated_at
        assert response.payload.not_before == state["task"]["created_at"]
        case.service.schemas.validate(
            "challenge-response.schema.json", response.model_dump(mode="json")
        )
        _assert_pending(state, challenge_count=1)
    else:
        assert bundle is not None
        response = case.service.authorize_task(case.task_id, canonicalize(bundle))
        assert response.reused is False
        assert response.credential["signature"]["signed_at"] == activated_at
        _assert_authorized(case, challenge, bundle, response)
    assert observed == [activated_at + 1]
    assert case.clock.value == activated_at


def test_public_registration_revalidates_and_rejects_one_principal_with_two_roles(case) -> None:
    setup = case.public_setup("duplicate-principal")
    finance = setup.keys[1].model_dump(mode="json")
    finance["principal_id"] = setup.keys[0].principal_id
    # model_copy can carry invalid input; the registration boundary must revalidate it.
    invalid = setup.model_copy(
        update={
            "keys": [setup.keys[0], RegisteredApprovalKey.model_validate(finance)],
        }
    )
    assert case.registration_state(invalid) == ([], [])
    with pytest.raises(ValidationError, match="two independent registered principals"):
        register_public_approval_policy(case.database_url, invalid)
    assert case.registration_state(invalid) == ([], [])
    _assert_pending(case.state(), challenge_count=0)


def test_service_rejects_two_registered_subject_aliases_for_one_principal(case) -> None:
    setup = case.public_setup("aliased-principal", tenant_id=case.tenant_id)
    finance = setup.keys[1].model_dump(mode="json")
    finance["principal_id"] = setup.keys[0].principal_id
    records = [setup.keys[0], RegisteredApprovalKey.model_validate(finance)]
    before = case.state()
    with connect(case.database_url) as connection, connection.transaction():
        assert (
            connection.execute(
                """
            UPDATE coauthorization_policies SET status = 'RETIRED'
            WHERE tenant_id = %s AND revision = %s AND status = 'ACTIVE'
            """,
                (case.tenant_id, case.setup.policy.revision),
            ).rowcount
            == 1
        )
        # Seed misprovisioned public rows directly; do not bypass a database trigger.
        for record in records:
            values = record.model_dump(mode="json")
            names = tuple(values)
            query = sql.SQL("INSERT INTO coauthorization_keys ({}) VALUES ({})").format(
                sql.SQL(", ").join(sql.Identifier(name) for name in names),
                sql.SQL(", ").join(sql.Placeholder() for _ in names),
            )
            connection.execute(query, tuple(values[name] for name in names))
        connection.execute(
            """
            INSERT INTO coauthorization_policies (
                tenant_id, revision, enterprise_subject_id, enterprise_key_id,
                finance_subject_id, finance_key_id, not_before, expires_at, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'ACTIVE')
            """,
            (
                case.tenant_id,
                setup.policy.revision,
                records[0].subject_id,
                records[0].key_id,
                records[1].subject_id,
                records[1].key_id,
                setup.policy.not_before,
                setup.policy.expires_at,
            ),
        )
    with pytest.raises(CoauthorizationError) as error:
        case.challenge()
    assert error.value.reason_code == CoauthorizationReason.SAME_PRINCIPAL
    assert case.state() == before
    _assert_pending(case.state(), challenge_count=0)


@pytest.mark.parametrize("role", ROLES)
def test_approval_registration_rejects_the_original_authority_public_key(case, role) -> None:
    setup = case.public_setup("authority-overlap")
    records = []
    for record in setup.keys:
        values = record.model_dump(mode="json")
        if record.role == role:
            values["public_key_hex"] = case.authority.public_key_hex
        records.append(RegisteredApprovalKey.model_validate(values))
    invalid = PublicApprovalSetup(policy=setup.policy, keys=records)
    assert case.registration_state(invalid) == ([], [])
    with pytest.raises(CoauthorizationError) as error:
        register_public_approval_policy(case.database_url, invalid)
    assert error.value.reason_code == CoauthorizationReason.UNTRUSTED_KEY
    assert case.registration_state(invalid) == ([], [])
    _assert_pending(case.state(), challenge_count=0)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("collision", ("key_id", "public_key"))
def test_runtime_registration_rejects_a_previously_registered_approval_identity(
    case,
    role,
    collision,
) -> None:
    approval = next(key for key in case.setup.keys if key.role == role)
    candidate = _runtime_registration_candidate(case, approval, collision)
    before = case.state()
    registered_before = case.registration_state(case.setup)
    assert len(registered_before[0]) == 2 and len(registered_before[1]) == 1
    with connect(case.database_url) as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM key_registry WHERE key_id = %s OR public_key_hex = %s",
                (candidate.key_id, candidate.public_key_hex),
            ).fetchall()
            == []
        )
    with pytest.raises(ValueError, match="runtime key overlaps a coauthorization key"):
        PostgresKeyRegistry(case.database_url).register(candidate)
    with connect(case.database_url) as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM key_registry WHERE key_id = %s OR public_key_hex = %s",
                (candidate.key_id, candidate.public_key_hex),
            ).fetchall()
            == []
        )
    assert case.registration_state(case.setup) == registered_before
    assert case.state() == before
    _assert_pending(case.state(), challenge_count=0)


@pytest.mark.parametrize("collision", ("key_id", "public_key"))
def test_approval_and_runtime_registration_race_is_exclusive_with_repeatable_read_default(
    case,
    monkeypatch,
    collision,
) -> None:
    setup = case.public_setup("registration-race")
    approval = next(key for key in setup.keys if key.role == "FINANCE_APPROVER")
    candidate = _runtime_registration_candidate(case, approval, collision)
    before = case.state()
    registered_before = case.registration_state(case.setup)
    assert case.registration_state(setup) == ([], [])
    barrier = Barrier(2)
    lock_observations: dict[str, tuple[int, str]] = {}
    real_identity_lock = identity_key_registry.lock_key_identities
    assert coauthorization_provisioning.lock_key_identities is real_identity_lock

    @contextmanager
    def connect_with_repeatable_read(database_url: str) -> Iterator[Any]:
        assert database_url == case.database_url
        with connect(database_url) as connection:
            # This changes only this real connection's next transaction default.
            connection.isolation_level = IsolationLevel.REPEATABLE_READ
            assert connection.isolation_level is IsolationLevel.REPEATABLE_READ
            yield connection

    def observed_identity_lock(registry: str) -> Any:
        def lock(connection: Any, identities: Iterator[tuple[str, str]]) -> None:
            pairs = tuple(identities)
            expected = (
                {(candidate.key_id, candidate.public_key_hex)}
                if registry == "runtime"
                else {(key.key_id, key.public_key_hex) for key in setup.keys}
            )
            assert set(pairs) == expected
            isolation = connection.execute(
                "SELECT current_setting('transaction_isolation')"
            ).fetchone()[0]
            assert isolation == "read committed"
            lock_observations[registry] = (connection.info.backend_pid, isolation)
            barrier.wait(timeout=10)
            real_identity_lock(connection, pairs)

        return lock

    def register_runtime() -> bool:
        try:
            assert PostgresKeyRegistry(case.database_url).register(candidate) == candidate
        except ValueError as error:
            assert str(error) == "runtime key overlaps a coauthorization key"
            return False
        return True

    def register_approvals() -> bool:
        try:
            register_public_approval_policy(case.database_url, setup)
        except CoauthorizationError as error:
            assert error.reason_code == CoauthorizationReason.UNTRUSTED_KEY
            assert str(error) == "approval key overlaps a runtime key"
            return False
        return True

    with monkeypatch.context() as patch:
        patch.setattr(identity_key_registry, "connect", connect_with_repeatable_read)
        patch.setattr(coauthorization_provisioning, "connect", connect_with_repeatable_read)
        patch.setattr(
            identity_key_registry, "lock_key_identities", observed_identity_lock("runtime")
        )
        patch.setattr(
            coauthorization_provisioning, "lock_key_identities", observed_identity_lock("approval")
        )
        # Both entry points open independent connections; the real advisory helper is retained.
        # The validated DSN also bounds SQL, lock and connection waits before any write.
        with ThreadPoolExecutor(max_workers=2) as executor:
            runtime_future = executor.submit(register_runtime)
            approval_future = executor.submit(register_approvals)
            runtime_succeeded = runtime_future.result(timeout=30)
            approval_succeeded = approval_future.result(timeout=30)

    assert set(lock_observations) == {"runtime", "approval"}
    assert len({pid for pid, _ in lock_observations.values()}) == 2
    assert {isolation for _, isolation in lock_observations.values()} == {"read committed"}
    assert int(runtime_succeeded) + int(approval_succeeded) == 1
    keys, policies = case.registration_state(setup)
    with connect(case.database_url) as connection, connection.cursor(row_factory=dict_row) as c:
        runtime_rows = c.execute(
            "SELECT * FROM key_registry WHERE key_id = %s OR public_key_hex = %s",
            (candidate.key_id, candidate.public_key_hex),
        ).fetchall()
    if runtime_succeeded:
        assert keys == [] and policies == []
        assert len(runtime_rows) == 1
        assert runtime_rows[0]["key_id"] == candidate.key_id
        assert runtime_rows[0]["public_key_hex"] == candidate.public_key_hex
        assert PostgresKeyRegistry(case.database_url).get(candidate.key_id) == candidate
    else:
        assert runtime_rows == []
        assert len(keys) == 2 and len(policies) == 1
        assert sorted(
            (RegisteredApprovalKey.model_validate(key).model_dump(mode="json") for key in keys),
            key=lambda key: key["key_id"],
        ) == sorted(
            (key.model_dump(mode="json") for key in setup.keys),
            key=lambda key: key["key_id"],
        )
        assert policies[0]["tenant_id"] == setup.policy.tenant_id
        assert policies[0]["revision"] == setup.policy.revision
        assert policies[0]["status"] == "ACTIVE"
    assert case.registration_state(case.setup) == registered_before
    assert case.state() == before
    _assert_pending(case.state(), challenge_count=0)


def test_required_flag_blocks_the_legacy_single_signer_root_service(case) -> None:
    request = AuthorizeTaskRequest(
        confirmed=True,
        confirmer_id=case.identifier("legacy-confirmer"),
        holder_agent_id=case.holder.subject_id,
        holder_key_id=case.holder.key_id,
        delegation_depth=2,
    )
    before = case.state()
    with pytest.raises(
        AuthorizationError, match="independent coauthorization is required"
    ) as error:
        case.root.authorize_task(case.task_id, request, current_time=case.clock.value)
    assert error.value.reason_code == ReasonCode.INVALID_SIGNATURE
    assert error.value.status_code == 403
    assert case.private_keys.loaded_references == []
    assert case.state() == before
    _assert_pending(case.state(), challenge_count=0)


def test_fault_after_real_root_inserts_rolls_back_the_whole_authorization(
    case, monkeypatch
) -> None:
    challenge = case.challenge()
    raw = canonicalize(case.signed_bundle(challenge.payload))
    before = case.state()
    original_persist = case.root._persist_authorization
    observed_root_ids: list[str] = []

    def persist_then_fail(connection: Any, **arguments: Any) -> None:
        assert arguments["write_base_confirmation"] is False
        original_persist(connection, **arguments)
        inserted = _read_state(connection, case.task_id)
        assert inserted["task"]["status"] == "AUTHORIZED"
        assert len(inserted["roots"]) == 1
        assert len(inserted["budgets"]) == 2
        assert inserted["confirmations"] == []
        assert inserted["challenges"][0]["status"] == "PENDING"
        assert inserted["authorizations"] == []
        observed_root_ids.append(inserted["roots"][0]["credential_id"])
        raise RuntimeError("injected fault after real root persistence")

    with monkeypatch.context() as patch:
        patch.setattr(case.root, "_persist_authorization", persist_then_fail)
        with pytest.raises(RuntimeError, match="injected fault after real root persistence"):
            case.service.authorize_task(case.task_id, raw)
    assert len(observed_root_ids) == 1
    after = case.state()
    assert after == before
    _assert_pending(after, challenge_count=1)
    with connect(case.database_url) as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM credentials WHERE credential_id = %s", (observed_root_ids[0],)
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                "SELECT 1 FROM credential_budget_state WHERE credential_id = %s",
                (observed_root_ids[0],),
            ).fetchone()
            is None
        )


def test_outbox_insert_failure_rolls_back_root_budget_consumption_and_association(
    case,
    monkeypatch,
) -> None:
    challenge = case.challenge()
    bundle = case.signed_bundle(challenge.payload)
    before = case.state()
    original_connect = coauthorization_service.connect
    observed_root_ids: list[str] = []

    class FailOutboxInsert:
        def __init__(self, connection: Any) -> None:
            self.connection = connection

        def __getattr__(self, name: str) -> Any:
            return getattr(self.connection, name)

        def execute(self, query: Any, parameters: Any = None) -> Any:
            if isinstance(query, str) and "INSERT INTO audit_outbox" in query:
                inserted = _read_state(self.connection, case.task_id)
                assert inserted["task"]["status"] == "AUTHORIZED"
                assert len(inserted["roots"]) == 1 and len(inserted["budgets"]) == 2
                assert inserted["confirmations"] == []
                assert inserted["challenges"][0]["status"] == "CONSUMED"
                assert len(inserted["authorizations"]) == 1
                assert inserted["audit_outbox"] == inserted["audit_events"] == []
                root_id = inserted["roots"][0]["credential_id"]
                assert inserted["challenges"][0]["root_credential_id"] == root_id
                assert inserted["authorizations"][0]["root_credential_id"] == root_id
                observed_root_ids.append(root_id)
                assert len(parameters) == 6
                assert parameters[0] == "OUTBOX-COAUTH-" + sm3_hex(root_id.encode("utf-8"))
                assert parameters[1] == COAUTHORIZATION_AUDIT_EVENT_TYPE
                assert parameters[2] == root_id
                evidence = parameters[4].obj
                validate_authorization_audit_evidence(evidence)
                assert evidence["signed_bundle"] == bundle
                assert evidence["credential"] == inserted["roots"][0]["signed_object"]
                assert parameters[3] == sm3_hex(canonicalize(evidence))
                assert parameters[5] == evidence["authorized_at"] == case.clock.value
                # Execute the real INSERT with one invalid NOT NULL value.
                failing_parameters = list(parameters)
                failing_parameters[3] = None
                return self.connection.execute(query, tuple(failing_parameters))
            return self.connection.execute(query, parameters)

    @contextmanager
    def fail_outbox_connect(database_url: str) -> Iterator[FailOutboxInsert]:
        assert database_url == case.database_url
        with original_connect(database_url) as connection:
            yield FailOutboxInsert(connection)

    with monkeypatch.context() as patch:
        patch.setattr(coauthorization_service, "connect", fail_outbox_connect)
        with pytest.raises(errors.NotNullViolation) as error:
            case.service.authorize_task(case.task_id, canonicalize(bundle))
    assert error.value.diag.column_name == "payload_hash"
    assert len(observed_root_ids) == 1
    after = case.state()
    assert after == before
    _assert_pending(after, challenge_count=1)
    root_id = observed_root_ids[0]
    with connect(case.database_url) as connection:
        for table in ("credentials", "credential_budget_state"):
            query = sql.SQL("SELECT 1 FROM {} WHERE credential_id = %s").format(
                sql.Identifier(table)
            )
            assert connection.execute(query, (root_id,)).fetchone() is None
        assert (
            connection.execute(
                "SELECT 1 FROM coauthorization_authorizations WHERE root_credential_id = %s",
                (root_id,),
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                """
            SELECT 1 FROM audit_outbox
            WHERE outbox_event_id = %s OR evidence_reference = %s
               OR payload ->> 'root_credential_id' = %s
            """,
                ("OUTBOX-COAUTH-" + sm3_hex(root_id.encode("utf-8")), root_id, root_id),
            ).fetchone()
            is None
        )


def test_consumed_retry_rejects_a_revoked_root_without_reissuing_or_changing_evidence(case) -> None:
    challenge = case.challenge()
    bundle = case.signed_bundle(challenge.payload)
    raw = canonicalize(bundle)
    response = case.service.authorize_task(case.task_id, raw)
    assert response.reused is False
    _assert_authorized(case, challenge, bundle, response)
    with connect(case.database_url) as connection, connection.transaction():
        connection.execute(
            """
            INSERT INTO credential_revocations (
                credential_id, revoked_at, revoked_by, revocation_reason
            ) VALUES (%s, %s, %s, 'Isolated coauthorization test')
            """,
            (response.root_credential_id, case.clock.value, case.identifier("revoker")),
        )
    _reject_unchanged(case, raw, CoauthorizationReason.ROOT_REVOKED_OR_INVALID)
    after = case.state()
    assert after["task"]["status"] == "AUTHORIZED"
    assert len(after["roots"]) == 1 and len(after["budgets"]) == 2
    assert after["roots"][0]["credential_id"] == response.root_credential_id
    assert after["challenges"][0]["status"] == "CONSUMED"
    assert len(after["authorizations"]) == 1 and len(after["revocations"]) == 1
    assert after["confirmations"] == []
