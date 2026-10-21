"""Full coauthorization-to-refund acceptance on an explicitly disposable PostgreSQL DB.

This module is opt-in through AGENTGUARD_COAUTHORIZATION_TEST_DATABASE_URL.  It
does not create databases, apply migrations, start services, use cloud
endpoints, or fall back to another database setting.  The database must be a
fresh local ``agentguard_coauth_test_*`` database because this workflow
appends immutable audit evidence and deliberately does not clean it up.

Approval private keys remain in memory.  Runtime signing keys are written only
under pytest's temporary directory because the current delegation, gateway,
and receipt production entry points intentionally use their file-backed key
boundary.  The local TestClient is an in-process transport; it is not a
network service.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from backend.admission.service import AdmissionService
from backend.audit.service import AuditService
from backend.authorization.service import RootAuthorizationService
from backend.business_action.contracts import ResolveRefundActionRequest
from backend.business_action.service import BusinessActionRegistryService
from backend.coauthorization.contracts import (
    APPROVAL_PURPOSE,
    ChallengeResponse,
    CreateChallengeRequest,
    PublicApprovalSetup,
    RegisteredApprovalKey,
    TrustedApprovalPolicy,
)
from backend.coauthorization.offline import (
    assemble_bundle,
    review_approval_task,
    sign_approval,
)
from backend.coauthorization.provisioning import register_public_approval_policy
from backend.coauthorization.service import CoauthorizationService
from backend.coauthorization.verifier import CoauthorizationError, CoauthorizationReason
from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.time import now_unix
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import DELEGATION_CREDENTIAL, EXECUTION_RECEIPT, HOLDER_PROOF
from backend.crypto.sm import (
    Sm2KeyPair,
    derive_public_key,
    generate_keypair,
    sign_payload,
    sm3_hex,
    verify_payload,
)
from backend.crypto.strict_json import parse_strict_json
from backend.delegation.contracts import DelegateCredentialRequest, DelegatedCapability
from backend.delegation.service import DelegationService
from backend.delegation.verifier import CredentialChainVerifier
from backend.gateway.contracts import RequestEnvelopeModel
from backend.gateway.dispatch import GatewayDispatchService
from backend.gateway.service import SecureGatewayService
from backend.identity.key_lifecycle import FilePrivateKeyStore
from backend.identity.key_registry import KeyRecord, PostgresKeyRegistry
from backend.receipt.service import ReceiptService
from backend.state.database import connect
from backend.tests.integration.test_coauthorization_postgres import (
    ROLES,
    _validated_database_url,
)
from backend.tools.app import make_app as make_tool_app
from backend.tools.store import PostgresToolStore

pytestmark = pytest.mark.integration

TEST_DATABASE_ENV = "AGENTGUARD_COAUTHORIZATION_TEST_DATABASE_URL"
LOCAL_DATABASE_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres"}

REQUIRED_COLUMNS: dict[str, set[str]] = {
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
        "created_at",
    },
    "agent_identities": {"agent_id", "display_name", "agent_type", "created_at"},
    "tickets": {"ticket_id", "tenant_id", "customer_id", "created_at", "updated_at"},
    "business_payment_verifications": {
        "tenant_id",
        "original_transaction_id",
        "customer_id",
        "verification_status",
        "refundable_amount_fen",
        "evidence_reference",
        "verified_at",
    },
    "refund_eligibility": {
        "ticket_id",
        "tenant_id",
        "customer_id",
        "trusted_action_slot",
        "verification_status",
        "original_transaction_id",
        "refund_reason_code",
        "refundable_amount_fen",
        "evidence_reference",
        "verified_at",
    },
    "tasks": {
        "task_id",
        "tenant_id",
        "ticket_id",
        "customer_id",
        "refund_total_fen",
        "max_tool_calls",
        "expires_at",
        "status",
        "created_at",
        "updated_at",
    },
    "credentials": {
        "credential_id",
        "credential_type",
        "signed_object",
        "signed_object_hash",
        "issuer_key_id",
        "holder_agent_id",
        "holder_key_id",
        "task_id",
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
    "execution_budget_reservations": {
        "execution_id",
        "credential_id",
        "quota_type",
        "amount",
        "status",
    },
    "business_actions": {
        "business_action_id",
        "action_scope_key",
        "tenant_id",
        "task_id",
        "tool_service",
        "tool_name",
        "status",
        "created_at",
        "updated_at",
    },
    "execution_records": {
        "execution_id",
        "initial_request_id",
        "request_hash",
        "credential_chain_hash",
        "task_id",
        "parameter_hash",
        "state",
        "decision",
        "receipt_status",
        "terminal_at",
        "terminal_state",
        "decision_at",
        "decision_value",
        "business_action_id",
    },
    "execution_requests": {"request_id", "execution_id", "request_hash", "admission_outcome"},
    "idempotency_records": {
        "business_idempotency_key",
        "business_action_id",
        "parameter_hash",
        "execution_id",
        "status",
        "updated_at",
    },
    "tool_execution_attempts": {
        "execution_attempt_id",
        "execution_id",
        "envelope_hash",
        "status",
        "tool_outcome",
    },
    "execution_receipts": {
        "receipt_id",
        "execution_id",
        "signed_receipt",
        "receipt_hash",
        "receipt_status",
    },
    "refunds": {
        "refund_id",
        "execution_id",
        "business_action_id",
        "business_idempotency_key",
        "parameter_hash",
        "task_id",
        "ticket_id",
        "customer_id",
        "amount_fen",
        "status",
    },
    "audit_outbox": {
        "outbox_event_id",
        "execution_id",
        "event_type",
        "evidence_reference",
        "payload_hash",
        "payload",
        "status",
        "created_at",
        "appended_at",
    },
    "audit_chain_head": {"singleton", "latest_event_sequence", "latest_event_hash"},
    "audit_events": {
        "event_sequence",
        "event_id",
        "outbox_event_id",
        "execution_id",
        "event_type",
        "event_timestamp",
        "payload_hash",
        "evidence_reference",
        "previous_event_hash",
        "event_hash",
        "schema_version",
    },
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
    "authorization_confirmations": {"task_id", "credential_id", "request_hash"},
}

EMPTY_DATA_TABLES = tuple(table for table in REQUIRED_COLUMNS if table not in {"audit_chain_head"})


@pytest.fixture(scope="module")
def full_workflow_database_url() -> str:
    candidate = os.getenv(TEST_DATABASE_ENV)
    if not candidate:
        pytest.skip(f"Set {TEST_DATABASE_ENV} explicitly; PostgreSQL workflow is unverified")
    parsed = urlsplit(candidate)
    if parsed.hostname not in LOCAL_DATABASE_HOSTS:
        pytest.fail(
            f"Refusing a non-local database host for {TEST_DATABASE_ENV}: {parsed.hostname!r}",
            pytrace=False,
        )
    database_url, expected_name = _validated_database_url(candidate)
    with connect(database_url) as connection:
        connection.execute("SET TRANSACTION READ ONLY")
        if connection.execute("SELECT current_database()").fetchone() != (expected_name,):
            pytest.fail("Refusing writes: current_database() differs from the validated name")
        columns: dict[str, set[str]] = {}
        for table, column in connection.execute(
            """
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = ANY(%s)
            """,
            (list(REQUIRED_COLUMNS),),
        ).fetchall():
            columns.setdefault(table, set()).add(column)
        missing = {
            table: sorted(expected - columns.get(table, set()))
            for table, expected in REQUIRED_COLUMNS.items()
            if not expected <= columns.get(table, set())
        }
        if missing:
            pytest.fail(
                "Apply the repository's current main migrations to the disposable DB first; "
                f"missing columns: {missing}",
                pytrace=False,
            )
        nonempty = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in EMPTY_DATA_TABLES
            if int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
        }
        head = connection.execute(
            "SELECT latest_event_sequence, latest_event_hash "
            "FROM audit_chain_head WHERE singleton = TRUE"
        ).fetchone()
        if nonempty or head != (0, "0" * 64):
            pytest.fail(
                "The full workflow requires a fresh disposable DB; "
                "refusing to append to existing data "
                f"(nonempty={nonempty}, audit_head={head!r})",
                pytrace=False,
            )
    return database_url


class FullWorkflowCase:
    """One isolated namespace whose final audit evidence is intentionally retained."""

    def __init__(self, database_url: str, tmp_path: Path) -> None:
        self.database_url = database_url
        self.prefix = f"coauth-full-{uuid4().hex}"
        self.clock_value = now_unix()
        self.private_root = tmp_path / "runtime-private"
        self.private_keys = FilePrivateKeyStore(self.private_root)
        self.runtime_pairs: dict[str, Sm2KeyPair] = {}
        self.task_ids: set[str] = set()

        self.tenant_id = "中文企业-" + self.prefix
        self.ticket_id = self.identifier("ticket")
        self.customer_id = "张三-" + self.prefix
        self.task_id = self.identifier("task")
        self.other_task_id = self.identifier("other-task")

        self.authority, _ = self._runtime_record(
            "authority", generate_keypair(), "AUTHORITY", KeyPurpose.AUTHORIZATION_ROOT_SIGNING
        )
        self.holder, _ = self._runtime_record(
            "holder", generate_keypair(), "AGENT", KeyPurpose.AGENT_HOLDER_SIGNING
        )
        self.delegate_holder, _ = self._runtime_record(
            "delegate", generate_keypair(), "AGENT", KeyPurpose.AGENT_HOLDER_SIGNING
        )
        self.refund_holder, _ = self._runtime_record(
            "refund", generate_keypair(), "AGENT", KeyPurpose.AGENT_HOLDER_SIGNING
        )
        self.gateway, _ = self._runtime_record(
            "gateway",
            generate_keypair(),
            "SERVICE",
            KeyPurpose.GATEWAY_EXECUTION_SIGNING,
            subject_id="secure-tool-gateway",
        )
        self.receipt, _ = self._runtime_record(
            "receipt",
            generate_keypair(),
            "SERVICE",
            KeyPurpose.EXECUTION_RECEIPT_SIGNING,
            subject_id="receipt-service",
        )

        self.approval_pairs: dict[str, Sm2KeyPair] = {}
        self.setup = self._public_setup()
        self.root = RootAuthorizationService(
            database_url=database_url,
            private_key_root=str(self.private_root),
            authority_subject_id=self.authority.subject_id,
            authority_key_id=self.authority.key_id,
            trusted_confirmers={self.identifier("legacy-confirmer"): "POLICY"},
            coauthorization_required=True,
        )
        self.service = CoauthorizationService(
            root_service=self.root,
            challenge_ttl_seconds=300,
            clock=lambda: self.clock_value,
        )
        self.challenge_request = CreateChallengeRequest(
            holder_agent_id=self.holder.subject_id,
            holder_key_id=self.holder.key_id,
            delegation_depth=2,
        )

    def identifier(self, suffix: str) -> str:
        return f"{self.prefix}-{suffix}"

    def _runtime_record(
        self,
        label: str,
        pair: Sm2KeyPair,
        subject_type: str,
        purpose: KeyPurpose,
        *,
        subject_id: str | None = None,
    ) -> tuple[KeyRecord, Sm2KeyPair]:
        key_id = self.identifier(f"{label}-key")
        self.runtime_pairs[key_id] = pair
        reference = self.private_keys.write(key_id, pair.private_key_hex)
        return KeyRecord(
            key_id=key_id,
            subject_id=subject_id or self.identifier(label),
            subject_type=subject_type,
            purpose=purpose,
            public_key_hex=pair.public_key_hex,
            status=KeyState.ACTIVE,
            material_state=KeyMaterialState.PRESENT,
            private_key_reference=reference,
            activated_at=self.clock_value - 120,
            created_at=self.clock_value - 120,
        ), pair

    def _public_setup(self) -> PublicApprovalSetup:
        records: list[RegisteredApprovalKey] = []
        for role, short in zip(ROLES, ("enterprise", "finance"), strict=True):
            key_id = self.identifier(f"approval-{short}-key")
            pair = generate_keypair()
            self.approval_pairs[key_id] = pair
            records.append(
                RegisteredApprovalKey(
                    tenant_id=self.tenant_id,
                    subject_id=self.identifier(f"{short}-approver"),
                    principal_id=self.identifier(f"{short}-principal"),
                    key_id=key_id,
                    role=role,
                    approval_purpose=APPROVAL_PURPOSE,
                    signing_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING.value,
                    algorithm="SM2",
                    public_key_hex=pair.public_key_hex,
                    status="ACTIVE",
                    activated_at=self.clock_value - 120,
                    expires_at=self.clock_value + 86_400,
                    retired_at=None,
                    revoked_at=None,
                    compromised_at=None,
                )
            )
        policy = TrustedApprovalPolicy(
            tenant_id=self.tenant_id,
            revision=self.identifier("approval-policy"),
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
            not_before=self.clock_value - 120,
            expires_at=self.clock_value + 7_200,
        )
        assert records[0].public_key_hex != records[1].public_key_hex
        return PublicApprovalSetup(policy=policy, keys=records)

    def seed(self) -> None:
        with connect(self.database_url) as connection, connection.transaction():
            for table, column in (
                ("tasks", "task_id"),
                ("tickets", "ticket_id"),
                ("agent_identities", "agent_id"),
                ("key_registry", "key_id"),
                ("coauthorization_keys", "key_id"),
                ("coauthorization_policies", "tenant_id"),
            ):
                if (
                    connection.execute(
                        f"SELECT 1 FROM {table} WHERE {column} LIKE %s LIMIT 1",
                        (self.prefix + "%",),
                    ).fetchone()
                    is not None
                ):
                    pytest.fail(f"refusing an occupied test namespace: {self.prefix}")
            for record in (self.holder, self.delegate_holder, self.refund_holder):
                connection.execute(
                    """
                    INSERT INTO agent_identities (agent_id, display_name, agent_type, created_at)
                    VALUES (%s, %s, 'coauthorization-full-workflow-test', %s)
                    """,
                    (record.subject_id, record.subject_id, self.clock_value - 60),
                )
            connection.execute(
                """
                INSERT INTO tickets (
                    ticket_id, tenant_id, customer_id, title, description, status,
                    created_at, updated_at
                ) VALUES (
                    %s, %s, %s, 'Full coauthorization workflow',
                    'Disposable acceptance case', 'OPEN', %s, %s
                )
                """,
                (
                    self.ticket_id,
                    self.tenant_id,
                    self.customer_id,
                    self.clock_value - 60,
                    self.clock_value - 60,
                ),
            )
            original_payment = self.identifier("original-payment")
            reference = "fixture://coauthorization-full-workflow/verified-payment"
            connection.execute(
                "INSERT INTO business_payment_verifications (tenant_id, original_transaction_id, "
                "customer_id, verification_status, refundable_amount_fen, evidence_reference, "
                "verified_at, created_at, updated_at) "
                "VALUES (%s, %s, %s, 'VERIFIED', 7000, %s, %s, %s, %s)",
                (
                    self.tenant_id,
                    original_payment,
                    self.customer_id,
                    reference,
                    self.clock_value - 60,
                    self.clock_value - 60,
                    self.clock_value - 60,
                ),
            )
            connection.execute(
                "INSERT INTO refund_eligibility (ticket_id, trusted_action_slot, tenant_id, "
                "customer_id, verification_status, original_transaction_id, refund_reason_code, "
                "refundable_amount_fen, evidence_reference, verified_at, created_at, updated_at) "
                "VALUES (%s, 'primary-refund', %s, %s, 'VERIFIED', %s, 'DUPLICATE_CHARGE', "
                "7000, %s, %s, %s, %s)",
                (
                    self.ticket_id,
                    self.tenant_id,
                    self.customer_id,
                    original_payment,
                    reference,
                    self.clock_value - 60,
                    self.clock_value - 60,
                    self.clock_value - 60,
                ),
            )
        registry = PostgresKeyRegistry(self.database_url)
        for record in (
            self.authority,
            self.holder,
            self.delegate_holder,
            self.refund_holder,
            self.gateway,
            self.receipt,
        ):
            registry.register(record)
        register_public_approval_policy(self.database_url, self.setup)
        self._create_task(self.task_id)
        self._create_task(self.other_task_id)

    def _create_task(self, task_id: str) -> None:
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
                    self.clock_value + 3_600,
                    self.clock_value - 60,
                    self.clock_value - 60,
                ),
            )
        self.task_ids.add(task_id)

    def challenge(self) -> ChallengeResponse:
        return self.service.create_challenge(self.task_id, self.challenge_request)

    def offline_bundle(self, challenge: ChallengeResponse) -> bytes:
        raw_challenge = canonicalize(challenge.model_dump(mode="json"))
        raw_setup = canonicalize(self.setup.model_dump(mode="json"))
        review = review_approval_task(
            raw_challenge,
            raw_setup,
            trusted_setup_sha256=hashlib.sha256(raw_setup).hexdigest(),
            expected_task_id=self.task_id,
            expected_approval_payload_hash=challenge.approval_payload_hash,
            now=self.clock_value,
        )
        evidence = {}
        for role in ROLES:
            record = next(key for key in self.setup.keys if key.role == role)
            pair = self.approval_pairs[record.key_id]
            assert derive_public_key(pair.private_key_hex) == record.public_key_hex
            evidence[role] = sign_approval(
                review,
                role=role,
                expected_subject_id=record.subject_id,
                expected_key_id=record.key_id,
                expected_principal_id=record.principal_id,
                private_key_hex=pair.private_key_hex,
                now=self.clock_value,
            )
        return assemble_bundle(
            review,
            canonicalize(evidence["ENTERPRISE_APPROVER"].model_dump(mode="json")),
            canonicalize(evidence["FINANCE_APPROVER"].model_dump(mode="json")),
            now=self.clock_value,
        )

    @staticmethod
    def single_approval_bundle(raw_bundle: bytes) -> bytes:
        document = deepcopy(parse_strict_json(raw_bundle))
        document["approvals"] = document["approvals"][:1]
        return canonicalize(document)

    def state_digest(self, task_id: str) -> tuple[object, ...]:
        with (
            connect(self.database_url) as connection,
            connection.cursor(row_factory=dict_row) as cursor,
        ):
            task = cursor.execute(
                "SELECT status::text AS status FROM tasks WHERE task_id = %s", (task_id,)
            ).fetchone()
            assert task is not None
            counts = cursor.execute(
                """
                SELECT
                    (SELECT count(*) FROM credentials WHERE task_id = %s) AS credentials,
                    (SELECT count(*) FROM coauthorization_authorizations
                     WHERE task_id = %s) AS authorizations,
                    (SELECT count(*) FROM audit_outbox WHERE payload ->> 'task_id' = %s) AS outbox
                """,
                (task_id, task_id, task_id),
            ).fetchone()
        assert counts is not None
        return (task["status"], counts["credentials"], counts["authorizations"], counts["outbox"])

    def delegate(
        self,
        parent: dict,
        issuer: KeyRecord,
        holder: KeyRecord,
        *,
        single_max_fen: int,
        refund_total_fen: int,
        max_tool_calls: int,
    ) -> dict:
        capability = deepcopy(
            next(
                item
                for item in parent["payload"]["capabilities"]
                if item["tool"] == "refund.create"
            )
        )
        capability["constraints"]["single_max_fen"] = single_max_fen
        request = DelegateCredentialRequest(
            holder_agent_id=holder.subject_id,
            holder_key_id=holder.key_id,
            capabilities=[DelegatedCapability.model_validate(capability)],
            quotas={
                "refund_total_fen": refund_total_fen,
                "max_tool_calls": max_tool_calls,
            },
            not_before=parent["payload"]["not_before"],
            expires_at=parent["payload"]["expires_at"] - 60,
        )
        return DelegationService(
            database_url=self.database_url,
            agent_id=issuer.subject_id,
            agent_key_id=issuer.key_id,
            private_key_root=str(self.private_root),
        ).delegate(
            parent["payload"]["credential_id"],
            request,
            current_time=now_unix(),
        )

    def request(
        self,
        chain: list[dict],
        *,
        business_action_id: str,
        amount_fen: int,
    ) -> RequestEnvelopeModel:
        timestamp = now_unix()
        leaf = chain[-1]["payload"]
        parameters = {
            "ticket_id": self.ticket_id,
            "customer_id": self.customer_id,
            "amount_fen": amount_fen,
        }
        chain_hash = sm3_hex(canonicalize(chain))
        parameter_hash = sm3_hex(canonicalize(parameters))
        proof_payload = {
            "schema_version": "1.0",
            "credential_chain_hash": chain_hash,
            "task_id": self.task_id,
            "tool_service": "refund-service",
            "tool_name": "refund.create",
            "tool_version": "v1",
            "canonical_parameter_hash": parameter_hash,
            "request_id": self.identifier("refund-request"),
            "issued_at": timestamp,
            "business_action_id": business_action_id,
        }
        pair = self.runtime_pairs[leaf["holder"]["key_id"]]
        signature = sign_payload(
            proof_payload,
            domain_separator=HOLDER_PROOF,
            key_id=leaf["holder"]["key_id"],
            key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            private_key_hex=pair.private_key_hex,
            public_key_hex=pair.public_key_hex,
            signed_at=timestamp,
        )
        return RequestEnvelopeModel.model_validate(
            {
                "schema_version": "1.0",
                "credential_chain": chain,
                "task_id": self.task_id,
                "tool_service": "refund-service",
                "tool_name": "refund.create",
                "tool_version": "v1",
                "canonical_parameters": parameters,
                "request_id": proof_payload["request_id"],
                "issued_at": timestamp,
                "holder_key_id": leaf["holder"]["key_id"],
                "business_action_id": business_action_id,
                "holder_proof": {"payload": proof_payload, "signature": signature},
            }
        )


@pytest.fixture
def full_workflow_case(
    full_workflow_database_url: str,
    tmp_path: Path,
) -> Iterator[FullWorkflowCase]:
    private_root = (tmp_path / "runtime-private").resolve()
    assert private_root.parent == tmp_path.resolve()
    assert not private_root.exists()
    case: FullWorkflowCase | None = None
    try:
        case = FullWorkflowCase(full_workflow_database_url, tmp_path)
        case.seed()
        yield case
    finally:
        if private_root.exists():
            store = FilePrivateKeyStore(private_root)
            for path in private_root.glob("*.private"):
                assert path.resolve().parent == private_root
                assert path.name.startswith("coauth-full-")
                store.destroy(path.name)
            assert not list(private_root.glob("*.private"))
        if case is not None:
            case.runtime_pairs.clear()
            case.approval_pairs.clear()


def test_full_coauthorization_delegation_gateway_refund_receipt_audit(
    full_workflow_case: FullWorkflowCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = full_workflow_case

    challenge = case.challenge()
    raw_bundle = case.offline_bundle(challenge)
    before_rejections = case.state_digest(case.task_id)

    with pytest.raises(CoauthorizationError) as single_error:
        case.service.authorize_task(
            case.task_id,
            case.single_approval_bundle(raw_bundle),
        )
    assert single_error.value.reason_code is CoauthorizationReason.INVALID_BUNDLE
    assert case.state_digest(case.task_id) == before_rejections

    with pytest.raises(CoauthorizationError) as cross_task_error:
        case.service.authorize_task(case.other_task_id, raw_bundle)
    assert cross_task_error.value.reason_code is CoauthorizationReason.TASK_OR_POLICY_MISMATCH
    assert case.state_digest(case.task_id) == before_rejections
    assert case.state_digest(case.other_task_id) == ("PENDING_AUTHORIZATION", 0, 0, 0)

    authorized = case.service.authorize_task(case.task_id, raw_bundle)
    root = authorized.credential
    assert authorized.reused is False
    assert root["payload"]["credential_id"] == authorized.root_credential_id
    assert root["payload"]["delegation_depth"] == 2
    assert root["payload"]["holder"] == {
        "agent_id": case.holder.subject_id,
        "key_id": case.holder.key_id,
    }

    first = case.delegate(
        root,
        case.holder,
        case.delegate_holder,
        single_max_fen=5_000,
        refund_total_fen=5_000,
        max_tool_calls=3,
    )
    second = case.delegate(
        first,
        case.delegate_holder,
        case.refund_holder,
        single_max_fen=3_000,
        refund_total_fen=3_000,
        max_tool_calls=2,
    )
    assert [
        root["payload"]["delegation_depth"],
        first["payload"]["delegation_depth"],
        second["payload"]["delegation_depth"],
    ] == [2, 1, 0]
    assert first["payload"]["parent_credential_id"] == root["payload"]["credential_id"]
    assert second["payload"]["parent_credential_id"] == first["payload"]["credential_id"]
    assert first["payload"]["quotas"] == {"refund_total_fen": 5_000, "max_tool_calls": 3}
    assert second["payload"]["quotas"] == {"refund_total_fen": 3_000, "max_tool_calls": 2}
    assert verify_payload(
        first["payload"],
        first["signature"],
        domain_separator=DELEGATION_CREDENTIAL,
        expected_key_id=case.holder.key_id,
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=case.holder.public_key_hex,
    )
    assert verify_payload(
        second["payload"],
        second["signature"],
        domain_separator=DELEGATION_CREDENTIAL,
        expected_key_id=case.delegate_holder.key_id,
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=case.delegate_holder.public_key_hex,
    )

    chain = CredentialChainVerifier(case.database_url).verify_chain(
        second["payload"]["credential_id"],
        current_time=now_unix(),
    )
    assert [item["payload"]["credential_id"] for item in chain] == [
        root["payload"]["credential_id"],
        first["payload"]["credential_id"],
        second["payload"]["credential_id"],
    ]

    action = BusinessActionRegistryService(case.database_url).resolve_refund(
        ResolveRefundActionRequest(task_id=case.task_id),
        current_time=now_unix(),
    )
    assert action["task_id"] == case.task_id
    request = case.request(
        chain,
        business_action_id=str(action["business_action_id"]),
        amount_fen=1_200,
    )

    gateway = SecureGatewayService(database_url=case.database_url)
    admission = AdmissionService(gateway)
    tool_app = make_tool_app(
        settings=Settings(
            database_url=case.database_url,
            storage="postgres",
            tool_kind="refund",
            gateway_audience=gateway.audience,
            gateway_key_id=case.gateway.key_id,
            gateway_public_key_hex=case.gateway.public_key_hex,
            envelope_ttl_seconds=30,
        ),
        store=PostgresToolStore(case.database_url),
    )
    tool_client = TestClient(tool_app)

    class LocalToolClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> LocalToolClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def post(self, url: str, **kwargs: object):
            assert url == "http://local-refund/internal/execute"
            return tool_client.post("/internal/execute", **kwargs)

    monkeypatch.setattr("backend.gateway.dispatch.httpx.Client", LocalToolClient)
    try:
        dispatch = GatewayDispatchService(
            gateway,
            admission,
            tool_urls={("refund-service", "refund.create"): "http://local-refund"},
            gateway_key_id=case.gateway.key_id,
            gateway_private_key_file=str(case.private_root / f"{case.gateway.key_id}.private"),
            envelope_ttl_seconds=30,
        )
        dispatched = dispatch.dispatch(request, current_time=request.issued_at)
    finally:
        tool_client.close()

    assert dispatched.status_code == 200
    assert dispatched.body["decision"] == "ALLOW"
    assert dispatched.body["state"] == "COMMITTED"
    execution_id = str(dispatched.body["execution_id"])
    with connect(case.database_url) as connection:
        execution = connection.execute(
            """
            SELECT state::text, decision::text, business_action_id, business_effect_id,
                   credential_chain_hash, receipt_status::text
            FROM execution_records WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        refund = connection.execute(
            """
            SELECT refund_id, execution_id, business_action_id, task_id, amount_fen, status
            FROM refunds WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        credential_ids = [item["payload"]["credential_id"] for item in chain]
        budgets = connection.execute(
            "SELECT credential_id, quota_type, reserved_value, committed_value "
            "FROM credential_budget_state WHERE credential_id = ANY(%s)",
            (credential_ids,),
        ).fetchall()
        reservations = connection.execute(
            "SELECT credential_id, quota_type, amount, status "
            "FROM execution_budget_reservations WHERE execution_id = %s",
            (execution_id,),
        ).fetchall()
    assert len(budgets) == 6
    assert set(budgets) == {
        (credential_id, quota_type, 0, amount)
        for credential_id in credential_ids
        for quota_type, amount in (("refund_total_fen", 1_200), ("max_tool_calls", 1))
    }
    assert len(reservations) == 6
    assert set(reservations) == {
        (credential_id, quota_type, amount, "COMMITTED")
        for credential_id in credential_ids
        for quota_type, amount in (("refund_total_fen", 1_200), ("max_tool_calls", 1))
    }
    assert execution is not None
    assert tuple(execution[:2]) == ("COMMITTED", "ALLOW")
    assert execution[2] == action["business_action_id"]
    assert execution[3] == refund[0]
    assert execution[4] == dispatched.body["credential_chain_hash"]
    assert execution[5] == "PENDING"
    assert refund is not None
    assert tuple(refund[1:]) == (
        execution_id,
        action["business_action_id"],
        case.task_id,
        1_200,
        "COMMITTED",
    )

    receipt_service = ReceiptService(
        case.database_url,
        private_key_file=str(case.private_root / f"{case.receipt.key_id}.private"),
        key_id=case.receipt.key_id,
    )
    receipt = receipt_service.issue(execution_id, current_time=now_unix())
    receipt_service.schemas.validate("execution-receipt.schema.json", receipt)
    assert verify_payload(
        receipt["payload"],
        receipt["signature"],
        domain_separator=EXECUTION_RECEIPT,
        expected_key_id=case.receipt.key_id,
        expected_key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
        public_key_hex=case.receipt.public_key_hex,
    )
    assert receipt["payload"]["execution_id"] == execution_id
    assert receipt["payload"]["task_id"] == case.task_id
    assert receipt["payload"]["credential_chain_hash"] == dispatched.body["credential_chain_hash"]
    assert receipt["payload"]["business_effect_id"] == refund[0]

    receipt_hash = sm3_hex(canonicalize(receipt))
    with connect(case.database_url) as connection:
        stored_receipt = connection.execute(
            "SELECT receipt_hash, receipt_status::text "
            "FROM execution_receipts WHERE execution_id = %s",
            (execution_id,),
        ).fetchone()
        pending = connection.execute(
            """
            SELECT event_type, evidence_reference, payload
            FROM audit_outbox
            WHERE evidence_reference = %s OR evidence_reference = %s
            ORDER BY event_type
            """,
            (authorized.root_credential_id, receipt["payload"]["receipt_id"]),
        ).fetchall()
    assert stored_receipt == (receipt_hash, "SIGNED")
    assert {row[0] for row in pending} == {
        "COAUTH_ROOT_AUTHORIZED",
        "RECEIPT_SIGNED",
        "EXECUTION_COMMITTED",
    }
    receipt_outbox = next(row[2] for row in pending if row[0] == "RECEIPT_SIGNED")
    assert receipt_outbox["execution_id"] == execution_id
    assert receipt_outbox["receipt_hash"] == receipt_hash

    appended = AuditService(case.database_url).append_pending(
        max_events=100,
        current_time=now_unix(),
    )
    assert appended["appended_count"] >= 3
    audit_verification = AuditService(case.database_url).verify(
        include_independent_checkpoint=False,
    )
    assert audit_verification["valid"] is True
    with connect(case.database_url) as connection:
        audit_rows = connection.execute(
            """
            SELECT event_type, evidence_reference, execution_id
            FROM audit_events
            WHERE evidence_reference = %s OR evidence_reference = %s
            ORDER BY event_sequence
            """,
            (authorized.root_credential_id, receipt["payload"]["receipt_id"]),
        ).fetchall()
    assert {row[0] for row in audit_rows} == {
        "COAUTH_ROOT_AUTHORIZED",
        "RECEIPT_SIGNED",
        "EXECUTION_COMMITTED",
    }
    assert all(
        row[2] is None if row[0] == "COAUTH_ROOT_AUTHORIZED" else row[2] == execution_id
        for row in audit_rows
    )
