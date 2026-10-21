"""Source-level audit contracts with inert connections, never PostgreSQL proof.

Positive evidence reuses the real SM2 approval fixtures and production ROOT
builder. The audit/UI helpers check structure and hash bindings; they do not
establish trusted signers, current permissions or deployed database behavior.
"""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import ValidationError as SchemaValidationError

from backend.audit import service as audit_module
from backend.audit.service import AuditError, AuditService
from backend.authorization.contracts import AuthorizeTaskRequest
from backend.authorization.credential import build_signed_root_credential
from backend.coauthorization.audit import (
    COAUTHORIZATION_AUDIT_EVENT_TYPE,
    COAUTHORIZATION_AUDIT_SCHEMA_VERSION,
    MAX_EVIDENCE_BYTES,
    make_authorization_audit_evidence,
    validate_authorization_audit_evidence,
)
from backend.coauthorization.contracts import COAUTHORIZATION_DOMAIN
from backend.coauthorization.verifier import verify_coauthorization
from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_EVENT_HASH, CAPABILITY_CREDENTIAL
from backend.crypto.sm import generate_keypair, sm3_hex, verify_payload
from backend.identity.key_registry import KeyRecord, PostgresKeyRegistry
from backend.tests.unit.test_audit_checkpoint_anchors import signed_anchors
from backend.tests.unit.test_coauthorization import (
    NOW,
    ApprovalCase,
    case as approval_case,
    keypairs,
)
from backend.ui_api import store as ui_store_module
from backend.ui_api.store import UiReadStore

ZERO_HASH = "0" * 64
APPENDED_AT = NOW + 5


@pytest.fixture
def signed_evidence(approval_case: ApprovalCase) -> dict[str, Any]:
    verified = verify_coauthorization(
        approval_case.raw(), trusted_task=approval_case.task,
        trusted_policy=approval_case.policy, trusted_challenge=approval_case.challenge,
        now=NOW, registry=approval_case.registry,
    )
    assert verified.verified_key_ids == tuple(
        approval_case.policy.required_signers.for_role(role).key_id
        for role in ("ENTERPRISE_APPROVER", "FINANCE_APPROVER")
    )
    for approval in approval_case.bundle["approvals"]:
        key = approval_case.records[approval["statement"]["key_id"]]
        assert verify_payload(
            approval["statement"], approval["signature"],
            domain_separator=COAUTHORIZATION_DOMAIN, expected_key_id=key.key_id,
            expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
            public_key_hex=key.public_key_hex,
        )
    pair = generate_keypair()
    authority = KeyRecord(
        key_id="audit-root-authority-key", subject_id="audit-root-authority",
        subject_type="AUTHORITY", purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=pair.public_key_hex, status=KeyState.ACTIVE,
        material_state=KeyMaterialState.PRESENT, private_key_reference="memory:audit-root",
        activated_at=NOW - 100, created_at=NOW - 100,
    )

    def load_private_key(reference: str) -> str:
        assert reference == authority.private_key_reference
        return pair.private_key_hex

    task = approval_case.task.model_dump(mode="json")
    task.update(approval_case.task.quotas.model_dump(mode="json"))
    credential = build_signed_root_credential(
        task=task,
        request=AuthorizeTaskRequest(
            confirmed=True, confirmer_id="coauthorization-v1",
            holder_agent_id=approval_case.task.holder.agent_id,
            holder_key_id=approval_case.task.holder.key_id,
            delegation_depth=approval_case.task.delegation_depth,
        ),
        authority_subject_id=authority.subject_id, authority_key=authority,
        private_keys=SimpleNamespace(load=load_private_key), current_time=NOW,
        schemas=SchemaStore(), credential_not_before=approval_case.task.not_before,
    )
    assert verify_payload(
        credential["payload"], credential["signature"],
        domain_separator=CAPABILITY_CREDENTIAL, expected_key_id=authority.key_id,
        expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=authority.public_key_hex,
    )
    evidence = make_authorization_audit_evidence(
        signed_bundle=approval_case.bundle, credential=credential, authorized_at=NOW,
    )
    validate_authorization_audit_evidence(evidence)
    assert evidence["signed_bundle"] == approval_case.bundle
    assert evidence["credential"] == credential
    assert MAX_EVIDENCE_BYTES == 65_536
    assert len(canonicalize(evidence, normalize_sets=False)) <= MAX_EVIDENCE_BYTES
    return evidence


class Rows:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self.rows)


class InertAuditConnection:
    """Return supplied rows and record writes, without SQL or transaction emulation."""

    def __init__(
        self, *, head: tuple[int, str], pending: list[tuple[Any, ...]],
        events: list[tuple[Any, ...]],
    ) -> None:
        self.head = head
        self.pending = pending
        self.events = events
        self.reads: list[tuple[str, tuple[Any, ...] | None]] = []
        self.writes: list[tuple[str, tuple[Any, ...] | None]] = []

    def __enter__(self) -> InertAuditConnection:
        return self

    def __exit__(self, *arguments: object) -> bool:
        return False

    def transaction(self) -> InertAuditConnection:
        return self

    def execute(self, query: str, parameters: tuple[Any, ...] | None = None) -> Rows:
        statement = " ".join(query.split())
        if statement.startswith(("INSERT ", "UPDATE ")):
            assert statement.startswith((
                "INSERT INTO audit_events ", "UPDATE audit_outbox ",
                "UPDATE audit_chain_head ",
            ))
            self.writes.append((statement, parameters))
            return Rows([])
        self.reads.append((statement, parameters))
        if statement.startswith("SET TRANSACTION "):
            return Rows([])
        if "FROM audit_chain_head " in statement:
            return Rows([self.head])
        if "FROM audit_events " in statement:
            return Rows(self.events)
        if "FROM audit_outbox " in statement:
            # Deliberately do not simulate WHERE; time rejection is an API invariant.
            return Rows(self.pending)
        raise AssertionError(f"unexpected inert audit query: {statement}")


def _service(
    monkeypatch: pytest.MonkeyPatch, *, pending: list[tuple[Any, ...]] | None = None,
    events: list[tuple[Any, ...]] | None = None, head: tuple[int, str] | None = None,
) -> tuple[AuditService, InertAuditConnection]:
    event_rows = events or []
    if head is None:
        head = (int(event_rows[-1][0]), str(event_rows[-1][8])) if event_rows else (0, ZERO_HASH)
    connection = InertAuditConnection(head=head, pending=pending or [], events=event_rows)

    def connect_inert(database_url: str) -> InertAuditConnection:
        assert database_url == "inert-audit-only"
        return connection

    monkeypatch.setattr(audit_module, "connect", connect_inert)
    return AuditService("inert-audit-only"), connection


def _authorization_outbox(evidence: dict[str, Any]) -> tuple[Any, ...]:
    return (
        "OUTBOX-COAUTH-" + sm3_hex(evidence["root_credential_id"].encode("utf-8")),
        None, COAUTHORIZATION_AUDIT_EVENT_TYPE, evidence["root_credential_id"],
        sm3_hex(canonicalize(evidence)), deepcopy(evidence), evidence["authorized_at"],
    )


def _legacy_outbox(suffix: str = "01", event_type: str = "EXECUTION_ADMITTED") -> tuple[Any, ...]:
    payload = {"execution_id": f"EXEC-LEGACY-{suffix}", "event_type": event_type}
    return (
        f"OUTBOX-LEGACY-{suffix}", payload["execution_id"], event_type,
        f"EVIDENCE-LEGACY-{suffix}", sm3_hex(canonicalize(payload)), payload, NOW - 1,
    )


def _event_body(row: tuple[Any, ...] | list[Any]) -> dict[str, Any]:
    return {
        "schema_version": row[9], "event_sequence": row[0], "event_id": row[1],
        "execution_id": row[2], "event_type": row[3], "timestamp": row[4],
        "payload_hash": row[5], "evidence_reference": row[6], "previous_event_hash": row[7],
    }


def _hash_event(event: dict[str, Any]) -> str:
    return sm3_hex(
        AUDIT_EVENT_HASH.encode("utf-8") + b"\x00"
        + bytes.fromhex(event["previous_event_hash"]) + canonicalize(event)
    )


def _event_row(
    outbox: tuple[Any, ...], *, sequence: int, previous_hash: str, version: str,
) -> tuple[Any, ...]:
    event_type = "EXECUTION_UNKNOWN" if outbox[2] == "RECOVERY_FAILED_FINAL" else outbox[2]
    row = (
        sequence, f"EVENT-INERT-{sequence}", outbox[1], event_type, APPENDED_AT,
        outbox[4], outbox[3], previous_hash, ZERO_HASH, version,
        outbox[0], deepcopy(outbox[5]), outbox[4], outbox[1], outbox[2], outbox[3],
        outbox[6], "APPENDED",
    )
    return row[:8] + (_hash_event(_event_body(row)),) + row[9:]


def _mixed_rows(evidence: dict[str, Any]) -> list[tuple[Any, ...]]:
    rows = []
    previous = ZERO_HASH
    for sequence, outbox, version in (
        (1, _legacy_outbox(), "1.0"),
        (2, _authorization_outbox(evidence), COAUTHORIZATION_AUDIT_SCHEMA_VERSION),
        (3, _legacy_outbox("03", "RECEIPT_SIGNED"), "1.0"),
    ):
        row = _event_row(outbox, sequence=sequence, previous_hash=previous, version=version)
        rows.append(row)
        previous = row[8]
    return rows


def _rehash_rows(rows: list[tuple[Any, ...]]) -> list[tuple[Any, ...]]:
    # Rehash the whole local chain so semantic rejection cannot rely on a stale event hash.
    result = []
    previous = ZERO_HASH
    for original in rows:
        row = list(original)
        row[7] = previous
        row[8] = _hash_event(_event_body(row))
        previous = row[8]
        result.append(tuple(row))
    return result


def test_append_coauthorization_saves_v2_without_normalizing_its_type(
    signed_evidence, monkeypatch,
) -> None:
    outbox = _authorization_outbox(signed_evidence)
    service, connection = _service(monkeypatch, pending=[outbox], head=(7, "7" * 64))
    result = service.append_pending(max_events=1, current_time=APPENDED_AT)
    assert len(connection.writes) == 3
    statement, stored = connection.writes[0]
    assert statement.startswith("INSERT INTO audit_events ")
    columns = [column.strip() for column in statement.partition("(")[2].partition(")")[0].split(",")]
    assert columns == [
        "event_sequence", "event_id", "outbox_event_id", "execution_id", "event_type",
        "event_timestamp", "payload_hash", "evidence_reference", "previous_event_hash",
        "event_hash", "schema_version",
    ]
    assert stored is not None and len(stored) == 11
    assert stored[0] == 8
    assert stored[2:9] == (
        outbox[0], None, COAUTHORIZATION_AUDIT_EVENT_TYPE, APPENDED_AT,
        outbox[4], outbox[3], "7" * 64,
    )
    assert stored[10] == COAUTHORIZATION_AUDIT_SCHEMA_VERSION == "2.0"
    body = {
        "schema_version": stored[10], "event_sequence": stored[0], "event_id": stored[1],
        "execution_id": stored[3], "event_type": stored[4], "timestamp": stored[5],
        "payload_hash": stored[6], "evidence_reference": stored[7],
        "previous_event_hash": stored[8],
    }
    assert stored[9] == _hash_event(body)
    service.coauthorization_schemas.validate("audit-event-v2.schema.json", body | {"event_hash": stored[9]})
    assert connection.writes[1][1] == (APPENDED_AT, outbox[0])
    assert "SET status = 'APPENDED'" in connection.writes[1][0]
    assert connection.writes[2][1] == (8, stored[9], APPENDED_AT)
    assert result == {
        "appended_count": 1, "latest_event_sequence": 8, "latest_event_hash": stored[9],
    }
    assert any(
        "payload_hash, payload, created_at" in query and parameters == (APPENDED_AT, 1)
        for query, parameters in connection.reads
    )


@pytest.mark.parametrize(("event_type", "normalized"), [
    ("EXECUTION_ADMITTED", "EXECUTION_ADMITTED"),
    ("RECOVERY_FAILED_FINAL", "EXECUTION_UNKNOWN"),
])
def test_legacy_append_keeps_v1_canonical_hash_profile(monkeypatch, event_type, normalized) -> None:
    service, connection = _service(monkeypatch, pending=[_legacy_outbox(event_type=event_type)])
    service.append_pending(current_time=APPENDED_AT)
    stored = connection.writes[0][1]
    assert stored is not None and len(stored) == 11
    assert stored[4] == normalized
    assert stored[10] == "1.0"
    body = {
        "schema_version": "1.0", "event_sequence": stored[0], "event_id": stored[1],
        "execution_id": stored[3], "event_type": normalized, "timestamp": APPENDED_AT,
        "payload_hash": stored[6], "evidence_reference": stored[7],
        "previous_event_hash": ZERO_HASH,
    }
    assert stored[9] == _hash_event(body)
    service.schemas.validate("audit-event.schema.json", body | {"event_hash": stored[9]})


@pytest.mark.parametrize(("index", "value"), [
    (4, ZERO_HASH), (5, None), (5, []), (5, "not-an-object"),
])
def test_legacy_append_rejects_wrong_digest_or_nonobject_body_before_writes(
    monkeypatch, index, value,
) -> None:
    outbox = list(_legacy_outbox())
    outbox[index] = value
    service, connection = _service(monkeypatch, pending=[tuple(outbox)])
    with pytest.raises(AuditError, match="payload hash"):
        service.append_pending(current_time=APPENDED_AT)
    assert connection.writes == []


def test_legacy_append_rejects_changed_body_with_original_digest(monkeypatch) -> None:
    outbox = list(_legacy_outbox())
    original_hash = outbox[4]
    outbox[5]["execution_id"] = "EXEC-TAMPERED"
    assert sm3_hex(canonicalize(outbox[5])) != original_hash
    service, connection = _service(monkeypatch, pending=[tuple(outbox)])
    with pytest.raises(AuditError, match="payload hash"):
        service.append_pending(current_time=APPENDED_AT)
    assert connection.writes == []


@pytest.mark.parametrize(("outbox_type", "event_type"), [
    ("EXECUTION_ADMITTED", "EXECUTION_ADMITTED"),
    ("RECOVERY_FAILED_FINAL", "EXECUTION_UNKNOWN"),
])
def test_legacy_verify_keeps_normalized_alias_and_real_body_hash(
    monkeypatch, outbox_type, event_type,
) -> None:
    outbox = _legacy_outbox(event_type=outbox_type)
    row = _event_row(outbox, sequence=1, previous_hash=ZERO_HASH, version="1.0")
    assert row[3] == event_type and row[14] == outbox_type
    assert row[5] == row[12] == sm3_hex(canonicalize(row[11]))
    assert row[8] == _hash_event(_event_body(row))
    service, connection = _service(monkeypatch, events=[row])
    assert service.verify(include_independent_checkpoint=False) == {
        "valid": True, "checked_events": 1, "latest_event_sequence": 1,
        "rollback_detected": False, "first_invalid_sequence": None,
    }
    assert connection.writes == []


@pytest.mark.parametrize("from_sequence", [1, 2])
def test_legacy_verify_rejects_only_outbox_body_changed_with_old_hash_ledger_and_head(
    signed_evidence, monkeypatch, from_sequence,
) -> None:
    rows = _mixed_rows(signed_evidence)
    original = rows[0]
    original_head = (rows[-1][0], rows[-1][8])
    changed = list(original)
    changed[11] = deepcopy(changed[11])
    changed[11]["execution_id"] = "EXEC-TAMPERED"
    rows[0] = tuple(changed)
    assert rows[0][:11] == original[:11] and rows[0][12:] == original[12:]
    assert _hash_event(_event_body(rows[0])) == original[8]
    assert sm3_hex(canonicalize(changed[11])) != original[12]
    service, connection = _service(monkeypatch, events=rows, head=original_head)
    result = service.verify(from_sequence=from_sequence, include_independent_checkpoint=False)
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 1
    assert result["rollback_detected"] is False
    assert connection.head == original_head
    assert connection.writes == []


def test_legacy_verify_rejects_rehashed_outbox_body_not_matching_event_digest(
    signed_evidence, monkeypatch,
) -> None:
    rows = _mixed_rows(signed_evidence)
    original = rows[0]
    changed = list(original)
    changed[11] = deepcopy(changed[11])
    changed[11]["execution_id"] = "EXEC-TAMPERED"
    changed[12] = sm3_hex(canonicalize(changed[11]))
    rows[0] = tuple(changed)
    assert rows[0][:11] == original[:11]
    assert changed[12] != changed[5]
    assert _hash_event(_event_body(rows[0])) == original[8]
    service, connection = _service(monkeypatch, events=rows)
    result = service.verify(include_independent_checkpoint=False)
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 1
    assert result["rollback_detected"] is False
    assert connection.writes == []


@pytest.mark.parametrize(("index", "value"), [
    (11, None), (12, ZERO_HASH), (13, "EXEC-WRONG"), (13, None),
    (14, "EXECUTION_RELEASED"), (14, "COAUTH_UNSUPPORTED"), (15, "EVIDENCE-WRONG"),
    (16, APPENDED_AT + 1), (16, str(NOW)), (16, True), (16, None),
    (17, "PENDING"), (17, None),
])
def test_legacy_verify_rejects_outbox_metadata_status_and_creation_time(
    signed_evidence, monkeypatch, index, value,
) -> None:
    rows = _mixed_rows(signed_evidence)
    original = rows[0]
    changed = list(original)
    changed[index] = value
    rows[0] = tuple(changed)
    assert rows[0][:11] == original[:11]
    assert _hash_event(_event_body(rows[0])) == original[8]
    service, connection = _service(monkeypatch, events=rows)
    result = service.verify(include_independent_checkpoint=False)
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 1
    assert result["rollback_detected"] is False
    assert connection.writes == []


@pytest.mark.parametrize(("index", "value"), [
    (0, "OUTBOX-WRONG"), (1, "EXEC-WRONG"), (2, "COAUTH_UNSUPPORTED"),
    (2, "EXECUTION_UNKNOWN"), (2, "UNRECOGNIZED_LEGACY_TYPE"),
    (3, "ROOT-WRONG"), (4, ZERO_HASH),
    (6, NOW + 1), (6, str(NOW)), (6, True),
])
def test_append_rejects_bad_metadata_and_downgrade_before_any_write(
    signed_evidence, monkeypatch, index, value,
) -> None:
    outbox = list(_authorization_outbox(signed_evidence))
    outbox[index] = value
    service, connection = _service(monkeypatch, pending=[tuple(outbox)])
    with pytest.raises(AuditError):
        service.append_pending(current_time=APPENDED_AT)
    assert connection.writes == []


@pytest.mark.parametrize("timestamp", [NOW - 1, str(NOW), True])
def test_append_explicitly_rejects_time_before_creation_or_noninteger_time(
    signed_evidence, monkeypatch, timestamp,
) -> None:
    service, connection = _service(monkeypatch, pending=[_authorization_outbox(signed_evidence)])
    with pytest.raises(AuditError, match="predates authorization"):
        service.append_pending(current_time=timestamp)
    assert connection.writes == []


@pytest.mark.parametrize("mutation", [
    lambda body: body.update(root_credential_id="ROOT-WRONG"),
    lambda body: body.update(root_credential_hash=ZERO_HASH),
    lambda body: body.update(bundle_hash=ZERO_HASH),
    lambda body: body.update(schema_version="2.0"),
    lambda body: body.update(tenant_id="tenant-wrong"),
    lambda body: body.update(authorized_at=NOW - 1),
    lambda body: body.pop("credential"),
    lambda body: body.update(unexpected_field=True),
    lambda body: body["signed_bundle"]["approvals"][0]["signature"].update(value="invalid-hex"),
    lambda body: body.update(oversized="x" * (MAX_EVIDENCE_BYTES + 1)),
])
def test_append_rejects_invalid_body_even_with_recomputed_outer_digest(
    signed_evidence, monkeypatch, mutation,
) -> None:
    evidence = deepcopy(signed_evidence)
    mutation(evidence)
    outbox = list(_authorization_outbox(signed_evidence))
    outbox[4] = sm3_hex(canonicalize(evidence))
    outbox[5] = evidence
    service, connection = _service(monkeypatch, pending=[tuple(outbox)])
    with pytest.raises(AuditError):
        service.append_pending(current_time=APPENDED_AT)
    assert connection.writes == []


@pytest.mark.parametrize("body", [None, [], "not-an-evidence-object"])
def test_append_rejects_nonobject_evidence_without_appending(signed_evidence, monkeypatch, body) -> None:
    outbox = list(_authorization_outbox(signed_evidence))
    outbox[5] = body
    service, connection = _service(monkeypatch, pending=[tuple(outbox)])
    with pytest.raises(AuditError):
        service.append_pending(current_time=APPENDED_AT)
    assert connection.writes == []


@pytest.mark.parametrize("from_sequence", [1, 2])
def test_verify_mixed_v1_v2_v1_chain(signed_evidence, monkeypatch, from_sequence) -> None:
    rows = _mixed_rows(signed_evidence)
    service, connection = _service(monkeypatch, events=rows)
    assert service.verify(from_sequence=from_sequence, include_independent_checkpoint=False) == {
        "valid": True, "checked_events": 4 - from_sequence, "latest_event_sequence": 3,
        "rollback_detected": False, "first_invalid_sequence": None,
    }
    assert connection.writes == []
    assert any("event.schema_version" in query and "outbox.status" in query for query, _ in connection.reads)


@pytest.mark.parametrize(("index", "value"), [
    (2, "EXEC-WRONG"), (3, "EXECUTION_UNKNOWN"), (4, NOW - 1),
    (5, ZERO_HASH), (6, "ROOT-WRONG"), (9, "1.0"), (9, "3.0"),
    (10, "OUTBOX-WRONG"), (11, None), (12, ZERO_HASH), (13, "EXEC-WRONG"),
    (14, "EXECUTION_UNKNOWN"), (15, "ROOT-WRONG"), (16, NOW + 1),
    (16, str(NOW)), (17, "PENDING"), (17, None),
])
def test_verify_rejects_v2_metadata_and_version_conflicts_after_chain_rehash(
    signed_evidence, monkeypatch, index, value,
) -> None:
    rows = _mixed_rows(signed_evidence)
    changed = list(rows[1])
    changed[index] = value
    rows[1] = tuple(changed)
    service, connection = _service(monkeypatch, events=_rehash_rows(rows))
    result = service.verify(include_independent_checkpoint=False)
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 2
    assert result["rollback_detected"] is False
    assert connection.writes == []


@pytest.mark.parametrize("rehash_payload", [False, True])
def test_verify_rejects_payload_tampering_with_or_without_updated_outer_hashes(
    signed_evidence, monkeypatch, rehash_payload,
) -> None:
    rows = _mixed_rows(signed_evidence)
    changed = list(rows[1])
    changed[11] = deepcopy(changed[11])
    changed[11]["root_credential_hash"] = ZERO_HASH
    if rehash_payload:
        changed[5] = changed[12] = sm3_hex(canonicalize(changed[11]))
    rows[1] = tuple(changed)
    service, connection = _service(monkeypatch, events=_rehash_rows(rows))
    result = service.verify(include_independent_checkpoint=False)
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 2
    assert connection.writes == []


def test_verify_rejects_coauthorization_disguised_as_rehashed_v1(signed_evidence, monkeypatch) -> None:
    rows = _mixed_rows(signed_evidence)
    changed = list(rows[1])
    changed[9] = "1.0"
    changed[3] = changed[14] = "EXECUTION_UNKNOWN"
    rows[1] = tuple(changed)
    service, connection = _service(monkeypatch, events=_rehash_rows(rows))
    result = service.verify(include_independent_checkpoint=False)
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 2
    assert connection.writes == []


def test_mixed_chain_passes_all_prefix_hashes_to_original_signed_checkpoint_verifier(
    signed_evidence, signed_anchors, monkeypatch,
) -> None:
    rows = _mixed_rows(signed_evidence)
    anchors = [signed_anchors(1, 1, rows[0][8]), signed_anchors(2, 2, rows[1][8])]
    service, connection = _service(monkeypatch, events=rows)
    monkeypatch.setattr(service, "_load_checkpoints", lambda: anchors)
    original_verify = service._verify_checkpoint
    observed = []
    main_snapshot = connection

    def verify_checkpoint(latest_sequence, latest_hash, *, event_hashes, checkpoints, connection):
        assert connection is main_snapshot
        observed.append((latest_sequence, latest_hash, dict(event_hashes), checkpoints))
        return original_verify(
            latest_sequence, latest_hash, event_hashes=event_hashes, checkpoints=checkpoints, connection=connection,
        )

    monkeypatch.setattr(service, "_verify_checkpoint", verify_checkpoint)
    result = service.verify(from_sequence=2, include_independent_checkpoint=True)
    assert result["valid"] is True and result["checked_events"] == 2
    assert observed == [(3, rows[-1][8], {row[0]: row[8] for row in rows}, anchors)]
    for anchor in anchors:
        assert anchor[3]["payload"]["schema_version"] == "1.0"
        assert anchor[3]["signature"]["key_purpose"] == KeyPurpose.AUDIT_CHECKPOINT_SIGNING.value
        service.schemas.validate("audit-checkpoint.schema.json", anchor[3])
    assert connection.writes == []


def test_original_checkpoint_detects_rehashed_legacy_prefix_in_mixed_chain(
    signed_evidence, signed_anchors, monkeypatch,
) -> None:
    rows = _mixed_rows(signed_evidence)
    anchors = [signed_anchors(1, 1, rows[0][8])]
    changed = list(rows[0])
    changed[6] = changed[15] = "EVIDENCE-REPLACED-PREFIX"
    rows[0] = tuple(changed)
    service, connection = _service(monkeypatch, events=_rehash_rows(rows))
    monkeypatch.setattr(service, "_load_checkpoints", lambda: anchors)
    result = service.verify(from_sequence=2, include_independent_checkpoint=True)
    assert result["valid"] is False
    assert result["rollback_detected"] is True
    assert result["first_invalid_sequence"] is None
    assert connection.writes == []


def test_frozen_v1_schema_still_rejects_v2_and_coauthorization_type(signed_evidence, monkeypatch) -> None:
    service, _ = _service(monkeypatch)
    row = _mixed_rows(signed_evidence)[1]
    event = _event_body(row) | {"event_hash": row[8]}
    service.coauthorization_schemas.validate("audit-event-v2.schema.json", event)
    with pytest.raises(SchemaValidationError):
        service.schemas.validate("audit-event.schema.json", event)
    with pytest.raises(SchemaValidationError):
        service.schemas.validate("audit-event.schema.json", event | {"schema_version": "1.0"})


@pytest.fixture
def no_ui_database_or_trust_lookup(monkeypatch) -> None:
    def forbidden(*arguments, **keywords):
        raise AssertionError("audit projection must only check structure and hash bindings")

    monkeypatch.setattr(ui_store_module, "connect", forbidden)
    monkeypatch.setattr(ui_store_module, "verify_payload", forbidden)
    monkeypatch.setattr(PostgresKeyRegistry, "resolve_for_verification_with_connection", forbidden)


def _ui_row(row: tuple[Any, ...]) -> tuple[Any, ...]:
    # UI selects the original nine event fields, version, then the evidence body.
    return row[:10] + (deepcopy(row[11]),)


def test_ui_projection_and_static_snapshot_expose_only_evidence_binding(
    signed_evidence, no_ui_database_or_trust_lookup,
) -> None:
    row = _ui_row(_mixed_rows(signed_evidence)[1])
    projection = UiReadStore._audit_projection(row)
    assert projection["evidence_binding_valid"] is True
    assert projection["execution_id"] is None
    assert projection["schema_version"] == "2.0"
    assert projection["event_type"] == COAUTHORIZATION_AUDIT_EVENT_TYPE
    assert projection["coauthorization_evidence"] == signed_evidence
    assert projection["revocation_evidence"] is None
    assert set(projection) == {
        "event_sequence", "event_id", "execution_id", "event_type", "timestamp",
        "payload_hash", "evidence_reference", "previous_event_hash", "event_hash",
        "schema_version", "coauthorization_evidence", "revocation_evidence", "evidence_binding_valid",
    }
    payload = signed_evidence["signed_bundle"]["payload"]
    task = (
        payload["task_id"], payload["tenant_id"], payload["ticket_id"], payload["customer_id"],
        payload["quotas"]["refund_total_fen"], payload["quotas"]["max_tool_calls"],
        payload["expires_at"], "AUTHORIZED", payload["not_before"], NOW,
    )
    snapshot = UiReadStore._snapshot_body(
        task=task, credentials=[], executions=[], receipts=[], refunds=[], notifications=[],
        audit_events=[row],
    )
    assert snapshot["audit_events"] == [projection]


@pytest.mark.parametrize(("index", "value"), [
    (2, "EXEC-WRONG"), (4, NOW - 1), (5, ZERO_HASH), (6, "ROOT-WRONG"),
    (9, "1.0"), (9, "3.0"), (10, None), (10, []), (10, {"invalid": True}),
])
def test_ui_projection_rejects_bad_body_hash_version_and_metadata(
    signed_evidence, no_ui_database_or_trust_lookup, index, value,
) -> None:
    row = list(_ui_row(_mixed_rows(signed_evidence)[1]))
    row[index] = value
    projection = UiReadStore._audit_projection(tuple(row))
    assert projection["evidence_binding_valid"] is False
    assert projection["coauthorization_evidence"] is None


def test_ui_projection_rejects_invalid_evidence_with_matching_outer_digest(
    signed_evidence, no_ui_database_or_trust_lookup,
) -> None:
    row = list(_ui_row(_mixed_rows(signed_evidence)[1]))
    row[10]["root_credential_hash"] = ZERO_HASH
    row[5] = sm3_hex(canonicalize(row[10]))
    projection = UiReadStore._audit_projection(tuple(row))
    assert projection["evidence_binding_valid"] is False
    assert projection["coauthorization_evidence"] is None


def test_ui_legacy_projection_has_no_coauthorization_binding_claim(
    signed_evidence, no_ui_database_or_trust_lookup,
) -> None:
    row = _ui_row(_mixed_rows(signed_evidence)[0])
    projection = UiReadStore._audit_projection(row)
    assert projection["schema_version"] == "1.0"
    assert projection["evidence_binding_valid"] is None
    assert projection["coauthorization_evidence"] is None
