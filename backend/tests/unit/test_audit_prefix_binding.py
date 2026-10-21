"""Audit prefix regression sources, authored without execution or collection.

Fake connections do not prove PostgreSQL isolation. Shape-valid SM2 signatures
and mocked verifiers do not prove cryptography. Digest assertions call real SM3;
hashlib SM3 availability and execution remain unverified in the authoring environment.
The signed-anchor fixture uses ephemeral SM2 keys only when these tests are run.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

import backend.audit.service as audit_module
from backend.audit.contracts import AuditVerifyResponse
from backend.audit.prefix_contracts import (
    MAX_PREFIX_EVENTS,
    AuditEventBinding,
    AuditPrefixRequest,
    AuditPrefixResponse,
)
from backend.audit.service import AuditService, AuditVerificationSnapshot
from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_CHECKPOINT, AUDIT_EVENT_HASH
from backend.crypto.sm import (
    generate_keypair,
    sign_payload,
    signed_object_hash,
    sm3_hex,
    verify_payload,
)
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry

TASK_ID = "TASK-PREFIX-TEST"
ZERO_HASH = "0" * 64
MAIN_DATABASE_URL = "mock-prefix-main-database"
SNAPSHOT_TRANSACTION = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
LEGACY_VERIFY_FIELDS = {
    "valid", "checked_events", "latest_event_sequence",
    "rollback_detected", "first_invalid_sequence",
}


def _event_digest(event: dict[str, Any]) -> str:
    body = {key: value for key, value in event.items() if key != "event_hash"}
    return sm3_hex(
        AUDIT_EVENT_HASH.encode("utf-8") + b"\x00"
        + bytes.fromhex(body["previous_event_hash"]) + canonicalize(body)
    )


def _core(sequence: int = 1, version: str = "1.0") -> dict[str, Any]:
    event = {
        "schema_version": version,
        "event_sequence": sequence,
        "event_id": f"EVENT-PREFIX-{sequence}",
        "execution_id": None,
        "event_type": "EXECUTION_ADMITTED" if version == "1.0" else "COAUTH_ROOT_AUTHORIZED",
        "timestamp": 100 + sequence,
        "payload_hash": "a" * 64,
        "evidence_reference": f"EVIDENCE-PREFIX-{sequence}",
        "previous_event_hash": ZERO_HASH if sequence == 1 else "b" * 64,
    }
    return event | {"event_hash": _event_digest(event)}


def _request_body(events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1.0", "task_id": TASK_ID,
        "events": deepcopy([_core()] if events is None else events),
    }


def _shape_anchor(checkpoint_sequence: int, event: dict[str, Any]) -> tuple[Any, ...]:
    # This is schema-shaped data, not an SM2 signature verification result.
    signed = {
        "payload": {
            "schema_version": "1.0", "checkpoint_sequence": checkpoint_sequence,
            "latest_event_sequence": event["event_sequence"],
            "latest_event_hash": event["event_hash"], "timestamp": 200,
        },
        "signature": {
            "algorithm": "SM2", "key_id": "audit-prefix-shape-key",
            "key_purpose": "AUDIT_CHECKPOINT_SIGNING",
            "encoding": "SM2_RS_HEX_128_LOWERCASE", "value": "0" * 128,
            "signed_at": 200,
        },
    }
    return checkpoint_sequence, event["event_sequence"], event["event_hash"], signed, 201


def _snapshot(
    events: list[dict[str, Any]] | None = None, *, covered_sequence: int | None = None,
    valid: bool = True, rollback: bool = False, first_invalid: int | None = None,
) -> AuditVerificationSnapshot:
    cores = deepcopy([_core()] if events is None else events)
    by_sequence = {event["event_sequence"]: event for event in cores}
    latest = max(by_sequence)
    anchor_sequence = latest if covered_sequence is None else covered_sequence
    signed = _shape_anchor(1, by_sequence[anchor_sequence])[3]
    return AuditVerificationSnapshot(
        response={
            "valid": valid, "checked_events": len(cores), "latest_event_sequence": latest,
            "rollback_detected": rollback, "first_invalid_sequence": first_invalid,
        },
        latest_event_hash=by_sequence[latest]["event_hash"],
        events=by_sequence,
        checkpoint={
            "signed_checkpoint": signed, "signed_object_hash": signed_object_hash(signed),
        } if valid else None,
    )


def _response(
    events: list[dict[str, Any]] | None = None, *, valid: bool = True,
    covered_sequence: int | None = None,
) -> dict[str, Any]:
    snapshot = _snapshot(events, valid=valid, covered_sequence=covered_sequence)
    anchor_sequence = (
        snapshot.checkpoint["signed_checkpoint"]["payload"]["latest_event_sequence"]
        if snapshot.checkpoint is not None else 0
    )
    return {
        "schema_version": "1.0", "task_id": TASK_ID,
        "verification": snapshot.response | {"latest_event_hash": snapshot.latest_event_hash},
        "checkpoint": deepcopy(snapshot.checkpoint),
        "event_bindings": [
            {
                "event_sequence": event["event_sequence"], "event_id": event["event_id"],
                "event_hash": event["event_hash"], "matched": True,
                "covered": bool(valid and event["event_sequence"] <= anchor_sequence),
                "verified_event": deepcopy(event),
            }
            for event in snapshot.events.values()
        ],
    }


def _at(document: dict[str, Any], path: tuple[str | int, ...]) -> Any:
    value: Any = document
    for key in path:
        value = value[key]
    return value


@pytest.fixture(autouse=True)
def no_live_database(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*arguments: Any, **keywords: Any) -> Any:
        raise AssertionError("prefix unit sources must not open a real database or trust store")

    monkeypatch.setattr(audit_module, "connect", forbidden)
    monkeypatch.setattr(PostgresKeyRegistry, "resolve_for_verification_with_connection", forbidden)


def _snapshot_service(
    monkeypatch: pytest.MonkeyPatch, snapshot: AuditVerificationSnapshot,
) -> tuple[AuditService, Mock]:
    subject = AuditService(MAIN_DATABASE_URL)
    read = Mock(return_value=snapshot)
    monkeypatch.setattr(subject, "_verification_snapshot", read)
    monkeypatch.setattr(subject, "verify", Mock(side_effect=AssertionError("extra legacy verify")))
    monkeypatch.setattr(
        subject, "_load_checkpoints", Mock(side_effect=AssertionError("extra checkpoint read")),
    )
    return subject, read


@pytest.mark.parametrize("versions", [("1.0",), ("2.0",), ("1.0", "2.0")])
def test_contract_accepts_complete_versioned_event_cores(versions: tuple[str, ...]) -> None:
    events = [_core(index, version) for index, version in enumerate(versions, start=1)]
    request = AuditPrefixRequest.model_validate(_request_body(events))
    report = AuditPrefixResponse.model_validate(_response(events))

    report.require_request_binding(request)

    assert request.events == events
    assert report.model_dump(mode="json")["event_bindings"][0]["verified_event"] == events[0]
    assert all(event["execution_id"] is None for event in request.events)


@pytest.mark.parametrize("version", ["1.0", "2.0"])
@pytest.mark.parametrize("field", ["event_sequence", "timestamp"])
@pytest.mark.parametrize("value", [True, False, 1.0, 101.0])
def test_request_rejects_boolean_or_float_event_integers(version, field, value) -> None:
    body = _request_body([_core(version=version)])
    body["events"][0][field] = value

    with pytest.raises(ValidationError):
        AuditPrefixRequest.model_validate(body)


@pytest.mark.parametrize("field", ["event_id", "event_sequence"])
def test_request_rejects_duplicate_id_or_sequence_independently(field: str) -> None:
    body = _request_body([_core(1), _core(2)])
    body["events"][1][field] = body["events"][0][field]

    with pytest.raises(ValidationError, match="unique"):
        AuditPrefixRequest.model_validate(body)


@pytest.mark.parametrize("path", [(), ("events", 0)])
def test_request_rejects_unknown_fields(path: tuple[str | int, ...]) -> None:
    body = _request_body()
    _at(body, path)["unexpected"] = "untrusted"

    with pytest.raises(ValidationError):
        AuditPrefixRequest.model_validate(body)


@pytest.mark.parametrize("size", [0, 101])
def test_contract_rejects_empty_or_over_100_batches(size: int) -> None:
    assert MAX_PREFIX_EVENTS == 100
    events = [_core(sequence) for sequence in range(1, size + 1)]
    with pytest.raises(ValidationError):
        AuditPrefixRequest.model_validate(_request_body(events))

    report = _response(events) if events else _response()
    if not events:
        report["event_bindings"] = []
    with pytest.raises(ValidationError):
        AuditPrefixResponse.model_validate(report)


def test_contract_accepts_exactly_100_events_and_bindings() -> None:
    events = [_core(sequence) for sequence in range(1, 101)]
    request = AuditPrefixRequest.model_validate(_request_body(events))
    report = AuditPrefixResponse.model_validate(_response(events))

    report.require_request_binding(request)

    assert len(request.events) == len(report.event_bindings) == 100


@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_request_requires_explicit_nullable_execution_id(version: str) -> None:
    body = _request_body([_core(version=version)])
    AuditPrefixRequest.model_validate(body)
    del body["events"][0]["execution_id"]

    with pytest.raises(ValidationError):
        AuditPrefixRequest.model_validate(body)


@pytest.mark.parametrize(("path", "field"), [
    ((), "checkpoint"), (("verification",), "first_invalid_sequence"),
    (("event_bindings", 0), "verified_event"),
    (("event_bindings", 0, "verified_event"), "execution_id"),
])
def test_response_requires_nullable_fields_to_be_present(path, field) -> None:
    report = _response(valid=False)
    if field == "verified_event":
        report["event_bindings"][0].update(matched=False, covered=False, verified_event=None)
    AuditPrefixResponse.model_validate(report)
    del _at(report, path)[field]

    with pytest.raises(ValidationError):
        AuditPrefixResponse.model_validate(report)


@pytest.mark.parametrize("path", [
    (), ("verification",), ("checkpoint",), ("checkpoint", "signed_checkpoint"),
    ("checkpoint", "signed_checkpoint", "payload"),
    ("checkpoint", "signed_checkpoint", "signature"),
    ("event_bindings", 0), ("event_bindings", 0, "verified_event"),
])
def test_response_rejects_unknown_fields_at_each_boundary(path) -> None:
    report = _response()
    _at(report, path)["unexpected"] = "untrusted"

    with pytest.raises(ValidationError):
        AuditPrefixResponse.model_validate(report)


@pytest.mark.parametrize(("path", "field"), [
    (("verification",), "checked_events"),
    (("verification",), "latest_event_sequence"),
    (("verification",), "first_invalid_sequence"),
    (("event_bindings", 0), "event_sequence"),
    (("event_bindings", 0, "verified_event"), "event_sequence"),
    (("event_bindings", 0, "verified_event"), "timestamp"),
    (("checkpoint", "signed_checkpoint", "payload"), "checkpoint_sequence"),
    (("checkpoint", "signed_checkpoint", "payload"), "latest_event_sequence"),
    (("checkpoint", "signed_checkpoint", "payload"), "timestamp"),
    (("checkpoint", "signed_checkpoint", "signature"), "signed_at"),
])
@pytest.mark.parametrize("kind", ["bool", "float"])
def test_response_rejects_boolean_or_float_integers_before_digest_validation(
    path, field, kind,
) -> None:
    report = _response(valid=field != "first_invalid_sequence")
    target = _at(report, path)
    original = target[field] if target[field] is not None else 1
    target[field] = True if kind == "bool" else float(original)

    with pytest.raises(ValidationError) as captured:
        AuditPrefixResponse.model_validate(report)

    expected_path = path + (field,)
    if "signed_checkpoint" in path:
        expected_path = ("checkpoint", "signed_checkpoint")
    elif "verified_event" in path:
        expected_path = ("event_bindings", 0, "verified_event")
    assert any(error["loc"] == expected_path for error in captured.value.errors())


@pytest.mark.parametrize("field", ["event_id", "event_sequence"])
def test_response_rejects_duplicate_bindings_even_with_aligned_core_metadata(field) -> None:
    report = _response([_core(1), _core(2)])
    first, second = report["event_bindings"]
    second[field] = second["verified_event"][field] = first[field]

    with pytest.raises(ValidationError, match="unique"):
        AuditPrefixResponse.model_validate(report)


@pytest.mark.parametrize("matched", [True, False])
def test_request_binding_checks_both_directions_of_complete_core_match(matched: bool) -> None:
    request = AuditPrefixRequest.model_validate(_request_body())
    report = _response()
    binding = report["event_bindings"][0]
    binding.update(matched=matched, covered=matched)
    if matched:
        binding["verified_event"]["timestamp"] += 1
    parsed = AuditPrefixResponse.model_validate(report)

    with pytest.raises(ValueError, match="complete event core"):
        parsed.require_request_binding(request)


@pytest.mark.parametrize("change", ["task", "count", "order", "id", "sequence", "hash"])
def test_request_binding_rejects_batch_or_identity_substitution(change: str) -> None:
    events = [_core(1), _core(2)]
    request = AuditPrefixRequest.model_validate(_request_body(events))
    # A negative report permits retained rows above its head, isolating request binding.
    report = _response(events, valid=change != "sequence")
    if change == "task":
        report["task_id"] = "TASK-OTHER"
    elif change == "count":
        report["event_bindings"].pop()
    elif change == "order":
        report["event_bindings"].reverse()
    else:
        field, value = {
            "id": ("event_id", "EVENT-OTHER"),
            "sequence": ("event_sequence", 3), "hash": ("event_hash", "f" * 64),
        }[change]
        binding = report["event_bindings"][0]
        binding[field] = binding["verified_event"][field] = value
        if change == "sequence":
            binding["covered"] = False
    parsed = AuditPrefixResponse.model_validate(report)

    with pytest.raises(ValueError):
        parsed.require_request_binding(request)


@pytest.mark.parametrize("matched", [True, False])
@pytest.mark.parametrize("boundary", ["above_head", "head_hash", "anchor_hash"])
def test_positive_report_rejects_nonnull_core_outside_head_or_anchor_even_if_uncovered(
    matched: bool, boundary: str,
) -> None:
    report = _response([_core(1), _core(2)], covered_sequence=1)
    AuditPrefixResponse.model_validate(report)
    index = 0 if boundary == "anchor_hash" else 1
    binding = report["event_bindings"][index]
    binding.update(matched=matched, covered=False)
    if boundary == "above_head":
        binding["event_sequence"] = binding["verified_event"]["event_sequence"] = 3
    else:
        binding["verified_event"]["event_hash"] = "f" * 64
        if matched:
            binding["event_hash"] = "f" * 64
    # The individual binding is valid; the positive report must enforce the boundary.
    AuditEventBinding.model_validate(binding)

    with pytest.raises(ValidationError, match="retained event differs"):
        AuditPrefixResponse.model_validate(report)


@pytest.mark.parametrize("matched", [True, False])
def test_positive_report_accepts_matching_head_and_lagging_anchor_hashes(matched: bool) -> None:
    events = [_core(1), _core(2)]
    report = _response(events, covered_sequence=1)
    requested = deepcopy(events)
    if not matched:
        for selected, binding in zip(requested, report["event_bindings"], strict=True):
            selected["timestamp"] += 1
            binding.update(matched=False, covered=False)
    request = AuditPrefixRequest.model_validate(_request_body(requested))

    parsed = AuditPrefixResponse.model_validate(report)
    parsed.require_request_binding(request)

    assert parsed.event_bindings[0].verified_event["event_hash"] == (
        parsed.checkpoint.signed_checkpoint["payload"]["latest_event_hash"]
    )
    assert parsed.event_bindings[1].verified_event["event_hash"] == parsed.verification.latest_event_hash
    assert [binding.matched for binding in parsed.event_bindings] == [matched, matched]


def test_positive_head_limit_does_not_reject_explicit_null_missing_event() -> None:
    events = [_core(1), _core(2)]
    report = _response(events, covered_sequence=1)
    missing = report["event_bindings"][1]
    missing.update(event_sequence=3, matched=False, covered=False, verified_event=None)
    selected = events[1] | {"event_sequence": 3}
    request = AuditPrefixRequest.model_validate(_request_body([events[0], selected]))

    parsed = AuditPrefixResponse.model_validate(report)
    parsed.require_request_binding(request)

    assert parsed.verification.valid is True
    assert parsed.event_bindings[1].verified_event is None
    assert not parsed.event_bindings[1].matched and not parsed.event_bindings[1].covered


@pytest.mark.parametrize("condition", ["head_hash_mismatch", "retained_above_head", "empty_head"])
def test_negative_rollback_report_allows_retained_core_head_disagreement(condition: str) -> None:
    events = [_core(1), _core(2)]
    report = _response(events, valid=False)
    report["verification"]["rollback_detected"] = True
    if condition == "head_hash_mismatch":
        report["verification"]["latest_event_hash"] = "f" * 64
    elif condition == "retained_above_head":
        report["verification"].update(
            latest_event_sequence=1, latest_event_hash=events[0]["event_hash"],
        )
    else:
        report["verification"].update(latest_event_sequence=0, latest_event_hash=ZERO_HASH)
    request = AuditPrefixRequest.model_validate(_request_body(events))

    parsed = AuditPrefixResponse.model_validate(report)
    parsed.require_request_binding(request)

    assert parsed.verification.valid is False and parsed.verification.rollback_detected is True
    assert parsed.checkpoint is None
    assert all(binding.matched and not binding.covered for binding in parsed.event_bindings)
    assert parsed.event_bindings[1].verified_event == events[1]


def test_checkpoint_digest_binds_exact_signed_object_with_real_sm3() -> None:
    report = _response()
    signed = report["checkpoint"]["signed_checkpoint"]
    expected = hashlib.new("sm3", canonicalize(signed)).hexdigest()

    parsed = AuditPrefixResponse.model_validate(report)

    assert parsed.checkpoint is not None
    assert parsed.checkpoint.signed_checkpoint == signed
    assert parsed.checkpoint.signed_object_hash == expected
    assert expected == signed_object_hash(signed)
    assert expected != hashlib.new("sm3", canonicalize(signed["payload"])).hexdigest()


@pytest.mark.parametrize("change", ["signature", "payload", "payload_only_digest"])
def test_checkpoint_rejects_changed_signed_object_or_payload_only_digest(change: str) -> None:
    report = _response()
    checkpoint = report["checkpoint"]
    signed = checkpoint["signed_checkpoint"]
    if change == "signature":
        signed["signature"]["value"] = "1" * 128
    elif change == "payload":
        signed["payload"]["checkpoint_sequence"] += 1
    else:
        checkpoint["signed_object_hash"] = sm3_hex(canonicalize(signed["payload"]))

    with pytest.raises(ValidationError, match="digest differs"):
        AuditPrefixResponse.model_validate(report)


@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_verify_events_exact_core_match_for_each_version(monkeypatch, version) -> None:
    event = _core(version=version)
    subject, read = _snapshot_service(monkeypatch, _snapshot([event]))
    reordered = dict(reversed(list(event.items())))
    request = AuditPrefixRequest.model_validate(_request_body([reordered]))

    result = subject.verify_events(request)

    assert result["event_bindings"][0] == {
        "event_sequence": event["event_sequence"], "event_id": event["event_id"],
        "event_hash": event["event_hash"], "matched": True, "covered": True,
        "verified_event": event,
    }
    read.assert_called_once_with(from_sequence=1, include_independent_checkpoint=True)


@pytest.mark.parametrize("changes", [
    {"timestamp": 102}, {"event_hash": "c" * 64}, {"previous_event_hash": "d" * 64},
    {"payload_hash": "e" * 64}, {"evidence_reference": "EVIDENCE-OTHER"},
    {"event_type": "EXECUTION_COMMITTED"}, {"execution_id": "EXECUTION-OTHER"},
    {"schema_version": "2.0", "event_type": "COAUTH_ROOT_AUTHORIZED"},
])
def test_verify_events_changed_core_is_neither_matched_nor_covered(monkeypatch, changes) -> None:
    event = _core()
    subject, read = _snapshot_service(monkeypatch, _snapshot([event]))
    request = AuditPrefixRequest.model_validate(_request_body([event | changes]))

    result = subject.verify_events(request)

    binding = result["event_bindings"][0]
    assert binding["matched"] is False
    assert binding["covered"] is False
    assert binding["verified_event"] == event
    assert binding["event_hash"] == request.events[0]["event_hash"]
    assert result["verification"]["valid"] is True
    read.assert_called_once_with(from_sequence=1, include_independent_checkpoint=True)


@pytest.mark.parametrize("selected", [_core(2), _core() | {"event_id": "EVENT-OTHER"}])
def test_verify_events_missing_sequence_or_id_returns_explicit_null_event(monkeypatch, selected):
    subject, _read = _snapshot_service(monkeypatch, _snapshot())
    request = AuditPrefixRequest.model_validate(_request_body([selected]))

    result = subject.verify_events(request)

    assert result["event_bindings"][0] == {
        "event_sequence": selected["event_sequence"], "event_id": selected["event_id"],
        "event_hash": selected["event_hash"], "matched": False, "covered": False,
        "verified_event": None,
    }


def test_verify_events_uses_one_snapshot_and_retained_anchor_without_latest_reread(monkeypatch):
    events = [_core(1), _core(2)]
    snapshot = _snapshot(events, covered_sequence=1)
    subject, read = _snapshot_service(monkeypatch, snapshot)
    request = AuditPrefixRequest.model_validate(_request_body(events))

    result = subject.verify_events(request)

    read.assert_called_once_with(from_sequence=1, include_independent_checkpoint=True)
    subject.verify.assert_not_called()
    subject._load_checkpoints.assert_not_called()
    assert result["verification"] == snapshot.response | {
        "latest_event_hash": snapshot.latest_event_hash,
    }
    assert result["checkpoint"] == snapshot.checkpoint
    assert result["checkpoint"]["signed_checkpoint"]["payload"]["latest_event_sequence"] == 1
    assert [binding["matched"] for binding in result["event_bindings"]] == [True, True]
    assert [binding["covered"] for binding in result["event_bindings"]] == [True, False]


@pytest.mark.parametrize(("rollback", "first_invalid"), [(False, 1), (True, None), (False, None)])
def test_invalid_rollback_or_failed_verification_cannot_cover_matching_events(
    monkeypatch, rollback, first_invalid,
) -> None:
    snapshot = _snapshot(valid=False, rollback=rollback, first_invalid=first_invalid)
    subject, _read = _snapshot_service(monkeypatch, snapshot)

    result = subject.verify_events(AuditPrefixRequest.model_validate(_request_body()))

    assert result["verification"]["valid"] is False
    assert result["verification"]["rollback_detected"] is rollback
    assert result["verification"]["first_invalid_sequence"] == first_invalid
    assert result["checkpoint"] is None
    assert result["event_bindings"][0]["matched"] is True
    assert result["event_bindings"][0]["covered"] is False


@pytest.mark.parametrize(("from_sequence", "include_checkpoint"), [(1, True), (2, False)])
def test_legacy_verify_remains_exactly_five_fields(monkeypatch, from_sequence, include_checkpoint):
    snapshot = _snapshot([_core(1), _core(2)])
    subject, read = _snapshot_service(monkeypatch, snapshot)

    result = AuditService.verify(
        subject, from_sequence=from_sequence, include_independent_checkpoint=include_checkpoint,
    )

    read.assert_called_once_with(
        from_sequence=from_sequence, include_independent_checkpoint=include_checkpoint,
    )
    assert result is snapshot.response
    assert set(result) == LEGACY_VERIFY_FIELDS
    assert set(AuditVerifyResponse.model_fields) == LEGACY_VERIFY_FIELDS
    assert AuditVerifyResponse.model_validate(result).model_dump(mode="json") == result


def _chain_rows(count: int = 3) -> list[tuple[Any, ...]]:
    rows = []
    previous = ZERO_HASH
    for sequence in range(1, count + 1):
        payload = {"execution_id": f"EXEC-PREFIX-{sequence}", "event_type": "EXECUTION_ADMITTED"}
        event = _core(sequence) | {
            "execution_id": payload["execution_id"], "payload_hash": sm3_hex(canonicalize(payload)),
            "previous_event_hash": previous,
        }
        event["event_hash"] = _event_digest(event)
        rows.append((
            sequence, event["event_id"], event["execution_id"], event["event_type"],
            event["timestamp"], event["payload_hash"], event["evidence_reference"], previous,
            event["event_hash"], event["schema_version"], f"OUTBOX-PREFIX-{sequence}",
            payload, event["payload_hash"], event["execution_id"], event["event_type"],
            event["evidence_reference"], event["timestamp"] - 1, "APPENDED",
        ))
        previous = event["event_hash"]
    return rows


class Rows:
    def __init__(self, connection: FakeAuditConnection, values: list[tuple[Any, ...]]) -> None:
        self.connection = connection
        self.values = values

    def fetchone(self) -> tuple[Any, ...] | None:
        assert self.connection.active, "rows must be fetched inside the snapshot context"
        return self.values[0] if self.values else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        assert self.connection.active, "rows must be fetched inside the snapshot context"
        return list(self.values)


class FakeAuditConnection:
    """Record one context and its SELECTs; this does not emulate PostgreSQL isolation."""

    def __init__(self, head: tuple[int, str], rows: list[tuple[Any, ...]]) -> None:
        self.head = head
        self.rows = rows
        self.active = False
        self.entries = 0
        self.statements: list[str] = []

    def __enter__(self) -> FakeAuditConnection:
        assert self.entries == 0, "main database must not be reopened for key trust or latest data"
        self.entries += 1
        self.active = True
        return self

    def __exit__(self, *arguments: object) -> bool:
        self.active = False
        return False

    def execute(self, query: str, parameters: tuple[Any, ...] | None = None) -> Rows:
        assert self.active, "queries must use the active main snapshot connection"
        assert parameters is None
        statement = " ".join(query.split())
        self.statements.append(statement)
        if statement == SNAPSHOT_TRANSACTION:
            assert len(self.statements) == 1
            return Rows(self, [])
        assert self.statements[0] == SNAPSHOT_TRANSACTION
        assert statement.startswith("SELECT "), "audit verification must not write"
        if "FROM audit_chain_head " in statement:
            return Rows(self, [self.head])
        if "FROM audit_events AS event " in statement:
            return Rows(self, self.rows)
        raise AssertionError(f"unexpected fake audit SQL: {statement}")


def _main_snapshot_service(
    monkeypatch: pytest.MonkeyPatch, rows: list[tuple[Any, ...]],
    checkpoints: list[tuple[Any, ...]], *, head: tuple[int, str] | None = None,
) -> SimpleNamespace:
    connection = FakeAuditConnection(head if head is not None else (rows[-1][0], rows[-1][8]), rows)

    def connect_main(database_url: str) -> FakeAuditConnection:
        assert database_url == MAIN_DATABASE_URL, "independent store reads must be mocked"
        return connection

    connect = Mock(side_effect=connect_main)
    monkeypatch.setattr(audit_module, "connect", connect)
    subject = AuditService(MAIN_DATABASE_URL, audit_database_url="mock-prefix-independent-store")
    load = Mock(return_value=checkpoints)
    monkeypatch.setattr(subject, "_load_checkpoints", load)
    return SimpleNamespace(subject=subject, connection=connection, connect=connect, load=load)


def _mock_checkpoint_crypto(monkeypatch: pytest.MonkeyPatch, connection: FakeAuditConnection):
    # Key resolution and SM2 verification are stubs here, not cryptographic evidence.
    key = SimpleNamespace(
        key_id="audit-prefix-shape-key", purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
        public_key_hex="a" * 128,
    )

    def resolve(used_connection, key_id, **keywords):
        assert used_connection is connection and connection.active
        assert key_id == key.key_id
        assert keywords["expected_subject_id"] == "audit-checkpoint-signer"
        assert keywords["expected_purpose"] is KeyPurpose.AUDIT_CHECKPOINT_SIGNING
        return key

    resolver = Mock(side_effect=resolve)
    verifier = Mock(return_value=True)
    monkeypatch.setattr(PostgresKeyRegistry, "resolve_for_verification_with_connection", resolver)
    monkeypatch.setattr(audit_module, "verify_payload", verifier)
    return resolver, verifier


def test_verify_rows_passes_same_active_readonly_rr_connection_into_checkpoint_key_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _chain_rows()
    anchors = [_shape_anchor(1, AuditService._row_event_core(rows[0]))]
    fake = _main_snapshot_service(monkeypatch, rows, anchors)
    resolver, verifier = _mock_checkpoint_crypto(monkeypatch, fake.connection)
    verify_rows = Mock(wraps=fake.subject._verify_rows)
    verify_checkpoint = Mock(wraps=fake.subject._verify_checkpoint)
    monkeypatch.setattr(fake.subject, "_verify_rows", verify_rows)
    monkeypatch.setattr(fake.subject, "_verify_checkpoint", verify_checkpoint)

    snapshot = fake.subject._verification_snapshot(
        from_sequence=1, include_independent_checkpoint=True,
    )

    verify_rows.assert_called_once_with(
        fake.connection, latest_sequence=3, latest_hash=rows[-1][8], all_rows=rows,
        checkpoint_rows=anchors, from_sequence=1, include_independent_checkpoint=True,
    )
    verify_checkpoint.assert_called_once_with(
        3, rows[-1][8], event_hashes={row[0]: row[8] for row in rows},
        checkpoints=anchors, connection=fake.connection,
    )
    resolver.assert_called_once_with(
        fake.connection, "audit-prefix-shape-key", expected_subject_id="audit-checkpoint-signer",
        expected_purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
        signed_at=200, trusted_registered_at=201,
    )
    verifier.assert_called_once_with(
        anchors[0][3]["payload"], anchors[0][3]["signature"],
        domain_separator=AUDIT_CHECKPOINT, expected_key_id="audit-prefix-shape-key",
        expected_key_purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING, public_key_hex="a" * 128,
    )
    fake.connect.assert_called_once_with(MAIN_DATABASE_URL)
    fake.load.assert_called_once_with()
    assert fake.connection.entries == 1 and not fake.connection.active
    assert len(fake.connection.statements) == 3
    assert fake.connection.statements[0] == SNAPSHOT_TRANSACTION
    assert snapshot.response["valid"] is True
    assert snapshot.events == {row[0]: AuditService._row_event_core(row) for row in rows}


def test_verified_anchor_uses_max_coverage_then_checkpoint_sequence_and_exact_object(monkeypatch):
    rows = _chain_rows()
    cores = [AuditService._row_event_core(row) for row in rows]
    anchors = [
        _shape_anchor(1, cores[1]), _shape_anchor(2, cores[0]),
        _shape_anchor(3, cores[1]), _shape_anchor(4, cores[0]),
    ]
    fake = _main_snapshot_service(monkeypatch, rows, anchors)
    resolver, verifier = _mock_checkpoint_crypto(monkeypatch, fake.connection)

    result = fake.subject.verify_events(AuditPrefixRequest.model_validate(_request_body(cores)))

    signed = anchors[2][3]
    assert result["checkpoint"] == {
        "signed_checkpoint": signed,
        "signed_object_hash": hashlib.new("sm3", canonicalize(signed)).hexdigest(),
    }
    assert resolver.call_count == verifier.call_count == len(anchors)
    assert [arguments.args[0] for arguments in verifier.call_args_list] == [
        row[3]["payload"] for row in anchors
    ]
    assert [binding["covered"] for binding in result["event_bindings"]] == [True, True, False]
    assert result["verification"]["latest_event_sequence"] == 3
    assert result["verification"]["latest_event_hash"] == rows[-1][8]
    fake.connect.assert_called_once_with(MAIN_DATABASE_URL)


@pytest.mark.parametrize("failure", ["invalid_event", "chain_rollback", "failed_anchor"])
def test_verify_rows_failure_never_retains_anchor_or_covers_events(monkeypatch, failure) -> None:
    rows = _chain_rows()
    head = (rows[-1][0], rows[-1][8])
    if failure == "invalid_event":
        changed = list(rows[0])
        changed[4] += 1  # Leave the original event hash to expose the changed core.
        rows[0] = tuple(changed)
    elif failure == "chain_rollback":
        head = (2, rows[-1][8])
    anchors = [_shape_anchor(1, AuditService._row_event_core(rows[0]))]
    fake = _main_snapshot_service(monkeypatch, rows, anchors, head=head)
    checkpoint = Mock(return_value=(failure != "failed_anchor", False))
    monkeypatch.setattr(fake.subject, "_verify_checkpoint", checkpoint)
    request = AuditPrefixRequest.model_validate(_request_body([
        AuditService._row_event_core(row) for row in rows
    ]))

    result = fake.subject.verify_events(request)

    assert result["verification"]["valid"] is False
    assert result["verification"]["rollback_detected"] is (failure == "chain_rollback")
    assert result["verification"]["first_invalid_sequence"] == (
        1 if failure == "invalid_event" else None
    )
    assert result["checkpoint"] is None
    assert all(binding["matched"] and not binding["covered"] for binding in result["event_bindings"])
    assert checkpoint.call_args.kwargs["connection"] is fake.connection
    fake.connect.assert_called_once_with(MAIN_DATABASE_URL)


@pytest.fixture
def signed_checkpoint_case(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    # Generated only during a future test run; no persisted or official key files.
    pair = generate_keypair()
    key = SimpleNamespace(
        key_id="audit-prefix-ephemeral-key", purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
        public_key_hex=pair.public_key_hex,
    )
    resolver = Mock(return_value=key)
    monkeypatch.setattr(PostgresKeyRegistry, "resolve_for_verification_with_connection", resolver)

    def make(checkpoint_sequence: int, event_sequence: int, event_hash: str):
        timestamp = 200 + checkpoint_sequence
        payload = {
            "schema_version": "1.0", "checkpoint_sequence": checkpoint_sequence,
            "latest_event_sequence": event_sequence, "latest_event_hash": event_hash,
            "timestamp": timestamp,
        }
        signature = sign_payload(
            payload, domain_separator=AUDIT_CHECKPOINT,
            key_id=key.key_id, key_purpose=key.purpose,
            private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex,
            signed_at=timestamp,
        )
        return (
            checkpoint_sequence, event_sequence, event_hash,
            {"payload": payload, "signature": signature}, timestamp + 1,
        )

    return SimpleNamespace(make=make, key=key, resolver=resolver, connection=object())


@pytest.mark.parametrize("bad_index", [0, 1])
@pytest.mark.parametrize(("failure", "rollback"), [
    ("invalid_shape", False), ("row_mismatch", False), ("invalid_signature", False),
    ("changed_prefix", True), ("missing_prefix", True), ("key_trust_failure", False),
])
def test_any_failed_historical_anchor_blocks_positive_even_with_real_valid_new_signature(
    signed_checkpoint_case, bad_index, failure, rollback,
) -> None:
    case = signed_checkpoint_case
    anchors = [case.make(1, 1, "1" * 64), case.make(2, 2, "2" * 64), case.make(3, 2, "2" * 64)]
    newest = anchors[-1][3]
    subject = AuditService(MAIN_DATABASE_URL)
    arguments = {
        "event_hashes": {1: "1" * 64, 2: "2" * 64}, "connection": case.connection,
    }
    assert verify_payload(
        newest["payload"], newest["signature"], domain_separator=AUDIT_CHECKPOINT,
        expected_key_id=case.key.key_id, expected_key_purpose=case.key.purpose,
        public_key_hex=case.key.public_key_hex,
    )
    assert subject._verify_checkpoint(2, "2" * 64, checkpoints=[anchors[-1]], **arguments) == (
        True, False,
    )
    bad = list(deepcopy(anchors[bad_index]))
    if failure == "invalid_shape":
        bad[3]["signature"]["algorithm"] = "RSA"
    elif failure == "row_mismatch":
        bad[0] += 10
    elif failure == "invalid_signature":
        bad[3]["payload"]["timestamp"] += 1
        bad[3]["signature"]["signed_at"] += 1
        assert not verify_payload(
            bad[3]["payload"], bad[3]["signature"], domain_separator=AUDIT_CHECKPOINT,
            expected_key_id=case.key.key_id, expected_key_purpose=case.key.purpose,
            public_key_hex=case.key.public_key_hex,
        )
    elif failure in {"changed_prefix", "missing_prefix"}:
        sequence = bad[1] if failure == "changed_prefix" else 3
        bad = list(case.make(bad[0], sequence, "f" * 64))
    else:
        failed_at = bad[3]["signature"]["signed_at"]

        def resolve(connection, key_id, **keywords):
            assert connection is case.connection and key_id == case.key.key_id
            if keywords["signed_at"] == failed_at:
                raise KeyRegistryError(ReasonCode.INVALID_SIGNATURE, "mock historical key untrusted")
            return case.key

        case.resolver.side_effect = resolve
    anchors[bad_index] = tuple(bad)

    assert subject._verify_checkpoint(2, "2" * 64, checkpoints=anchors, **arguments) == (
        False, rollback,
    )


def test_real_signed_new_anchor_cannot_hide_old_changed_prefix_in_full_report(
    monkeypatch: pytest.MonkeyPatch, signed_checkpoint_case,
) -> None:
    case = signed_checkpoint_case
    rows = _chain_rows(2)
    anchors = [case.make(1, 1, "f" * 64), case.make(2, 2, rows[-1][8])]
    fake = _main_snapshot_service(monkeypatch, rows, anchors)
    request = AuditPrefixRequest.model_validate(_request_body([
        AuditService._row_event_core(row) for row in rows
    ]))

    result = fake.subject.verify_events(request)

    assert result["verification"]["valid"] is False
    assert result["verification"]["rollback_detected"] is True
    assert result["verification"]["first_invalid_sequence"] is None
    assert result["checkpoint"] is None
    assert all(binding["matched"] and not binding["covered"] for binding in result["event_bindings"])
    assert all(arguments.args[0] is fake.connection for arguments in case.resolver.call_args_list)
    fake.connect.assert_called_once_with(MAIN_DATABASE_URL)


def test_legacy_without_checkpoint_keeps_five_fields_and_does_not_load_anchors(monkeypatch) -> None:
    rows = _chain_rows()
    fake = _main_snapshot_service(monkeypatch, rows, [])
    checkpoint = Mock(side_effect=AssertionError("legacy opt-out must not verify checkpoints"))
    monkeypatch.setattr(fake.subject, "_verify_checkpoint", checkpoint)

    result = fake.subject.verify(from_sequence=2, include_independent_checkpoint=False)

    assert result == {
        "valid": True, "checked_events": 2, "latest_event_sequence": 3,
        "rollback_detected": False, "first_invalid_sequence": None,
    }
    assert set(result) == LEGACY_VERIFY_FIELDS
    fake.load.assert_not_called()
    checkpoint.assert_not_called()
    fake.connect.assert_called_once_with(MAIN_DATABASE_URL)
