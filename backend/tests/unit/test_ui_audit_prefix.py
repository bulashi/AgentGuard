"""BFF audit prefix test sources, authored without execution or collection.

Task snapshots and HTTP calls are mocked. Checkpoint signatures are deliberately
shape-valid SM2 placeholders, not cryptographic proof. Signed-object digests use
the real SM3 helper with hashlib reference assertions. SM3 availability and test
execution remain unverified in the authoring environment. No real database,
service, persisted key, or browser is needed.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest
from pydantic import ValidationError

import backend.ui_api.service as service_module
import backend.ui_api.store as store_module
from backend.audit.prefix_contracts import AuditEventBinding, AuditPrefixRequest, AuditPrefixResponse
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_EVENT_HASH
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore

TASK_ID = "TASK-UI-PREFIX-TEST"
AUDIT_URL = "https://audit-prefix.invalid"
PREFIX_PATH = "/extensions/audit-prefix-binding/v1/verify-events"


def _cores() -> list[dict[str, Any]]:
    events = []
    previous = "0" * 64
    for sequence in (1, 2):
        event = {
            "schema_version": "1.0", "event_sequence": sequence,
            "event_id": f"EVENT-UI-PREFIX-{sequence}", "execution_id": None,
            "event_type": "EXECUTION_ADMITTED", "timestamp": 100 + sequence,
            "payload_hash": "a" * 64, "evidence_reference": f"EVIDENCE-UI-PREFIX-{sequence}",
            "previous_event_hash": previous,
        }
        event["event_hash"] = sm3_hex(
            AUDIT_EVENT_HASH.encode("utf-8") + b"\x00"
            + bytes.fromhex(previous) + canonicalize(event)
        )
        events.append(event)
        previous = event["event_hash"]
    return events


def _report(events: list[dict[str, Any]], *, valid: bool = True) -> dict[str, Any]:
    latest = events[-1]
    # Shape-valid signature only: BFF contract validation does not verify SM2.
    signed = {
        "payload": {
            "schema_version": "1.0", "checkpoint_sequence": 1,
            "latest_event_sequence": latest["event_sequence"],
            "latest_event_hash": latest["event_hash"], "timestamp": 200,
        },
        "signature": {
            "algorithm": "SM2", "key_id": "audit-ui-prefix-shape-key",
            "key_purpose": "AUDIT_CHECKPOINT_SIGNING",
            "encoding": "SM2_RS_HEX_128_LOWERCASE", "value": "0" * 128,
            "signed_at": 200,
        },
    }
    return {
        "schema_version": "1.0", "task_id": TASK_ID,
        "verification": {
            "valid": valid, "checked_events": len(events),
            "latest_event_sequence": latest["event_sequence"],
            "latest_event_hash": latest["event_hash"], "rollback_detected": False,
            "first_invalid_sequence": None,
        },
        "checkpoint": {
            "signed_checkpoint": signed, "signed_object_hash": signed_object_hash(signed),
        } if valid else None,
        "event_bindings": [
            {
                "event_sequence": event["event_sequence"], "event_id": event["event_id"],
                "event_hash": event["event_hash"], "matched": True, "covered": valid,
                "verified_event": deepcopy(event),
            }
            for event in events
        ],
    }


def _at(document: dict[str, Any], path: tuple[str | int, ...]) -> Any:
    value: Any = document
    for key in path:
        value = value[key]
    return value


def _set_anchor(report: dict[str, Any], event: dict[str, Any]) -> None:
    checkpoint = report["checkpoint"]
    checkpoint["signed_checkpoint"]["payload"].update(
        latest_event_sequence=event["event_sequence"], latest_event_hash=event["event_hash"],
    )
    checkpoint["signed_object_hash"] = signed_object_hash(checkpoint["signed_checkpoint"])


@pytest.fixture(autouse=True)
def no_live_database_or_http(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*arguments: Any, **keywords: Any) -> Any:
        raise AssertionError("BFF prefix unit sources must not reach a real database or HTTP service")

    monkeypatch.setattr(store_module, "connect", forbidden)
    for name in ("Client", "post", "get", "request"):
        monkeypatch.setattr(service_module.httpx, name, forbidden)


def _bff(
    monkeypatch: pytest.MonkeyPatch, events: list[dict[str, Any]] | None = None,
) -> SimpleNamespace:
    cores = _cores() if events is None else deepcopy(events)
    request = AuditPrefixRequest.model_validate({
        "schema_version": "1.0", "task_id": TASK_ID, "events": deepcopy(cores),
    })
    snapshot = {
        "task": {"task_id": TASK_ID},
        "audit_events": [
            event | {"coauthorization_evidence": None, "evidence_binding_valid": None}
            for event in deepcopy(cores)
        ],
    }
    store = Mock(spec=UiReadStore)
    store.task_snapshot.return_value = snapshot
    subject = UiService(SimpleNamespace(audit_service_url=AUDIT_URL), store)
    post = Mock(return_value=_report(cores))
    get = Mock(side_effect=AssertionError("BFF prefix must not fetch a separate latest checkpoint"))
    monkeypatch.setattr(subject, "_post", post)
    monkeypatch.setattr(subject, "_get", get)
    return SimpleNamespace(
        subject=subject, store=store, post=post, get=get,
        request=request, cores=cores, snapshot=snapshot,
    )


def test_bff_rejects_request_task_mismatch_before_snapshot_or_upstream(monkeypatch) -> None:
    fake = _bff(monkeypatch)
    body = fake.request.model_dump(mode="json")
    body["task_id"] = "TASK-FOREIGN"
    request = AuditPrefixRequest.model_validate(body)

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, request)

    assert captured.value.status_code == 403
    assert captured.value.reason_code == "CROSS_TASK"
    assert fake.store.mock_calls == []
    fake.post.assert_not_called()
    fake.get.assert_not_called()


def test_bff_rejects_missing_task_without_upstream_call(monkeypatch) -> None:
    fake = _bff(monkeypatch)
    fake.store.task_snapshot.return_value = None

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 404
    assert captured.value.reason_code == "CROSS_TASK"
    assert fake.store.mock_calls == [call.task_snapshot(TASK_ID)]
    fake.post.assert_not_called()
    fake.get.assert_not_called()


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("changes", [
    {"event_id": "EVENT-FOREIGN"}, {"event_sequence": 99},
    {"event_sequence": 99, "event_id": "EVENT-FOREIGN"},
])
def test_bff_rejects_any_foreign_sequence_id_pair_before_upstream(monkeypatch, index, changes):
    fake = _bff(monkeypatch)
    body = fake.request.model_dump(mode="json")
    body["events"][index].update(changes)
    request = AuditPrefixRequest.model_validate(body)

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, request)

    assert captured.value.status_code == 403
    assert captured.value.reason_code == "CROSS_TASK"
    assert fake.store.mock_calls == [call.task_snapshot(TASK_ID)]
    fake.post.assert_not_called()
    fake.get.assert_not_called()


@pytest.mark.parametrize("path", [
    (), ("verification",), ("checkpoint",), ("checkpoint", "signed_checkpoint"),
    ("checkpoint", "signed_checkpoint", "payload"),
    ("checkpoint", "signed_checkpoint", "signature"),
    ("event_bindings", 0), ("event_bindings", 0, "verified_event"),
])
def test_bff_rejects_upstream_extra_fields_with_502(monkeypatch, path) -> None:
    fake = _bff(monkeypatch)
    _at(fake.post.return_value, path)["unexpected"] = "untrusted"

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"
    fake.post.assert_called_once_with(AUDIT_URL, PREFIX_PATH, fake.request.model_dump(mode="json"))
    fake.get.assert_not_called()


@pytest.mark.parametrize(("path", "field"), [
    ((), "schema_version"), ((), "task_id"), ((), "verification"),
    ((), "checkpoint"), ((), "event_bindings"),
    (("verification",), "latest_event_hash"), (("verification",), "first_invalid_sequence"),
    (("event_bindings", 0), "verified_event"),
    (("event_bindings", 0, "verified_event"), "execution_id"),
])
def test_bff_rejects_missing_fields_including_explicit_nullable_fields(monkeypatch, path, field):
    fake = _bff(monkeypatch)
    report = _report(fake.cores, valid=False)
    if field == "verified_event":
        report["event_bindings"][0].update(matched=False, covered=False, verified_event=None)
    AuditPrefixResponse.model_validate(report)
    del _at(report, path)[field]
    fake.post.return_value = report

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"
    fake.post.assert_called_once()


@pytest.mark.parametrize("change", ["task", "count", "order", "id", "sequence", "hash"])
def test_bff_requires_upstream_report_to_bind_complete_requested_batch(monkeypatch, change):
    fake = _bff(monkeypatch)
    # A negative report permits retained rows above its head, isolating request binding.
    report = _report(fake.cores, valid=change != "sequence")
    fake.post.return_value = report
    if change == "task":
        report["task_id"] = "TASK-FOREIGN"
    elif change == "count":
        report["event_bindings"].pop()
    elif change == "order":
        report["event_bindings"].reverse()
    else:
        field, value = {
            "id": ("event_id", "EVENT-FOREIGN"), "sequence": ("event_sequence", 99),
            "hash": ("event_hash", "f" * 64),
        }[change]
        binding = report["event_bindings"][0]
        binding[field] = binding["verified_event"][field] = value
        if change == "sequence":
            binding["covered"] = False
    # These pass the response model; rejection must come from request binding.
    AuditPrefixResponse.model_validate(report)

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"
    assert fake.store.mock_calls == [call.task_snapshot(TASK_ID)]
    fake.post.assert_called_once()


@pytest.mark.parametrize("changes", [
    {"timestamp": 102}, {"previous_event_hash": "d" * 64}, {"payload_hash": "e" * 64},
    {"evidence_reference": "EVIDENCE-FOREIGN"}, {"event_type": "EXECUTION_COMMITTED"},
    {"execution_id": "EXEC-FOREIGN"},
    {"schema_version": "2.0", "event_type": "COAUTH_ROOT_AUTHORIZED"},
])
def test_bff_rejects_true_match_flag_with_different_complete_core(monkeypatch, changes):
    fake = _bff(monkeypatch)
    report = fake.post.return_value
    report["event_bindings"][0]["verified_event"].update(changes)
    AuditPrefixResponse.model_validate(report)

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"


def test_bff_rejects_false_match_flag_with_identical_complete_core(monkeypatch) -> None:
    fake = _bff(monkeypatch)
    report = fake.post.return_value
    report["event_bindings"][0].update(matched=False, covered=False)
    AuditPrefixResponse.model_validate(report)

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"


@pytest.mark.parametrize("change", [
    "covered_without_match", "missing_event_matches", "covered_past_anchor",
    "positive_rollback", "positive_invalid_sequence", "positive_wrong_count",
    "positive_without_anchor", "duplicate_binding", "wrong_digest",
])
def test_bff_rejects_inconsistent_positive_or_coverage_claims(monkeypatch, change) -> None:
    fake = _bff(monkeypatch)
    report = fake.post.return_value
    if change == "covered_without_match":
        report["event_bindings"][0]["matched"] = False
    elif change == "missing_event_matches":
        report["event_bindings"][0]["verified_event"] = None
    elif change == "covered_past_anchor":
        _set_anchor(report, fake.cores[0])
    elif change == "positive_rollback":
        report["verification"]["rollback_detected"] = True
    elif change == "positive_invalid_sequence":
        report["verification"]["first_invalid_sequence"] = 1
    elif change == "positive_wrong_count":
        report["verification"]["checked_events"] = 1
    elif change == "positive_without_anchor":
        report["checkpoint"] = None
    elif change == "duplicate_binding":
        report["event_bindings"][1] = deepcopy(report["event_bindings"][0])
    else:
        report["checkpoint"]["signed_object_hash"] = "f" * 64

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"


@pytest.mark.parametrize("matched", [True, False])
@pytest.mark.parametrize("boundary", ["above_head", "head_hash", "anchor_hash"])
def test_bff_rejects_positive_nonnull_core_head_or_anchor_violation_with_502(
    monkeypatch, matched, boundary,
) -> None:
    fake = _bff(monkeypatch)
    report = fake.post.return_value
    _set_anchor(report, fake.cores[0])
    report["event_bindings"][1]["covered"] = False
    AuditPrefixResponse.model_validate(report)
    binding = report["event_bindings"][0 if boundary == "anchor_hash" else 1]
    binding.update(matched=matched, covered=False)
    if boundary == "above_head":
        binding["event_sequence"] = binding["verified_event"]["event_sequence"] = 3
    else:
        binding["verified_event"]["event_hash"] = "f" * 64
        if matched:
            binding["event_hash"] = "f" * 64
    AuditEventBinding.model_validate(binding)
    with pytest.raises(ValidationError, match="retained event differs"):
        AuditPrefixResponse.model_validate(report)

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"
    assert isinstance(captured.value.__cause__, ValidationError)
    assert fake.store.mock_calls == [call.task_snapshot(TASK_ID)]
    fake.post.assert_called_once_with(AUDIT_URL, PREFIX_PATH, fake.request.model_dump(mode="json"))
    fake.get.assert_not_called()


@pytest.mark.parametrize("matched", [True, False])
def test_bff_accepts_positive_head_and_anchor_hashes_including_unmatched_boundary_cores(
    monkeypatch, matched,
) -> None:
    fake = _bff(monkeypatch)
    report = fake.post.return_value
    _set_anchor(report, fake.cores[0])
    report["event_bindings"][1]["covered"] = False
    if not matched:
        body = fake.request.model_dump(mode="json")
        for selected, binding in zip(body["events"], report["event_bindings"], strict=True):
            selected["timestamp"] += 1
            binding.update(matched=False, covered=False)
        fake.request = AuditPrefixRequest.model_validate(body)

    result = fake.subject.audit_prefix(TASK_ID, fake.request)

    assert result == report
    assert result["event_bindings"][0]["verified_event"]["event_hash"] == (
        result["checkpoint"]["signed_checkpoint"]["payload"]["latest_event_hash"]
    )
    assert result["event_bindings"][1]["verified_event"]["event_hash"] == (
        result["verification"]["latest_event_hash"]
    )
    assert [binding["matched"] for binding in result["event_bindings"]] == [matched, matched]
    fake.post.assert_called_once_with(AUDIT_URL, PREFIX_PATH, fake.request.model_dump(mode="json"))
    fake.get.assert_not_called()


@pytest.mark.parametrize("condition", ["head_hash_mismatch", "retained_above_head", "empty_head"])
def test_bff_allows_negative_rollback_report_with_retained_core_head_disagreement(
    monkeypatch, condition,
) -> None:
    fake = _bff(monkeypatch)
    report = _report(fake.cores, valid=False)
    report["verification"]["rollback_detected"] = True
    if condition == "head_hash_mismatch":
        report["verification"]["latest_event_hash"] = "f" * 64
    elif condition == "retained_above_head":
        report["verification"].update(
            latest_event_sequence=1, latest_event_hash=fake.cores[0]["event_hash"],
        )
    else:
        report["verification"].update(latest_event_sequence=0, latest_event_hash="0" * 64)
    fake.post.return_value = report

    result = fake.subject.audit_prefix(TASK_ID, fake.request)

    assert result == report
    assert result["checkpoint"] is None
    assert result["verification"]["valid"] is False
    assert result["verification"]["rollback_detected"] is True
    assert all(binding["matched"] and not binding["covered"] for binding in result["event_bindings"])
    fake.post.assert_called_once_with(AUDIT_URL, PREFIX_PATH, fake.request.model_dump(mode="json"))
    fake.get.assert_not_called()


@pytest.mark.parametrize(("path", "field", "value"), [
    (("verification",), "valid", 1), (("verification",), "rollback_detected", 0),
    (("verification",), "checked_events", 2.0),
    (("verification",), "latest_event_sequence", True),
    (("event_bindings", 0), "event_sequence", 1.0),
    (("event_bindings", 0), "matched", 1), (("event_bindings", 0), "covered", 1),
])
def test_bff_strict_response_does_not_coerce_integers_or_flags(monkeypatch, path, field, value):
    fake = _bff(monkeypatch)
    _at(fake.post.return_value, path)[field] = value

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"


@pytest.mark.parametrize("upstream", [None, [], "not-a-prefix-report"])
def test_bff_rejects_nonobject_upstream_reports(monkeypatch, upstream) -> None:
    fake = _bff(monkeypatch)
    fake.post.return_value = upstream

    with pytest.raises(UiApiError) as captured:
        fake.subject.audit_prefix(TASK_ID, fake.request)

    assert captured.value.status_code == 502
    assert captured.value.reason_code == "CONTROLLED_RESULT_INVALID"


@pytest.mark.parametrize("state", [
    "positive", "failed_anchor", "rollback", "invalid_chain", "checkpoint_lags",
    "unmatched_core", "mixed_versions", "missing_verified_event", "missing_beyond_head",
])
def test_bff_allows_bound_positive_negative_and_partial_coverage_reports(monkeypatch, state):
    events = _cores()
    if state == "mixed_versions":
        events[1].update(schema_version="2.0", event_type="COAUTH_ROOT_AUTHORIZED")
        body = {key: value for key, value in events[1].items() if key != "event_hash"}
        events[1]["event_hash"] = sm3_hex(
            AUDIT_EVENT_HASH.encode("utf-8") + b"\x00"
            + bytes.fromhex(body["previous_event_hash"]) + canonicalize(body)
        )
    fake = _bff(monkeypatch, events)
    report = _report(events, valid=state not in {"failed_anchor", "rollback", "invalid_chain"})
    if state == "rollback":
        report["verification"]["rollback_detected"] = True
    elif state == "invalid_chain":
        report["verification"]["first_invalid_sequence"] = 1
    elif state == "checkpoint_lags":
        _set_anchor(report, events[0])
        report["event_bindings"][1]["covered"] = False
    elif state == "unmatched_core":
        body = fake.request.model_dump(mode="json")
        body["events"][0]["timestamp"] += 1
        fake.request = AuditPrefixRequest.model_validate(body)
        report["event_bindings"][0].update(matched=False, covered=False)
    elif state == "missing_verified_event":
        report["event_bindings"][0].update(matched=False, covered=False, verified_event=None)
    elif state == "missing_beyond_head":
        report["event_bindings"][1].update(
            event_sequence=3, matched=False, covered=False, verified_event=None,
        )
        body = fake.request.model_dump(mode="json")
        body["events"][1]["event_sequence"] = 3
        fake.request = AuditPrefixRequest.model_validate(body)
        fake.snapshot["audit_events"][1]["event_sequence"] = 3
    fake.post.return_value = report

    result = fake.subject.audit_prefix(TASK_ID, fake.request)

    assert result == report
    if result["checkpoint"] is not None:
        assert result["checkpoint"]["signed_object_hash"] == hashlib.new(
            "sm3", canonicalize(result["checkpoint"]["signed_checkpoint"]),
        ).hexdigest()
    assert fake.store.mock_calls == [call.task_snapshot(TASK_ID)]
    fake.post.assert_called_once_with(AUDIT_URL, PREFIX_PATH, fake.request.model_dump(mode="json"))
    fake.get.assert_not_called()
    AuditPrefixResponse.model_validate(result).require_request_binding(fake.request)
