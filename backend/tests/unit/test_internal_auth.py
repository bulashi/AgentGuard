from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import (
    CALLER_HEADER,
    PROOF_HEADER,
    InternalAuthenticator,
    InternalAuthError,
    SqliteNonceStore,
)

KEYS = {
    "recovery-trigger->recovery-worker": "11" * 32,
    "recovery-worker->refund-service": "22" * 32,
    "recovery-worker->notification-service": "33" * 32,
    "recovery-worker->receipt-service": "44" * 32,
}
BODY = b'{"execution_id":"EXEC-001"}'
PATH = "/internal/reconcile"
CURRENT = 1000


def authenticator(
    tmp_path: Path, service_id: str, *, required: bool = True, current: int = CURRENT,
    keys: dict[str, str] | None = None,
) -> InternalAuthenticator:
    return InternalAuthenticator(
        service_id=service_id, keys_json=json.dumps(KEYS if keys is None else keys),
        required=required, clock=lambda: current,
        nonce_store=SqliteNonceStore(tmp_path / f"{service_id}.sqlite3"),
    )


def signed_headers(tmp_path: Path, **kwargs) -> dict[str, str]:
    return authenticator(tmp_path, "recovery-worker").request_headers(
        recipient="refund-service", method="POST", path=PATH, body=BODY, **kwargs,
    )


def verify(receiver: InternalAuthenticator, headers: dict[str, str], **changes) -> str:
    return receiver.verify_headers(**{
        "headers": headers, "method": "POST", "path": PATH, "body": BODY,
        "allowed_callers": {"recovery-worker"}, **changes,
    })


def test_valid_proof_and_fresh_nonce_are_required_per_retry(tmp_path: Path) -> None:
    receiver = authenticator(tmp_path, "refund-service")
    first = signed_headers(tmp_path)
    second = signed_headers(tmp_path)
    assert first[PROOF_HEADER] != second[PROOF_HEADER]
    assert verify(receiver, first) == "recovery-worker"
    with pytest.raises(InternalAuthError) as caught:
        verify(receiver, first)
    assert caught.value.reason_code == ReasonCode.REPLAY_DETECTED
    assert verify(receiver, second) == "recovery-worker"


@pytest.mark.parametrize("headers", [{}, {CALLER_HEADER: "recovery-worker"}])
def test_constant_identity_string_cannot_authenticate(tmp_path: Path, headers) -> None:
    with pytest.raises(InternalAuthError):
        verify(authenticator(tmp_path, "refund-service"), headers)
    assert not (tmp_path / "refund-service.sqlite3").exists()


@pytest.mark.parametrize("changes", [
    {"method": "GET"}, {"path": "/internal/execute"},
    {"body": b'{"execution_id":"EXEC-OTHER"}'},
    {"body": b'{ "execution_id": "EXEC-001" }'},
    {"allowed_callers": {"agent-refund"}},
])
def test_proof_binds_exact_method_path_bytes_and_allowed_caller(tmp_path: Path, changes) -> None:
    headers = signed_headers(tmp_path)
    receiver = authenticator(tmp_path, "refund-service")
    with pytest.raises(InternalAuthError):
        verify(receiver, headers, **changes)
    assert verify(receiver, headers) == "recovery-worker"


@pytest.mark.parametrize(("field", "value"), [
    ("version", "v0"), ("caller", "agent-refund"), ("recipient", "notification-service"),
    ("method", "GET"), ("path", "/internal/execute"), ("issued_at", True),
    ("issued_at", "1000"), ("issued_at", -1), ("issued_at", 1.0),
    ("nonce", "x" * 32), ("nonce", "0" * 31), ("mac_sm3", "0" * 64),
    ("mac_sm3", "A" * 64), ("body_sm3", "0" * 64), ("unexpected", True),
])
def test_tampered_or_ambiguous_proof_is_rejected(tmp_path: Path, field, value) -> None:
    original = signed_headers(tmp_path)
    headers = dict(original)
    proof = json.loads(headers[PROOF_HEADER])
    proof[field] = value
    headers[PROOF_HEADER] = json.dumps(proof)
    receiver = authenticator(tmp_path, "refund-service")
    with pytest.raises(InternalAuthError):
        verify(receiver, headers)
    assert verify(receiver, original) == "recovery-worker"


def test_duplicate_proof_fields_and_identity_mismatch_are_rejected(tmp_path: Path) -> None:
    original = signed_headers(tmp_path)
    receiver = authenticator(tmp_path, "refund-service")
    duplicate = dict(original)
    duplicate[PROOF_HEADER] = duplicate[PROOF_HEADER][:-1] + ',"issued_at":1000}'
    with pytest.raises(InternalAuthError):
        verify(receiver, duplicate)
    mismatched = {**original, CALLER_HEADER: "agent-refund"}
    with pytest.raises(InternalAuthError):
        verify(receiver, mismatched)
    assert verify(receiver, original) == "recovery-worker"


@pytest.mark.parametrize(("issued_at", "accepted"), [
    (CURRENT - 60, True), (CURRENT - 61, False),
    (CURRENT + 5, True), (CURRENT + 6, False),
])
def test_freshness_boundaries(tmp_path: Path, issued_at: int, accepted: bool) -> None:
    headers = signed_headers(tmp_path, issued_at=issued_at)
    receiver = authenticator(tmp_path, "refund-service")
    if accepted:
        assert verify(receiver, headers) == "recovery-worker"
    else:
        with pytest.raises(InternalAuthError) as caught:
            verify(receiver, headers)
        assert caught.value.reason_code == ReasonCode.REQUEST_STALE
        assert not (tmp_path / "refund-service.sqlite3").exists()


def test_replay_is_rejected_by_another_guard_after_receiver_restart(tmp_path: Path) -> None:
    headers = signed_headers(tmp_path)
    assert verify(authenticator(tmp_path, "refund-service"), headers) == "recovery-worker"
    with pytest.raises(InternalAuthError) as caught:
        verify(authenticator(tmp_path, "refund-service"), headers)
    assert caught.value.reason_code == ReasonCode.REPLAY_DETECTED


def test_parallel_replay_has_exactly_one_atomic_claim(tmp_path: Path) -> None:
    headers = signed_headers(tmp_path)

    def attempt(_: int) -> str:
        try:
            return verify(authenticator(tmp_path, "refund-service"), headers)
        except InternalAuthError as exc:
            return exc.reason_code.value

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(32)))
    assert results.count("recovery-worker") == 1
    assert results.count("REPLAY_DETECTED") == 31


def test_missing_edge_and_wrong_edge_secret_fail_closed(tmp_path: Path) -> None:
    headers = signed_headers(tmp_path)
    for keys in ({}, {"recovery-worker->refund-service": "55" * 32}):
        receiver = authenticator(tmp_path, "refund-service", keys=keys)
        with pytest.raises(InternalAuthError):
            verify(receiver, headers)
    with pytest.raises(InternalAuthError):
        authenticator(tmp_path, "agent-refund", keys={}).request_headers(
            recipient="recovery-worker", method="POST", path="/internal/recovery/run",
            body=BODY,
        )


def test_nonce_store_unavailable_cannot_authorize_a_request(tmp_path: Path) -> None:
    receiver = authenticator(tmp_path, "refund-service")
    receiver._nonce_store = Mock(claim=Mock(side_effect=OSError("private path")))
    with pytest.raises(InternalAuthError) as caught:
        verify(receiver, signed_headers(tmp_path))
    assert caught.value.status_code == 503
    assert str(caught.value) == "TOOL_EXECUTION_UNKNOWN"


def test_unsigned_compatibility_requires_explicit_disabled_configuration(tmp_path: Path) -> None:
    receiver = authenticator(tmp_path, "refund-service", required=False)
    assert verify(receiver, {CALLER_HEADER: "recovery-worker"}) == "recovery-worker"
    with pytest.raises(InternalAuthError):
        verify(receiver, {CALLER_HEADER: "agent-refund"})
    with pytest.raises(InternalAuthError):
        verify(receiver, {CALLER_HEADER: "recovery-worker", PROOF_HEADER: "malformed"})


@pytest.mark.parametrize("value", [
    "not-json", "[]", '{"wrong-edge":"SECRET-DO-NOT-LOG"}',
    '{"recovery-worker->refund-service":true}',
    '{"recovery-worker->refund-service":"a"}',
    '{"recovery-worker->refund-service":"SECRET-DO-NOT-LOG",'
    '"recovery-worker->refund-service":"SECRET-DO-NOT-LOG"}',
])
def test_malformed_key_configuration_does_not_disclose_values(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        InternalAuthenticator(service_id="refund-service", keys_json=value)
    assert str(caught.value) == "invalid internal authentication key configuration"
    assert "SECRET-DO-NOT-LOG" not in str(caught.value)


def test_missing_configuration_and_mismatched_service_id_are_not_silently_disabled() -> None:
    with pytest.raises(ValueError, match="must be explicit"):
        InternalAuthenticator.from_settings(SimpleNamespace(), service_id="refund-service")
    settings = SimpleNamespace(
        internal_auth_required=True, internal_auth_keys=json.dumps(KEYS),
        internal_auth_service_id="agent-refund", freshness_window_seconds=60,
        allowed_clock_skew_seconds=5,
    )
    with pytest.raises(ValueError, match="identity mismatch"):
        InternalAuthenticator.from_settings(settings, service_id="refund-service")


def test_nonce_pruning_does_not_forget_still_fresh_proofs(tmp_path: Path) -> None:
    store = SqliteNonceStore(tmp_path / "nonces.sqlite3")
    args = {"caller": "recovery-worker", "recipient": "refund-service", "nonce": "a" * 32}
    assert store.claim(**args, expires_at=1065, current_time=1000)
    assert not store.claim(**args, expires_at=1065, current_time=1065)
    assert store.claim(**args, expires_at=1200, current_time=1066)


def test_clock_rollback_cannot_resurrect_pruned_replay(tmp_path: Path) -> None:
    headers = signed_headers(tmp_path, nonce="1" * 32)
    assert verify(authenticator(tmp_path, "refund-service"), headers) == "recovery-worker"
    newer = signed_headers(tmp_path, issued_at=1066, nonce="2" * 32)
    assert verify(
        authenticator(tmp_path, "refund-service", current=1066), newer,
    ) == "recovery-worker"
    with pytest.raises(InternalAuthError) as caught:
        verify(authenticator(tmp_path, "refund-service", current=1000), headers)
    assert caught.value.reason_code == ReasonCode.REQUEST_STALE
