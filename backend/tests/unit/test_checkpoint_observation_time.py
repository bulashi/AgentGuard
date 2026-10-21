"""Real checkpoint signing and public witness validation over controlled database reads."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import backend.checkpoint.service as checkpoint_module
from backend.audit import witness
from backend.audit.service import AuditService
from backend.checkpoint.service import CheckpointError, CheckpointService
from backend.common.enums import KeyPurpose
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_CHECKPOINT
from backend.crypto.sm import generate_keypair, sign_payload


class CheckpointMemory:
    def __init__(self, events, on_head_read):
        self.events = events
        self.on_head_read = on_head_read
        self.checkpoints = {}
        self.insertions = 0

    @contextmanager
    def transaction(self):
        yield

    def execute(self, sql, parameters=None):
        sql = " ".join(sql.split())
        if "FROM audit_chain_head" in sql:
            self.on_head_read()
            head = (len(self.events), self.events[-1]["event_hash"])
            if "MAX(" in sql:
                head += (max(event["timestamp"] for event in self.events),)
            row = head
        elif "WHERE latest_event_sequence = %s" in sql:
            checkpoint = self.checkpoints.get(parameters[0])
            row = None if checkpoint is None else (checkpoint,)
        elif "MAX(checkpoint_sequence)" in sql:
            row = (len(self.checkpoints) + 1,)
        elif "INSERT INTO audit_checkpoints" in sql:
            self.insertions += 1
            self.checkpoints[parameters[1]] = deepcopy(parameters[8].obj)
            row = None
        else:
            raise AssertionError(f"unexpected checkpoint SQL: {sql}")
        return SimpleNamespace(fetchone=lambda: row)


def checkpoint_case(monkeypatch, *, event_times=(101,), read_time=101):
    pair = generate_keypair()
    key = SimpleNamespace(
        key_id="checkpoint-time-key", purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
        public_key_hex=pair.public_key_hex,
    )
    events = []
    previous = witness.ZERO_HASH
    for sequence, timestamp in enumerate(event_times, 1):
        event = {
            "schema_version": "1.0", "event_sequence": sequence,
            "event_id": f"CHECKPOINT-TIME-EVENT-{sequence}", "execution_id": None,
            "event_type": "AUTHORIZATION_DENIED", "timestamp": timestamp,
            "payload_hash": "a" * 64, "evidence_reference": f"REF-{sequence}",
            "previous_event_hash": previous,
        }
        event["event_hash"] = AuditService._event_hash(event)
        previous = event["event_hash"]
        events.append(event)
    clock = SimpleNamespace(timestamp=100)
    storage = CheckpointMemory(events, lambda: setattr(clock, "timestamp", read_time))

    @contextmanager
    def fake_connect(url):
        assert url in {"unit-main", "unit-audit"}
        yield storage

    monkeypatch.setattr(checkpoint_module, "connect", fake_connect)
    monkeypatch.setattr(checkpoint_module, "now_unix", lambda: clock.timestamp)
    monkeypatch.setattr(
        checkpoint_module.PostgresKeyRegistry, "resolve_for_signing_with_connection",
        lambda *_args, **_kwargs: key,
    )
    key_path = Mock(spec=["read_text"])
    key_path.read_text.return_value = pair.private_key_hex
    monkeypatch.setattr(checkpoint_module, "Path", Mock(return_value=key_path))
    service = CheckpointService(
        "unit-main", "unit-audit", private_key_file="unit-key-file", key_id=key.key_id,
    )

    def signed_checkpoint(timestamp):
        payload = {
            "schema_version": "1.0", "checkpoint_sequence": 1,
            "latest_event_sequence": len(events), "latest_event_hash": previous,
            "timestamp": timestamp,
        }
        return {
            "payload": payload,
            "signature": sign_payload(
                payload, domain_separator=AUDIT_CHECKPOINT, key_id=key.key_id,
                key_purpose=key.purpose, private_key_hex=pair.private_key_hex,
                public_key_hex=pair.public_key_hex, signed_at=timestamp,
            ),
        }

    def verify(checkpoint):
        trust = {
            "schema_version": "1.0", "record_type": "AUDIT_WITNESS_TRUST_CONTEXT_V1",
            "stream_id": "CHECKPOINT-TIME-STREAM", "checkpoint_domain": AUDIT_CHECKPOINT,
            "event_hash_domain": witness.AUDIT_EVENT_HASH,
            "checkpoint_signer": {
                "key_id": key.key_id, "key_purpose": key.purpose.value,
                "algorithm": "SM2", "public_key_hex": pair.public_key_hex,
            },
        }
        snapshot = {
            "schema_version": "1.0", "record_type": "AUDIT_WITNESS_SNAPSHOT_V1",
            "stream_id": trust["stream_id"], "checkpoint_domain": AUDIT_CHECKPOINT,
            "event_hash_domain": witness.AUDIT_EVENT_HASH,
            "source_head": {
                "latest_event_sequence": len(events), "latest_event_hash": previous,
            },
            "audit_events": events,
        }
        return witness.verify_snapshot(
            canonicalize(snapshot), raw_trust_context=canonicalize(trust),
            trusted_context_sm3=witness.canonical_sm3(trust),
            raw_checkpoint=canonicalize(checkpoint),
            trusted_checkpoint_sm3=witness.canonical_sm3(checkpoint),
            expected_stream_id=trust["stream_id"],
        )

    return SimpleNamespace(
        service=service, storage=storage, verify=verify, clock=clock,
        signed_checkpoint=signed_checkpoint,
    )


def test_head_committed_after_entry_clock_is_signed_at_observation_time(monkeypatch):
    case = checkpoint_case(monkeypatch)
    checkpoint = case.service.run_once()
    assert checkpoint["payload"]["timestamp"] == 101
    assert checkpoint["signature"]["signed_at"] == 101
    assert case.verify(checkpoint).checkpoint == checkpoint
    assert case.service.run_once(current_time=200) == checkpoint
    assert case.storage.insertions == 1


@pytest.mark.parametrize("clock_time", [100, True, -1, 9_007_199_254_740_992])
def test_clock_before_prefix_or_outside_safe_integer_cannot_write_checkpoint(
    monkeypatch, clock_time,
):
    case = checkpoint_case(monkeypatch)
    with pytest.raises(CheckpointError):
        case.service.run_once(current_time=clock_time)
    assert case.storage.insertions == 0
    assert case.storage.checkpoints == {}


def test_earlier_prefix_event_still_bounds_checkpoint_time(monkeypatch):
    # Append timestamps need not increase when workers observe their clocks before lock waits.
    case = checkpoint_case(monkeypatch, event_times=(103, 101), read_time=102)
    with pytest.raises(CheckpointError):
        case.service.run_once()
    assert case.storage.insertions == 0
    checkpoint = case.service.run_once(current_time=103)
    assert case.verify(checkpoint).checkpoint == checkpoint


def test_bad_historical_same_head_is_rejected_without_rewriting_signed_anchor(monkeypatch):
    case = checkpoint_case(monkeypatch)
    old = case.signed_checkpoint(100)
    with pytest.raises(witness.WitnessError) as invalid:
        case.verify(old)
    assert invalid.value.reason_code == "AUDIT_WITNESS_PREFIX_INVALID"
    case.storage.checkpoints[1] = deepcopy(old)
    with pytest.raises(CheckpointError):
        case.service.run_once(current_time=200)
    assert case.storage.checkpoints[1] == old
    assert case.storage.insertions == 0
