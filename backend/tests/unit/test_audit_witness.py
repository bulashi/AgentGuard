"""Real SM2 signatures and adversarial public prefixes; no deployed key files."""

from __future__ import annotations

import json
from copy import deepcopy
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator

from backend.audit import witness
from backend.audit.service import AuditService
from backend.common.enums import KeyPurpose
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_CHECKPOINT, CAPABILITY_CREDENTIAL
from backend.crypto.sm import generate_keypair, sign_payload, sm3_hex


def make_case_factory():
    pair, other = generate_keypair(), generate_keypair()

    def make(count=3, checkpoint_sequence=7, *, rewrite=False, wrong_key=False,
             domain=AUDIT_CHECKPOINT, timestamp=None):
        events = []
        previous = witness.ZERO_HASH
        for sequence in range(1, count + 1):
            version = ("1.0", "2.0", "3.0")[(sequence - 1) % 3]
            event = {
                "schema_version": version, "event_sequence": sequence,
                "event_id": f"EVENT-{sequence}", "execution_id": None,
                "event_type": {"1.0": "AUTHORIZATION_DENIED", "2.0": "COAUTH_ROOT_AUTHORIZED",
                               "3.0": "COAUTH_REVOCATION_APPLIED"}[version],
                "timestamp": 100 + sequence,
                "payload_hash": sm3_hex(canonicalize({"synthetic_event": sequence})),
                "evidence_reference": f"REF-{sequence}", "previous_event_hash": previous,
            }
            if rewrite and sequence == 1:
                event["evidence_reference"] = "REWRITTEN-REF"
            event["event_hash"] = AuditService._event_hash(event)
            previous = event["event_hash"]
            events.append(event)
        checkpoint_time = timestamp if timestamp is not None else 200 + checkpoint_sequence
        payload = {
            "schema_version": "1.0", "checkpoint_sequence": checkpoint_sequence,
            "latest_event_sequence": count, "latest_event_hash": previous,
            "timestamp": checkpoint_time,
        }
        signing_pair = other if wrong_key else pair
        signature = sign_payload(
            payload, domain_separator=domain, key_id="witness-test-key",
            key_purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING, signed_at=checkpoint_time,
            private_key_hex=signing_pair.private_key_hex,
            public_key_hex=signing_pair.public_key_hex,
        )
        trust = {
            "schema_version": "1.0", "record_type": "AUDIT_WITNESS_TRUST_CONTEXT_V1",
            "stream_id": "TEST-AUDIT-STREAM", "checkpoint_domain": AUDIT_CHECKPOINT,
            "event_hash_domain": witness.AUDIT_EVENT_HASH,
            "checkpoint_signer": {
                "key_id": "witness-test-key", "key_purpose": "AUDIT_CHECKPOINT_SIGNING",
                "algorithm": "SM2", "public_key_hex": pair.public_key_hex,
            },
        }
        snapshot = {
            "schema_version": "1.0", "record_type": "AUDIT_WITNESS_SNAPSHOT_V1",
            "stream_id": trust["stream_id"], "checkpoint_domain": AUDIT_CHECKPOINT,
            "event_hash_domain": witness.AUDIT_EVENT_HASH,
            "source_head": {"latest_event_sequence": count, "latest_event_hash": previous},
            "audit_events": events,
        }
        return {"trust": trust, "checkpoint": {"payload": payload, "signature": signature},
                "snapshot": snapshot, "other_public_key": other.public_key_hex}

    return make


@pytest.fixture(scope="module")
def case_factory():
    return make_case_factory()


def _verify(case, **overrides):
    arguments = {
        "raw_snapshot": canonicalize(case["snapshot"]),
        "raw_trust_context": canonicalize(case["trust"]),
        "trusted_context_sm3": witness.canonical_sm3(case["trust"]),
        "raw_checkpoint": canonicalize(case["checkpoint"]),
        "trusted_checkpoint_sm3": witness.canonical_sm3(case["checkpoint"]),
        "expected_stream_id": case["trust"]["stream_id"],
    }
    return witness.verify_snapshot(**(arguments | overrides))


def _assert_error(code, operation, *args, **kwargs):
    with pytest.raises(witness.WitnessError) as error:
        operation(*args, **kwargs)
    assert error.value.reason_code == "AUDIT_WITNESS_" + code


def _read(store, evidence, entry):
    return witness.read_witness_store(
        store, evidence, trusted_witness_sequence=entry["witness_sequence"],
        trusted_witness_sm3=entry["entry_sm3"],
    )


def test_real_sm2_mixed_prefix_matches_frozen_hash_preimage(case_factory):
    case = case_factory()
    verified = _verify(case)
    assert [event["schema_version"] for event in verified.snapshot["audit_events"]] == [
        "1.0", "2.0", "3.0",
    ]
    for event in verified.snapshot["audit_events"]:
        core = {key: value for key, value in event.items() if key != "event_hash"}
        expected = sm3_hex(witness.AUDIT_EVENT_HASH.encode() + b"\x00"
                           + bytes.fromhex(event["previous_event_hash"]) + canonicalize(core))
        assert expected == AuditService._event_hash(core) == event["event_hash"]


@pytest.mark.parametrize("options", [{"wrong_key": True}, {"domain": CAPABILITY_CREDENTIAL}])
def test_real_wrong_key_and_domain_signatures_fail(case_factory, options):
    _assert_error("SIGNATURE_INVALID", _verify, case_factory(**options))


@pytest.mark.parametrize("part,pin", [("trust", "trusted_context_sm3"),
                                     ("checkpoint", "trusted_checkpoint_sm3")])
def test_caller_pins_are_required(case_factory, part, pin):
    case = case_factory()
    _assert_error("CONTEXT_PIN_MISMATCH" if part == "trust" else "CHECKPOINT_PIN_MISMATCH",
                  _verify, case, **{pin: "0" * 64})


def test_attacker_public_key_cannot_replace_caller_root(case_factory):
    case = case_factory(wrong_key=True)
    trusted = witness.canonical_sm3(case["trust"])
    case["trust"]["checkpoint_signer"]["public_key_hex"] = case["other_public_key"]
    _assert_error("CONTEXT_PIN_MISMATCH", _verify, case, trusted_context_sm3=trusted)
    case["snapshot"]["public_key_hex"] = case["other_public_key"]
    _assert_error("INPUT_INVALID", _verify, case)


@pytest.mark.parametrize("failure", ["invalid_point", "stream", "expected_stream", "domain",
                                     "purpose", "unsigned_metadata", "signature_tamper"])
def test_fixed_identity_domain_and_signature_metadata(case_factory, failure):
    case = case_factory()
    overrides = {}
    expected = "INPUT_INVALID"
    if failure == "invalid_point":
        case["trust"]["checkpoint_signer"]["public_key_hex"] = "0" * 128
        expected = "PUBLIC_KEY_INVALID"
    elif failure in {"stream", "expected_stream"}:
        if failure == "stream":
            case["snapshot"]["stream_id"] = "OTHER-STREAM"
        else:
            overrides["expected_stream_id"] = "OTHER-STREAM"
        expected = "STREAM_MISMATCH"
    elif failure == "domain":
        case["trust"]["checkpoint_domain"] = CAPABILITY_CREDENTIAL
    elif failure == "purpose":
        case["checkpoint"]["signature"]["key_purpose"] = "EXECUTION_RECEIPT_SIGNING"
    elif failure == "unsigned_metadata":
        case["checkpoint"]["signature"]["signed_at"] += 1
        expected = "SIGNATURE_INVALID"
    else:
        value = case["checkpoint"]["signature"]["value"]
        case["checkpoint"]["signature"]["value"] = ("0" if value[0] != "0" else "1") + value[1:]
        expected = "SIGNATURE_INVALID"
    _assert_error(expected, _verify, case, **overrides)


@pytest.mark.parametrize("part", ["snapshot", "trust_context", "checkpoint"])
@pytest.mark.parametrize("raw", [
    b'{"schema_version":"1.0","schema_version":"1.0"}', b'{"x":1.0}',
    b'{"x":1e0}', b'{"x":NaN}', b'{"x":9007199254740992}', b'{"x":"\xff"}',
    b'{"x":"\\ud800"}', b"[" * 130 + b"0" + b"]" * 130, b"{} trailing", b"",
])
def test_bounded_strict_json_on_every_input(case_factory, part, raw):
    _assert_error("INPUT_INVALID", _verify, case_factory(), **{"raw_" + part: raw})


def test_actual_snapshot_byte_limit_and_canonical_pin_semantics(case_factory):
    case = case_factory()
    _assert_error(
        "INPUT_INVALID", _verify, case,
        raw_snapshot=b" " * (witness.MAX_SNAPSHOT_BYTES + 1),
    )
    # Pins are explicitly canonical-object pins, not hashes of presentation whitespace.
    assert _verify(
        case, raw_checkpoint=json.dumps(case["checkpoint"], indent=2).encode(),
    ).checkpoint


@pytest.mark.parametrize("part,limit", [
    ("trust_context", witness.MAX_CONTEXT_BYTES), ("checkpoint", witness.MAX_CHECKPOINT_BYTES),
])
def test_trust_and_checkpoint_byte_limits(case_factory, part, limit):
    _assert_error("INPUT_INVALID", _verify, case_factory(), **{"raw_" + part: b" " * (limit + 1)})


def test_safe_integer_checkpoint_boundary_and_strict_sequences(case_factory, tmp_path):
    valid = _verify(case_factory(checkpoint_sequence=witness.MAX_SAFE_INTEGER,
                                timestamp=witness.MAX_SAFE_INTEGER))
    store = tmp_path / "custody"
    initial = witness.initialize_witness_store(store, valid, observed_at=witness.MAX_SAFE_INTEGER)
    assert _read(store, valid, initial) == [initial]
    for invalid in (True, 0, -1, "1", witness.MAX_STORE_ENTRIES + 1):
        _assert_error(
            "EXPECTATION_INVALID", witness.read_witness_store, store, valid,
            trusted_witness_sequence=invalid, trusted_witness_sm3=initial["entry_sm3"],
        )
    _assert_error("EXPECTATION_INVALID", witness.initialize_witness_store,
                  tmp_path / "invalid-time", valid, observed_at=True)


def test_event_count_limit_is_checked_by_schema(case_factory, monkeypatch):
    case = case_factory()
    schemas = witness.witness_schemas()
    bounded = deepcopy(schemas.documents["snapshot.schema.json"])
    bounded["properties"]["audit_events"]["maxItems"] = 2
    monkeypatch.setitem(schemas.documents, "snapshot.schema.json", bounded)
    _assert_error("INPUT_INVALID", _verify, case)


@pytest.mark.parametrize("attack,reason", [
    ("delete_first", "PREFIX_INVALID"), ("delete_middle", "PREFIX_INVALID"),
    ("delete_tail", "PREFIX_INVALID"), ("reverse", "PREFIX_INVALID"),
    ("duplicate_id", "PREFIX_INVALID"), ("edit_core", "PREFIX_INVALID"),
    ("false_sequence", "INPUT_INVALID"), ("future_event", "PREFIX_INVALID"),
    ("head_only", "PREFIX_INVALID"), ("unsigned_suffix", "PREFIX_INVALID"),
])
def test_entire_prefix_is_required(case_factory, attack, reason):
    case = case_factory()
    events = case["snapshot"]["audit_events"]
    if attack.startswith("delete_"):
        del events[{"delete_first": 0, "delete_middle": 1, "delete_tail": -1}[attack]]
    elif attack == "reverse":
        events.reverse()
    elif attack == "duplicate_id":
        events[1]["event_id"] = events[0]["event_id"]
    elif attack == "edit_core":
        events[0]["payload_hash"] = "f" * 64
    elif attack == "false_sequence":
        events[0]["event_sequence"] = True
    elif attack == "future_event":
        events[0]["timestamp"] = 500
    elif attack == "head_only":
        case["snapshot"]["source_head"]["latest_event_hash"] = "f" * 64
    else:
        events.append(deepcopy(events[-1]))
    _assert_error(reason, _verify, case)


def test_immutable_growth_idempotence_and_result_contract(case_factory, tmp_path):
    first = _verify(case_factory())
    store = tmp_path / "custody"
    initial = witness.initialize_witness_store(store, first, observed_at=1000)
    original_bytes = (store / "000000000001.json").read_bytes()
    newer = _verify(case_factory(count=6, checkpoint_sequence=8))
    latest, modified = witness.advance_witness_store(
        store, newer, trusted_witness_sequence=1, trusted_witness_sm3=initial["entry_sm3"],
        observed_at=1001,
    )
    assert modified and latest["witness_sequence"] == 2
    assert latest["previous_entry_sm3"] == initial["entry_sm3"]
    assert (store / "000000000001.json").read_bytes() == original_bytes
    entries = _read(store, newer, latest)
    witness.verify_against_witness(newer, entries)
    duplicate, changed = witness.advance_witness_store(
        store, newer, trusted_witness_sequence=2, trusted_witness_sm3=latest["entry_sm3"],
        observed_at=1002,
    )
    assert duplicate == latest and changed is False and len(list(store.iterdir())) == 2
    result = witness.make_result("verify", newer, latest, store_modified=False,
                                 checked_witness_entries=len(entries))
    witness.witness_schemas().validate("result.schema.json", result)
    assert result["verified"] and result["checked_events"] == 6
    assert all(result[claim] is False for claim in witness.FALSE_CLAIMS)


@pytest.mark.parametrize("options,reason", [
    ({"count": 2, "checkpoint_sequence": 8}, "SOURCE_ROLLBACK"),
    ({"count": 3, "checkpoint_sequence": 6}, "SOURCE_ROLLBACK"),
    ({"count": 3, "checkpoint_sequence": 7, "rewrite": True}, "CHECKPOINT_CONFLICT"),
    ({"count": 3, "checkpoint_sequence": 8, "rewrite": True}, "PREFIX_REWRITTEN"),
    ({"count": 6, "checkpoint_sequence": 8, "rewrite": True}, "PREFIX_REWRITTEN"),
    ({"count": 6, "checkpoint_sequence": 8, "timestamp": 206}, "SOURCE_ROLLBACK"),
])
def test_resigned_source_attacks_cannot_advance_fixed_witness(
    case_factory, tmp_path, options, reason,
):
    trusted = _verify(case_factory())
    store = tmp_path / "custody"
    entry = witness.initialize_witness_store(store, trusted, observed_at=1000)
    before = (store / "000000000001.json").read_bytes()
    candidate = _verify(case_factory(**options))  # The malicious new SM2 signature is valid.
    _assert_error(
        reason, witness.advance_witness_store, store, candidate,
        trusted_witness_sequence=1, trusted_witness_sm3=entry["entry_sm3"],
        observed_at=1001,
    )
    assert [path.name for path in store.iterdir()] == ["000000000001.json"]
    assert (store / "000000000001.json").read_bytes() == before


def test_every_historical_anchor_is_checked(case_factory):
    valid = _verify(case_factory(count=6, checkpoint_sequence=9))
    old_wrong = _verify(case_factory(count=1, checkpoint_sequence=1, rewrite=True))
    old_matching = _verify(case_factory(count=3, checkpoint_sequence=7))
    entries = [{"checkpoint": old_wrong.checkpoint}, {"checkpoint": old_matching.checkpoint}]
    _assert_error("PREFIX_REWRITTEN", witness.verify_against_witness, valid, entries)


def test_same_event_head_with_a_new_checkpoint_can_advance(case_factory, tmp_path):
    store = tmp_path / "custody"
    first = witness.initialize_witness_store(store, _verify(case_factory()), observed_at=1000)
    newer = _verify(case_factory(checkpoint_sequence=8))
    next_entry, modified = witness.advance_witness_store(
        store, newer, trusted_witness_sequence=1, trusted_witness_sm3=first["entry_sm3"],
        observed_at=1001,
    )
    assert modified and next_entry["witness_sequence"] == 2
    assert next_entry["checkpoint"]["payload"]["latest_event_sequence"] == 3


@pytest.mark.parametrize("attack,reason", [
    ("delete_tail", "STORE_PIN_MISMATCH"), ("delete_first", "STORE_PIN_MISMATCH"),
    ("edit_old", "STORE_INVALID"), ("rehash_old_and_tip", "STORE_PIN_MISMATCH"),
    ("rename_first", "STORE_INVALID"), ("unknown_file", "STORE_INVALID"),
])
def test_caller_tip_detects_witness_deletion_and_rewriting(case_factory, tmp_path, attack, reason):
    store = tmp_path / "custody"
    initial = witness.initialize_witness_store(store, _verify(case_factory()), observed_at=1000)
    evidence = _verify(case_factory(count=6, checkpoint_sequence=8))
    latest, _ = witness.advance_witness_store(
        store, evidence, trusted_witness_sequence=1, trusted_witness_sm3=initial["entry_sm3"],
        observed_at=1001,
    )
    first_path, second_path = store / "000000000001.json", store / "000000000002.json"
    if attack.startswith("delete_"):
        (first_path if attack == "delete_first" else second_path).unlink()
    elif attack in {"edit_old", "rehash_old_and_tip"}:
        entry = json.loads(first_path.read_bytes())
        entry["observed_at"] += 1
        if attack == "rehash_old_and_tip":
            entry["entry_sm3"] = witness.canonical_sm3(
                {key: value for key, value in entry.items() if key != "entry_sm3"})
            tail = json.loads(second_path.read_bytes())
            tail["previous_entry_sm3"] = entry["entry_sm3"]
            tail["entry_sm3"] = witness.canonical_sm3(
                {key: value for key, value in tail.items() if key != "entry_sm3"})
            second_path.write_bytes(canonicalize(tail))
        first_path.write_bytes(canonicalize(entry))
    elif attack == "rename_first":
        first_path.rename(store / "000000000003.json")
    else:
        (store / "untrusted.json").write_bytes(b"{}")
    _assert_error(reason, _read, store, evidence, latest)


def test_store_never_reinitializes_or_prunes_at_capacity(case_factory, tmp_path, monkeypatch):
    store = tmp_path / "custody"
    evidence = _verify(case_factory())
    entry = witness.initialize_witness_store(store, evidence, observed_at=1000)
    _assert_error(
        "STORE_EXISTS", witness.initialize_witness_store, store, evidence, observed_at=1001,
    )
    newer = _verify(case_factory(count=6, checkpoint_sequence=8))
    monkeypatch.setattr(witness, "MAX_STORE_ENTRIES", 1)
    _assert_error(
        "STORE_LIMIT", witness.advance_witness_store, store, newer,
        trusted_witness_sequence=1, trusted_witness_sm3=entry["entry_sm3"],
        observed_at=1001,
    )
    monkeypatch.setattr(witness, "MAX_STORE_ENTRIES", 128)
    monkeypatch.setattr(witness, "MAX_STORE_BYTES", (store / "000000000001.json").stat().st_size)
    _assert_error(
        "STORE_LIMIT", witness.advance_witness_store, store, newer,
        trusted_witness_sequence=1, trusted_witness_sm3=entry["entry_sm3"],
        observed_at=1001,
    )
    assert len(list(store.iterdir())) == 1


def test_first_entry_size_limit_refuses_before_creation(case_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(witness, "MAX_STORE_BYTES", 1)
    _assert_error("STORE_LIMIT", witness.initialize_witness_store,
                  tmp_path / "custody", _verify(case_factory()), observed_at=1000)
    assert not (tmp_path / "custody").exists()


def test_offline_verification_never_signs_loads_private_material_or_connects(
    case_factory, monkeypatch,
):
    case = case_factory()
    forbidden = Mock(side_effect=AssertionError("unexpected live or private operation"))
    monkeypatch.setattr("backend.crypto.sm.sign_payload", forbidden)
    monkeypatch.setattr("backend.identity.key_lifecycle.FilePrivateKeyStore.load", forbidden)
    monkeypatch.setattr("psycopg.connect", forbidden)
    monkeypatch.setattr("socket.socket.connect", forbidden)
    _verify(case)
    forbidden.assert_not_called()


def test_extension_schemas_are_valid_and_failure_contract_is_truthful():
    schemas = witness.witness_schemas()
    for schema in schemas.documents.values():
        Draft202012Validator.check_schema(schema)
    failure = witness.failure_result(None, "AUDIT_WITNESS_INPUT_INVALID")
    schemas.validate("result.schema.json", failure)
    assert not failure["verified"] and not failure["success"]
