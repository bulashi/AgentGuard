"""Public, file-only audit witnesses; trust pins must come from the caller."""

from __future__ import annotations

import hmac
import os
import re
import stat
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PureWindowsPath

from jsonschema import ValidationError
from referencing import Resource

from backend.coauthorization.public_keys import valid_public_point
from backend.common.enums import KeyPurpose
from backend.common.schema import PROJECT_ROOT, SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import AUDIT_CHECKPOINT, AUDIT_EVENT_HASH
from backend.crypto.sm import SM2_SIGNATURE_ENCODING, SM2_USER_ID_UTF8, sm3_hex, verify_payload
from backend.crypto.strict_json import MAX_SAFE_INTEGER, parse_strict_json

SCHEMA_ROOT = PROJECT_ROOT / "protocol" / "extensions" / "audit-witness-v1"
MAX_CONTEXT_BYTES = 16_384
MAX_CHECKPOINT_BYTES = 16_384
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_ENTRY_BYTES = MAX_SNAPSHOT_BYTES + 65_536
MAX_EVENTS = 10_000
MAX_STORE_ENTRIES = 128
MAX_STORE_BYTES = 64 * 1024 * 1024
ZERO_HASH = "0" * 64
REPARSE_POINT = 0x400
IDENTIFIER = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
FALSE_CLAIMS = (
    "authorizes_execution", "proves_latest_source_state", "proves_independent_custody",
    "proves_uncompromised_signer", "proves_signed_stream_identity",
    "proves_event_payloads", "proves_trusted_wall_clock",
)


class WitnessError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__("audit witness operation refused")
        self.reason_code = reason_code


@dataclass(frozen=True)
class VerifiedSnapshot:
    trust_context: dict
    checkpoint: dict
    snapshot: dict
    trust_context_sm3: str
    checkpoint_sm3: str


@lru_cache(maxsize=1)
def witness_schemas() -> SchemaStore:
    schemas = SchemaStore(SCHEMA_ROOT)
    for root in (PROJECT_ROOT / "protocol" / "schemas",
                 PROJECT_ROOT / "protocol" / "extensions" / "coauthorization-v1",
                 PROJECT_ROOT / "protocol" / "extensions" / "dispatch-revocation" / "v1"):
        schemas.registry = schemas.registry.with_resources(
            (document["$id"], Resource.from_contents(document))
            for document in SchemaStore(root).documents.values()
        )
    return schemas


def _document(raw: bytes, limit: int, schema: str) -> dict:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= limit:
            raise ValueError("invalid size")
        document = parse_strict_json(raw)
        witness_schemas().validate(schema, document)
        canonicalize(document)
        return document
    except (ValueError, TypeError, RecursionError, ValidationError):
        raise WitnessError("AUDIT_WITNESS_INPUT_INVALID") from None


def canonical_sm3(document: dict) -> str:
    return sm3_hex(canonicalize(document))


def _digest_pin(actual: str, expected: str, code: str) -> None:
    if (type(expected) is not str or re.fullmatch(r"[0-9a-f]{64}", expected) is None
            or not hmac.compare_digest(actual, expected)):
        raise WitnessError(code)


def _verify_public_snapshot(snapshot: dict, checkpoint: dict, trust: dict) -> None:
    if any(snapshot[name] != trust[name] for name in (
        "stream_id", "checkpoint_domain", "event_hash_domain",
    )):
        raise WitnessError("AUDIT_WITNESS_STREAM_MISMATCH")
    payload, signature = checkpoint["payload"], checkpoint["signature"]
    signer = trust["checkpoint_signer"]
    if signature["signed_at"] != payload["timestamp"] or not verify_payload(
        payload, signature, domain_separator=AUDIT_CHECKPOINT,
        expected_key_id=signer["key_id"],
        expected_key_purpose=KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
        public_key_hex=signer["public_key_hex"],
    ):
        raise WitnessError("AUDIT_WITNESS_SIGNATURE_INVALID")
    events, head = snapshot["audit_events"], snapshot["source_head"]
    if (head["latest_event_sequence"] != payload["latest_event_sequence"]
            or head["latest_event_hash"] != payload["latest_event_hash"]
            or len(events) != payload["latest_event_sequence"] or len(events) > MAX_EVENTS):
        raise WitnessError("AUDIT_WITNESS_PREFIX_INVALID")
    previous = ZERO_HASH
    event_ids: set[str] = set()
    for sequence, event in enumerate(events, 1):
        core = {key: value for key, value in event.items() if key != "event_hash"}
        # This is the frozen AuditService._event_hash preimage, without importing DB services.
        calculated = sm3_hex(
            AUDIT_EVENT_HASH.encode("utf-8") + b"\x00"
            + bytes.fromhex(event["previous_event_hash"]) + canonicalize(core)
        )
        if (event["event_sequence"] != sequence or event["event_id"] in event_ids
                or event["previous_event_hash"] != previous
                or calculated != event["event_hash"]
                or event["timestamp"] > payload["timestamp"]):
            raise WitnessError("AUDIT_WITNESS_PREFIX_INVALID")
        event_ids.add(event["event_id"])
        previous = event["event_hash"]
    if previous != payload["latest_event_hash"]:
        raise WitnessError("AUDIT_WITNESS_PREFIX_INVALID")


def verify_snapshot(
    raw_snapshot: bytes, *, raw_trust_context: bytes, trusted_context_sm3: str,
    raw_checkpoint: bytes, trusted_checkpoint_sm3: str, expected_stream_id: str,
) -> VerifiedSnapshot:
    """Verify an exact signed prefix. No package key, network or private material is used."""
    if type(expected_stream_id) is not str or re.fullmatch(IDENTIFIER, expected_stream_id) is None:
        raise WitnessError("AUDIT_WITNESS_EXPECTATION_INVALID")
    trust = _document(raw_trust_context, MAX_CONTEXT_BYTES, "trust-context.schema.json")
    context_hash = canonical_sm3(trust)
    _digest_pin(context_hash, trusted_context_sm3, "AUDIT_WITNESS_CONTEXT_PIN_MISMATCH")
    if trust["stream_id"] != expected_stream_id:
        raise WitnessError("AUDIT_WITNESS_STREAM_MISMATCH")
    signer = trust["checkpoint_signer"]
    if (not valid_public_point(signer["public_key_hex"])
            or re.fullmatch(IDENTIFIER, signer["key_id"]) is None):
        raise WitnessError("AUDIT_WITNESS_PUBLIC_KEY_INVALID")
    checkpoint = _document(raw_checkpoint, MAX_CHECKPOINT_BYTES, "checkpoint.schema.json")
    checkpoint_hash = canonical_sm3(checkpoint)
    _digest_pin(checkpoint_hash, trusted_checkpoint_sm3, "AUDIT_WITNESS_CHECKPOINT_PIN_MISMATCH")
    snapshot = _document(raw_snapshot, MAX_SNAPSHOT_BYTES, "snapshot.schema.json")
    _verify_public_snapshot(snapshot, checkpoint, trust)
    return VerifiedSnapshot(trust, checkpoint, snapshot, context_hash, checkpoint_hash)


def verify_against_witness(evidence: VerifiedSnapshot, entries: list[dict]) -> None:
    """A valid new SM2 signature cannot erase any already retained anchor."""
    candidate = evidence.checkpoint["payload"]
    for entry in entries:
        old = entry["checkpoint"]["payload"]
        if (candidate["checkpoint_sequence"] < old["checkpoint_sequence"]
                or candidate["latest_event_sequence"] < old["latest_event_sequence"]
                or candidate["timestamp"] < old["timestamp"]):
            raise WitnessError("AUDIT_WITNESS_SOURCE_ROLLBACK")
        if (candidate["checkpoint_sequence"] == old["checkpoint_sequence"]
                and canonicalize(evidence.checkpoint) != canonicalize(entry["checkpoint"])):
            raise WitnessError("AUDIT_WITNESS_CHECKPOINT_CONFLICT")
        event = evidence.snapshot["audit_events"][old["latest_event_sequence"] - 1]
        if event["event_hash"] != old["latest_event_hash"]:
            raise WitnessError("AUDIT_WITNESS_PREFIX_REWRITTEN")


def local_path(value: str | Path) -> Path:
    path = Path(os.path.abspath(value))
    if (path.drive.startswith("\\\\") or str(path).startswith("//")
            or ":" in str(path)[len(path.drive):]
            or any(PureWindowsPath(part).is_reserved()
                   for part in path.parts if part != path.anchor)):
        raise WitnessError("AUDIT_WITNESS_FILE_UNSAFE")
    for component in (path, *path.parents):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT):
            raise WitnessError("AUDIT_WITNESS_FILE_UNSAFE")
    return path


def _json_path(value: str | Path) -> Path:
    path = local_path(value)
    parts = [part.lower() for part in path.parts]
    if (path.suffix.lower() != ".json"
            or any(parts[index:index + 2] == ["keys", "private"]
                   for index in range(len(parts) - 1))):
        raise WitnessError("AUDIT_WITNESS_FILE_UNSAFE")
    return path


def read_json_file(value: str | Path, limit: int) -> bytes:
    path = _json_path(value)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
        raise WitnessError("AUDIT_WITNESS_FILE_INVALID")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(metadata, opened):
            raise WitnessError("AUDIT_WITNESS_FILE_INVALID")
        raw = stream.read(limit + 1)
        finished = os.fstat(stream.fileno())
        local_path(path)
        if (not os.path.samestat(opened, finished) or opened.st_size != finished.st_size
                or opened.st_mtime_ns != finished.st_mtime_ns or len(raw) != finished.st_size):
            raise WitnessError("AUDIT_WITNESS_FILE_INVALID")
    if not 0 < len(raw) <= limit:
        raise WitnessError("AUDIT_WITNESS_FILE_INVALID")
    return raw


def new_json_path(value: str | Path) -> Path:
    path = _json_path(value)
    if not path.parent.is_dir():
        raise WitnessError("AUDIT_WITNESS_FILE_UNSAFE")
    if path.exists():
        raise WitnessError("AUDIT_WITNESS_FILE_EXISTS")
    return path


def write_new_json(value: str | Path, raw: bytes) -> None:
    path = new_json_path(value)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise WitnessError("AUDIT_WITNESS_FILE_EXISTS") from None
    with os.fdopen(descriptor, "wb") as stream:
        local_path(path)
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or stream.write(raw) != len(raw):
            raise WitnessError("AUDIT_WITNESS_FILE_INVALID")
        stream.flush()
        os.fsync(stream.fileno())


def read_witness_store(
    value: str | Path, evidence: VerifiedSnapshot, *,
    trusted_witness_sequence: int, trusted_witness_sm3: str,
) -> list[dict]:
    if (type(trusted_witness_sequence) is not int
            or not 1 <= trusted_witness_sequence <= MAX_STORE_ENTRIES):
        raise WitnessError("AUDIT_WITNESS_EXPECTATION_INVALID")
    path = local_path(value)
    names: list[str] = []
    with os.scandir(path) as files:
        for item in files:
            if re.fullmatch(r"[0-9]{12}\.json", item.name) is None:
                raise WitnessError("AUDIT_WITNESS_STORE_INVALID")
            names.append(item.name)
            if len(names) > MAX_STORE_ENTRIES:
                raise WitnessError("AUDIT_WITNESS_STORE_LIMIT")
    names.sort()
    if len(names) != trusted_witness_sequence:
        raise WitnessError("AUDIT_WITNESS_STORE_PIN_MISMATCH")
    entries: list[dict] = []
    total_bytes = 0
    for sequence, name in enumerate(names, 1):
        if name != f"{sequence:012d}.json":
            raise WitnessError("AUDIT_WITNESS_STORE_INVALID")
        size = local_path(path / name).lstat().st_size
        if total_bytes + size > MAX_STORE_BYTES:
            raise WitnessError("AUDIT_WITNESS_STORE_LIMIT")
        raw = read_json_file(path / name, MAX_ENTRY_BYTES)
        total_bytes += len(raw)
        if total_bytes > MAX_STORE_BYTES:
            raise WitnessError("AUDIT_WITNESS_STORE_LIMIT")
        entry = _document(raw, MAX_ENTRY_BYTES, "witness-entry.schema.json")
        body = {key: value for key, value in entry.items() if key != "entry_sm3"}
        previous_entry_sm3 = entries[-1]["entry_sm3"] if entries else ZERO_HASH
        if (entry["witness_sequence"] != sequence
                or entry["previous_entry_sm3"] != previous_entry_sm3
                or entry["trust_context_sm3"] != evidence.trust_context_sm3
                or entry["entry_sm3"] != canonical_sm3(body)):
            raise WitnessError("AUDIT_WITNESS_STORE_INVALID")
        _verify_public_snapshot(entry["snapshot"], entry["checkpoint"], evidence.trust_context)
        historic = VerifiedSnapshot(
            evidence.trust_context, entry["checkpoint"], entry["snapshot"],
            evidence.trust_context_sm3, canonical_sm3(entry["checkpoint"]),
        )
        verify_against_witness(historic, entries)
        if entries and (entry["checkpoint"]["payload"]["checkpoint_sequence"]
                        <= entries[-1]["checkpoint"]["payload"]["checkpoint_sequence"]):
            raise WitnessError("AUDIT_WITNESS_STORE_INVALID")
        entries.append(entry)
    _digest_pin(entries[-1]["entry_sm3"], trusted_witness_sm3, "AUDIT_WITNESS_STORE_PIN_MISMATCH")
    return entries


def _new_entry(evidence: VerifiedSnapshot, entries: list[dict], observed_at: int) -> dict:
    if type(observed_at) is not int or not 0 <= observed_at <= MAX_SAFE_INTEGER:
        raise WitnessError("AUDIT_WITNESS_EXPECTATION_INVALID")
    entry = {
        "schema_version": "1.0", "record_type": "AUDIT_WITNESS_ENTRY_V1",
        "witness_sequence": len(entries) + 1,
        "previous_entry_sm3": entries[-1]["entry_sm3"] if entries else ZERO_HASH,
        "trust_context_sm3": evidence.trust_context_sm3,
        "checkpoint": evidence.checkpoint, "snapshot": evidence.snapshot,
        "observed_at": observed_at,
    }
    entry["entry_sm3"] = canonical_sm3(entry)
    witness_schemas().validate("witness-entry.schema.json", entry)
    return entry


def initialize_witness_store(
    value: str | Path, evidence: VerifiedSnapshot, *, observed_at: int,
) -> dict:
    entry = _new_entry(evidence, [], observed_at)
    raw = canonicalize(entry)
    if len(raw) > MAX_ENTRY_BYTES or len(raw) > MAX_STORE_BYTES:
        raise WitnessError("AUDIT_WITNESS_STORE_LIMIT")
    path = local_path(value)
    if not path.parent.is_dir():
        raise WitnessError("AUDIT_WITNESS_FILE_UNSAFE")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise WitnessError("AUDIT_WITNESS_STORE_EXISTS") from None
    write_new_json(path / "000000000001.json", raw)
    return entry


def advance_witness_store(
    value: str | Path, evidence: VerifiedSnapshot, *, trusted_witness_sequence: int,
    trusted_witness_sm3: str, observed_at: int,
) -> tuple[dict, bool]:
    entries = read_witness_store(
        value, evidence, trusted_witness_sequence=trusted_witness_sequence,
        trusted_witness_sm3=trusted_witness_sm3,
    )
    verify_against_witness(evidence, entries)
    if canonicalize(evidence.checkpoint) == canonicalize(entries[-1]["checkpoint"]):
        return entries[-1], False
    if len(entries) >= MAX_STORE_ENTRIES:
        raise WitnessError("AUDIT_WITNESS_STORE_LIMIT")
    entry = _new_entry(evidence, entries, observed_at)
    raw = canonicalize(entry)
    path = local_path(value)
    total_bytes = sum(local_path(path / f"{index:012d}.json").stat().st_size
                      for index in range(1, len(entries) + 1))
    if len(raw) > MAX_ENTRY_BYTES or total_bytes + len(raw) > MAX_STORE_BYTES:
        raise WitnessError("AUDIT_WITNESS_STORE_LIMIT")
    # Competing writers choose the same next filename; exclusive creation permits only one.
    write_new_json(path / f"{len(entries) + 1:012d}.json", raw)
    return entry, True


def make_result(
    operation: str, evidence: VerifiedSnapshot, entry: dict, *,
    store_modified: bool, checked_witness_entries: int,
) -> dict:
    anchor = evidence.checkpoint["payload"]
    result = failure_result(operation, "AUDIT_WITNESS_OK") | {
        "success": True, "verified": True, "store_modified": store_modified,
        "stream_id": evidence.trust_context["stream_id"],
        "trust_context_sm3": evidence.trust_context_sm3,
        "checkpoint_sm3": evidence.checkpoint_sm3,
        "checkpoint_sequence": anchor["checkpoint_sequence"],
        "latest_event_sequence": anchor["latest_event_sequence"],
        "latest_event_hash": anchor["latest_event_hash"],
        "checked_events": len(evidence.snapshot["audit_events"]),
        "checked_witness_entries": checked_witness_entries,
        "witness_sequence": entry["witness_sequence"], "witness_sm3": entry["entry_sm3"],
    }
    witness_schemas().validate("result.schema.json", result)
    return result


def failure_result(operation: str | None, reason_code: str) -> dict:
    return {
        "schema_version": "1.0", "record_type": "AUDIT_WITNESS_RESULT_V1",
        "operation": operation, "success": False, "verified": False,
        "reason_code": reason_code, "store_modified": False, "report_file_written": False,
        "verification_scope": "CALLER_PINNED_CHECKPOINT_FULL_PREFIX_LOCAL_WITNESS",
        "checkpoint_domain": AUDIT_CHECKPOINT, "event_hash_domain": AUDIT_EVENT_HASH,
        "sm2_user_id": SM2_USER_ID_UTF8, "signature_encoding": SM2_SIGNATURE_ENCODING,
        **dict.fromkeys(FALSE_CLAIMS, False),
    }
