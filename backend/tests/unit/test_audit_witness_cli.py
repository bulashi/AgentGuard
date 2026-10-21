"""Real public-file CLI flows and fail-closed filesystem boundaries."""

from __future__ import annotations

import builtins
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from backend.audit import witness
from backend.crypto.canonical_json import canonicalize
from backend.tests.unit.test_audit_witness import make_case_factory
from scripts import audit_witness as cli


@pytest.fixture(scope="module")
def shared_case_factory():
    return make_case_factory()


def _inputs(tmp_path, case):
    paths = {}
    for name in ("trust", "checkpoint", "snapshot"):
        path = tmp_path / (name + ".json")
        path.write_bytes(canonicalize(case[name]))
        paths[name] = path
    return paths


def _arguments(paths, case, store, command="init", tip=None, output=None):
    arguments = [
        command, "--trust-context", str(paths["trust"]), "--trusted-context-sm3",
        witness.canonical_sm3(case["trust"]), "--checkpoint", str(paths["checkpoint"]),
        "--trusted-checkpoint-sm3", witness.canonical_sm3(case["checkpoint"]),
        "--expected-stream-id", case["trust"]["stream_id"], "--snapshot", str(paths["snapshot"]),
        "--store", str(store),
    ]
    if tip is not None:
        arguments.extend(["--trusted-witness-sequence", str(tip["witness_sequence"]),
                          "--trusted-witness-sm3", tip["witness_sm3"]])
    if output is not None:
        arguments.extend(["--output", str(output)])
    return arguments


def _invoke(arguments, capsys, expected=0):
    assert cli.main(arguments) == expected
    captured = capsys.readouterr()
    assert captured.err == "" and len(captured.out.splitlines()) == 1
    result = json.loads(captured.out)
    witness.witness_schemas().validate("result.schema.json", result)
    assert all(result[claim] is False for claim in witness.FALSE_CLAIMS)
    return result


def test_cli_init_advance_verify_and_external_tip_rejection(shared_case_factory, tmp_path, capsys):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    store = tmp_path / "custody"
    first = _invoke(_arguments(paths, case, store), capsys)
    assert first["witness_sequence"] == 1 and first["store_modified"]
    assert first["checked_witness_entries"] == 0
    initial_bytes = (store / "000000000001.json").read_bytes()
    case = shared_case_factory(count=6, checkpoint_sequence=8)
    paths = _inputs(tmp_path, case)
    candidate = _invoke(_arguments(paths, case, store, "verify", first), capsys)
    assert candidate["checkpoint_sequence"] == 8 and candidate["latest_event_sequence"] == 6
    assert candidate["checkpoint_sm3"] == witness.canonical_sm3(case["checkpoint"])
    assert candidate["witness_sequence"] == first["witness_sequence"]
    assert candidate["witness_sm3"] == first["witness_sm3"]
    assert candidate["checked_witness_entries"] == 1 and candidate["store_modified"] is False
    assert (store / "000000000001.json").read_bytes() == initial_bytes
    assert len(list(store.iterdir())) == 1
    advanced = _invoke(_arguments(paths, case, store, "advance", first), capsys)
    assert advanced["witness_sequence"] == 2 and advanced["store_modified"]
    assert advanced["checked_witness_entries"] == 1
    output = tmp_path / "verified-report.json"
    verified = _invoke(_arguments(paths, case, store, "verify", advanced, output), capsys)
    assert verified["checked_witness_entries"] == 2 and verified["store_modified"] is False
    assert json.loads(output.read_bytes()) == verified
    assert (store / "000000000001.json").read_bytes() == initial_bytes
    stale = _invoke(_arguments(paths, case, store, "verify", first), capsys, expected=2)
    assert stale["reason_code"] == "AUDIT_WITNESS_STORE_PIN_MISMATCH"
    assert stale["verified"] is False and stale["store_modified"] is False


def test_real_subprocess_cli_uses_json_stdout(shared_case_factory, tmp_path):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    arguments = _arguments(paths, case, tmp_path / "custody")
    process = subprocess.run(
        [sys.executable, str(cli.PROJECT_ROOT / "scripts" / "audit_witness.py"), *arguments],
        cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False,
    )
    assert process.returncode == 0 and process.stderr == ""
    result = json.loads(process.stdout)
    assert result["verified"] and result["witness_sequence"] == 1


@pytest.mark.parametrize(
    "mutation", ["missing_pin", "abbreviation", "negative_sequence", "unknown"],
)
def test_invalid_arguments_are_machine_readable(
    shared_case_factory, tmp_path, capsys, mutation,
):
    case = shared_case_factory()
    args = _arguments(_inputs(tmp_path, case), case, tmp_path / "custody", command="verify")
    if mutation == "abbreviation":
        args[args.index("--expected-stream-id")] = "--expected-stream"
    elif mutation == "negative_sequence":
        args.extend(["--trusted-witness-sequence", "-1", "--trusted-witness-sm3", "0" * 64])
    elif mutation == "unknown":
        args[0] = "export"
    result = _invoke(args, capsys, expected=2)
    assert not result["success"] and not (tmp_path / "custody").exists()


@pytest.mark.parametrize(
    "arguments", [["--help"], ["init", "--help"], ["advance", "--help"], ["verify", "--help"]],
)
def test_help_is_text_not_a_machine_operation_result(arguments, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("usage:") and len(captured.out.splitlines()) > 1


@pytest.mark.parametrize(
    "attack", ["rollback", "same_sequence", "rewrite", "delete", "duplicate_json"],
)
def test_cli_attack_failures_preserve_existing_custody(
    shared_case_factory, tmp_path, capsys, attack,
):
    first_case = shared_case_factory()
    paths = _inputs(tmp_path, first_case)
    store = tmp_path / "custody"
    tip = _invoke(_arguments(paths, first_case, store), capsys)
    before = (store / "000000000001.json").read_bytes()
    if attack == "rollback":
        case = shared_case_factory(count=2, checkpoint_sequence=8)
    else:
        case = shared_case_factory(
            count=3 if attack == "same_sequence" else 6,
            checkpoint_sequence=7 if attack == "same_sequence" else 8, rewrite=True,
        )
    paths = _inputs(tmp_path, case)
    if attack == "delete":
        case["snapshot"]["audit_events"].pop(0)
        paths["snapshot"].write_bytes(canonicalize(case["snapshot"]))
    elif attack == "duplicate_json":
        paths["snapshot"].write_bytes(b'{"schema_version":"1.0","schema_version":"1.0"}')
    result = _invoke(_arguments(paths, case, store, "advance", tip), capsys, expected=2)
    assert result["reason_code"] == {
        "rollback": "AUDIT_WITNESS_SOURCE_ROLLBACK",
        "same_sequence": "AUDIT_WITNESS_CHECKPOINT_CONFLICT",
        "rewrite": "AUDIT_WITNESS_PREFIX_REWRITTEN",
        "delete": "AUDIT_WITNESS_PREFIX_INVALID",
        "duplicate_json": "AUDIT_WITNESS_INPUT_INVALID",
    }[attack]
    assert (store / "000000000001.json").read_bytes() == before and len(list(store.iterdir())) == 1


def test_safe_new_files_and_known_private_paths_are_rejected_before_open(tmp_path, monkeypatch):
    path = tmp_path / "public.json"
    witness.write_new_json(path, b"{}")
    assert witness.read_json_file(path, 2) == b"{}"
    with pytest.raises(witness.WitnessError):
        witness.read_json_file(path, 1)
    with pytest.raises(witness.WitnessError) as error:
        witness.write_new_json(path, b"overwrite")
    assert error.value.reason_code == "AUDIT_WITNESS_FILE_EXISTS"
    assert path.read_bytes() == b"{}"
    private = tmp_path / "keys" / "private" / "renamed.json"
    forbidden = Mock(side_effect=AssertionError("private file must not be opened"))
    monkeypatch.setattr(Path, "open", forbidden)
    for unsafe in (private, tmp_path / "audit.private", tmp_path / "NUL.json",
                   str(path) + ":stream.json", r"\\server\share\public.json"):
        with pytest.raises(witness.WitnessError):
            witness.read_json_file(unsafe, 1024)
    forbidden.assert_not_called()


def test_existing_report_is_rejected_before_store_creation(
    shared_case_factory, tmp_path, capsys,
):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    report = tmp_path / "existing.json"
    report.write_bytes(b"original")
    store = tmp_path / "custody"
    result = _invoke(_arguments(paths, case, store, output=report), capsys, expected=2)
    assert result["reason_code"] == "AUDIT_WITNESS_FILE_EXISTS"
    assert result["store_modified"] is False
    assert report.read_bytes() == b"original" and not store.exists()


@pytest.mark.parametrize("populated", [False, True])
def test_init_existing_store_reports_no_modification(
    shared_case_factory, tmp_path, capsys, populated,
):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    store = tmp_path / "custody"
    arguments = _arguments(paths, case, store)
    if populated:
        _invoke(arguments, capsys)
    else:
        store.mkdir()
    before = {path.name: path.read_bytes() for path in store.iterdir()}
    result = _invoke(arguments, capsys, expected=2)
    assert result["reason_code"] == "AUDIT_WITNESS_STORE_EXISTS"
    assert result["store_modified"] is False and result["success"] is False
    assert {path.name: path.read_bytes() for path in store.iterdir()} == before


@pytest.mark.parametrize("race_stage", ["preflight", "exclusive_create"])
def test_init_file_creation_race_reports_unknown_modification(
    shared_case_factory, tmp_path, monkeypatch, capsys, race_stage,
):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    store = tmp_path / "custody"
    first_entry = store / "000000000001.json"
    competing_bytes = b"competing-writer"
    if race_stage == "preflight":
        original_path = witness.new_json_path

        def competing_path(value):
            if Path(value) == first_entry:
                assert store.is_dir()
                first_entry.write_bytes(competing_bytes)
            return original_path(value)

        monkeypatch.setattr(witness, "new_json_path", competing_path)
    else:
        original_open = witness.os.open

        def competing_open(value, flags, mode):
            if Path(value) == first_entry:
                assert store.is_dir()
                first_entry.write_bytes(competing_bytes)
            return original_open(value, flags, mode)

        monkeypatch.setattr(witness.os, "open", competing_open)
    result = _invoke(_arguments(paths, case, store), capsys, expected=2)
    assert result["reason_code"] == "AUDIT_WITNESS_FILE_EXISTS"
    assert result["store_modified"] is None
    assert result["success"] is False and result["verified"] is False
    assert result["report_file_written"] is False
    assert store.is_dir() and list(store.iterdir()) == [first_entry]
    assert first_entry.read_bytes() == competing_bytes


def test_report_cannot_be_written_into_witness_store(
    shared_case_factory, tmp_path, capsys,
):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    store = tmp_path / "custody"
    tip = _invoke(_arguments(paths, case, store), capsys)
    result = _invoke(_arguments(paths, case, store, "verify", tip, store / "report.json"),
                     capsys, expected=2)
    assert result["reason_code"] == "AUDIT_WITNESS_OUTPUT_UNSAFE"
    assert len(list(store.iterdir())) == 1


def test_symlink_and_parent_links_are_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "public.json").write_bytes(b"{}")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"OS does not permit creating a test symlink: {exc.winerror}")
    with pytest.raises(witness.WitnessError) as error:
        witness.read_json_file(link / "public.json", 1024)
    assert error.value.reason_code == "AUDIT_WITNESS_FILE_UNSAFE"
    with pytest.raises(witness.WitnessError):
        witness.write_new_json(link / "new.json", b"{}")
    assert not (real / "new.json").exists()


def test_os_exclusive_creation_handles_a_competing_writer(tmp_path, monkeypatch):
    path = tmp_path / "racing.json"
    original_open = os.open

    def competing_open(value, flags, mode):
        Path(value).write_bytes(b"competing-writer")
        return original_open(value, flags, mode)

    monkeypatch.setattr(witness.os, "open", competing_open)
    with pytest.raises(witness.WitnessError) as error:
        witness.write_new_json(path, b"replacement")
    assert error.value.reason_code == "AUDIT_WITNESS_FILE_EXISTS"
    assert path.read_bytes() == b"competing-writer"


def test_cli_has_no_network_database_private_key_or_signing_calls(
    shared_case_factory, tmp_path, monkeypatch, capsys,
):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    forbidden = Mock(side_effect=AssertionError("unexpected private or live operation"))
    monkeypatch.setattr("socket.socket.connect", forbidden)
    monkeypatch.setattr("psycopg.connect", forbidden)
    monkeypatch.setattr("backend.identity.key_lifecycle.FilePrivateKeyStore.load", forbidden)
    monkeypatch.setattr("backend.crypto.sm.sign_payload", forbidden)
    store = tmp_path / "custody"
    tip = _invoke(_arguments(paths, case, store), capsys)
    _invoke(_arguments(paths, case, store, "verify", tip), capsys)
    forbidden.assert_not_called()


def test_report_write_failure_retains_truthful_verification_receipt(
    shared_case_factory, tmp_path, monkeypatch, capsys,
):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    output = tmp_path / "report.json"
    original = witness.write_new_json

    def write(value, raw):
        if Path(value) == output:
            raise OSError("synthetic secret in local exception")
        return original(value, raw)

    monkeypatch.setattr(witness, "write_new_json", write)
    result = _invoke(
        _arguments(paths, case, tmp_path / "custody", output=output), capsys, expected=2,
    )
    assert result["verified"] and result["store_modified"] and not result["success"]
    assert result["reason_code"] == "AUDIT_WITNESS_REPORT_WRITE_FAILED"
    assert result["witness_sequence"] == 1 and not output.exists()


def test_startup_failure_emits_json_without_import_exception(monkeypatch, capsys):
    original_import = builtins.__import__

    def failing_import(name, *args, **kwargs):
        if name == "backend.audit":
            raise ImportError("synthetic secret in unavailable dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", failing_import)
    assert cli.main([]) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and "synthetic secret" not in captured.out
    result = json.loads(captured.out)
    assert result["reason_code"] == "AUDIT_WITNESS_STARTUP_FAILURE"
    witness.witness_schemas().validate("result.schema.json", result)


def test_partial_store_io_failure_reports_unknown_modification(
    shared_case_factory, tmp_path, monkeypatch, capsys,
):
    case = shared_case_factory()
    paths = _inputs(tmp_path, case)
    store = tmp_path / "custody"
    monkeypatch.setattr(
        witness, "write_new_json", Mock(side_effect=OSError("synthetic local failure")),
    )
    result = _invoke(_arguments(paths, case, store), capsys, expected=2)
    assert result["reason_code"] == "AUDIT_WITNESS_LOCAL_FAILURE"
    assert result["store_modified"] is None and store.is_dir() and not list(store.iterdir())
