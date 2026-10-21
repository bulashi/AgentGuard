"""Unrun CLI/export boundary source tests; mocks do not prove DB locks or SM2."""

from __future__ import annotations

from copy import deepcopy
from unittest.mock import Mock

import pytest

from backend.coauthorization import evidence_export
from backend.coauthorization.evidence_verifier import EvidenceVerificationError
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash
from scripts import verify_coauthorization_evidence as cli


def _arguments(command: str = "verify") -> list[str]:
    arguments = [
        command, "--trust-context", "trust.json", "--trusted-context-sha256", "a" * 64,
        "--checkpoint", "checkpoint.json", "--trusted-checkpoint-sha256", "b" * 64,
        "--expected-task-id", "TASK-TEST", "--expected-root-credential-id", "ROOT-TEST",
        "--expected-approval-payload-hash", "c" * 64,
    ]
    return arguments + (
        ["--package", "package.json"] if command == "verify" else
        ["--output", "output.json", "--confirm-read-only-export"]
    )


def test_parser_requires_explicit_export_and_no_abbreviated_arguments() -> None:
    parser = cli.build_parser()
    assert parser.parse_args(_arguments()).command == "verify"
    assert parser.parse_args(_arguments("export")).confirm_read_only_export is True
    with pytest.raises(cli.CliError):
        parser.parse_args(_arguments("export")[:-1])
    arguments = _arguments()
    arguments[arguments.index("--expected-task-id")] = "--expected-task"
    with pytest.raises(cli.CliError):
        parser.parse_args(arguments)


def test_json_reader_is_bounded_and_rejects_private_file(tmp_path) -> None:
    path = tmp_path / "public.json"
    path.write_bytes(b"{}")
    assert cli._read_json_file(str(path), 2) == b"{}"
    with pytest.raises(cli.CliError):
        cli._read_json_file(str(path), 1)
    private = tmp_path / "test.private"
    private.write_bytes(b"this is synthetic, not private key material")
    with pytest.raises(cli.CliError):
        cli._read_json_file(str(private), 128)


def test_writer_refuses_escape_and_never_overwrites_existing_file(tmp_path, monkeypatch) -> None:
    output_root = tmp_path / "artifacts" / "coauthorization"
    monkeypatch.setattr(cli, "OUTPUT_ROOT", output_root)
    raw = b'{"synthetic_source_test":true}'
    output = output_root / "new.json"
    cli._write_new_package(str(output), raw)
    assert output.read_bytes() == raw
    with pytest.raises(cli.CliError) as error:
        cli._write_new_package(str(output), b"replacement")
    assert error.value.reason_code == "COAUTH_EVIDENCE_OUTPUT_EXISTS"
    assert output.read_bytes() == raw
    for path in (tmp_path / "outside.json", output_root / ".." / "escape.json", output_root / "key.private"):
        with pytest.raises(cli.CliError):
            cli._write_new_package(str(path), raw)
        assert not path.exists()


def test_verify_command_never_invokes_database_export(monkeypatch, capsys) -> None:
    from backend.coauthorization import evidence_verifier

    reads = Mock(side_effect=lambda path, limit: path.encode("ascii"))
    verification = Mock(return_value={"verified": True, "authorizes_execution": False})
    forbidden_export = Mock(side_effect=AssertionError("file-only verify must not connect"))
    monkeypatch.setattr(cli, "_read_json_file", reads)
    monkeypatch.setattr(evidence_verifier, "verify_evidence_package", verification)
    monkeypatch.setattr(evidence_export, "export_evidence_package", forbidden_export)
    assert cli.main(_arguments()) == 0
    forbidden_export.assert_not_called()
    assert verification.call_args.args == (b"package.json",)
    assert verification.call_args.kwargs["expected_task_id"] == "TASK-TEST"
    assert '"authorizes_execution":false' in capsys.readouterr().out


def test_missing_export_configuration_does_not_query_or_write(monkeypatch, capsys) -> None:
    monkeypatch.delenv("AGENTGUARD_EVIDENCE_READ_DATABASE_URL", raising=False)
    monkeypatch.setattr(cli, "_read_json_file", Mock(return_value=b"{}"))
    monkeypatch.setattr(cli, "_output_path", Mock())
    export = Mock()
    write = Mock()
    monkeypatch.setattr(evidence_export, "export_evidence_package", export)
    monkeypatch.setattr(cli, "_write_new_package", write)
    assert cli.main(_arguments("export")) == 2
    export.assert_not_called()
    write.assert_not_called()
    assert "COAUTH_EVIDENCE_EXPORT_CONFIGURATION_MISSING" in capsys.readouterr().err


@pytest.mark.parametrize("failure", [
    EvidenceVerificationError("COAUTH_EVIDENCE_SIGNATURE_INVALID"),
    RuntimeError("synthetic secret marker in DSN or parser exception"),
])
def test_errors_do_not_echo_raw_exception_or_claim_verification(monkeypatch, capsys, failure) -> None:
    from backend.coauthorization import evidence_verifier

    monkeypatch.setattr(cli, "_read_json_file", Mock(return_value=b"{}"))
    monkeypatch.setattr(evidence_verifier, "verify_evidence_package", Mock(side_effect=failure))
    assert cli.main(_arguments()) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert '"verified": false' in output.err
    assert "synthetic secret marker" not in output.err


class _Cursor:
    def __init__(self, row: dict) -> None:
        self.row = row
        self.calls: list[tuple[str, tuple]] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, parameters):
        self.calls.append((query, parameters))
        return self

    def fetchone(self):
        return self.row

    def fetchall(self):
        return [{"synthetic_event": True}]


class _ReadConnection:
    def __init__(self, row: dict) -> None:
        self.reader = _Cursor(row)
        self.setup: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def transaction(self):
        return self

    def cursor(self, **kwargs):
        return self.reader

    def execute(self, query):
        self.setup.append(query)


def _export_case(monkeypatch):
    # These dictionaries are boundary stubs, not signed approval fixtures.
    root = {"payload": {"task_id": "TASK-TEST"}, "signature": {"test_stub": True}}
    evidence = {"tenant_id": "tenant-A", "root_credential_hash": signed_object_hash(root), "credential": root}
    row = {
        "outbox_event_id": "OUTBOX-STUB", "execution_id": None, "event_type": "COAUTH_ROOT_AUTHORIZED",
        "evidence_reference": "ROOT-TEST", "payload_hash": "c" * 64,
        "payload": evidence, "created_at": 120, "status": "APPENDED", "signed_object": root,
        "signed_object_hash": signed_object_hash(root), "task_id": "TASK-TEST",
        "tenant_id": "tenant-A", "credential_type": "ROOT",
    }
    connection = _ReadConnection(row)
    connect = Mock(return_value=connection)
    verification = Mock(return_value={"verified": True})
    monkeypatch.setattr(evidence_export, "connect", connect)
    monkeypatch.setattr(evidence_export, "load_pinned_trust_context", Mock(return_value={}))
    monkeypatch.setattr(evidence_export, "load_pinned_checkpoint", Mock(return_value={
        "payload": {"latest_event_sequence": 1},
    }))
    monkeypatch.setattr(evidence_export.AuditService, "_validate_coauthorization_outbox", Mock())
    monkeypatch.setattr(evidence_export, "verify_evidence_package", verification)
    inputs = {
        "raw_trust_context": b"{}", "trusted_context_sha256": "a" * 64,
        "raw_checkpoint": b"{}", "trusted_checkpoint_sha256": "b" * 64,
        "expected_task_id": "TASK-TEST", "expected_root_credential_id": "ROOT-TEST",
        "expected_approval_payload_hash": "c" * 64, "observed_at": 180,
    }
    return connection, connect, verification, inputs


def test_export_uses_one_read_only_snapshot_and_verifies_actual_selected_bytes(monkeypatch) -> None:
    connection, connect, verification, inputs = _export_case(monkeypatch)
    raw, result = evidence_export.export_evidence_package("synthetic DSN, no network", **inputs)
    assert connection.setup == ["SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"]
    assert connect.call_count == 1
    assert len(connection.reader.calls) == 2
    assert all(query.lstrip().startswith("SELECT") for query, _ in connection.reader.calls)
    assert connection.reader.calls[1][1] == (1, evidence_export.MAX_EVENTS + 1)
    assert verification.call_args.args == (raw,)
    assert result == {"verified": True}
    assert raw == canonicalize({
        "schema_version": "1.0", "record_type": "COAUTHORIZATION_EVIDENCE_PACKAGE_V1",
        "authorization_evidence": connection.reader.row["payload"],
        "audit_events": [{"synthetic_event": True}],
    }, normalize_sets=False)


def test_bad_trust_refuses_before_database_connection(monkeypatch) -> None:
    _, connect, verification, inputs = _export_case(monkeypatch)
    monkeypatch.setattr(evidence_export, "load_pinned_trust_context", Mock(side_effect=
        EvidenceVerificationError("COAUTH_EVIDENCE_TRUST_PIN_MISMATCH")))
    with pytest.raises(EvidenceVerificationError):
        evidence_export.export_evidence_package("synthetic DSN, no network", **inputs)
    connect.assert_not_called()
    verification.assert_not_called()


@pytest.mark.parametrize("field,value", [
    ("status", "PENDING"), ("task_id", "OTHER-TASK"),
    ("tenant_id", "OTHER-TENANT"), ("credential_type", "DELEGATION"),
    ("signed_object_hash", "f" * 64),
])
def test_export_refuses_inconsistent_selected_root_or_pending_outbox(monkeypatch, field, value) -> None:
    connection, _, verification, inputs = _export_case(monkeypatch)
    connection.reader.row[field] = value
    with pytest.raises(EvidenceVerificationError):
        evidence_export.export_evidence_package("synthetic DSN, no network", **inputs)
    verification.assert_not_called()


def test_export_does_not_return_when_prefix_crypto_verification_refuses(monkeypatch) -> None:
    _, _, verification, inputs = _export_case(monkeypatch)
    verification.side_effect = EvidenceVerificationError("COAUTH_EVIDENCE_AUDIT_BINDING_INVALID")
    original = deepcopy(inputs)
    with pytest.raises(EvidenceVerificationError):
        evidence_export.export_evidence_package("synthetic DSN, no network", **inputs)
    assert inputs == original
