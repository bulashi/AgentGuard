"""CLI boundary tests with synthetic keys and temporary local files.

Ordering/error mocks test the CLI boundary, not cryptographic correctness.
The separate real-core cases use the existing SM2 API without crypto mocks.
Writing these tests is not evidence that they have been executed or passed.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import runpy
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.authorization.policy import build_root_capabilities
from backend.coauthorization import offline
from backend.coauthorization.contracts import (
    APPROVAL_PURPOSE,
    COAUTHORIZATION_DOMAIN,
    MAX_BUNDLE_BYTES,
    ApprovalEvidence,
    ChallengeResponse,
    CoauthorizationBundle,
    PublicApprovalSetup,
    TrustedApprovalPolicy,
    TrustedTask,
)
from backend.coauthorization.verifier import (
    EXTENSION_SCHEMA_ROOT,
    approval_payload_hash,
    build_approval_payload,
)
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import SM2_CURVE_ORDER, derive_public_key, verify_payload
from scripts import coauthorization_approver as cli

NOW = 1_800_000_120
ENTERPRISE = "ENTERPRISE_APPROVER"
FINANCE = "FINANCE_APPROVER"
ROLES = (ENTERPRISE, FINANCE)
SYNTHETIC_PRIVATE = {ENTERPRISE: f"{1:064x}", FINANCE: f"{2:064x}"}
ERROR_SECRET = "secret-diagnostic-never-print"


@dataclass
class CliCase:
    project_root: Path
    task_file: Path
    public_file: Path
    private_files: dict[str, Path]
    setup: PublicApprovalSetup
    challenge: ChallengeResponse
    trusted_sha256: str

    @property
    def output_root(self) -> Path:
        return self.project_root / "artifacts" / "coauthorization"

    @property
    def output(self) -> Path:
        return self.output_root / "approval.json"

    def arguments(
        self, command: str, *, role: str = ENTERPRISE, output: Path | None = None,
    ) -> list[str]:
        arguments = [
            command, "--task-file", str(self.task_file),
            "--trusted-public-file", str(self.public_file),
            "--trusted-public-sha256", self.trusted_sha256,
            "--expected-task-id", self.challenge.payload.task_id,
            "--expected-approval-payload-hash", self.challenge.approval_payload_hash,
        ]
        if command == "sign":
            record = next(key for key in self.setup.keys if key.role == role)
            arguments.extend([
                "--role", role, "--subject-id", record.subject_id,
                "--key-id", record.key_id, "--principal-id", record.principal_id,
                "--private-key-file", str(self.private_files[role]),
                "--confirm-task-approval",
            ])
        elif command == "assemble":
            arguments.extend([
                "--enterprise-approval-file", str(self.project_root / "enterprise.json"),
                "--finance-approval-file", str(self.project_root / "finance.json"),
            ])
        if command != "review":
            arguments.extend(["--output", str(output or self.output)])
        return arguments

    def review(self) -> offline.OfflineApprovalReview:
        return offline.review_approval_task(
            self.task_file.read_bytes(), self.public_file.read_bytes(),
            trusted_setup_sha256=self.trusted_sha256,
            expected_task_id=self.challenge.payload.task_id,
            expected_approval_payload_hash=self.challenge.approval_payload_hash,
            now=NOW,
        )

    def write_real_approvals(self) -> tuple[bytes, bytes]:
        review = self.review()
        raw_approvals = []
        for role, name in ((ENTERPRISE, "enterprise.json"), (FINANCE, "finance.json")):
            record = next(key for key in self.setup.keys if key.role == role)
            evidence = offline.sign_approval(
                review, role=role, expected_subject_id=record.subject_id,
                expected_key_id=record.key_id, expected_principal_id=record.principal_id,
                private_key_hex=SYNTHETIC_PRIVATE[role], now=NOW,
            )
            raw = canonicalize(evidence.model_dump(mode="json"))
            (self.project_root / name).write_bytes(raw)
            raw_approvals.append(raw)
        return raw_approvals[0], raw_approvals[1]


@pytest.fixture(scope="module")
def synthetic_public_keys() -> dict[str, str]:
    return {role: derive_public_key(SYNTHETIC_PRIVATE[role]) for role in ROLES}


@pytest.fixture
def case(tmp_path, monkeypatch, synthetic_public_keys) -> CliCase:
    project_root = tmp_path / "project"
    project_root.mkdir()
    task = TrustedTask.model_validate({
        "tenant_id": "tenant-A", "task_id": "TASK-OFFLINE-01",
        "ticket_id": "T10086", "customer_id": "C9527",
        "holder": {"agent_id": "agent-coordinator", "key_id": "holder-key-01"},
        "capabilities": build_root_capabilities(
            ticket_id="T10086", customer_id="C9527", refund_total_fen=7000,
        ),
        "quotas": {"refund_total_fen": 7000, "max_tool_calls": 4},
        "not_before": NOW - 100, "expires_at": NOW + 1800,
        "delegation_depth": 2, "status": "PENDING_AUTHORIZATION",
    })
    policy = TrustedApprovalPolicy.model_validate({
        "tenant_id": "tenant-A", "revision": "approval-policy-v1",
        "required_signers": {
            "enterprise_approver": {"subject_id": "enterprise", "key_id": "enterprise-key"},
            "finance_approver": {"subject_id": "finance", "key_id": "finance-key"},
        },
        "not_before": NOW - 200, "expires_at": NOW + 2000,
    })
    keys = []
    private_files = {}
    for role in ROLES:
        signer = policy.required_signers.for_role(role)
        keys.append({
            "tenant_id": "tenant-A", "subject_id": signer.subject_id,
            "principal_id": f"principal-{signer.subject_id}", "key_id": signer.key_id,
            "role": role, "approval_purpose": APPROVAL_PURPOSE,
            "signing_purpose": "AUTHORIZATION_ROOT_SIGNING", "algorithm": "SM2",
            "public_key_hex": synthetic_public_keys[role],
            "status": "ACTIVE", "activated_at": NOW - 1000, "expires_at": NOW + 5000,
            "retired_at": None, "revoked_at": None, "compromised_at": None,
        })
        private_directory = project_root / "private" / signer.subject_id
        private_directory.mkdir(parents=True)
        private_files[role] = private_directory / f"{signer.key_id}.private"
        private_files[role].write_bytes(SYNTHETIC_PRIVATE[role].encode("ascii"))
    setup = PublicApprovalSetup.model_validate({
        "policy": policy.model_dump(mode="json"), "keys": keys,
    })
    payload = build_approval_payload(
        task=task, policy=policy, challenge_id="challenge-offline-01",
        approval_not_before=NOW - 60, approval_expires_at=NOW + 120,
    )
    challenge = ChallengeResponse(
        payload=payload, approval_payload_hash=approval_payload_hash(payload),
        task_capabilities=task.capabilities,
    )
    task_file, public_file = project_root / "task.json", project_root / "public.json"
    task_file.write_bytes(canonicalize(challenge.model_dump(mode="json")))
    raw_setup = canonicalize(setup.model_dump(mode="json"))
    public_file.write_bytes(raw_setup)
    # This test fixture defines its own trust anchor; the CLI never derives one.
    trusted_sha256 = hashlib.sha256(raw_setup).hexdigest()
    monkeypatch.setattr(cli, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(cli, "now_unix", lambda: NOW)
    return CliCase(
        project_root, task_file, public_file, private_files, setup, challenge, trusted_sha256,
    )


def _set_argument(arguments: list[str], flag: str, value: str) -> None:
    arguments[arguments.index(flag) + 1] = value


def _remove_argument(arguments: list[str], flag: str) -> None:
    index = arguments.index(flag)
    del arguments[index:index + (1 if flag == "--confirm-task-approval" else 2)]


def _forbidden(*args, **kwargs):
    pytest.fail("forbidden CLI branch was reached")


def _assert_error(capsys, code: str) -> None:
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(f"{code}: ")
    assert len(captured.err) < 500
    assert ERROR_SECRET not in captured.err
    assert "Traceback" not in captured.err


class _ObservedFile:
    def __init__(self, stream, path: Path, reads: list[tuple[Path, int]]) -> None:
        self.stream, self.path, self.reads = stream, path, reads

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def read(self, size: int = -1) -> bytes:
        self.reads.append((self.path, size))
        return self.stream.read(size)


def _observe_reads(monkeypatch) -> list[tuple[Path, int]]:
    reads = []
    original = Path.open

    def observed(path, mode="r", *args, **kwargs):
        stream = original(path, mode, *args, **kwargs)
        return _ObservedFile(stream, path, reads) if mode == "rb" else stream

    monkeypatch.setattr(Path, "open", observed)
    return reads


def _mark_reparse(monkeypatch, selected: Path) -> None:
    original = Path.lstat

    def lstat(path, *args, **kwargs):
        metadata = original(path, *args, **kwargs)
        if path == selected:
            return SimpleNamespace(
                st_mode=metadata.st_mode, st_file_attributes=cli._REPARSE_POINT,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", lstat)


def test_review_displays_full_public_context_without_private_reads_or_output(
    case, monkeypatch, capsys,
) -> None:
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    before = set(case.project_root.rglob("*"))
    assert cli.main(case.arguments("review")) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert captured.err == ""
    assert document["observation_kind"] == "OFFLINE_TASK_REVIEW"
    assert document["payload"] == case.challenge.payload.model_dump(mode="json")
    assert document["task_capabilities"] == [
        capability.model_dump(mode="json") for capability in case.challenge.task_capabilities
    ]
    assert document["signature_domain"] == COAUTHORIZATION_DOMAIN
    assert document["trusted_public_sha256"] == case.trusted_sha256
    assert document["policy"] == case.setup.policy.model_dump(mode="json")
    assert document["public_setup"] == case.setup.model_dump(mode="json")
    assert document["checked_at"] == NOW
    assert document["local_time"]
    assert "signature" not in document and "approvals" not in document
    assert "\u5f53\u524d\u64a4\u9500\u72b6\u6001" in " ".join(document["boundaries"])
    assert "\u4e3b\u4f53\u72ec\u7acb\u6027" in " ".join(document["boundaries"])
    assert "\u4ec5\u4fe1\u4efb" in captured.out
    assert r"\u4ec5\u4fe1\u4efb" not in captured.out
    assert set(case.project_root.rglob("*")) == before


@pytest.mark.parametrize("command", ("review", "sign", "assemble"))
@pytest.mark.parametrize("missing", (
    "--task-file", "--trusted-public-file", "--trusted-public-sha256",
    "--expected-task-id", "--expected-approval-payload-hash",
))
def test_all_commands_require_every_operator_pin(case, monkeypatch, capsys, command, missing):
    arguments = case.arguments(command)
    _remove_argument(arguments, missing)
    monkeypatch.setattr(cli, "review_approval_task", _forbidden)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_ARGUMENTS_INVALID")


@pytest.mark.parametrize("missing", (
    "--role", "--subject-id", "--key-id", "--principal-id", "--private-key-file",
    "--confirm-task-approval", "--output",
))
def test_missing_sign_requirements_never_open_a_private_key(case, monkeypatch, capsys, missing):
    arguments = case.arguments("sign")
    _remove_argument(arguments, missing)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    monkeypatch.setattr(cli, "review_approval_task", _forbidden)
    assert cli.main(arguments) == 2
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_CLI_ARGUMENTS_INVALID")


@pytest.mark.parametrize("missing", (
    "--enterprise-approval-file", "--finance-approval-file", "--output",
))
def test_assemble_requires_both_files_and_an_output(case, capsys, missing):
    arguments = case.arguments("assemble")
    _remove_argument(arguments, missing)
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_ARGUMENTS_INVALID")


@pytest.mark.parametrize("command", ("review", "assemble"))
@pytest.mark.parametrize("extra", (
    ["--private-key-file", "secret.private"],
    ["--private-key-hex", ERROR_SECRET * 10_000],
    ["--confirm-task-approval"],
))
def test_public_commands_reject_private_or_signing_arguments(
    case, monkeypatch, capsys, command, extra,
):
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(case.arguments(command) + extra) == 2
    _assert_error(capsys, "COAUTH_CLI_ARGUMENTS_INVALID")


@pytest.mark.parametrize("arguments", (
    [], [ERROR_SECRET * 10_000], ["review", ERROR_SECRET * 10_000],
))
def test_argparse_errors_are_bounded_and_do_not_echo_raw_arguments(capsys, arguments):
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_ARGUMENTS_INVALID")


@pytest.mark.parametrize("replacement", (
    ("--role", ERROR_SECRET * 10_000),
    ("--role", "enterprise_approver"),
    ("--confirm-task-approval", "--confirm-task-approval=false"),
))
def test_invalid_role_or_false_confirmation_is_sanitized(
    case, monkeypatch, capsys, replacement,
):
    arguments = case.arguments("sign")
    flag, value = replacement
    if flag == "--confirm-task-approval":
        arguments[arguments.index(flag)] = value
    else:
        _set_argument(arguments, flag, value)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_ARGUMENTS_INVALID")


def test_explicit_false_confirmation_stops_before_preflight_or_review(case, monkeypatch):
    arguments = cli.build_parser().parse_args(case.arguments("sign"))
    arguments.confirm_task_approval = False
    monkeypatch.setattr(cli, "_preflight_output", _forbidden)
    monkeypatch.setattr(cli, "review_approval_task", _forbidden)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    with pytest.raises(cli._CliError) as error:
        cli._run(arguments)
    assert error.value.code == "COAUTH_CLI_ARGUMENTS_INVALID"


@pytest.mark.parametrize("extra", (
    ["--private-key-hex", ERROR_SECRET], ["--skip"],
    ["--now", str(NOW)], ["--config", "ignored.json"],
))
def test_sign_has_no_inline_key_skip_time_or_configuration_override(case, capsys, extra):
    assert cli.main(case.arguments("sign") + extra) == 2
    _assert_error(capsys, "COAUTH_CLI_ARGUMENTS_INVALID")


@pytest.mark.parametrize("flag,value,reason", (
    ("--trusted-public-sha256", "f" * 64, "COAUTH_OFFLINE_TRUST_PIN_MISMATCH"),
    ("--trusted-public-sha256", "", "COAUTH_OFFLINE_TRUST_PIN_MISMATCH"),
    ("--expected-task-id", "OTHER-TASK", "COAUTH_OFFLINE_TASK_BINDING_MISMATCH"),
    ("--expected-approval-payload-hash", "f" * 64, "COAUTH_OFFLINE_TASK_BINDING_MISMATCH"),
))
def test_trust_and_task_binding_fail_before_private_reads(
    case, monkeypatch, capsys, flag, value, reason,
):
    arguments = case.arguments("sign")
    _set_argument(arguments, flag, value)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(arguments) == 1
    assert not case.output.exists()
    _assert_error(capsys, reason)


@pytest.mark.parametrize("flag,value", (
    ("--role", FINANCE), ("--subject-id", "wrong-subject"),
    ("--key-id", "wrong-key"), ("--principal-id", "wrong-principal"),
))
def test_pinned_role_and_all_identity_bindings_are_checked_before_private_reads(
    case, monkeypatch, capsys, flag, value,
):
    arguments = case.arguments("sign")
    _set_argument(arguments, flag, value)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    monkeypatch.setattr(cli, "sign_approval", _forbidden)
    assert cli.main(arguments) == 1
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_OFFLINE_SIGNER_MISMATCH")


@pytest.mark.parametrize("kind", ("outside", "traversal", "suffix", "ads", "reserved"))
def test_output_escape_and_unsafe_names_fail_before_private_reads_or_signing(
    case, monkeypatch, capsys, kind,
):
    output = {
        "outside": case.project_root / "elsewhere.json",
        "traversal": case.output_root / ".." / "escaped.json",
        "suffix": case.output_root / "approval.private",
        "ads": case.output_root / "approval:stream.json",
        "reserved": case.output_root / "NUL.json",
    }[kind]
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    monkeypatch.setattr(cli, "sign_approval", _forbidden)
    assert cli.main(case.arguments("sign", output=output)) == 2
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_UNSAFE")


def test_existing_output_is_preserved_before_private_reads(case, monkeypatch, capsys):
    case.output_root.mkdir(parents=True)
    case.output.write_bytes(b"existing-public-file")
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    monkeypatch.setattr(cli, "sign_approval", _forbidden)
    assert cli.main(case.arguments("sign")) == 2
    assert case.output.read_bytes() == b"existing-public-file"
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_EXISTS")


@pytest.mark.parametrize("input_flag", ("--task-file", "--trusted-public-file"))
def test_output_cannot_alias_a_public_input(case, monkeypatch, capsys, input_flag):
    case.output_root.mkdir(parents=True)
    original = case.task_file if input_flag == "--task-file" else case.public_file
    before = original.read_bytes()
    case.output.write_bytes(before)
    arguments = case.arguments("sign")
    _set_argument(arguments, input_flag, str(case.output))
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(arguments) == 2
    assert case.output.read_bytes() == before
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_ALIAS")


def test_output_cannot_alias_a_private_input_even_with_a_json_name(case, monkeypatch, capsys):
    arguments = case.arguments("sign")
    _set_argument(arguments, "--private-key-file", str(case.output))
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_ALIAS")


@pytest.mark.parametrize("private_directory", ("project", "artifacts", "public"))
def test_private_and_public_output_directories_are_separated_before_reads_or_writes(
    case, monkeypatch, capsys, private_directory,
):
    directory = {
        "project": case.project_root,
        "artifacts": case.project_root / "artifacts",
        "public": case.output_root / "signer",
    }[private_directory]
    directory.mkdir(parents=True, exist_ok=True)
    private_file = directory / "own.private"
    private_file.write_bytes(SYNTHETIC_PRIVATE[ENTERPRISE].encode("ascii"))
    output = case.output_root / "new-directory" / "approval.json"
    arguments = case.arguments("sign", output=output)
    _set_argument(arguments, "--private-key-file", str(private_file))
    monkeypatch.setattr(cli, "_read_public_file", _forbidden)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    monkeypatch.setattr(cli, "sign_approval", _forbidden)
    monkeypatch.setattr(cli, "_write_public_file", _forbidden)
    assert cli.main(arguments) == 2
    assert not output.parent.exists()
    _assert_error(
        capsys,
        "COAUTH_CLI_PRIVATE_INPUT_INVALID" if private_directory == "public"
        else "COAUTH_CLI_OUTPUT_UNSAFE",
    )


def test_private_reader_rejects_a_key_in_the_public_output_tree_before_opening(
    case, monkeypatch,
):
    case.output_root.mkdir(parents=True)
    private_file = case.output_root / "own.private"
    private_file.write_bytes(SYNTHETIC_PRIVATE[ENTERPRISE].encode("ascii"))
    monkeypatch.setattr(Path, "open", _forbidden)
    with pytest.raises(cli._CliError) as caught:
        cli._read_private_key(private_file)
    assert caught.value.code == "COAUTH_CLI_PRIVATE_INPUT_INVALID"


@pytest.mark.parametrize(
    "raw",
    (b"", b"x" * (MAX_BUNDLE_BYTES + 1)),
    ids=("empty", "oversized"),
)
def test_writer_rejects_empty_or_oversized_outputs_before_directory_creation(case, raw):
    with pytest.raises(cli._CliError) as caught:
        cli._write_public_file(case.output, raw, [])
    assert caught.value.code == "COAUTH_CLI_LOCAL_FAILURE"
    assert not case.output_root.exists()


def test_existing_hard_link_to_input_is_rejected(case, monkeypatch, capsys):
    case.output_root.mkdir(parents=True)
    try:
        os.link(case.task_file, case.output)
    except OSError:
        pytest.skip("filesystem does not permit creating a synthetic hard link")
    before = case.task_file.read_bytes()
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(case.arguments("sign")) == 2
    assert case.task_file.read_bytes() == case.output.read_bytes() == before
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_ALIAS")


@pytest.mark.parametrize("ancestor", ("project", "artifacts", "coauthorization", "nested"))
def test_every_output_ancestor_rejects_windows_reparse_or_junction_metadata(
    case, monkeypatch, capsys, ancestor,
):
    nested = case.output_root / "nested"
    nested.mkdir(parents=True)
    selected = {
        "project": case.project_root, "artifacts": case.project_root / "artifacts",
        "coauthorization": case.output_root, "nested": nested,
    }[ancestor]
    _mark_reparse(monkeypatch, selected)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    monkeypatch.setattr(cli, "sign_approval", _forbidden)
    assert cli.main(case.arguments("sign", output=nested / "approval.json")) == 2
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_UNSAFE")


def test_existing_output_reparse_point_is_rejected(case, monkeypatch, capsys):
    case.output_root.mkdir(parents=True)
    case.output.write_bytes(b"preserve")
    _mark_reparse(monkeypatch, case.output)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(case.arguments("sign")) == 2
    assert case.output.read_bytes() == b"preserve"
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_UNSAFE")


def test_real_output_symlink_to_outside_is_rejected(case, monkeypatch, capsys):
    outside = case.project_root / "outside"
    outside.mkdir()
    case.output_root.mkdir(parents=True)
    link = case.output_root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("filesystem does not permit creating a synthetic directory symlink")
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(case.arguments("sign", output=link / "approval.json")) == 2
    assert not (outside / "approval.json").exists()
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_UNSAFE")


@pytest.mark.parametrize("flag", ("--task-file", "--trusted-public-file"))
def test_public_directories_are_not_read_as_documents(case, monkeypatch, capsys, flag):
    arguments = case.arguments("sign")
    _set_argument(arguments, flag, str(case.project_root))
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_PUBLIC_INPUT_INVALID")


@pytest.mark.parametrize("which", ("task", "public"))
def test_oversized_public_inputs_fail_before_private_reads(case, monkeypatch, capsys, which):
    path = case.task_file if which == "task" else case.public_file
    path.write_bytes(b"x" * (MAX_BUNDLE_BYTES + 1))
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(case.arguments("sign")) == 2
    _assert_error(capsys, "COAUTH_CLI_PUBLIC_INPUT_INVALID")


def test_public_reads_are_bounded_and_an_exact_limit_document_is_accepted(
    case, monkeypatch, capsys,
):
    raw_task = case.task_file.read_bytes()
    case.task_file.write_bytes(raw_task + b" " * (MAX_BUNDLE_BYTES - len(raw_task)))
    reads = _observe_reads(monkeypatch)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(case.arguments("review")) == 0
    assert reads == [
        (case.task_file, MAX_BUNDLE_BYTES + 1), (case.public_file, MAX_BUNDLE_BYTES + 1),
    ]
    assert json.loads(capsys.readouterr().out)["checked_at"] == NOW


@pytest.mark.parametrize("raw", (
    b"", b"\xff", b"{", b"{} trailing", b"[]", b'{"schema_version":"1.0","schema_version":"1.0"}',
    b'{"unexpected":NaN}', b'{"unexpected":1.5}', b'\xef\xbb\xbf{}',
))
def test_raw_parse_and_schema_failures_are_reported_without_private_reads(
    case, monkeypatch, capsys, raw,
):
    case.task_file.write_bytes(raw)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(case.arguments("sign")) == 1
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_OFFLINE_INPUT_INVALID")


@pytest.mark.parametrize("raw", (b"\xff", b"{", b'\xef\xbb\xbf{}', b'{"policy":{},"policy":{}}'))
def test_pinned_public_setup_still_requires_strict_utf8_and_json(case, monkeypatch, capsys, raw):
    case.public_file.write_bytes(raw)
    arguments = case.arguments("sign")
    _set_argument(arguments, "--trusted-public-sha256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(arguments) == 1
    _assert_error(capsys, "COAUTH_OFFLINE_INPUT_INVALID")


@pytest.mark.parametrize("which", ("task", "public", "private"))
def test_input_reparse_metadata_is_rejected(case, monkeypatch, capsys, which):
    path = {
        "task": case.task_file, "public": case.public_file,
        "private": case.private_files[ENTERPRISE],
    }[which]
    _mark_reparse(monkeypatch, path)
    monkeypatch.setattr(cli, "sign_approval", _forbidden)
    assert cli.main(case.arguments("sign")) == 2
    expected = "PRIVATE" if which == "private" else "PUBLIC"
    _assert_error(capsys, f"COAUTH_CLI_{expected}_INPUT_INVALID")


@pytest.mark.parametrize("which", ("task", "private"))
def test_real_input_symlinks_are_rejected(case, capsys, which):
    path = case.task_file if which == "task" else case.private_files[ENTERPRISE]
    link = case.project_root / ("linked.json" if which == "task" else "linked.private")
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("filesystem does not permit creating a synthetic file symlink")
    arguments = case.arguments("sign")
    _set_argument(arguments, "--task-file" if which == "task" else "--private-key-file", str(link))
    assert cli.main(arguments) == 2
    expected = "PUBLIC" if which == "task" else "PRIVATE"
    _assert_error(capsys, f"COAUTH_CLI_{expected}_INPUT_INVALID")


@pytest.mark.parametrize("ending", (b"", b"\n", b"\r\n"))
def test_private_adapter_reads_at_most_66_bytes_and_accepts_only_optional_lf_or_crlf(
    case, monkeypatch, ending,
):
    path = case.private_files[ENTERPRISE]
    path.write_bytes(SYNTHETIC_PRIVATE[ENTERPRISE].encode("ascii") + ending)
    reads = _observe_reads(monkeypatch)
    assert cli._read_private_key(path) == SYNTHETIC_PRIVATE[ENTERPRISE]
    assert reads == [(path, 66)]


@pytest.mark.parametrize("raw", (
    b"", b"1" * 63, b"1" * 65, b"1" * 67, b"A" * 64, b"g" * 64,
    b" " + b"1" * 64, b"1" * 64 + b" ", b"1" * 64 + b"\r",
    b"1" * 64 + b"\n\n", b"\xef\xbb\xbf" + b"1" * 64, b"\xff" * 64,
    b'{"private_key_hex":"' + b"1" * 64 + b'"}',
))
def test_private_encoding_failures_do_not_reach_core_signing(
    case, monkeypatch, capsys, raw,
):
    case.private_files[ENTERPRISE].write_bytes(raw)
    monkeypatch.setattr(cli, "sign_approval", _forbidden)
    assert cli.main(case.arguments("sign")) == 2
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_CLI_PRIVATE_INPUT_INVALID")


def test_private_input_requires_private_suffix_and_a_regular_file(case, monkeypatch, capsys):
    directory = case.project_root / "directory.private"
    directory.mkdir()
    arguments = case.arguments("sign")
    _set_argument(arguments, "--private-key-file", str(directory))
    monkeypatch.setattr(cli, "sign_approval", _forbidden)
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_PRIVATE_INPUT_INVALID")
    _set_argument(arguments, "--private-key-file", str(case.task_file))
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_PRIVATE_INPUT_INVALID")


@pytest.mark.parametrize("scalar", (0, SM2_CURVE_ORDER - 1, SM2_CURVE_ORDER, SM2_CURVE_ORDER + 1))
def test_format_valid_private_scalar_range_is_rejected_by_the_real_core(case, capsys, scalar):
    case.private_files[ENTERPRISE].write_bytes(f"{scalar:064x}".encode("ascii"))
    assert cli.main(case.arguments("sign")) == 1
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_OFFLINE_KEY_INVALID")


def test_valid_but_wrong_role_private_key_is_rejected_by_the_real_core(case, capsys):
    case.private_files[ENTERPRISE].write_bytes(SYNTHETIC_PRIVATE[FINANCE].encode("ascii"))
    assert cli.main(case.arguments("sign")) == 1
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_OFFLINE_PRIVATE_KEY_MISMATCH")


@pytest.mark.parametrize("role", ROLES)
def test_real_sm2_signing_writes_only_one_schema_valid_statement_and_signature(case, capsys, role):
    assert cli.main(case.arguments("sign", role=role)) == 0
    raw = case.output.read_bytes()
    document = json.loads(raw)
    assert set(document) == {"statement", "signature"}
    assert canonicalize(document) == raw
    SchemaStore(EXTENSION_SCHEMA_ROOT).validate("single-approval.schema.json", document)
    evidence = ApprovalEvidence.model_validate(document)
    record = next(key for key in case.setup.keys if key.role == role)
    assert evidence.statement.role == role
    assert evidence.statement.approval_payload_hash == case.challenge.approval_payload_hash
    assert verify_payload(
        evidence.statement.model_dump(mode="json"), evidence.signature.model_dump(mode="json"),
        domain_separator=COAUTHORIZATION_DOMAIN, expected_key_id=record.key_id,
        expected_key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        public_key_hex=record.public_key_hex,
    )
    captured = capsys.readouterr()
    assert captured.out.strip() == (
        "COAUTHORIZATION_APPROVAL_WRITTEN; LOCAL_SNAPSHOT_VERIFICATION_ONLY; "
        "\u53ea\u751f\u6210\u5ba1\u6279\u58f0\u660e\uff0c\u672a\u7b7e\u53d1\u6839\u6388\u6743\u3002"
    )
    assert captured.err == ""
    assert SYNTHETIC_PRIVATE[role] not in captured.out + captured.err + raw.decode("ascii")


def test_largest_allowed_sm2_signing_scalar_is_delegated_to_the_real_core(case, capsys):
    private = f"{SM2_CURVE_ORDER - 2:064x}"
    setup = case.setup.model_dump(mode="json")
    setup["keys"][0]["public_key_hex"] = derive_public_key(private)
    raw_setup = canonicalize(setup)
    case.public_file.write_bytes(raw_setup)
    case.private_files[ENTERPRISE].write_bytes(private.encode("ascii"))
    arguments = case.arguments("sign")
    _set_argument(arguments, "--trusted-public-sha256", hashlib.sha256(raw_setup).hexdigest())
    assert cli.main(arguments) == 0
    assert ApprovalEvidence.model_validate(json.loads(case.output.read_bytes())).statement.role == ENTERPRISE
    assert capsys.readouterr().err == ""


def test_output_preflight_review_identity_and_private_read_precede_fresh_signing_time(
    case, monkeypatch, capsys,
):
    events = []
    times = iter((NOW, NOW + 1, NOW + 2, NOW + 3))
    original_preflight = cli._preflight_output
    original_read = cli._read_private_key

    def preflight(*args, **kwargs):
        events.append("preflight")
        return original_preflight(*args, **kwargs)

    def review(*args, **kwargs):
        events.append("review")
        assert kwargs["now"] in (NOW, NOW + 2, NOW + 3)
        return offline.review_approval_task(*args, **kwargs)

    def private(*args, **kwargs):
        events.append("private")
        return original_read(*args, **kwargs)

    def sign(*args, **kwargs):
        events.append("sign")
        assert kwargs["now"] == NOW + 1
        return offline.sign_approval(*args, **kwargs)

    monkeypatch.setattr(cli, "now_unix", lambda: next(times))
    monkeypatch.setattr(cli, "_preflight_output", preflight)
    monkeypatch.setattr(cli, "review_approval_task", review)
    monkeypatch.setattr(cli, "_read_private_key", private)
    monkeypatch.setattr(cli, "sign_approval", sign)
    assert cli.main(case.arguments("sign")) == 0
    assert events[:4] == ["preflight", "review", "private", "sign"]
    evidence = ApprovalEvidence.model_validate(json.loads(case.output.read_bytes()))
    assert evidence.statement.approved_at == evidence.signature.signed_at == NOW + 1
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("fresh_time", (NOW - 1, NOW + 120))
@pytest.mark.parametrize("command", ("sign", "assemble"))
def test_real_core_rejects_time_reversal_or_expiration_after_review(
    case, monkeypatch, capsys, fresh_time, command,
):
    if command == "assemble":
        case.write_real_approvals()
    times = iter((NOW, fresh_time))
    monkeypatch.setattr(cli, "now_unix", lambda: next(times))
    assert cli.main(case.arguments(command)) == 1
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_OFFLINE_TIME_INVALID")


def test_real_assemble_preserves_core_canonical_bytes_and_uses_no_private_input(
    case, monkeypatch, capsys,
):
    raw_enterprise, raw_finance = case.write_real_approvals()
    expected = offline.assemble_bundle(case.review(), raw_enterprise, raw_finance, now=NOW + 1)
    times = iter((NOW, NOW + 1, NOW + 2, NOW + 3))
    monkeypatch.setattr(cli, "now_unix", lambda: next(times))
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    original_read = cli._read_public_file
    reads = []

    def read(value):
        reads.append(Path(value))
        return original_read(value)

    monkeypatch.setattr(cli, "_read_public_file", read)
    assert cli.main(case.arguments("assemble")) == 0
    assert case.output.read_bytes() == expected
    bundle = CoauthorizationBundle.model_validate(json.loads(expected))
    assert tuple(item.statement.role for item in bundle.approvals) == ROLES
    assert reads == [
        case.task_file, case.public_file,
        case.project_root / "enterprise.json", case.project_root / "finance.json",
    ]
    assert case.review().task.status == "PENDING_AUTHORIZATION"
    captured = capsys.readouterr()
    assert captured.out.strip() == (
        "COAUTHORIZATION_BUNDLE_WRITTEN; LOCAL_SNAPSHOT_VERIFICATION_ONLY; "
        "\u53ea\u751f\u6210\u53cc\u7b7e\u8bc1\u636e\uff0c\u672a\u7b7e\u53d1\u6839\u6388\u6743\u3002"
    )
    assert captured.err == ""


@pytest.mark.parametrize("command", ("sign", "assemble"))
@pytest.mark.parametrize("operation_time,late_time,code,status", (
    (NOW + 1, NOW + 120, "COAUTH_OFFLINE_TIME_INVALID", 1),
    (NOW + 2, NOW + 1, "COAUTH_CLI_CLOCKBACK", 2),
))
def test_late_expiry_or_clockback_after_crypto_prevents_any_output(
    case, monkeypatch, capsys, command, operation_time, late_time, code, status,
):
    if command == "assemble":
        case.write_real_approvals()
    times = iter((NOW, operation_time, late_time))
    monkeypatch.setattr(cli, "now_unix", lambda: next(times))
    assert cli.main(case.arguments(command)) == status
    assert not case.output.exists()
    assert not case.output_root.exists()
    _assert_error(capsys, code)


@pytest.mark.parametrize("command", ("sign", "assemble"))
@pytest.mark.parametrize("before_write,after_write,code", (
    (NOW + 2, NOW + 120, "COAUTH_CLI_OUTPUT_NOT_CURRENT"),
    (NOW + 3, NOW + 2, "COAUTH_CLI_OUTPUT_CLOCKBACK"),
))
def test_expiry_or_clockback_during_write_reports_failure_and_preserves_the_file(
    case, monkeypatch, capsys, command, before_write, after_write, code,
):
    if command == "assemble":
        case.write_real_approvals()
    times = iter((NOW, NOW + 1, before_write, after_write))
    monkeypatch.setattr(cli, "now_unix", lambda: next(times))
    assert cli.main(case.arguments(command)) == 2
    assert case.output.exists()
    document = json.loads(case.output.read_bytes())
    assert set(document) == ({"statement", "signature"} if command == "sign" else {"payload", "approvals"})
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(f"{code}: ")
    assert "\u8bf7\u52ff\u89c6\u4f5c\u5f53\u524d\u53ef\u7528\u6216\u5df2\u6388\u6743" in captured.err
    assert ERROR_SECRET not in captured.err and "Traceback" not in captured.err


@pytest.mark.parametrize("command", ("sign", "assemble"))
def test_late_reviews_reuse_exact_raw_context_and_pins_without_repeating_crypto(
    case, monkeypatch, capsys, command,
):
    if command == "assemble":
        case.write_real_approvals()
    raw_challenge, raw_setup = case.task_file.read_bytes(), case.public_file.read_bytes()
    reviews, crypto_times = [], []
    times = iter((NOW, NOW + 1, NOW + 2, NOW + 3))

    def review(raw_task, raw_public, **kwargs):
        reviews.append((raw_task, raw_public, dict(kwargs)))
        return offline.review_approval_task(raw_task, raw_public, **kwargs)

    def sign(*args, **kwargs):
        crypto_times.append(kwargs["now"])
        return offline.sign_approval(*args, **kwargs)

    def assemble(*args, **kwargs):
        crypto_times.append(kwargs["now"])
        return offline.assemble_bundle(*args, **kwargs)

    monkeypatch.setattr(cli, "now_unix", lambda: next(times))
    monkeypatch.setattr(cli, "review_approval_task", review)
    monkeypatch.setattr(cli, "sign_approval", sign)
    monkeypatch.setattr(cli, "assemble_bundle", assemble)
    assert cli.main(case.arguments(command)) == 0
    assert crypto_times == [NOW + 1]
    assert [entry[2]["now"] for entry in reviews] == [NOW, NOW + 2, NOW + 3]
    for task_bytes, public_bytes, pins in reviews:
        assert (task_bytes, public_bytes) == (raw_challenge, raw_setup)
        assert pins["trusted_setup_sha256"] == case.trusted_sha256
        assert pins["expected_task_id"] == case.challenge.payload.task_id
        assert pins["expected_approval_payload_hash"] == case.challenge.approval_payload_hash
    document = json.loads(case.output.read_bytes())
    if command == "sign":
        assert document["statement"]["approved_at"] == NOW + 1
    else:
        assert {item["statement"]["approved_at"] for item in document["approvals"]} == {NOW}
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("flag", ("--enterprise-approval-file", "--finance-approval-file"))
def test_assemble_output_alias_preflight_happens_before_core_review(case, monkeypatch, capsys, flag):
    arguments = case.arguments("assemble")
    _set_argument(arguments, flag, str(case.output))
    monkeypatch.setattr(cli, "review_approval_task", _forbidden)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    assert cli.main(arguments) == 2
    _assert_error(capsys, "COAUTH_CLI_OUTPUT_ALIAS")


@pytest.mark.parametrize(
    "bad_raw",
    (b"\xff", b"{", b"{}", b"x" * (MAX_BUNDLE_BYTES + 1)),
    ids=("invalid_utf8", "invalid_json", "wrong_schema", "oversized"),
)
def test_assemble_single_approval_inputs_are_bounded_and_strict(case, monkeypatch, capsys, bad_raw):
    case.write_real_approvals()
    (case.project_root / "enterprise.json").write_bytes(bad_raw)
    monkeypatch.setattr(cli, "_read_private_key", _forbidden)
    oversized = len(bad_raw) > MAX_BUNDLE_BYTES
    assert cli.main(case.arguments("assemble")) == (2 if oversized else 1)
    assert not case.output.exists()
    _assert_error(
        capsys, "COAUTH_CLI_PUBLIC_INPUT_INVALID" if oversized else "COAUTH_OFFLINE_INPUT_INVALID",
    )


def test_assemble_rejects_duplicate_roles_instead_of_creating_an_authorization(case, capsys):
    raw_enterprise, _ = case.write_real_approvals()
    (case.project_root / "finance.json").write_bytes(raw_enterprise)
    assert cli.main(case.arguments("assemble")) == 1
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_OFFLINE_APPROVAL_INVALID")


def test_exclusive_creation_does_not_overwrite_a_file_created_after_preflight(
    case, monkeypatch, capsys,
):
    original = Path.open
    modes = []

    def open_after_race(path, mode="r", *args, **kwargs):
        if path == case.output:
            modes.append(mode)
            if mode == "xb":
                with original(path, "wb") as competitor:
                    competitor.write(b"competing-public-output")
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_after_race)
    assert cli.main(case.arguments("sign")) == 1
    assert modes == ["xb"]
    assert case.output.read_bytes() == b"competing-public-output"
    _assert_error(capsys, "COAUTH_CLI_LOCAL_FAILURE")


def test_failed_write_leaves_only_its_new_partial_file_and_sanitizes_the_error(
    case, monkeypatch, capsys,
):
    original = Path.open

    class PartialWriter(_ObservedFile):
        def write(self, raw):
            self.stream.write(raw[:12])
            self.stream.flush()
            raise OSError(ERROR_SECRET + SYNTHETIC_PRIVATE[ENTERPRISE])

    def partial(path, mode="r", *args, **kwargs):
        stream = original(path, mode, *args, **kwargs)
        return PartialWriter(stream, path, []) if mode == "xb" else stream

    monkeypatch.setattr(Path, "open", partial)
    assert cli.main(case.arguments("sign")) == 1
    assert case.output.exists() and len(case.output.read_bytes()) == 12
    _assert_error(capsys, "COAUTH_CLI_LOCAL_FAILURE")


@pytest.mark.parametrize("known_code", (True, False))
def test_offline_errors_emit_only_allowlisted_codes_and_fixed_messages(
    case, monkeypatch, capsys, known_code,
):
    code = "COAUTH_OFFLINE_KEY_INVALID" if known_code else ERROR_SECRET * 10_000

    def fail(*args, **kwargs):
        raise offline.OfflineApprovalError(code, ERROR_SECRET + SYNTHETIC_PRIVATE[ENTERPRISE])

    monkeypatch.setattr(cli, "sign_approval", fail)
    assert cli.main(case.arguments("sign")) == 1
    assert not case.output.exists()
    _assert_error(capsys, code if known_code else "COAUTH_CLI_OFFLINE_REJECTED")


@pytest.mark.parametrize("stage", ("review", "private", "sign", "assemble", "write"))
def test_unexpected_local_errors_never_print_paths_private_contents_or_tracebacks(
    case, monkeypatch, capsys, stage,
):
    if stage == "assemble":
        case.write_real_approvals()

    def fail(*args, **kwargs):
        raise RuntimeError(ERROR_SECRET + str(case.private_files[ENTERPRISE]))

    attribute = {
        "review": "review_approval_task", "private": "_read_private_key",
        "sign": "sign_approval", "assemble": "assemble_bundle", "write": "_write_public_file",
    }[stage]
    monkeypatch.setattr(cli, attribute, fail)
    assert cli.main(case.arguments("assemble" if stage == "assemble" else "sign")) == 1
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_CLI_LOCAL_FAILURE")


@pytest.mark.parametrize(
    "stage", ("parser", "review", "private", "sign", "assemble", "write"),
)
def test_cancellation_uses_a_fixed_error_exit_without_traceback(
    case, monkeypatch, capsys, stage,
):
    if stage == "assemble":
        case.write_real_approvals()

    def cancel(*args, **kwargs):
        raise KeyboardInterrupt(ERROR_SECRET + SYNTHETIC_PRIVATE[ENTERPRISE])

    attribute = {
        "parser": "build_parser", "review": "review_approval_task",
        "private": "_read_private_key", "sign": "sign_approval",
        "assemble": "assemble_bundle", "write": "_write_public_file",
    }[stage]
    monkeypatch.setattr(cli, attribute, cancel)
    assert cli.main(case.arguments("assemble" if stage == "assemble" else "sign")) == 130
    assert not case.output.exists()
    _assert_error(capsys, "COAUTH_CLI_CANCELLED")


def test_cancellation_during_output_preserves_partial_file_but_never_reports_success(
    case, monkeypatch, capsys,
):
    def cancelled_write(output, raw, inputs, **kwargs):
        output.parent.mkdir(parents=True)
        output.write_bytes(raw[:12])
        raise KeyboardInterrupt(ERROR_SECRET)

    monkeypatch.setattr(cli, "_write_public_file", cancelled_write)
    assert cli.main(case.arguments("sign")) == 130
    assert case.output.exists() and len(case.output.read_bytes()) == 12
    _assert_error(capsys, "COAUTH_CLI_CANCELLED")


@pytest.mark.parametrize("dependency", (
    "backend.coauthorization.contracts", "backend.coauthorization.offline",
    "backend.coauthorization.verifier", "backend.common.schema",
    "backend.common.time", "backend.crypto.canonical_json",
))
@pytest.mark.parametrize("cancelled", (False, True))
def test_project_dependency_startup_failure_is_fixed_and_redacted(
    monkeypatch, capsys, dependency, cancelled,
):
    original_import = builtins.__import__

    def import_with_failure(name, *args, **kwargs):
        if name == dependency:
            failure = KeyboardInterrupt if cancelled else ImportError
            raise failure(ERROR_SECRET + SYNTHETIC_PRIVATE[ENTERPRISE])
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_with_failure)
    with pytest.raises(SystemExit) as caught:
        runpy.run_path(str(Path(cli.__file__).resolve()), run_name="_coauth_startup_boundary")
    assert caught.value.code == (130 if cancelled else 1)
    _assert_error(capsys, "COAUTH_CLI_CANCELLED" if cancelled else "COAUTH_CLI_STARTUP_FAILURE")


def test_error_reporting_falls_back_to_a_fixed_ascii_code_on_non_unicode_stderr(monkeypatch):
    parts = []

    class AsciiStderr:
        def write(self, value):
            value.encode("ascii", errors="strict")
            parts.append(value)
            return len(value)

        def flush(self):
            return None

    monkeypatch.setattr(cli.sys, "stderr", AsciiStderr())
    cli._report_error("COAUTH_CLI_PRIVATE_INPUT_INVALID")
    assert "".join(parts) == "COAUTH_CLI_PRIVATE_INPUT_INVALID\n"


@pytest.mark.parametrize("arguments", (
    ["--help"], ["review", "--help"], ["sign", "--help"], ["assemble", "--help"],
))
def test_help_returns_zero_and_states_snapshot_adapter_and_path_boundaries(capsys, arguments):
    assert cli.main(arguments) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    text = "".join(captured.out.split())
    assert "HSM" in text and "\u751f\u4ea7ACL" in text
    assert "\u5e76\u53d1\u66ff\u6362\u8def\u5f84" in text
    assert "\u5f53\u524d\u64a4\u9500\u72b6\u6001" in text
    assert "\u663e\u793a\u5e2e\u52a9\u4fe1\u606f\u5e76\u9000\u51fa" in text
    if arguments[0] in ("review", "assemble"):
        assert "--private-key-file" not in text
