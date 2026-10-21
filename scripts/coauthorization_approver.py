"""Offline CLI using independently pinned public approval metadata.

The plaintext .private adapter is for development, not an HSM or production
ACL boundary. Path checks assume a trusted local operator and administrator;
they cannot eliminate concurrent path replacement by those principals.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path

_CANCELLED_MESSAGE = (
    "\u64cd\u4f5c\u5df2\u53d6\u6d88\uff1a\u82e5\u5df2\u65b0\u5efa\u8f93\u51fa"
    "\u6587\u4ef6\uff0c\u8bf7\u4eba\u5de5\u6838\u5bf9\uff0c\u4e0d\u80fd\u89c6"
    "\u4f5c\u6709\u6548\u5ba1\u6279\u6216\u5df2\u6388\u6743\u3002"
)
_STARTUP_FAILURE_MESSAGE = (
    "\u542f\u52a8\u5931\u8d25\uff1a\u8bf7\u6838\u5bf9\u9879\u76ee\u4f9d\u8d56"
    "\u4e0e\u89e3\u91ca\u5668\uff0c\u672c\u6b21\u6ca1\u6709\u5b8c\u6210\u5ba1"
    "\u6279\u3002"
)


def _emit_error(code: str, message: str) -> None:
    try:
        print(f"{code}: {message}", file=sys.stderr)
    except (OSError, UnicodeError):
        try:
            print(code, file=sys.stderr)
        except (OSError, UnicodeError):
            pass


try:
    from backend.coauthorization.contracts import MAX_BUNDLE_BYTES
    from backend.coauthorization.offline import (
        OfflineApprovalError,
        OfflineApprovalReview,
        assemble_bundle,
        review_approval_task,
        sign_approval,
    )
    from backend.coauthorization.verifier import CoauthorizationReason
    from backend.common.schema import PROJECT_ROOT
    from backend.common.time import now_unix
    from backend.crypto.canonical_json import canonicalize
except KeyboardInterrupt:
    _emit_error("COAUTH_CLI_CANCELLED", _CANCELLED_MESSAGE)
    raise SystemExit(130) from None
except Exception:
    _emit_error("COAUTH_CLI_STARTUP_FAILURE", _STARTUP_FAILURE_MESSAGE)
    raise SystemExit(1) from None

MAX_PRIVATE_KEY_BYTES = 66
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_PRIVATE_ENCODING = re.compile(rb"[0-9a-f]{64}(?:\r?\n)?")
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}
_OFFLINE_REASON_CODES = frozenset({
    "COAUTH_OFFLINE_INPUT_INVALID", "COAUTH_OFFLINE_TRUST_PIN_MISMATCH",
    "COAUTH_OFFLINE_TASK_BINDING_MISMATCH", "COAUTH_OFFLINE_POLICY_MISMATCH",
    "COAUTH_OFFLINE_SCOPE_MISMATCH", "COAUTH_OFFLINE_TIME_INVALID",
    "COAUTH_OFFLINE_KEY_INVALID", "COAUTH_OFFLINE_SIGNER_MISMATCH",
    "COAUTH_OFFLINE_PRIVATE_KEY_MISMATCH", "COAUTH_OFFLINE_SIGNATURE_INVALID",
    "COAUTH_OFFLINE_APPROVAL_INVALID",
}) | frozenset(reason.value for reason in CoauthorizationReason)
_BOUNDARIES = (
    (
        "\u4ec5\u4fe1\u4efb\u64cd\u4f5c\u8005\u72ec\u7acb\u6838\u5bf9\u7684\u516c\u5171"
        "\u5feb\u7167\u3002\u672c\u5730\u9a8c\u7b7e\u4e0d\u7b49\u4e8e\u6839\u6388\u6743"
        "\uff0c\u4e0d\u6d88\u8d39\u6311\u6218\uff0c\u4e0d\u80fd\u8bc1\u660e\u5f53\u524d"
        "\u64a4\u9500\u72b6\u6001\u6216\u73b0\u5b9e\u4e2d\u7684\u4e3b\u4f53\u72ec\u7acb"
        "\u6027\u3002"
    ),
    (
        ".private \u660e\u6587\u8f6f\u6587\u4ef6\u4ec5\u7528\u4e8e\u5f00\u53d1\uff0c"
        "\u4e0d\u63d0\u4f9b HSM \u6216\u751f\u4ea7 ACL \u9694\u79bb\u4fdd\u8bc1\uff1bPy"
        "thon \u4e0d\u80fd\u4fdd\u8bc1\u79c1\u94a5\u5185\u5b58\u53ef\u9760\u6e05\u96f6"
        "\u3002"
    ),
    (
        "\u8def\u5f84\u68c0\u67e5\u548c\u72ec\u5360\u521b\u5efa\u4ee5\u53ef\u4fe1\u672c"
        "\u673a\u64cd\u4f5c\u8005\u53ca\u7ba1\u7406\u5458\u4e3a\u524d\u63d0\uff0c\u4ecd"
        "\u5b58\u5728\u5176\u5e76\u53d1\u66ff\u6362\u8def\u5f84\u7684\u7ade\u4e89\u3002"
        "\u5199\u51fa\u5931\u8d25\u53ef\u80fd\u7559\u4e0b\u65b0\u5efa\u7684\u90e8\u5206"
        "\u6587\u4ef6\uff0c\u9700\u4eba\u5de5\u6838\u5bf9\u3002"
    ),
    (
        "\u5199\u51fa\u524d\u540e\u53d6\u65f6\u4ec5\u662f\u672c\u5730\u89c2\u6d4b\uff0c"
        "\u4e0d\u627f\u8bfa\u65f6\u949f\u4e0e\u6587\u4ef6\u8f93\u51fa\u539f\u5b50\u4e00"
        "\u81f4\uff1b\u6700\u7ec8 Authority \u4ecd\u987b\u6838\u9a8c\u5f53\u524d\u6743"
        "\u9650\u3002"
    ),
)
_ERROR_MESSAGES = {
    "COAUTH_CLI_CANCELLED": _CANCELLED_MESSAGE,
    "COAUTH_CLI_STARTUP_FAILURE": _STARTUP_FAILURE_MESSAGE,
    "COAUTH_CLI_ARGUMENTS_INVALID": (
        "\u53c2\u6570\u9519\u8bef\uff1a\u8bf7\u68c0\u67e5\u5fc5\u586b\u53c2\u6570\u5e76\u53c2\u8003 --help\u3002"
    ),
    "COAUTH_CLI_PUBLIC_INPUT_INVALID": (
        "\u516c\u5171\u8f93\u5165\u65e0\u6548\uff1a\u9700\u8981\u4e0d\u8d85\u8fc7 32768 bytes \u7684\u666e\u901a\u6587\u4ef6\u3002"
    ),
    "COAUTH_CLI_PRIVATE_INPUT_INVALID": (
        "\u79c1\u94a5\u6587\u4ef6\u65e0\u6548\uff1a\u9700\u8981 .private \u666e\u901a\u6587\u4ef6\uff0c\u5185\u5bb9\u4e3a 64 \u4f4d\u5c0f\u5199 hex \u548c\u53ef\u9009\u6362\u884c\u3002"
    ),
    "COAUTH_CLI_OUTPUT_UNSAFE": (
        "\u8f93\u51fa\u8def\u5f84\u65e0\u6548\uff1a\u8bf7\u4f7f\u7528\u9879\u76ee artifacts/coauthorization \u76ee\u5f55\u4e0b\u7684\u5b89\u5168 .json \u8def\u5f84\u3002"
    ),
    "COAUTH_CLI_OUTPUT_ALIAS": (
        "\u8f93\u51fa\u4e0e\u8f93\u5165\u6587\u4ef6\u91cd\u5408\uff0c\u8bf7\u9009\u62e9\u65b0\u7684\u8f93\u51fa\u8def\u5f84\u3002"
    ),
    "COAUTH_CLI_OUTPUT_EXISTS": (
        "\u8f93\u51fa\u5df2\u5b58\u5728\uff0c\u8bf7\u9009\u62e9\u65b0\u7684\u8f93\u51fa\u8def\u5f84\u3002"
    ),
    "COAUTH_CLI_OFFLINE_REJECTED": (
        "\u79bb\u7ebf\u6821\u9a8c\u672a\u901a\u8fc7\uff1a\u8bf7\u68c0\u67e5\u4efb\u52a1\u3001\u72ec\u7acb\u6838\u5bf9\u7684 pin\u3001\u8eab\u4efd\u7ed1\u5b9a\u548c\u6709\u6548\u65f6\u95f4\u3002"
    ),
    "COAUTH_CLI_LOCAL_FAILURE": (
        "\u672c\u5730\u64cd\u4f5c\u5931\u8d25\uff1a\u8bf7\u68c0\u67e5\u6587\u4ef6\u8bbf\u95ee\u548c\u8f93\u51fa\u76ee\u5f55\uff1b\u65b0\u5efa\u6587\u4ef6\u53ef\u80fd\u4e0d\u5b8c\u6574\u3002"
    ),
    "COAUTH_CLI_CLOCKBACK": (
        "\u672c\u5730\u65f6\u949f\u5012\u9000\uff0c\u5df2\u62d2\u7edd\u5199\u51fa\u5ba1\u6279\u8bc1\u636e\u3002"
    ),
    "COAUTH_CLI_OUTPUT_NOT_CURRENT": (
        "\u5199\u51fa\u540e\u65f6\u6548\u590d\u6838\u5931\u8d25\uff1a\u6587\u4ef6\u4fdd\u7559\u4f9b\u6838\u5bf9\uff0c\u8bf7\u52ff\u89c6\u4f5c\u5f53\u524d\u53ef\u7528\u6216\u5df2\u6388\u6743\u3002"
    ),
    "COAUTH_CLI_OUTPUT_CLOCKBACK": (
        "\u5199\u51fa\u540e\u672c\u5730\u65f6\u949f\u5012\u9000\uff1a\u6587\u4ef6\u4fdd\u7559\u4f9b\u6838\u5bf9\uff0c\u8bf7\u52ff\u89c6\u4f5c\u5f53\u524d\u53ef\u7528\u6216\u5df2\u6388\u6743\u3002"
    ),
}


class _CliError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("allow_abbrev", False)
        kwargs.setdefault("add_help", False)
        super().__init__(*args, **kwargs)
        self.add_argument(
            "-h", "--help", action="help",
            help="\u663e\u793a\u5e2e\u52a9\u4fe1\u606f\u5e76\u9000\u51fa\u3002",
        )

    def error(self, message: str) -> None:
        # argparse messages can contain unbounded or secret command-line input.
        raise _CliError("COAUTH_CLI_ARGUMENTS_INVALID")


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="coauthorization_approver",
        description="\u79bb\u7ebf\u4efb\u52a1\u5ba1\u6279\uff1a\u4f7f\u7528\u64cd\u4f5c\u8005\u72ec\u7acb\u6838\u5bf9\u7684\u516c\u5171 pin\u3002",
        epilog=" ".join(_BOUNDARIES),
    )
    commands = parser.add_subparsers(
        dest="command", required=True, title="\u5b50\u547d\u4ee4",
    )
    descriptions = {
        "review": "\u5ba1\u9605\u5b8c\u6574\u4efb\u52a1\u3001\u80fd\u529b\u3001\u7b7e\u540d\u57df\u548c\u516c\u5171\u653f\u7b56\u3002",
        "sign": "\u7b7e\u7f72\u5355\u65b9\u5ba1\u6279\u58f0\u660e\u3002",
        "assemble": "\u6838\u9a8c\u5e76\u7ec4\u88c5\u53cc\u7b7e\u8bc1\u636e\u3002",
    }
    for command in ("review", "sign", "assemble"):
        child = commands.add_parser(
            command, description=descriptions[command], help=descriptions[command],
            epilog=" ".join(_BOUNDARIES),
        )
        child.add_argument("--task-file", required=True)
        child.add_argument("--trusted-public-file", required=True)
        child.add_argument(
            "--trusted-public-sha256", required=True,
            help="\u5fc5\u987b\u7531\u64cd\u4f5c\u8005\u901a\u8fc7\u72ec\u7acb\u53ef\u4fe1\u9014\u5f84\u6838\u5bf9\u3002",
        )
        child.add_argument("--expected-task-id", required=True)
        child.add_argument("--expected-approval-payload-hash", required=True)
        if command == "sign":
            child.add_argument(
                "--role", required=True,
                choices=("ENTERPRISE_APPROVER", "FINANCE_APPROVER"),
            )
            child.add_argument("--subject-id", required=True)
            child.add_argument("--key-id", required=True)
            child.add_argument("--principal-id", required=True)
            child.add_argument(
                "--private-key-file", required=True,
                help="\u5f00\u53d1\u7528 .private \u660e\u6587\u79c1\u94a5\u6587\u4ef6\u8def\u5f84\u3002",
            )
            child.add_argument(
                "--confirm-task-approval", action="store_true", required=True,
                help="\u786e\u8ba4\u5df2\u5ba1\u9605\u5b8c\u6574\u4efb\u52a1\u5e76\u540c\u610f\u672c\u6b21\u7b7e\u7f72\u3002",
            )
        elif command == "assemble":
            child.add_argument("--enterprise-approval-file", required=True)
            child.add_argument("--finance-approval-file", required=True)
        if command != "review":
            child.add_argument(
                "--output", required=True,
                help="\u9879\u76ee artifacts/coauthorization \u76ee\u5f55\u4e0b\u7684\u65b0 .json \u6587\u4ef6\u3002",
            )
    return parser


def _is_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _check_ancestors(path: Path, code: str) -> None:
    for component in reversed((path, *path.parents)):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        if _is_reparse(metadata) or (
            component != path and not stat.S_ISDIR(metadata.st_mode)
        ):
            raise _CliError(code)


def _read_bounded_file(
    value: str | Path, *, limit: int, read_size: int, code: str,
) -> bytes:
    path = Path(value).absolute()
    _check_ancestors(path, code)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        raise _CliError(code)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode) or _is_reparse(opened)
            or not os.path.samestat(metadata, opened) or opened.st_size > limit
        ):
            raise _CliError(code)
        _check_ancestors(path, code)
        raw = stream.read(read_size)
        finished = os.fstat(stream.fileno())
        if (
            not os.path.samestat(opened, finished)
            or opened.st_size != finished.st_size
            or len(raw) != finished.st_size or len(raw) > limit
        ):
            raise _CliError(code)
    return raw


def _read_public_file(value: str | Path) -> bytes:
    return _read_bounded_file(
        value, limit=MAX_BUNDLE_BYTES, read_size=MAX_BUNDLE_BYTES + 1,
        code="COAUTH_CLI_PUBLIC_INPUT_INVALID",
    )


def _checked_private_path(value: str | Path) -> Path:
    code = "COAUTH_CLI_PRIVATE_INPUT_INVALID"
    path = Path(value).absolute()
    if path.suffix != ".private":
        raise _CliError(code)
    _check_ancestors(path, code)
    path = path.resolve()
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_PRIVATE_KEY_BYTES:
        raise _CliError(code)
    public_root = PROJECT_ROOT.absolute() / "artifacts" / "coauthorization"
    _check_ancestors(public_root, code)
    if path.is_relative_to(public_root.resolve()):
        raise _CliError(code)
    return path


def _read_private_key(value: str | Path) -> str:
    path = _checked_private_path(value)
    raw = _read_bounded_file(
        path, limit=MAX_PRIVATE_KEY_BYTES, read_size=MAX_PRIVATE_KEY_BYTES,
        code="COAUTH_CLI_PRIVATE_INPUT_INVALID",
    )
    if _PRIVATE_ENCODING.fullmatch(raw) is None:
        raise _CliError("COAUTH_CLI_PRIVATE_INPUT_INVALID")
    return raw[:64].decode("ascii", errors="strict")


def _preflight_output(
    value: str | Path, inputs: list[Path], *, private_key_file: Path | None = None,
) -> Path:
    code = "COAUTH_CLI_OUTPUT_UNSAFE"
    root = PROJECT_ROOT.absolute() / "artifacts" / "coauthorization"
    candidate = Path(value).absolute()
    _check_ancestors(root, code)
    _check_ancestors(candidate, code)
    root = root.resolve()
    candidate = candidate.resolve()
    if candidate.suffix != ".json" or not candidate.is_relative_to(root):
        raise _CliError(code)
    for part in candidate.relative_to(root).parts:
        if (
            part.endswith((" ", "."))
            or any(character in '<>:"|?*' or ord(character) < 32 for character in part)
            or part.split(".", 1)[0].upper() in _RESERVED_NAMES
        ):
            raise _CliError(code)
    _check_ancestors(root, code)
    _check_ancestors(candidate, code)
    for source in inputs:
        if candidate == source.absolute().resolve():
            raise _CliError("COAUTH_CLI_OUTPUT_ALIAS")
    if private_key_file is not None:
        private_path = _checked_private_path(private_key_file)
        if candidate.is_relative_to(private_path.parent):
            raise _CliError(code)
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        return candidate
    if _is_reparse(metadata):
        raise _CliError(code)
    for source in inputs:
        try:
            if candidate.samefile(source):
                raise _CliError("COAUTH_CLI_OUTPUT_ALIAS")
        except FileNotFoundError:
            continue
    raise _CliError("COAUTH_CLI_OUTPUT_EXISTS")


def _write_public_file(
    output: Path, raw: bytes, inputs: list[Path], *, private_key_file: Path | None = None,
) -> None:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BUNDLE_BYTES:
        raise _CliError("COAUTH_CLI_LOCAL_FAILURE")
    output = _preflight_output(output, inputs, private_key_file=private_key_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    output = _preflight_output(output, inputs, private_key_file=private_key_file)
    # Exclusive creation prevents overwrite; a failed partial write is not deleted.
    with output.open("xb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
            raise _CliError("COAUTH_CLI_OUTPUT_UNSAFE")
        if stream.write(raw) != len(raw):
            raise _CliError("COAUTH_CLI_LOCAL_FAILURE")
        stream.flush()
        os.fsync(stream.fileno())


def _print_review(review: OfflineApprovalReview, trusted_sha256: str) -> None:
    document = {
        "observation_kind": "OFFLINE_TASK_REVIEW",
        "payload": review.challenge.payload.model_dump(mode="json"),
        "approval_payload_hash": review.challenge.approval_payload_hash,
        "task_capabilities": [
            capability.model_dump(mode="json")
            for capability in review.challenge.task_capabilities
        ],
        "signature_domain": review.challenge.signature_domain,
        "trusted_public_sha256": trusted_sha256,
        "policy": review.setup.policy.model_dump(mode="json"),
        "public_setup": review.setup.model_dump(mode="json"),
        "task": review.task.model_dump(mode="json"),
        "checked_at": review.checked_at,
        "local_time": datetime.fromtimestamp(review.checked_at).astimezone().isoformat(),
        "boundaries": list(_BOUNDARIES),
    }
    print(json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False))


def _check_signer(review: OfflineApprovalReview, arguments: argparse.Namespace) -> None:
    record = next((key for key in review.setup.keys if key.role == arguments.role), None)
    if record is None or (record.subject_id, record.key_id, record.principal_id) != (
        arguments.subject_id, arguments.key_id, arguments.principal_id,
    ):
        raise OfflineApprovalError(
            "COAUTH_OFFLINE_SIGNER_MISMATCH",
            "operator does not match the pinned approval role",
        )


def _recheck_time(review: OfflineApprovalReview, minimum_time: int) -> int:
    observed_at = now_unix()
    if type(observed_at) is int and observed_at < minimum_time:
        raise _CliError("COAUTH_CLI_CLOCKBACK")
    review_approval_task(
        review.raw_challenge, review.raw_public_setup,
        trusted_setup_sha256=review.trusted_setup_sha256,
        expected_task_id=review.expected_task_id,
        expected_approval_payload_hash=review.expected_approval_payload_hash,
        now=observed_at,
    )
    return observed_at


def _run(arguments: argparse.Namespace) -> None:
    inputs = [Path(arguments.task_file), Path(arguments.trusted_public_file)]
    output = None
    private_key_file = None
    if arguments.command == "sign":
        if arguments.confirm_task_approval is not True:
            raise _CliError("COAUTH_CLI_ARGUMENTS_INVALID")
        private_key_file = Path(arguments.private_key_file)
        inputs.append(private_key_file)
    elif arguments.command == "assemble":
        inputs.extend((
            Path(arguments.enterprise_approval_file), Path(arguments.finance_approval_file),
        ))
    if arguments.command != "review":
        output = _preflight_output(
            arguments.output, inputs, private_key_file=private_key_file,
        )
    raw_task = _read_public_file(arguments.task_file)
    raw_setup = _read_public_file(arguments.trusted_public_file)
    review = review_approval_task(
        raw_task, raw_setup,
        trusted_setup_sha256=arguments.trusted_public_sha256,
        expected_task_id=arguments.expected_task_id,
        expected_approval_payload_hash=arguments.expected_approval_payload_hash,
        now=now_unix(),
    )
    if arguments.command == "review":
        _print_review(review, arguments.trusted_public_sha256)
        return
    if arguments.command == "sign":
        _check_signer(review, arguments)
        private_key = _read_private_key(arguments.private_key_file)
        try:
            operation_time = now_unix()
            evidence = sign_approval(
                review, role=arguments.role,
                expected_subject_id=arguments.subject_id,
                expected_key_id=arguments.key_id,
                expected_principal_id=arguments.principal_id,
                private_key_hex=private_key, now=operation_time,
            )
        finally:
            # Release this reference; Python does not guarantee zeroization.
            del private_key
        raw_output = canonicalize(evidence.model_dump(mode="json"))
    else:
        raw_enterprise = _read_public_file(arguments.enterprise_approval_file)
        raw_finance = _read_public_file(arguments.finance_approval_file)
        operation_time = now_unix()
        raw_output = assemble_bundle(
            review, raw_enterprise, raw_finance, now=operation_time,
        )
    before_write_time = _recheck_time(review, operation_time)
    _write_public_file(output, raw_output, inputs, private_key_file=private_key_file)
    try:
        _recheck_time(review, before_write_time)
    except _CliError as error:
        code = (
            "COAUTH_CLI_OUTPUT_CLOCKBACK" if error.code == "COAUTH_CLI_CLOCKBACK"
            else "COAUTH_CLI_OUTPUT_NOT_CURRENT"
        )
        raise _CliError(code) from None
    except Exception:
        raise _CliError("COAUTH_CLI_OUTPUT_NOT_CURRENT") from None
    marker = (
        "COAUTHORIZATION_APPROVAL_WRITTEN" if arguments.command == "sign"
        else "COAUTHORIZATION_BUNDLE_WRITTEN"
    )
    explanation = (
        "\u53ea\u751f\u6210\u5ba1\u6279\u58f0\u660e\uff0c\u672a\u7b7e\u53d1\u6839\u6388"
        "\u6743\u3002"
        if arguments.command == "sign" else
        "\u53ea\u751f\u6210\u53cc\u7b7e\u8bc1\u636e\uff0c\u672a\u7b7e\u53d1\u6839\u6388"
        "\u6743\u3002"
    )
    print(f"{marker}; LOCAL_SNAPSHOT_VERIFICATION_ONLY; {explanation}")


def _report_error(code: str) -> None:
    if type(code) is not str or (
        code not in _ERROR_MESSAGES and code not in _OFFLINE_REASON_CODES
    ):
        code = "COAUTH_CLI_OFFLINE_REJECTED"
    message = _ERROR_MESSAGES.get(code, _ERROR_MESSAGES["COAUTH_CLI_OFFLINE_REJECTED"])
    _emit_error(code, message)


def main(argv: list[str] | None = None) -> int:
    try:
        try:
            arguments = build_parser().parse_args(argv)
        except SystemExit as error:
            return 0 if error.code == 0 else 2
        _run(arguments)
    except KeyboardInterrupt:
        _report_error("COAUTH_CLI_CANCELLED")
        return 130
    except _CliError as error:
        _report_error(error.code)
        return 2
    except OfflineApprovalError as error:
        # Never interpolate exception text or an untrusted reason_code.
        _report_error(error.reason_code)
        return 1
    except Exception:
        _report_error("COAUTH_CLI_LOCAL_FAILURE")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
