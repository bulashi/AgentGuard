"""Explicit read-only export or file-only verification of signed authorization evidence."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path, PureWindowsPath

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = PROJECT_ROOT / "artifacts" / "coauthorization"
REPARSE_POINT = 0x400


class CliError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__("evidence operation refused")
        self.reason_code = code


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliError("COAUTH_EVIDENCE_ARGUMENTS_INVALID")


def build_parser() -> argparse.ArgumentParser:
    parser = SafeParser(
        allow_abbrev=False,
        description="\u53ea\u8bfb\u5bfc\u51fa\u6216\u79bb\u7ebf\u6838\u9a8c\u5171\u540c\u6388\u6743\u8bc1\u636e\u3002",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "export"):
        child = commands.add_parser(name, allow_abbrev=False)
        child.add_argument("--trust-context", required=True)
        child.add_argument("--trusted-context-sha256", required=True)
        child.add_argument("--checkpoint", required=True)
        child.add_argument("--trusted-checkpoint-sha256", required=True)
        child.add_argument("--expected-task-id", required=True)
        child.add_argument("--expected-root-credential-id", required=True)
        child.add_argument("--expected-approval-payload-hash", required=True)
        child.add_argument("--expected-revocation-event-id", type=int)
        child.add_argument("--expected-source-kind", choices=(
            "APPROVAL_KEY_REVOKED", "APPROVAL_KEY_COMPROMISED", "APPROVAL_POLICY_REVOKED", "AUTHORIZATION_WITHDRAWN",
        ))
        child.add_argument("--expected-source-identifier")
        if name == "verify":
            child.add_argument("--package", required=True)
        else:
            child.add_argument("--output", required=True)
            child.add_argument("--confirm-read-only-export", action="store_true", required=True)
    return parser


def _check_path(path: Path) -> None:
    if path.drive.startswith("\\\\") or any(
        PureWindowsPath(component).is_reserved()
        for component in path.parts if component != path.anchor
    ):
        raise CliError("COAUTH_EVIDENCE_FILE_INVALID")
    for component in (path, *path.parents):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT:
            raise CliError("COAUTH_EVIDENCE_FILE_INVALID")


def _read_json_file(value: str, limit: int) -> bytes:
    path = Path(os.path.abspath(value))
    if path.suffix.lower() != ".json" or ":" in str(path)[len(path.drive):]:
        raise CliError("COAUTH_EVIDENCE_FILE_INVALID")
    _check_path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
        raise CliError("COAUTH_EVIDENCE_FILE_INVALID")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(metadata, opened):
            raise CliError("COAUTH_EVIDENCE_FILE_INVALID")
        raw = stream.read(limit + 1)
        finished = os.fstat(stream.fileno())
        if not os.path.samestat(opened, finished) or (
            opened.st_size != finished.st_size or opened.st_mtime_ns != finished.st_mtime_ns
        ):
            raise CliError("COAUTH_EVIDENCE_FILE_INVALID")
    if not 0 < len(raw) <= limit:
        raise CliError("COAUTH_EVIDENCE_FILE_INVALID")
    return raw


def _output_path(value: str) -> Path:
    path = Path(os.path.abspath(value))
    if (
        path.suffix.lower() != ".json" or ":" in str(path)[len(path.drive):]
        or not path.is_relative_to(OUTPUT_ROOT) or path == OUTPUT_ROOT
    ):
        raise CliError("COAUTH_EVIDENCE_OUTPUT_UNSAFE")
    _check_path(path)
    if path.exists():
        raise CliError("COAUTH_EVIDENCE_OUTPUT_EXISTS")
    return path


def _write_new_package(value: str, raw: bytes) -> None:
    path = _output_path(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    _check_path(path)
    try:
        with path.open("xb") as stream:
            if stream.write(raw) != len(raw):
                raise CliError("COAUTH_EVIDENCE_LOCAL_FAILURE")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise CliError("COAUTH_EVIDENCE_OUTPUT_EXISTS") from None


def main(argv: list[str] | None = None) -> int:
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from backend.coauthorization.evidence_verifier import (
            MAX_CHECKPOINT_BYTES, MAX_PACKAGE_BYTES, MAX_TRUST_BYTES,
            EvidenceVerificationError, verify_evidence_package,
        )
        from backend.common.time import now_unix
    except Exception:
        _error("COAUTH_EVIDENCE_STARTUP_FAILURE")
        return 2
    try:
        args = build_parser().parse_args(argv)
        revocation_values = (args.expected_revocation_event_id, args.expected_source_kind, args.expected_source_identifier)
        if any(value is not None for value in revocation_values) and not all(value is not None for value in revocation_values):
            raise CliError("COAUTH_EVIDENCE_ARGUMENTS_INVALID")
        inputs = {
            "raw_trust_context": _read_json_file(args.trust_context, MAX_TRUST_BYTES),
            "trusted_context_sha256": args.trusted_context_sha256,
            "raw_checkpoint": _read_json_file(args.checkpoint, MAX_CHECKPOINT_BYTES),
            "trusted_checkpoint_sha256": args.trusted_checkpoint_sha256,
            "expected_task_id": args.expected_task_id,
            "expected_root_credential_id": args.expected_root_credential_id,
            "expected_approval_payload_hash": args.expected_approval_payload_hash,
            "observed_at": now_unix(),
        }
        verify_operation = verify_evidence_package
        if args.expected_revocation_event_id is not None:
            from backend.coauthorization.revocation_evidence import verify_revocation_evidence_package

            verify_operation = verify_revocation_evidence_package
            inputs.update({
                "expected_revocation_event_id": args.expected_revocation_event_id,
                "expected_source_kind": args.expected_source_kind,
                "expected_source_identifier": args.expected_source_identifier,
            })
        if args.command == "verify":
            result = verify_operation(_read_json_file(args.package, MAX_PACKAGE_BYTES), **inputs)
        else:
            _output_path(args.output)
            from backend.coauthorization.evidence_export import export_evidence_package

            export_operation = export_evidence_package
            if args.expected_revocation_event_id is not None:
                from backend.coauthorization.revocation_evidence import export_revocation_evidence_package

                export_operation = export_revocation_evidence_package

            database_url = os.environ.get("AGENTGUARD_EVIDENCE_READ_DATABASE_URL")
            if not database_url:
                raise CliError("COAUTH_EVIDENCE_EXPORT_CONFIGURATION_MISSING")
            raw_package, result = export_operation(database_url, **inputs)
            _write_new_package(args.output, raw_package)
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 0
    except (CliError, EvidenceVerificationError) as exc:
        _error(exc.reason_code)
    except KeyboardInterrupt:
        _error("COAUTH_EVIDENCE_CANCELLED")
    except Exception:
        _error("COAUTH_EVIDENCE_LOCAL_FAILURE")
    return 2


def _error(code: str) -> None:
    # Never emit submitted files, raw signatures, paths, DSNs or exception details.
    try:
        print(json.dumps({"verified": False, "reason_code": code}, ensure_ascii=True), file=sys.stderr)
    except (OSError, UnicodeError):
        pass


if __name__ == "__main__":
    raise SystemExit(main())
