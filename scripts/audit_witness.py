"""Offline custody and verification of caller-pinned public audit prefixes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ArgumentsError(ValueError):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ArgumentsError("audit witness arguments invalid")


def build_parser() -> argparse.ArgumentParser:
    parser = SafeParser(allow_abbrev=False, description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "advance", "verify"):
        child = commands.add_parser(command, allow_abbrev=False)
        child.add_argument("--trust-context", required=True)
        child.add_argument("--trusted-context-sm3", required=True)
        child.add_argument("--checkpoint", required=True)
        child.add_argument("--trusted-checkpoint-sm3", required=True)
        child.add_argument("--expected-stream-id", required=True)
        child.add_argument("--snapshot", required=True)
        child.add_argument("--store", required=True)
        child.add_argument("--output")
        if command != "init":
            child.add_argument("--trusted-witness-sequence", type=int, required=True)
            child.add_argument("--trusted-witness-sm3", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from backend.audit import witness
    except Exception:
        print(json.dumps(_startup_failure(), ensure_ascii=True, separators=(",", ":")))
        return 2

    operation = None
    mutation_attempted = False
    result = None
    try:
        args = build_parser().parse_args(argv)
        operation = args.command
        store_path = witness.local_path(args.store)
        output = witness.new_json_path(args.output) if args.output else None
        if output is not None and output.is_relative_to(store_path):
            raise witness.WitnessError("AUDIT_WITNESS_OUTPUT_UNSAFE")
        evidence = witness.verify_snapshot(
            witness.read_json_file(args.snapshot, witness.MAX_SNAPSHOT_BYTES),
            raw_trust_context=witness.read_json_file(args.trust_context, witness.MAX_CONTEXT_BYTES),
            trusted_context_sm3=args.trusted_context_sm3,
            raw_checkpoint=witness.read_json_file(args.checkpoint, witness.MAX_CHECKPOINT_BYTES),
            trusted_checkpoint_sm3=args.trusted_checkpoint_sm3,
            expected_stream_id=args.expected_stream_id,
        )
        if operation == "verify":
            entries = witness.read_witness_store(
                store_path, evidence, trusted_witness_sequence=args.trusted_witness_sequence,
                trusted_witness_sm3=args.trusted_witness_sm3,
            )
            witness.verify_against_witness(evidence, entries)
            entry, modified, checked = entries[-1], False, len(entries)
        else:
            from backend.common.time import now_unix

            mutation_attempted = True
            if operation == "init":
                entry = witness.initialize_witness_store(
                    store_path, evidence, observed_at=now_unix(),
                )
                modified, checked = True, 0
            else:
                entry, modified = witness.advance_witness_store(
                    store_path, evidence, trusted_witness_sequence=args.trusted_witness_sequence,
                    trusted_witness_sm3=args.trusted_witness_sm3, observed_at=now_unix(),
                )
                checked = args.trusted_witness_sequence
        result = witness.make_result(
            operation, evidence, entry, store_modified=modified, checked_witness_entries=checked,
        )
        if output is not None:
            report = result | {"report_file_written": True}
            try:
                witness.write_new_json(output, witness.canonicalize(report))
            except (OSError, witness.WitnessError):
                result.update(success=False, reason_code="AUDIT_WITNESS_REPORT_WRITE_FAILED")
            else:
                result = report
    except ArgumentsError:
        result = witness.failure_result(operation, "AUDIT_WITNESS_ARGUMENTS_INVALID")
    except witness.WitnessError as exc:
        result = witness.failure_result(operation, exc.reason_code)
        if mutation_attempted and exc.reason_code in {
            "AUDIT_WITNESS_FILE_EXISTS", "AUDIT_WITNESS_FILE_INVALID", "AUDIT_WITNESS_FILE_UNSAFE",
        }:
            # An init file conflict may follow successful directory creation.
            result["store_modified"] = None
    except (OSError, ValueError, TypeError, KeyboardInterrupt):
        result = witness.failure_result(operation, "AUDIT_WITNESS_LOCAL_FAILURE")
        result["store_modified"] = None if mutation_attempted else False
    except Exception:
        result = witness.failure_result(operation, "AUDIT_WITNESS_LOCAL_FAILURE")
        result["store_modified"] = None if mutation_attempted else False
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0 if result["success"] else 2


def _startup_failure() -> dict:
    # Keep a public result available even if the verification dependencies cannot import.
    return {
        "schema_version": "1.0", "record_type": "AUDIT_WITNESS_RESULT_V1",
        "operation": None, "success": False, "verified": False,
        "reason_code": "AUDIT_WITNESS_STARTUP_FAILURE", "store_modified": False,
        "report_file_written": False,
        "verification_scope": "CALLER_PINNED_CHECKPOINT_FULL_PREFIX_LOCAL_WITNESS",
        "checkpoint_domain": "AGENTGUARD|AUDIT_CHECKPOINT|V1",
        "event_hash_domain": "AGENTGUARD|AUDIT_EVENT_HASH|V1",
        "sm2_user_id": "1234567812345678",
        "signature_encoding": "SM2_RS_HEX_128_LOWERCASE",
        "authorizes_execution": False, "proves_latest_source_state": False,
        "proves_independent_custody": False, "proves_uncompromised_signer": False,
        "proves_signed_stream_identity": False, "proves_event_payloads": False,
        "proves_trusted_wall_clock": False,
    }


if __name__ == "__main__":
    raise SystemExit(main())
