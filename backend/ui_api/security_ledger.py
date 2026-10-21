"""Read verified test-batch evidence without exposing reusable signed packets."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from backend.crypto.canonical_json import CanonicalizationError, canonicalize
from backend.crypto.sm import sm3_hex
from scripts.native_web import is_link
from scripts.source_manifest import snapshot


def current_ledger(
    root: Path, artifact_root: Path, scenarios: list[dict[str, Any]]
) -> dict[str, Any]:
    path = artifact_root / "security" / "current-ledger-summary.json"
    unavailable: dict[str, Any] = {"status": "NOT_PUBLISHED", "records": []}
    if not path.is_file():
        return unavailable
    try:
        if any(is_link(item) for item in (artifact_root, path.parent, path)):
            raise ValueError("linked ledger evidence is not accepted")
        summary = json.loads(path.read_text(encoding="utf-8"))
        if summary["status"] != "VERIFIED":
            raise ValueError("ledger has not passed its independent verifier")
        if summary["source_snapshot_sha256"] != snapshot(root)["snapshot_sha256"]:
            return {"status": "SOURCE_CHANGED", "records": []}
        ledger = Path(summary["ledger_path"])
        if not ledger.is_absolute():
            ledger = root / ledger
        if not ledger.resolve().is_relative_to(root.resolve()) or not ledger.is_file():
            raise ValueError("ledger file is missing or outside the project")
        if any(is_link(item) for item in (ledger, *ledger.parents)):
            raise ValueError("ledger file cannot be a link")
        with ledger.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != summary["ledger_sha256"]:
            raise ValueError("ledger differs from the independently verified batch")
        if ledger.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("ledger exceeds the read-only projection limit")
        records = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
        definitions = {item["id"]: item for item in scenarios}
        observed = {item["scenario_id"]: item for item in records}
        if len(records) != len(definitions) or set(observed) != set(definitions):
            raise ValueError("ledger does not cover the exact scenario matrix")
        if any(
            item["status"] != "PASS"
            or item["test_ref"] != definitions[identifier]["test_ref"]
            or item["nodeid"] != item["test_ref"]
            or item["run_id"] != summary["run_id"]
            or item["source_snapshot_sha256"] != summary["source_snapshot_sha256"]
            for identifier, item in observed.items()
        ):
            raise ValueError("ledger result is not bound to its unique test")
        return {
            "status": "VERIFIED",
            "scope": "isolated_test_batch_not_current_task",
            "run_id": summary["run_id"],
            "verified_at": summary["verified_at"],
            "source_snapshot_sha256": summary["source_snapshot_sha256"],
            "ledger_sha256": digest,
            "records": [public_record(item) for item in records],
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {"status": "INVALID_EVIDENCE", "records": []}


def public_record(record: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "scenario_id",
        "nodeid",
        "test_ref",
        "status",
        "run_id",
        "started_at",
        "finished_at",
        "source_snapshot_sha256",
        "execution_layer",
        "evidence_scope",
        "expected_effect_delta",
        "execution_ids",
        "receipt_ids",
    )
    result = {key: record[key] for key in allowed if key in record}
    for name in ("before", "after"):
        state = record.get(name, {})
        result[name] = {
            key: state[key]
            for key in (
                "scope",
                "budget",
                "counts",
                "global_counts",
                "status",
                "reason",
            )
            if key in state
        }
    result["assertions"] = [
        {key: item[key] for key in ("name", "result", "expected", "observed") if key in item}
        for item in record.get("assertions", [])
    ]
    result["observations"] = []
    for item in record.get("observations", []):
        value = {
            key: item[key] for key in ("kind", "label", "status_code", "call_id") if key in item
        }
        body = item.get("body", {})
        if isinstance(body, dict):
            value["body"] = {
                key: body[key]
                for key in (
                    "decision",
                    "state",
                    "reason_code",
                    "execution_id",
                    "admission_outcome",
                )
                if key in body
            }
            if isinstance(body.get("detail"), dict):
                value["body"]["reason_code"] = body["detail"].get("reason_code")
        result["observations"].append(value)
    result["requests"] = []
    fields = (
        "schema_version",
        "task_id",
        "tool_service",
        "tool_name",
        "tool_version",
        "canonical_parameters",
        "request_id",
        "issued_at",
        "holder_key_id",
        "business_action_id",
    )
    for call in record.get("requests", []):
        if call.get("phase") == "setup" or "/gateway/" not in call.get("url", ""):
            continue
        captured = call.get("request", {})
        body = captured.get("json")
        value = {key: call[key] for key in ("call_id", "phase") if key in call}
        context = {
            "status": "N/A",
            "reason": "request does not establish a canonical tool RequestContext",
            "raw_request_hash": captured.get("raw_request_hash"),
        }
        if isinstance(body, dict) and all(key in body for key in fields):
            chain = body.get("credential_chain")
            if isinstance(chain, list):
                try:
                    context = {key: body[key] for key in fields} | {
                        "request_hash": sm3_hex(canonicalize(body)),
                        "credential_chain_hash": sm3_hex(canonicalize(chain)),
                        "parameter_hash": sm3_hex(canonicalize(body["canonical_parameters"])),
                    }
                except CanonicalizationError:
                    pass
        value["request"] = context
        result["requests"].append(value)
    # Assertions are observations too; recursively omit authority material from their values.
    return remove_authority_material(result)


def remove_authority_material(value: Any) -> Any:
    if isinstance(value, list):
        return [remove_authority_material(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {
        key: remove_authority_material(item)
        for key, item in value.items()
        if key not in {"credential_chain", "holder_proof", "signed_receipt", "signature", "raw_hex"}
        and not any(
            word in key.lower() for word in ("private_key", "password", "api_key", "launch_token")
        )
    }
