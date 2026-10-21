from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

import backend.ui_api.security_ledger as module
from scripts.verify_business_workspace import public_only


def fixture(root: Path, monkeypatch: pytest.MonkeyPatch):
    digest = "a" * 64
    monkeypatch.setattr(module, "snapshot", lambda _root: {"snapshot_sha256": digest})
    artifacts = root / "artifacts"
    directory = artifacts / "security"
    directory.mkdir(parents=True)
    record = {
        "scenario_id": "wrong_customer",
        "test_ref": "tests::case[wrong_customer]",
        "nodeid": "tests::case[wrong_customer]",
        "status": "PASS",
        "run_id": "batch-01",
        "source_snapshot_sha256": digest,
        "before": {"counts": {"refunds": 0}, "budget": [], "receipts": []},
        "after": {
            "counts": {"refunds": 0},
            "budget": [],
            "receipts": [
                {"signed_receipt": {"signature": {"value": "never-public"}}},
            ],
        },
        "observations": [
            {
                "kind": "gateway_deny",
                "status_code": 403,
                "body": {
                    "decision": "DENY",
                    "reason_code": "RESOURCE_NOT_ALLOWED",
                    "receipt": {"signature": {"value": "never-public"}},
                },
            }
        ],
        "assertions": [
            {
                "name": "actual denial",
                "result": "PASS",
                "expected": True,
                "observed": {"holder_proof": {"signature": {"value": "never-public"}}},
            }
        ],
    }
    ledger = directory / "batch.jsonl"
    ledger.write_text(json.dumps(record) + "\n", encoding="utf-8")
    summary = {
        "status": "VERIFIED",
        "run_id": "batch-01",
        "verified_at": "2026-10-08T15:00:00Z",
        "source_snapshot_sha256": digest,
        "ledger_path": str(ledger),
        "ledger_sha256": hashlib.sha256(ledger.read_bytes()).hexdigest(),
        "records": [{"scenario_id": "forged-summary", "status": "PASS"}],
    }
    path = directory / "current-ledger-summary.json"
    path.write_text(json.dumps(summary), encoding="utf-8")
    definitions = [{"id": "wrong_customer", "test_ref": record["test_ref"]}]
    return artifacts, path, ledger, summary, definitions


def test_ledger_projection_uses_digest_bound_jsonl_not_unbound_summary_records(
    tmp_path, monkeypatch
):
    artifacts, _path, _ledger, _summary, definitions = fixture(tmp_path, monkeypatch)
    value = module.current_ledger(tmp_path, artifacts, definitions)
    assert value["status"] == "VERIFIED"
    assert value["scope"] == "isolated_test_batch_not_current_task"
    assert value["records"][0]["scenario_id"] == "wrong_customer"
    assert value["records"][0]["after"]["counts"]["refunds"] == 0
    assert "receipts" not in value["records"][0]["after"]
    assert value["records"][0]["observations"][0]["body"]["reason_code"] == "RESOURCE_NOT_ALLOWED"
    public_only(value)
    assert "never-public" not in json.dumps(value)


@pytest.mark.parametrize("changed", ["source", "digest", "run", "path", "status", "mapping"])
def test_unverified_or_stale_ledgers_never_supply_pass_rows(tmp_path, monkeypatch, changed):
    artifacts, path, ledger, summary, definitions = fixture(tmp_path, monkeypatch)
    if changed == "source":
        summary["source_snapshot_sha256"] = "b" * 64
    elif changed == "digest":
        ledger.write_text(ledger.read_text("utf-8") + "{}\n", encoding="utf-8")
    elif changed == "run":
        summary["run_id"] = "another-batch"
    elif changed == "path":
        summary["ledger_path"] = "../outside.jsonl"
    elif changed == "status":
        summary["status"] = "FAIL"
    else:
        definitions = deepcopy(definitions)
        definitions[0]["test_ref"] = "tests::a-different-case"
    path.write_text(json.dumps(summary), encoding="utf-8")
    value = module.current_ledger(tmp_path, artifacts, definitions)
    assert value["status"] in {"SOURCE_CHANGED", "INVALID_EVIDENCE"}
    assert value["records"] == []


def test_unpublished_ledger_is_explicitly_not_published(tmp_path):
    assert module.current_ledger(tmp_path, tmp_path / "artifacts", []) == {
        "status": "NOT_PUBLISHED",
        "records": [],
    }


def test_public_request_has_thirteen_fields_without_reusable_signatures():
    body = {
        "schema_version": "1.0",
        "task_id": "task-01",
        "tool_service": "refund-service",
        "tool_name": "refund.create",
        "tool_version": "1.0",
        "canonical_parameters": {"customer_id": "outside", "amount_fen": 7000},
        "request_id": "request-01",
        "issued_at": "2026-10-08T15:00:00Z",
        "holder_key_id": "agent-refund-key-01",
        "business_action_id": "action-01",
        "credential_chain": [{"signature": {"value": "never-public"}}],
        "holder_proof": {"signature": {"value": "never-public"}},
    }
    value = module.public_record(
        {
            "requests": [
                {
                    "call_id": "HTTP-0001",
                    "phase": "attack",
                    "url": "http://127.0.0.1:28003/gateway/dispatch",
                    "request": {"json": body},
                }
            ]
        }
    )
    request = value["requests"][0]["request"]
    assert len(request) == 13
    assert request["canonical_parameters"]["customer_id"] == "outside"
    assert all(
        len(request[key]) == 64
        for key in ("request_hash", "credential_chain_hash", "parameter_hash")
    )
    public_only(value)
    assert "never-public" not in json.dumps(value)


def test_parse_rejection_request_is_not_a_fabricated_context():
    value = module.public_record(
        {
            "requests": [
                {
                    "call_id": "HTTP-0001",
                    "phase": "attack",
                    "url": "http://127.0.0.1:28003/gateway/admit",
                    "request": {
                        "json": {"status": "N/A", "reason": "duplicate keys"},
                        "raw_request_hash": "a" * 64,
                        "raw_hex": "never-public",
                    },
                }
            ]
        }
    )
    assert value["requests"][0]["request"]["status"] == "N/A"
    assert value["requests"][0]["request"]["raw_request_hash"] == "a" * 64
    assert "request_id" not in value["requests"][0]["request"]
    assert "never-public" not in json.dumps(value)
