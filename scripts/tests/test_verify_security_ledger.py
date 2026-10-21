from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import httpx
import psycopg
import pytest

from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.tests.security import ledger_support as support
from scripts import verify_security_ledger as verifier

SCENARIOS = support.read_matrix()
SOURCE_HASH = "a" * 64
RUN_ID = "contract-only-not-an-integration-run"


@pytest.fixture(autouse=True)
def no_live_services(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("contract tests must not contact PostgreSQL or HTTP services")

    monkeypatch.setattr(psycopg, "connect", forbidden)
    monkeypatch.setattr(httpx.Client, "send", forbidden)
    monkeypatch.delenv("AGENTGUARD_SECURITY_LEDGER_RUN_ID", raising=False)
    monkeypatch.delenv("AGENTGUARD_RUN_ID", raising=False)
    monkeypatch.delenv("AGENTGUARD_SOURCE_SNAPSHOT_SHA256", raising=False)


def snapshot() -> dict[str, Any]:
    # Deliberately synthetic contract data, never runtime evidence or a published ledger.
    scope = {
        "kind": "scenario_tasks_and_credential_chains",
        "task_ids": ["TASK-contract"],
        "credential_chains": [["ROOT-contract", "CASE-contract", "LEAF-contract"]],
        "raw_request_hashes": [],
    }
    result: dict[str, Any] = {
        "scope": scope,
        "budget": [],
        "database_probe": {
            "database_name": "agentguard_test_backend_aabbcc",
            "driver": "psycopg",
            "backend_pid": 123,
            "server_version": "contract-fixture",
            "observed_at": 1,
        },
    }
    for credential_id in scope["credential_chains"][0]:
        for quota in ("max_tool_calls", "refund_total_fen"):
            result["budget"].append(
                {
                    "credential_id": credential_id,
                    "quota_type": quota,
                    "limit": 10 if quota == "max_tool_calls" else 10_000,
                    "reserved": 0,
                    "committed": 0,
                    "version": 0,
                }
            )
    result["budget"].sort(key=lambda row: (row["credential_id"], row["quota_type"]))
    for table in verifier._TABLES:
        result[table] = []
    result["credentials"] = [
        {"credential_id": value, "task_id": "TASK-contract"}
        for value in scope["credential_chains"][0]
    ]
    result["counts"] = {table: len(result[table]) for table in verifier._TABLES}
    result["global_counts"] = {
        table: 0
        for table in (
            "refunds",
            "notifications",
            "executions",
            "requests",
            "receipts",
            "tool_attempts",
        )
    }
    result["audit_events"] = []
    result["revocations"] = []
    return result


def call(
    identifier: str,
    raw: bytes,
    response: dict[str, Any],
    *,
    status: int = 200,
    url: str = "http://127.0.0.1:28003/gateway/dispatch",
) -> dict[str, Any]:
    from backend.crypto.strict_json import StrictJsonError, parse_strict_json

    try:
        parsed = parse_strict_json(raw) if raw else None
    except StrictJsonError:
        parsed = support.not_applicable("no unambiguous RequestContext")
    return {
        "call_id": identifier,
        "phase": "attack_window",
        "method": "POST",
        "url": url,
        "transport": "httpx.HTTPTransport",
        "started_at": "2026-10-08T00:00:00+00:00",
        "finished_at": "2026-10-08T00:00:01+00:00",
        "started_monotonic_ns": 1,
        "finished_monotonic_ns": 2,
        "request": {"raw_hex": raw.hex(), "raw_request_hash": sm3_hex(raw), "json": parsed},
        "response": {"status_code": status, "json": response},
    }


def parse_record(identifier: str = "malformed_json") -> dict[str, Any]:
    raw = {
        "malformed_json": b'{"broken":',
        "invalid_utf8": b"\xff\xfe",
        "duplicate_json_key": b'{"x":1,"x":2}',
        "integer_overflow": b'{"amount_fen":9007199254740992}',
        "unknown_field": b'{"unexpected_security_field":"contract-fixture"}',
    }[identifier]
    raw_hash = sm3_hex(raw)
    before = snapshot()
    before["scope"]["raw_request_hashes"] = [raw_hash]
    after = deepcopy(before)
    payload = {
        "schema_version": "1.0",
        "event_id": "EVENT-RAW-contract",
        "raw_request_hash": raw_hash,
        "parser_stage": {
            "invalid_utf8": "UTF8",
            "duplicate_json_key": "DUPLICATE_KEY",
            "integer_overflow": "SCHEMA",
            "unknown_field": "SCHEMA",
        }.get(identifier, "JSON"),
        "reason_code": support.PARSE_REASONS[identifier],
        "source_context": {"transport": "HTTP", "source_label": "/gateway/dispatch"},
        "received_at": 1,
    }
    after["audit_events"] = [
        {
            "outbox_event_id": "OUTBOX-contract",
            "execution_id": None,
            "event_type": "RAW_REQUEST_REJECTED",
            "payload": payload,
            "payload_hash": sm3_hex(canonicalize(payload)),
            "status": "APPENDED",
            "event_sequence": 1,
            "event_hash": "b" * 64,
            "previous_event_hash": "0" * 64,
        }
    ]
    response = {"status": "rejected_at_parse", "reason_code": "REQUEST_SCHEMA_INVALID"}
    audit_response = {
        "valid": True,
        "rollback_detected": False,
        "latest_event_sequence": 1,
        "checked_events": 1,
        "first_invalid_sequence": None,
    }
    requests = [
        call("HTTP-0001", raw, response, status=400),
        call(
            "HTTP-0002",
            b'{"from_sequence":1,"include_independent_checkpoint":true}',
            audit_response,
            url="http://127.0.0.1:28007/audit/verify",
        ),
    ]
    files = {"contract-fixture.py": "c" * 64}
    return {
        "schema_version": support.LEDGER_SCHEMA,
        "run_id": RUN_ID,
        "scenario_id": identifier,
        "nodeid": support.test_ref(identifier),
        **support.scenario_contract(identifier),
        "source_snapshot_sha256": SOURCE_HASH,
        "source_snapshot": {
            "sha256": SOURCE_HASH,
            "reference": "contract fixture",
            "input_files": files,
            "input_files_sha256": hashlib.sha256(
                json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        },
        "source_inputs_unchanged": True,
        "status": "PASS",
        "started_at": "2026-10-08T00:00:00+00:00",
        "finished_at": "2026-10-08T00:00:02+00:00",
        "configuration": {
            "deployment": "native",
            "stub_used": False,
            "cloud_llm_enabled": False,
            "database": {
                "kind": "postgresql",
                "host": "127.0.0.1",
                "port": None,
                "name": "agentguard_test_backend_aabbcc",
            },
            "audit_database": {
                "kind": "postgresql",
                "host": "127.0.0.1",
                "port": None,
                "name": "agentguard_audit_test_backend_aabbcc",
            },
            "database_probe": before["database_probe"],
            "audit_database_probe": before["database_probe"]
            | {"database_name": "agentguard_audit_test_backend_aabbcc"},
        },
        "assertions": [
            {
                "name": "synthetic contract check",
                "result": "PASS",
                "observed": True,
                "expected": True,
            }
        ],
        "requests": requests,
        "observations": [
            {
                "kind": "parse_rejection",
                "label": identifier,
                "call_id": "HTTP-0001",
                "status_code": 400,
                "body": response,
            }
        ],
        "before": before,
        "after": after,
        "operation_windows": [
            {
                "name": "attack_window",
                "measurement": "primary",
                "before": deepcopy(before),
                "after": deepcopy(after),
            }
        ],
        "audit_verification": {
            "status": "VERIFIED",
            "call_id": "HTTP-0002",
            "checkpoint_scope": "local_isolated_audit_database",
            "response": requests[1]["response"],
        },
        "execution_ids": support.not_applicable("parse boundary"),
        "receipt_ids": support.not_applicable("parse boundary"),
    }


@pytest.mark.parametrize("identifier", support.PARSE_REASONS)
def test_parse_contract_matches_rejected_audit_semantics(identifier: str) -> None:
    record = parse_record(identifier)
    scenario = next(item for item in SCENARIOS if item["id"] == identifier)
    verifier.validate_record(record, scenario)
    public = verifier.public_record(record)
    assert public["before"]["counts"]["refunds"] == public["after"]["counts"]["refunds"] == 0
    assert public["before"]["budgets"] == record["before"]["budget"]
    assert public["audit_events"][0]["reason_code"] == support.PARSE_REASONS[identifier]
    verifier.assert_public_projection(public)


def test_exact_matrix_and_real_collectable_nodeids() -> None:
    nodeids = verifier.collect_nodeids()
    assert len(nodeids) == len(set(nodeids)) == 36
    assert set(nodeids) == {scenario["test_ref"] for scenario in SCENARIOS}
    overflow = next(item for item in SCENARIOS if item["id"] == "integer_overflow")
    assert overflow["expected_decision"] == "REJECT_AT_PARSE"


@pytest.mark.parametrize("text", ['{"x":1,"x":2}\n', '{"x":NaN}\n', "[]\n", "\n"])
def test_jsonl_rejects_ambiguous_nonrecord_or_nonjson(text: str, tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        verifier.read_jsonl(path)


@pytest.mark.parametrize(
    "kind",
    [
        "FAIL",
        "NOT_RUN",
        "stub",
        "missing_quota",
        "uppercase_quota",
        "over_budget",
        "count_lie",
        "global_effect",
        "fake_raw_context",
        "fake_receipt",
        "fake_transport",
        "missing_assertion",
        "source_changed",
        "unbound_raw_hash",
        "unauthorized_snapshot",
    ],
)
def test_record_rejects_missing_degraded_or_fabricated_evidence(kind: str) -> None:
    record = parse_record()
    if kind in {"FAIL", "NOT_RUN"}:
        record["status"] = kind
    elif kind == "stub":
        record["configuration"]["stub_used"] = True
    elif kind == "missing_quota":
        record["before"]["budget"].pop()
    elif kind == "uppercase_quota":
        record["before"]["budget"][0]["quota_type"] = "MAX_TOOL_CALLS"
    elif kind == "over_budget":
        record["before"]["budget"][0]["reserved"] = 11
    elif kind == "count_lie":
        record["after"]["counts"]["refunds"] = 1
    elif kind == "global_effect":
        record["after"]["global_counts"]["refunds"] = 1
    elif kind == "fake_raw_context":
        record["requests"][0]["request"]["json"] = {"task_id": "TASK-guessed"}
    elif kind == "fake_receipt":
        record["observations"][0]["body"]["receipt"] = {"payload": {"decision": "DENY"}}
    elif kind == "fake_transport":
        record["requests"][0]["transport"] = "httpx.MockTransport"
    elif kind == "missing_assertion":
        record["assertions"] = []
    elif kind == "source_changed":
        record["source_inputs_unchanged"] = False
    elif kind == "unbound_raw_hash":
        record["requests"][0]["request"]["raw_request_hash"] = "d" * 64
    else:
        record["configuration"]["database"]["name"] = "agentguard_main"
    with pytest.raises(ValueError):
        verifier.validate_record(record, SCENARIOS[0])


@pytest.mark.parametrize(
    "value",
    [
        {"Authorization": "example"},
        {"private_key_hex": "example"},
        {"nested": [{"password": "example"}]},
        {"note": "Bearer an-internal-secret"},
        {"note": "postgresql://operator:password@127.0.0.1/example"},
    ],
)
def test_sensitive_server_ledger_fields_are_rejected(value: Any) -> None:
    with pytest.raises(ValueError):
        verifier._no_secrets(value)


def test_failure_record_persists_with_secret_redaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_SOURCE_SNAPSHOT_SHA256", SOURCE_HASH)
    ledger = support.ScenarioLedger(
        SCENARIOS[0], SCENARIOS[0]["test_ref"], RUN_ID, tmp_path / "ledger.jsonl"
    )
    ledger.secrets = ("private-example", b"private-example".hex())
    ledger.record["diagnostic"] = {
        "headers": {"Authorization": "Bearer internal"},
        "nested": {"private_key_hex": "private-example"},
        "text": "private-example",
        "dsn": "postgresql://operator:password@localhost/example",
    }
    ledger.finish("FAIL", AssertionError("private-example"))
    ledger.persist()
    saved = verifier.read_jsonl(ledger.path)[0]
    assert saved["status"] == "FAIL"
    assert "private-example" not in ledger.path.read_text(encoding="utf-8")
    assert "headers" not in saved["diagnostic"] and saved["diagnostic"]["nested"] == {}
    assert saved["failure"]["message"] == "[REDACTED]"


def test_not_run_records_are_not_copied_passes(tmp_path: Path) -> None:
    path = tmp_path / "unexecuted.jsonl"
    support.write_not_run(SCENARIOS, path, RUN_ID, "inactive isolated test environment")
    rows = verifier.read_jsonl(path)
    assert len(rows) == 36 and len({row["nodeid"] for row in rows}) == 36
    assert all(row["status"] == "NOT_RUN" and not row["requests"] for row in rows)


def test_illegal_allow_receipt_cannot_substitute_for_signed_deny() -> None:
    response = {
        "decision": "DENY",
        "reason_code": "IDEMPOTENCY_CONFLICT",
        "state": "COMMITTED",
        "execution_id": "EXEC-legal",
        "receipt": {"payload": {"decision": "ALLOW"}},
    }
    observation = {
        "kind": "gateway_deny",
        "call_id": "HTTP-attack",
        "status_code": 409,
        "body": response,
    }
    record = {"observations": [observation]}
    calls = {"HTTP-attack": {"response": {"status_code": 409, "json": response}}}
    with pytest.raises(ValueError, match="terminal DENY"):
        verifier._deny_observations(record, calls, {}, ["IDEMPOTENCY_CONFLICT"])


def signed_denial_snapshot() -> dict[str, Any]:
    from backend.common.enums import KeyPurpose
    from backend.crypto.domains import EXECUTION_RECEIPT
    from backend.crypto.sm import generate_keypair, sign_payload, signed_object_hash

    pair = generate_keypair()
    payload = {
        "schema_version": "1.0",
        "receipt_id": "RECEIPT-contract",
        "receipt_type": "AUTHORIZATION_DENIAL",
        "execution_id": "EXEC-contract",
        "request_id": "REQUEST-contract",
        "request_hash": "a" * 64,
        "credential_chain_hash": "b" * 64,
        "tenant_id": "tenant-A",
        "task_id": "TASK-contract",
        "tool_service": "refund-service",
        "tool_name": "refund.create",
        "tool_version": "v1",
        "parameter_hash": "c" * 64,
        "decision": "DENY",
        "reason_code": "BUDGET_EXCEEDED",
        "business_action_id": "ACTION-contract",
        "business_idempotency_key": "d" * 64,
        "business_effect_id": None,
        "business_result_hash": None,
        "budget_reserved": 0,
        "budget_committed": 0,
        "started_at": 1,
        "finished_at": 2,
        "decision_at": 2,
        "business_effect_finalized_at": None,
        "receipt_issued_at": 3,
        "receipt_signing_key_id": "KEY-contract",
    }
    receipt = {
        "payload": payload,
        "signature": sign_payload(
            payload,
            domain_separator=EXECUTION_RECEIPT,
            key_id="KEY-contract",
            key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
            private_key_hex=pair.private_key_hex,
            public_key_hex=pair.public_key_hex,
            signed_at=3,
        ),
    }
    execution = {
        field: payload[field]
        for field in (
            "execution_id",
            "task_id",
            "tenant_id",
            "tool_service",
            "tool_name",
            "tool_version",
            "request_hash",
            "credential_chain_hash",
            "parameter_hash",
            "business_action_id",
            "business_effect_id",
            "business_result_hash",
            "decision",
            "decision_at",
        )
    }
    execution.update(
        {
            "state": "DENIED",
            "initial_request_id": payload["request_id"],
            "created_at": 1,
            "terminal_at": 2,
            "result": None,
        }
    )
    result = snapshot()
    result["executions"] = [execution]
    result["receipts"] = [
        {
            "receipt_id": payload["receipt_id"],
            "execution_id": payload["execution_id"],
            "decision": "DENY",
            "reason_code": payload["reason_code"],
            "signed_receipt": receipt,
            "receipt_hash": signed_object_hash(receipt),
            "purpose": KeyPurpose.EXECUTION_RECEIPT_SIGNING.value,
            "key_id": "KEY-contract",
            "public_key_hex": pair.public_key_hex,
        }
    ]
    return result


def test_receipt_contract_recomputes_real_sm2_signature_and_safe_projection() -> None:
    value = signed_denial_snapshot()
    verified = verifier._stored_receipts(value)
    assert len(verified) == 1
    public = verifier._public_receipt(value["receipts"][0]["signed_receipt"])
    assert public["payload"]["decision"] == "DENY"
    assert "value" not in public["signature"] and len(public["signature"]["fingerprint_sm3"]) == 64
    verifier.assert_public_projection(public)


@pytest.mark.parametrize(
    "kind", ["signature", "request_binding", "task_binding", "time_binding", "budget_binding"]
)
def test_real_signature_alone_cannot_replace_correct_durable_binding(kind: str) -> None:
    from backend.crypto.sm import signed_object_hash

    value = signed_denial_snapshot()
    execution = value["executions"][0]
    row = value["receipts"][0]
    if kind == "signature":
        signature = row["signed_receipt"]["signature"]
        signature["value"] = ("0" if signature["value"][0] != "0" else "1") + signature["value"][1:]
        row["receipt_hash"] = signed_object_hash(row["signed_receipt"])
    elif kind == "request_binding":
        execution["initial_request_id"] = "REQUEST-other"
    elif kind == "task_binding":
        execution["task_id"] = "TASK-other"
    elif kind == "time_binding":
        execution["terminal_at"] = 3
    else:
        value["reservations"] = [
            {"execution_id": "EXEC-contract", "amount": 1000, "status": "COMMITTED"}
        ]
    with pytest.raises(ValueError):
        verifier._stored_receipts(value)


@pytest.mark.parametrize("kind", ["wrong_amount", "wrong_calls", "unsettled"])
def test_every_credential_level_must_match_actual_settlement(kind: str) -> None:
    before = snapshot()
    after = deepcopy(before)
    for row in after["budget"]:
        row["committed"] = 1000 if row["quota_type"] == "refund_total_fen" else 1
    after["executions"] = [{"execution_id": "EXEC-contract", "state": "COMMITTED"}]
    after["refunds"] = [
        {"execution_id": "EXEC-contract", "amount_fen": 1000, "status": "COMMITTED"}
    ]
    record = {"before": before, "after": after}
    verifier._validate_settled_budget(record, amount=1000, count=1)
    if kind == "wrong_amount":
        next(row for row in after["budget"] if row["quota_type"] == "refund_total_fen")[
            "committed"
        ] = 999
    elif kind == "wrong_calls":
        next(row for row in after["budget"] if row["quota_type"] == "max_tool_calls")[
            "committed"
        ] = 0
    else:
        after["budget"][0]["reserved"] = 1
    with pytest.raises(ValueError):
        verifier._validate_settled_budget(record, amount=1000, count=1)


def test_legal_baseline_is_not_an_unauthorized_effect() -> None:
    before = snapshot()
    before["refunds"] = [{"refund_id": "REFUND-legal", "execution_id": "EXEC-legal"}]
    before["counts"]["refunds"] = before["global_counts"]["refunds"] = 1
    record = {"before": before, "after": deepcopy(before)}
    verifier._zero_window(record)
    record["after"]["refunds"].append({"refund_id": "REFUND-unauthorized"})
    with pytest.raises(ValueError, match="refunds"):
        verifier._zero_window(record)


def batch_records() -> list[dict[str, Any]]:
    rows = []
    for scenario in SCENARIOS:
        record = parse_record()
        record.update(
            {
                "scenario_id": scenario["id"],
                "nodeid": scenario["test_ref"],
                **support.scenario_contract(scenario["id"]),
            }
        )
        record["after"]["scope"]["task_ids"] = ["TASK-contract-" + scenario["id"]]
        rows.append(record)
    return rows


@pytest.mark.parametrize(
    "kind", ["missing", "duplicate", "fake_node", "source", "mixed_run", "copied_scope"]
)
def test_batch_rejects_missing_duplicate_or_copied_scenarios(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(verifier, "validate_record", lambda *_args: None)
    records = batch_records()
    if kind == "missing":
        records.pop()
    elif kind == "duplicate":
        records[-1] = deepcopy(records[0])
    elif kind == "fake_node":
        records[-1]["nodeid"] += "-fake"
    elif kind == "source":
        records[-1]["source_snapshot_sha256"] = "b" * 64
    elif kind == "mixed_run":
        records[-1]["run_id"] = "different-run"
    else:
        records[-1]["after"]["scope"] = deepcopy(records[0]["after"]["scope"])
    with pytest.raises(ValueError):
        verifier.validate_records(
            records,
            expected_source_snapshot_sha256=SOURCE_HASH,
            nodeids=[scenario["test_ref"] for scenario in SCENARIOS],
        )


def test_public_projection_excludes_reusable_proofs_in_every_view() -> None:
    record = parse_record("unknown_field")
    body = {
        "schema_version": "1.0",
        "task_id": "TASK-contract",
        "tool_service": "refund-service",
        "tool_name": "refund.create",
        "tool_version": "v1",
        "canonical_parameters": {"amount_fen": 1},
        "request_id": "REQUEST-contract",
        "issued_at": 1,
        "holder_key_id": "KEY-contract",
        "business_action_id": "ACTION-contract",
        "credential_chain": [
            {
                "payload": {"credential_id": "LEAF-contract"},
                "signature": {"value": "not-for-browser"},
            }
        ],
        "holder_proof": {"signature": {"value": "not-for-browser"}},
    }
    record["requests"][0]["request"]["json"] = body
    record["assertions"].append(
        {"name": "raw receipt comparison", "result": "PASS", "observed": body, "expected": body}
    )
    public = verifier.public_record(record)
    request = public["observations"][0]["request"]
    assert len(request) == 13 and request["task_id"] == "TASK-contract"
    text = json.dumps(public)
    assert '"credential_chain"' not in text and '"holder_proof"' not in text
    assert "not-for-browser" not in text and '"raw_hex"' not in text
    verifier.assert_public_projection(public)


@pytest.mark.parametrize(
    "bad",
    [
        {"credential_chain": []},
        {"holder_proof": {}},
        {"signature": {"value": "sensitive"}},
        {"nested": [{"raw_hex": "abc"}]},
    ],
)
def test_public_projection_fails_closed_on_unsafe_fields(bad: Any) -> None:
    with pytest.raises(ValueError):
        verifier.assert_public_projection(bad)


def junit_xml(records: list[dict[str, Any]]) -> ElementTree.Element:
    root = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(root, "testsuite", tests="36")
    for record in records:
        ElementTree.SubElement(
            suite,
            "testcase",
            classname="backend.tests.security.test_scenario_ledger_postgres",
            name="test_scenario[" + record["scenario_id"] + "]",
        )
    return root


@pytest.mark.parametrize("kind", ["failure", "skip", "missing", "duplicate"])
def test_junit_cannot_publish_missing_or_unexecuted_scenarios(kind: str, tmp_path: Path) -> None:
    records = batch_records()
    root = junit_xml(records)
    suite = root.find("testsuite")
    assert suite is not None
    if kind == "failure":
        ElementTree.SubElement(suite[0], "failure")
    elif kind == "skip":
        ElementTree.SubElement(suite[0], "skipped")
    elif kind == "missing":
        suite.remove(suite[-1])
    else:
        suite[-1].set("name", suite[0].get("name"))
    path = tmp_path / "junit.xml"
    ElementTree.ElementTree(root).write(path, encoding="utf-8")
    with pytest.raises(ValueError):
        verifier._validate_junit(path, records)


def test_publication_is_explicit_and_failure_preserves_previous_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = batch_records()
    path = tmp_path / "contract.jsonl"
    for record in records:
        support.append_record(path, record)
    destination = tmp_path / "artifacts/security/current-ledger-summary.json"
    monkeypatch.setattr(verifier, "SUMMARY_PATH", destination)
    monkeypatch.setattr(
        verifier, "collect_nodeids", lambda: [scenario["test_ref"] for scenario in SCENARIOS]
    )
    monkeypatch.setattr(verifier, "validate_record", lambda *_args: None)
    monkeypatch.setattr(verifier, "_validate_source", lambda *_args: {})
    monkeypatch.setattr(
        verifier, "verify_live_postgres", lambda *_args: {"postgresql": "contract-fixture-only"}
    )
    options = {
        "expected_source_snapshot_sha256": SOURCE_HASH,
        "database_url": "postgresql://127.0.0.1/agentguard_test_backend_aabbcc",
        "audit_database_url": "postgresql://127.0.0.1/agentguard_audit_test_backend_aabbcc",
    }
    # Publication I/O contract only: real certification functions are explicitly mocked here.
    summary = verifier.validate_ledger(path, **options)
    assert summary["status"] == "VERIFIED" and len(summary["records"]) == 36
    assert not destination.exists()
    verifier.validate_ledger(path, publish=True, **options)
    previous = destination.read_bytes()
    assert json.loads(previous)["validation"]["postgresql"] == "contract-fixture-only"

    def failed(*_args: Any) -> None:
        raise ValueError("actual/source evidence did not validate")

    monkeypatch.setattr(verifier, "_validate_source", failed)
    with pytest.raises(ValueError):
        verifier.validate_ledger(path, publish=True, **options)
    assert destination.read_bytes() == previous


def test_no_live_postgres_means_no_verified_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "contract.jsonl"
    for record in batch_records():
        support.append_record(path, record)
    monkeypatch.setattr(
        verifier, "collect_nodeids", lambda: [scenario["test_ref"] for scenario in SCENARIOS]
    )
    monkeypatch.setattr(verifier, "validate_record", lambda *_args: None)
    monkeypatch.setattr(verifier, "_validate_source", lambda *_args: {})
    monkeypatch.delenv("AGENTGUARD_DATABASE_URL", raising=False)
    monkeypatch.delenv("AGENTGUARD_AUDIT_DATABASE_URL", raising=False)
    destination = tmp_path / "must-not-exist.json"
    monkeypatch.setattr(verifier, "SUMMARY_PATH", destination)
    with pytest.raises(ValueError, match="PostgreSQL URLs"):
        verifier.validate_ledger(path, expected_source_snapshot_sha256=SOURCE_HASH, publish=True)
    assert not destination.exists()


def test_source_manifest_mismatch_never_uses_a_different_snapshot() -> None:
    with pytest.raises(ValueError, match="SHA256"):
        verifier._validate_source([parse_record()], SOURCE_HASH, {"snapshot_sha256": "b" * 64})


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://127.0.0.1/agentguard",
        "postgresql://db.example/agentguard_test_backend_aabbcc",
        "postgresql://127.0.0.1/agentguard_test_backend_aabbcc?host=main",
        "postgresql://127.0.0.1/not_a_test",
    ],
)
def test_database_isolation_guard_refuses_main_or_remote_databases(url: str) -> None:
    with pytest.raises(ValueError):
        support.database_target(url)
