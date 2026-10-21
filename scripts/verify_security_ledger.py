from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.tests.security import ledger_support as support  # noqa: E402

SUMMARY_PATH = ROOT / "artifacts/security/current-ledger-summary.json"
_SHA256 = re.compile(r"[a-f0-9]{64}")
_TABLES = (
    "refunds",
    "notifications",
    "executions",
    "requests",
    "tool_attempts",
    "reservations",
    "receipts",
    "credentials",
    "retrievals",
    "replay_denials",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise ValueError(f"non-JSON numeric constant: {value}")

    result = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        require(bool(line.strip()), f"blank JSONL line {number}")
        try:
            value = json.loads(line, object_pairs_hook=pairs, parse_constant=constant)
        except ValueError as exc:
            raise ValueError(f"invalid JSONL line {number}: {exc}") from exc
        require(isinstance(value, dict), f"JSONL line {number} is not a record")
        result.append(value)
    return result


def _no_secrets(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            require(
                key.lower() not in support._OMITTED_KEYS, f"forbidden sensitive ledger field: {key}"
            )
            require(
                not key.lower().endswith(("_password", "_api_key", "_private_key_hex")),
                "sensitive ledger field",
            )
            _no_secrets(item)
    elif isinstance(value, list):
        for item in value:
            _no_secrets(item)
    elif isinstance(value, str):
        require(
            not re.search(r"(?i)postgres(?:ql)?(?:\+psycopg)?://[^/\s@]+@", value),
            "ledger contains database credentials",
        )
        require(
            not re.search(r"(?i)Bearer\s+\S+|-----BEGIN .*PRIVATE KEY-----", value),
            "ledger contains authorization/private material",
        )


def _budget_rows(value: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    scope = value["scope"]
    ids = {identifier for chain in scope["credential_chains"] for identifier in chain}
    rows = value["budget"]
    require(
        len(rows) == 2 * len(ids) and bool(ids),
        "missing quota rows at one or more credential levels",
    )
    result = {}
    for row in rows:
        key = (row["credential_id"], row["quota_type"])
        require(key not in result, "duplicate credential/quota budget row")
        require(
            key[0] in ids and key[1] in {"refund_total_fen", "max_tool_calls"},
            "budget scope or lowercase quota type mismatch",
        )
        for name in ("limit", "reserved", "committed", "version"):
            require(
                type(row[name]) is int and 0 <= row[name] <= 9_007_199_254_740_991,
                f"invalid integer budget {name}",
            )
        require(
            row["reserved"] + row["committed"] <= row["limit"],
            "reserved plus committed exceeds quota",
        )
        result[key] = row
    require(
        set(result)
        == {
            (identifier, quota)
            for identifier in ids
            for quota in ("refund_total_fen", "max_tool_calls")
        },
        "incomplete chain-level quota coverage",
    )
    return result


def _validate_snapshot(value: dict[str, Any], database_name: str) -> None:
    require(
        isinstance(value, dict) and "counts" in value, "before/after snapshot is NOT_RUN or N/A"
    )
    scope = value["scope"]
    require(scope["kind"] == "scenario_tasks_and_credential_chains", "unmarked delta scope")
    require(
        bool(scope["task_ids"]) and len(set(scope["task_ids"])) == len(scope["task_ids"]),
        "empty or duplicate task scope",
    )
    probe = value["database_probe"]
    require(
        probe["database_name"] == database_name and probe["driver"] == "psycopg",
        "snapshot is not the isolated PostgreSQL database",
    )
    require(
        type(probe["backend_pid"]) is int
        and probe["backend_pid"] > 0
        and bool(probe["server_version"]),
        "missing live PostgreSQL identity evidence",
    )
    _budget_rows(value)
    for table in _TABLES:
        require(isinstance(value[table], list), f"missing raw PostgreSQL {table} rows")
        require(
            type(value["counts"][table]) is int and value["counts"][table] == len(value[table]),
            f"reported {table} count differs from the raw rows",
        )
    for table in ("refunds", "notifications", "executions", "credentials", "retrievals"):
        require(
            all(row["task_id"] in scope["task_ids"] for row in value[table]),
            f"{table} row escaped its declared task scope",
        )
    for table, count in value["global_counts"].items():
        require(
            type(count) is int and count >= value["counts"][table],
            f"invalid isolated-database global {table} count",
        )
    executions = {row["execution_id"] for row in value["executions"]}
    for table in (
        "refunds",
        "notifications",
        "requests",
        "tool_attempts",
        "reservations",
        "receipts",
    ):
        require(
            all(row["execution_id"] in executions for row in value[table]),
            f"unbound {table} execution ID",
        )


def _stored_receipts(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from backend.common.enums import KeyPurpose
    from backend.common.schema import SchemaStore
    from backend.crypto.canonical_json import canonicalize
    from backend.crypto.domains import EXECUTION_RECEIPT
    from backend.crypto.sm import signed_object_hash, sm3_hex, verify_payload

    executions = {row["execution_id"]: row for row in value["executions"]}
    result = {}
    for row in value["receipts"]:
        receipt = row["signed_receipt"]
        SchemaStore().validate("execution-receipt.schema.json", receipt)
        payload, signature = receipt["payload"], receipt["signature"]
        require(row["receipt_id"] not in result, "duplicate stored receipt ID")
        require(
            payload["receipt_id"] == row["receipt_id"]
            and payload["execution_id"] == row["execution_id"],
            "receipt ID/execution binding mismatch",
        )
        require(
            row["purpose"] == KeyPurpose.EXECUTION_RECEIPT_SIGNING.value
            and row["key_id"] == signature["key_id"],
            "receipt signer purpose/key mismatch",
        )
        require(
            signed_object_hash(receipt) == row["receipt_hash"],
            "stored signed receipt hash mismatch",
        )
        require(
            verify_payload(
                payload,
                signature,
                domain_separator=EXECUTION_RECEIPT,
                expected_key_id=row["key_id"],
                expected_key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
                public_key_hex=row["public_key_hex"],
            ),
            "invalid real receipt signature",
        )
        execution = executions[row["execution_id"]]
        for field in (
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
        ):
            require(payload[field] == execution[field], f"receipt does not bind durable {field}")
        replay = [
            attempt
            for attempt in value["replay_denials"]
            if attempt["denial_execution_id"] == row["execution_id"]
        ]
        cancellations = [
            record for record in value.get("dispatch_cancellations", [])
            if record["denial_execution_id"] == row["execution_id"]
        ]
        require(len(cancellations) <= 1, "dispatch denial links are ambiguous")
        request_id = cancellations[0]["request_id"] if cancellations else replay[0]["request_id"] if replay else execution["initial_request_id"]
        require(
            payload["request_id"] == request_id,
            "receipt does not bind the durable initial/denial request",
        )
        require(
            payload["started_at"] == execution["created_at"]
            and payload["decision_at"] == execution["decision_at"]
            and payload["finished_at"] == execution["terminal_at"]
            and 0
            <= payload["started_at"]
            <= payload["decision_at"]
            <= payload["finished_at"]
            <= payload["receipt_issued_at"]
            == signature["signed_at"],
            "signed receipt timing is not bound to trusted execution times",
        )
        reservations = [
            item for item in value["reservations"] if item["execution_id"] == row["execution_id"]
        ]
        require(
            payload["budget_reserved"]
            == sum(item["amount"] for item in reservations if item["status"] == "RESERVED")
            and payload["budget_committed"]
            == sum(item["amount"] for item in reservations if item["status"] == "COMMITTED"),
            "receipt budget totals differ from actual reservation rows",
        )
        require(
            payload["decision"] == row["decision"] == execution["decision"],
            "signed receipt decision disagrees with durable execution",
        )
        require(
            payload["reason_code"] == row["reason_code"],
            "receipt reason code disagrees with PostgreSQL",
        )
        if payload["decision"] == "DENY":
            require(
                execution["state"] == "DENIED" and payload["budget_committed"] == 0,
                "signed denial does not bind a zero-budget DENIED execution",
            )
            require(
                payload["business_effect_id"] is None and payload["business_result_hash"] is None,
                "signed denial claims a business effect",
            )
        elif execution["result"] is not None:
            require(
                sm3_hex(canonicalize(execution["result"]))
                == execution["business_result_hash"]
                == payload["business_result_hash"],
                "result hash is not bound to the actual stored result",
            )
        result[row["receipt_id"]] = row
    return result


def _request_index(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from backend.crypto.sm import sm3_hex
    from backend.crypto.strict_json import StrictJsonError, parse_strict_json

    result = {}
    ports = set(support.ISOLATED_PORTS.values())
    proxy = record.get("fault", {}).get("proxy_url")
    for call in record["requests"]:
        require(call["call_id"] not in result, "copied/duplicate HTTP call ID")
        require(
            call["transport"] == "httpx.HTTPTransport",
            "stub/ASGI HTTP transport cannot prove integration",
        )
        target = urlsplit(call["url"])
        allowed = target.port in ports or bool(proxy and call["url"] == proxy + "/internal/execute")
        require(
            target.scheme == "http" and target.hostname in {"127.0.0.1", "localhost"} and allowed,
            "request is not to an isolated stack or the declared real-response fault proxy",
        )
        require(
            not target.username and not target.password and not target.query,
            "HTTP URL contains secrets or routing overrides",
        )
        raw = bytes.fromhex(call["request"]["raw_hex"])
        require(
            sm3_hex(raw) == call["request"]["raw_request_hash"],
            "recorded raw HTTP request hash mismatch",
        )
        try:
            parsed = parse_strict_json(raw) if raw else None
        except StrictJsonError:
            require(
                _is_na(call["request"]["json"]),
                "illegal raw bytes were assigned a fabricated RequestContext",
            )
        else:
            require(
                parsed == call["request"]["json"],
                "declared request JSON differs from actual transmitted bytes",
            )
        require(
            type(call["started_monotonic_ns"]) is int
            and call["finished_monotonic_ns"] >= call["started_monotonic_ns"],
            "missing actual HTTP timing evidence",
        )
        if "error_type" in call:
            require(
                record["scenario_id"] == "timeout_retry"
                and call["error_type"] == "ReadTimeout"
                and proxy
                and call["url"].startswith(proxy + "/"),
                "unexpected failed HTTP call",
            )
        else:
            require(type(call["response"]["status_code"]) is int, "HTTP request did not execute")
        result[call["call_id"]] = call
    require(bool(result), "no actual HTTP requests recorded")
    return result


def _observation(record: dict[str, Any], calls: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    observations = [item for item in record["observations"] if item["kind"] == kind]
    for item in observations:
        require(item["call_id"] in calls, "observation has no actual HTTP request")
        response = calls[item["call_id"]]["response"]
        require(
            item["body"] == response["json"] and item["status_code"] == response["status_code"],
            "observed decision was not returned by HTTP",
        )
    return observations


def _deny_observations(
    record: dict[str, Any], calls: dict[str, Any], receipts: dict[str, Any], reasons: list[str]
) -> list[dict[str, Any]]:
    observations = _observation(record, calls, "gateway_deny")
    for observation in observations:
        body = observation["body"]
        require(
            observation["status_code"] in {400, 403, 409}
            and body["decision"] == "DENY"
            and body["state"] == "DENIED",
            "Gateway denial was not a terminal DENY",
        )
        require(
            body["reason_code"] in reasons and body["reason_code"] != "ALLOWED",
            "Gateway reason differs from the scenario definition",
        )
        receipt = body.get("receipt")
        require(isinstance(receipt, dict), "Gateway denial has no signed DENY receipt")
        payload = receipt["payload"]
        stored = receipts.get(payload["receipt_id"])
        require(
            stored is not None and stored["signed_receipt"] == receipt,
            "returned receipt is not the real PostgreSQL receipt",
        )
        require(
            payload["decision"] == "DENY" and payload["execution_id"] == body["execution_id"],
            "a legal ALLOW receipt cannot stand in for attack denial evidence",
        )
        request = calls[observation["call_id"]]["request"]["json"]
        require(
            payload["request_id"] == request["request_id"],
            "denial receipt does not bind the attack request",
        )
    return observations


def _allow_observations(
    record: dict[str, Any], calls: dict[str, Any], receipts: dict[str, Any]
) -> list[dict[str, Any]]:
    observations = _observation(record, calls, "gateway_allow")
    for observation in observations:
        body = observation["body"]
        require(
            observation["status_code"] == 200
            and body["decision"] == "ALLOW"
            and body["state"] == "COMMITTED"
            and body["reason_code"] == "ALLOWED",
            "legal execution did not actually commit",
        )
        receipt = body["receipt"]
        payload = receipt["payload"]
        stored = receipts.get(payload["receipt_id"])
        require(
            payload["decision"] == "ALLOW"
            and payload["execution_id"] == body["execution_id"]
            and stored is not None
            and receipt == stored["signed_receipt"],
            "legal receipt is not bound to the actual committed execution",
        )
    return observations


def _zero_window(record: dict[str, Any], *, lifecycle: bool = False) -> None:
    before, after = record["before"], record["after"]
    require(before["budget"] == after["budget"], "attack/read/parse changed a credential budget")
    tables = ["refunds", "notifications", "tool_attempts", "reservations"]
    if lifecycle:
        tables.extend(("executions", "receipts", "requests"))
    for table in tables:
        require(before[table] == after[table], f"attack/read/parse changed scoped {table}")
        if table in before["global_counts"]:
            require(
                before["global_counts"][table] == after["global_counts"][table],
                f"attack/read/parse changed global {table}",
            )


def _validate_parse(
    record: dict[str, Any], calls: dict[str, Any], scenario: dict[str, Any]
) -> None:
    from backend.common.schema import SchemaStore
    from backend.crypto.canonical_json import canonicalize
    from backend.crypto.sm import sm3_hex

    _zero_window(record, lifecycle=True)
    observations = _observation(record, calls, "parse_rejection")
    require(len(observations) == 1, "parse scenario did not execute exactly one raw attack")
    observation = observations[0]
    body = observation["body"]
    require(
        observation["status_code"] == 400 and body["status"] == "rejected_at_parse",
        "raw request was not actually rejected at the parse/schema boundary",
    )
    require(
        "execution_id" not in body and "receipt" not in body,
        "illegal raw JSON cannot have a RequestContext or signed ExecutionReceipt",
    )
    raw_hash = calls[observation["call_id"]]["request"]["raw_request_hash"]
    events = [
        row
        for row in record["after"]["audit_events"]
        if row["payload"].get("raw_request_hash") == raw_hash
    ]
    require(len(events) == 1, "missing or duplicate actual RejectedAuditEvent")
    event = events[0]
    SchemaStore().validate("rejected-audit-event.schema.json", event["payload"])
    require(
        event["event_type"] == "RAW_REQUEST_REJECTED" and event["execution_id"] is None,
        "raw rejection was attributed to a fabricated execution",
    )
    require(
        event["payload"]["reason_code"] == support.PARSE_REASONS[scenario["id"]],
        "raw parser reason does not match the actual scenario",
    )
    require(
        sm3_hex(canonicalize(event["payload"])) == event["payload_hash"],
        "RejectedAuditEvent payload hash mismatch",
    )
    require(
        event["status"] == "APPENDED"
        and type(event["event_sequence"]) is int
        and event["event_sequence"] > 0,
        "raw rejection did not enter the verified audit chain",
    )
    require(
        isinstance(record["execution_ids"], dict)
        and record["execution_ids"].get("status") == "N/A"
        and bool(record["execution_ids"].get("reason")),
        "parse execution IDs must explicitly be N/A with a reason",
    )
    require(
        isinstance(record["receipt_ids"], dict)
        and record["receipt_ids"].get("status") == "N/A"
        and bool(record["receipt_ids"].get("reason")),
        "parse receipt IDs must explicitly be N/A with a reason",
    )


def _validate_settled_budget(record: dict[str, Any], *, amount: int, count: int) -> None:
    before = _budget_rows(record["before"])
    after = _budget_rows(record["after"])
    for key, row in after.items():
        expected = amount if key[1] == "refund_total_fen" else count
        require(
            row["reserved"] == before[key]["reserved"] == 0,
            "committed scenario leaves reserved budget or has an undeclared baseline",
        )
        require(
            row["committed"] - before[key]["committed"] == expected,
            "actual effect/committed amount mismatch at a credential level",
        )
    committed = [row for row in record["after"]["executions"] if row["state"] == "COMMITTED"]
    require(len(committed) == count, "unexpected committed execution count")
    effects = record["after"]["refunds"]
    require(
        len(effects) == count and sum(row["amount_fen"] for row in effects) == amount,
        "actual refund rows do not match the authorized budget settlement",
    )
    require(
        len({row["execution_id"] for row in effects}) == count,
        "duplicate execution business effect",
    )
    require(
        all(row["status"] == "COMMITTED" for row in effects),
        "refund business effect is not committed",
    )


def _validate_audit(record: dict[str, Any], calls: dict[str, Any]) -> None:
    from backend.crypto.canonical_json import canonicalize
    from backend.crypto.sm import sm3_hex

    verification = record["audit_verification"]
    require(
        verification["status"] == "VERIFIED" and verification["call_id"] in calls,
        "audit verification was not executed",
    )
    call = calls[verification["call_id"]]
    require(
        call["url"].endswith("/audit/verify") and verification["response"] == call["response"],
        "audit result is not bound to the actual HTTP verifier",
    )
    result = call["response"]["json"]
    require(
        call["response"]["status_code"] == 200
        and result["valid"] is True
        and result["rollback_detected"] is False,
        "audit chain/checkpoint verification did not pass",
    )
    events = record["after"]["audit_events"]
    for event in events:
        require(
            sm3_hex(canonicalize(event["payload"])) == event["payload_hash"],
            "audit payload differs from the chained hash",
        )
        require(
            event["status"] == "APPENDED"
            and type(event["event_sequence"]) is int
            and event["event_sequence"] > 0,
            "scenario audit event was not appended",
        )
        require(
            bool(_SHA256.fullmatch(event["event_hash"] or ""))
            and bool(_SHA256.fullmatch(event["previous_event_hash"] or "")),
            "missing audit chain hash evidence",
        )
        require(
            event["event_sequence"] <= result["latest_event_sequence"],
            "scenario event was outside the verified audit prefix",
        )


def validate_record(record: dict[str, Any], scenario: dict[str, Any]) -> None:
    identifier = scenario["id"]
    try:
        require(record["schema_version"] == support.LEDGER_SCHEMA, "unsupported ledger schema")
        require(record["status"] == "PASS", "FAIL/NOT_RUN is not verified evidence")
        require(
            record["scenario_id"] == identifier and record["nodeid"] == scenario["test_ref"],
            "scenario/nodeid mapping mismatch",
        )
        for key, expected in support.scenario_contract(identifier).items():
            require(record[key] == scenario[key] == expected, f"execution contract mismatch: {key}")
        _no_secrets(record)
        configuration = record["configuration"]
        require(
            configuration["deployment"] == "native"
            and configuration["stub_used"] is False
            and configuration["cloud_llm_enabled"] is False,
            "stub/cloud/degraded evidence is not a real integration run",
        )
        target = _configuration_target(configuration["database"])
        database_name = target["name"]
        audit_target = _configuration_target(configuration["audit_database"], audit=True)
        require(
            database_name.split("backend_", 1)[1] == audit_target["name"].split("backend_", 1)[1],
            "main/audit isolation suffix mismatch",
        )
        require(
            configuration["database_probe"]["database_name"] == database_name,
            "missing real PostgreSQL configuration probe",
        )
        require(
            configuration["audit_database_probe"]["database_name"] == audit_target["name"],
            "missing isolated audit PostgreSQL probe",
        )
        require(
            record["source_inputs_unchanged"] is True,
            "source inputs changed during scenario execution",
        )
        require(
            record["assertions"] and all(item["result"] == "PASS" for item in record["assertions"]),
            "missing or failed explicit scenario assertions",
        )
        for side in ("before", "after"):
            _validate_snapshot(record[side], database_name)
        require(
            record["before"]["scope"] == record["after"]["scope"],
            "before/after delta scopes differ",
        )
        windows = record["operation_windows"]
        require(
            windows and len({window["name"] for window in windows}) == len(windows),
            "missing or duplicate operation windows",
        )
        primary = [window for window in windows if window["measurement"] == "primary"]
        require(
            len(primary) == 1 and primary[0]["before"] == record["before"],
            "missing independently measured primary window",
        )
        for window in windows:
            for side in ("before", "after"):
                _validate_snapshot(window[side], database_name)
            require(
                window["before"]["scope"] == window["after"]["scope"] == record["before"]["scope"],
                "step window escaped scenario scope",
            )
        for table in (*_TABLES, "budget", "global_counts", "revocations"):
            require(
                primary[0]["after"][table] == record["after"][table],
                f"audit verification altered primary-window {table}",
            )
        for field, table, key in (
            ("execution_ids", "executions", "execution_id"),
            ("receipt_ids", "receipts", "receipt_id"),
        ):
            expected = [row[key] for row in record["after"][table]]
            require(
                record[field] == expected if expected else _is_na(record[field]),
                f"unbound or undeclared N/A {field}",
            )
        before_budget, after_budget = _budget_rows(record["before"]), _budget_rows(record["after"])
        for key, row in after_budget.items():
            require(
                row["limit"] == before_budget[key]["limit"]
                and row["version"] >= before_budget[key]["version"],
                "quota was raised or budget version rolled back",
            )
        for table, delta in scenario["expected_effect_delta"].items():
            require(
                record["after"]["counts"][table] - record["before"]["counts"][table] == delta,
                f"unexpected scoped {table} delta",
            )
            require(
                record["after"]["global_counts"][table] - record["before"]["global_counts"][table]
                == delta,
                f"unexpected effect outside the scoped tasks: {table}",
            )
        calls = _request_index(record)
        receipts = _stored_receipts(record["after"])
        _validate_audit(record, calls)
        _validate_scenario(record, calls, receipts, scenario)
    except (KeyError, TypeError, ValueError, AssertionError) as exc:
        raise ValueError(f"{identifier}: {exc}") from exc


def _is_na(value: Any) -> bool:
    return isinstance(value, dict) and value.get("status") == "N/A" and bool(value.get("reason"))


def _configuration_target(value: dict[str, Any], *, audit: bool = False) -> dict[str, Any]:
    host = f"[{value['host']}]" if ":" in value["host"] else value["host"]
    port = "" if value.get("port") is None else f":{value['port']}"
    return support.database_target(f"postgresql://{host}{port}/{value['name']}", audit=audit)


def _window(record: dict[str, Any], name: str) -> dict[str, Any]:
    found = [window for window in record["operation_windows"] if window["name"] == name]
    require(len(found) == 1, f"missing real before/after operation window: {name}")
    return found[0]


def _same_effects(window: dict[str, Any], *, budgets: bool = True) -> None:
    before, after = window["before"], window["after"]
    for table in ("refunds", "notifications", "tool_attempts", "reservations"):
        require(before[table] == after[table], f"retry/recovery created new {table}")
    if budgets:
        require(before["budget"] == after["budget"], "retry changed its credential budget")
    for table in ("refunds", "notifications", "tool_attempts"):
        require(
            before["global_counts"][table] == after["global_counts"][table],
            f"retry/recovery created global {table}",
        )


def _gateway_envelope(record: dict[str, Any], call: dict[str, Any]) -> dict[str, Any]:
    from backend.common.enums import KeyPurpose
    from backend.common.schema import SchemaStore
    from backend.crypto.domains import GATEWAY_EXECUTION_ENVELOPE
    from backend.crypto.sm import verify_payload

    envelope = call["request"]["json"]
    SchemaStore().validate("gateway-execution-envelope.schema.json", envelope)
    signer = record["gateway_signature"]
    require(
        signer["source"] == "isolated PostgreSQL key_registry"
        and signer["purpose"] == KeyPurpose.GATEWAY_EXECUTION_SIGNING.value,
        "not a genuine gateway signer",
    )
    require(
        verify_payload(
            envelope["payload"],
            envelope["signature"],
            domain_separator=GATEWAY_EXECUTION_ENVELOPE,
            expected_key_id=signer["key_id"],
            expected_key_purpose=KeyPurpose.GATEWAY_EXECUTION_SIGNING,
            public_key_hex=signer["public_key_hex"],
        ),
        "invalid Tool boundary signature",
    )
    return envelope


def _validate_retry(
    record: dict[str, Any], calls: dict[str, Any], receipts: dict[str, Any]
) -> None:
    observations = _allow_observations(record, calls, receipts)
    require(len(observations) == 2, "positive scenario requires two actual HTTP executions/retries")
    first, second = observations
    a, b = (calls[item["call_id"]]["request"]["json"] for item in observations)
    require(
        a["request_id"] != b["request_id"]
        and a["canonical_parameters"] == b["canonical_parameters"],
        "retry/distinct-action request inputs do not match the scenario",
    )
    if record["scenario_id"] == "same_action_same_params_retry":
        require(
            a["business_action_id"] == b["business_action_id"], "retry changed the trusted action"
        )
        require(
            first["body"]["execution_id"] == second["body"]["execution_id"]
            and first["body"]["receipt"] == second["body"]["receipt"],
            "legal retry created a new execution or receipt",
        )
        require(
            second["body"]["admission_outcome"] == "IDEMPOTENT_RETURN",
            "legal retry was not an idempotent return",
        )
        _same_effects(_window(record, "legal_retry"))
        _validate_settled_budget(record, amount=1000, count=1)
    else:
        require(
            a["business_action_id"] != b["business_action_id"]
            and first["body"]["execution_id"] != second["body"]["execution_id"],
            "distinct approved actions were conflated",
        )
        require(
            second["body"]["admission_outcome"] == "NEW_EXECUTION",
            "second action was not separately authorized",
        )
        _validate_settled_budget(record, amount=2000, count=2)


def _validate_recovery(
    record: dict[str, Any], calls: dict[str, Any], receipts: dict[str, Any]
) -> None:
    fault = record["fault"]
    real = calls[fault["real_tool_call_id"]]
    require(
        real["url"].endswith(":28303/internal/execute") and real["response"]["status_code"] == 200,
        "recovery fault did not follow a real successful protected Tool HTTP call",
    )
    envelope = _gateway_envelope(record, real)
    execution_id = fault["execution_id"]
    require(
        envelope["payload"]["execution_id"] == execution_id,
        "fault is not bound to the admitted execution",
    )
    if record["scenario_id"] == "crash_after_tool_success":
        require(
            fault["mode"] == "process_exit_after_real_tool_success"
            and fault["worker_exit_code"] == 86,
            "crash scenario did not exit its owned worker after real Tool success",
        )
    else:
        require(
            fault["mode"] == "withheld_real_http_response" and fault["error_type"] == "ReadTimeout",
            "timeout scenario did not withhold a real response",
        )
        timed = [call for call in calls.values() if call.get("error_type") == "ReadTimeout"]
        require(
            len(timed) == 1 and timed[0]["request"]["json"] == envelope,
            "timeout has no actual matching TCP read failure",
        )
        require(
            fault["real_tool_response"] == real["response"]["json"],
            "forwarded Tool success was fabricated",
        )
        unknown = _observation(record, calls, "gateway_unknown")
        require(
            len(unknown) == 1
            and unknown[0]["body"]["state"] == "UNKNOWN"
            and unknown[0]["body"]["execution_id"] == execution_id
            and unknown[0]["body"]["receipt"] is None,
            "UNKNOWN retry manufactured a terminal outcome",
        )
        _same_effects(_window(record, "unknown_retry"))
    effect_window = _window(record, "real_effect_before_settlement")
    require(
        effect_window["after"]["counts"]["refunds"] - effect_window["before"]["counts"]["refunds"]
        == 1
        and effect_window["after"]["counts"]["receipts"] == 0,
        "fault evidence lacks an actual effect before settlement or fabricates a receipt",
    )
    unsettled = _budget_rows(effect_window["after"])
    for key, row in unsettled.items():
        require(
            row["committed"] == 0
            and row["reserved"] == (1000 if key[1] == "refund_total_fen" else 1),
            "pre-recovery reservation is not present at every level",
        )
    recovery = _observation(record, calls, "recovery")
    require(
        len(recovery) == 1
        and recovery[0]["status_code"] == 200
        and len(recovery[0]["body"]["decisions"]) == 1,
        "recovery endpoint was not actually executed for one execution",
    )
    decision = recovery[0]["body"]["decisions"][0]
    require(
        decision["execution_id"] == execution_id and decision["state"] == "COMMITTED",
        "recovery did not commit the original execution",
    )
    receipt = decision["receipt"]
    require(
        receipt["payload"]["decision"] == "ALLOW"
        and receipts[receipt["payload"]["receipt_id"]]["signed_receipt"] == receipt,
        "recovery receipt is not the actual signed ALLOW receipt",
    )
    recovery_window = _window(record, "recovery")
    for table in ("refunds", "notifications", "tool_attempts"):
        require(
            recovery_window["before"][table] == recovery_window["after"][table],
            "recovery repeated the business effect/Tool call",
        )
        require(
            recovery_window["before"]["global_counts"][table]
            == recovery_window["after"]["global_counts"][table],
            "recovery created an out-of-scope effect",
        )
    retried = _allow_observations(record, calls, receipts)
    require(
        len(retried) == 1
        and retried[0]["body"]["execution_id"] == execution_id
        and retried[0]["body"]["receipt"] == receipt
        and retried[0]["body"]["admission_outcome"] == "IDEMPOTENT_RETURN",
        "post-recovery retry did not reuse the real execution and receipt",
    )
    _same_effects(_window(record, "post_recovery_retry"))
    _validate_settled_budget(record, amount=1000, count=1)


def _validate_race(
    record: dict[str, Any], calls: dict[str, Any], receipts: dict[str, Any], reasons: list[str]
) -> None:
    orders = record["transaction_orders"]
    require(
        len(orders) == 2 and {order["first"] for order in orders} == {"revocation", "admission"},
        "both transaction orderings were not exercised",
    )
    for order in orders:
        require(
            type(order["locker_pid"]) is int
            and order["locker_pid"] > 0
            and len(order["waiters"]) == 2,
            "race lacks actual PostgreSQL blocking evidence",
        )
        for minimum, waiters in enumerate(order["waiters"], 1):
            reachable = {order["locker_pid"]}
            for _ in range(len(waiters)):
                reachable |= {
                    row["pid"] for row in waiters if reachable.intersection(row["blocking_pids"])
                }
            require(
                len({row["pid"] for row in waiters if row["pid"] in reachable}) >= minimum,
                "race waiters were not queued behind the controlled PostgreSQL transaction",
            )
        require(
            any(
                row["credential_id"] == order["root_credential_id"]
                for row in record["after"]["revocations"]
            ),
            "raced revocation was not committed",
        )
    denied = _deny_observations(record, calls, receipts, reasons)
    require(
        len(denied) == 2
        and {item["label"] for item in denied}
        == {"revocation_before_admission", "future_admission_after_revocation"},
        "race did not reject both post-revocation requests",
    )
    admitted = [
        item
        for item in _observation(record, calls, "gateway_admit")
        if item["label"] == "admission_before_revocation"
    ]
    require(
        len(admitted) == 1
        and admitted[0]["status_code"] == 200
        and admitted[0]["body"]["decision"] == "ALLOW"
        and admitted[0]["body"]["state"] == "ADMITTED"
        and admitted[0]["body"]["receipt"] is None,
        "winning admission was fabricated or assigned a terminal receipt",
    )
    winning_task = next(order["task_id"] for order in orders if order["first"] == "admission")
    order = next(order for order in orders if order["first"] == "admission")
    cancelled = order.get("dispatch_cancellation")
    require(isinstance(cancelled, dict), "race lacks durable dispatch cancellation evidence")
    require(cancelled in record["after"].get("dispatch_cancellations", []), "race cancellation differs from PostgreSQL snapshot")
    executions = {row["execution_id"]: row for row in record["after"]["executions"]}
    original = executions.get(cancelled["execution_id"], {})
    denied_execution = executions.get(cancelled["denial_execution_id"], {})
    require(original.get("task_id") == winning_task and original.get("state") == "RELEASED" and original.get("decision") == "ALLOW", "winning original admission was rewritten or not cancelled")
    require(denied_execution.get("state") == "DENIED" and denied_execution.get("decision") == "DENY" and denied_execution.get("request_hash") == original.get("request_hash"), "dispatch cancellation has no independent bound DENY")
    before, after = _budget_rows(record["before"]), _budget_rows(record["after"])
    for key, row in after.items():
        require(
            row["reserved"] == before[key]["reserved"]
            and row["committed"] == before[key]["committed"],
            "revoked undispatched admission did not release all reservations",
        )
    for table in ("refunds", "notifications", "tool_attempts"):
        require(
            record["before"][table] == record["after"][table],
            "revocation race unexpectedly executed a protected Tool",
        )
    require(
        _is_na(record["new_allow_receipt_evidence"]),
        "nonterminal race admission requires explicit N/A receipt evidence",
    )


def _validate_scenario(
    record: dict[str, Any],
    calls: dict[str, Any],
    receipts: dict[str, Any],
    scenario: dict[str, Any],
) -> None:
    from backend.crypto.canonical_json import canonicalize
    from backend.crypto.sm import sm3_hex

    identifier = scenario["id"]
    reasons = scenario["expected_reason_codes"]
    if identifier in support.PARSE_REASONS:
        _validate_parse(record, calls, scenario)
    elif identifier in support.DELEGATION_SCENARIOS:
        _zero_window(record, lifecycle=True)
        observed = _observation(record, calls, "delegation_deny")
        require(
            len(observed) == 1
            and observed[0]["status_code"] == 403
            and observed[0]["body"]["reason_code"] in reasons,
            "delegation attack was not actually denied",
        )
        require(
            record["before"]["credentials"] == record["after"]["credentials"]
            and _is_na(record["receipt_ids"])
            and _is_na(record["execution_ids"]),
            "delegation rejection created partial authority or a fabricated receipt",
        )
    elif identifier in support.TOOL_SCENARIOS:
        _zero_window(record, lifecycle=True)
        observed = _observation(record, calls, "tool_deny")
        require(
            len(observed) == 1
            and observed[0]["status_code"]
            == (409 if identifier == "gateway_envelope_replay" else 403)
            and observed[0]["body"]["detail"]["reason_code"] in reasons
            and "receipt" not in observed[0]["body"],
            "protected Tool did not reject the envelope",
        )
        envelope = _gateway_envelope(record, calls[observed[0]["call_id"]])
        require(
            _is_na(record["new_receipt_evidence"]),
            "Tool rejection must explicitly have no new Gateway receipt",
        )
        if identifier == "gateway_envelope_replay":
            baseline = _observation(record, calls, "tool_allow")
            require(
                len(baseline) == 1
                and baseline[0]["status_code"] == 200
                and calls[baseline[0]["call_id"]]["request"]["json"] == envelope
                and record["before"]["counts"]["refunds"] == 1,
                "envelope replay is missing the real successful baseline",
            )
        else:
            from datetime import datetime

            started = datetime.fromisoformat(
                calls[observed[0]["call_id"]]["started_at"]
            ).timestamp()
            require(
                envelope["payload"]["expires_at"] < started
                and envelope["payload"]["expires_at"] > envelope["payload"]["issued_at"],
                "expired-envelope test used invalid timing or never expired",
            )
    elif identifier in support.RETRIEVAL_SCENARIOS:
        _zero_window(record, lifecycle=True)
        observed = _observation(record, calls, "retrieval_deny")
        require(
            len(observed) == 1
            and observed[0]["status_code"] == 403
            and observed[0]["body"]["reason_code"] in reasons
            and "result" not in observed[0]["body"]
            and "receipt" not in observed[0]["body"],
            "retrieval denial leaked a result or manufactured a receipt",
        )
        request = calls[observed[0]["call_id"]]["request"]["json"]
        events = record["after"]["audit_events"]
        require(
            any(
                event["event_type"] == "RESULT_RETRIEVAL_DENIED"
                and event["payload"].get("retrieval_request_id") == request["request_id"]
                and event["payload"].get("reason_code") == observed[0]["body"]["reason_code"]
                and event["payload"].get("request_hash") == sm3_hex(canonicalize(request))
                for event in events
            ),
            "retrieval denial lacks its actual audit event",
        )
        require(
            record["before"]["counts"]["refunds"] == 1 and _is_na(record["new_receipt_evidence"]),
            "retrieval legal baseline or N/A new receipt evidence is missing",
        )
        if identifier == "result_retrieval_replay":
            baseline = _observation(record, calls, "retrieval_allow")
            require(
                len(baseline) == 1
                and baseline[0]["status_code"] == 200
                and calls[baseline[0]["call_id"]]["request"]["json"] == request,
                "retrieval replay did not repeat the actual earlier authorized read",
            )
    elif identifier in support.RECOVERY_SCENARIOS:
        _validate_recovery(record, calls, receipts)
    elif identifier == "revocation_race":
        _validate_race(record, calls, receipts, reasons)
    elif identifier in {"same_action_same_params_retry", "different_action_same_params"}:
        _validate_retry(record, calls, receipts)
    elif identifier == "concurrent_double_spend":
        allowed = _allow_observations(record, calls, receipts)
        denied = _deny_observations(record, calls, receipts, reasons)
        require(
            len(allowed) == len(denied) == 1,
            "double spend requires one real ALLOW and one real DENY",
        )
        a, b = (calls[item["call_id"]] for item in (allowed[0], denied[0]))
        require(
            a["request"]["json"]["business_action_id"]
            != b["request"]["json"]["business_action_id"],
            "concurrency merely repeated the same action",
        )
        require(
            max(a["started_monotonic_ns"], b["started_monotonic_ns"])
            < min(a["finished_monotonic_ns"], b["finished_monotonic_ns"]),
            "double spend requests did not overlap in real time",
        )
        _validate_settled_budget(record, amount=6000, count=1)
    else:
        _zero_window(record)
        denied = _deny_observations(record, calls, receipts, reasons)
        require(len(denied) == 1, "scenario did not execute its own signed Gateway denial")
        if identifier in {"request_replay", "same_action_different_params"}:
            legal = _allow_observations(record, calls, receipts)
            require(
                len(legal) == 1
                and legal[0]["body"]["execution_id"] != denied[0]["body"]["execution_id"],
                "attack reused the legitimate ALLOW execution",
            )
            for table in ("executions", "receipts"):
                old = record["before"][table]
                require(
                    all(row in record["after"][table] for row in old),
                    "attack overwrote legitimate prior execution evidence",
                )
            a, b = (calls[item["call_id"]]["request"]["json"] for item in (legal[0], denied[0]))
            require(
                a["business_action_id"] == b["business_action_id"]
                and record["before"]["counts"]["refunds"] == 1,
                "attack lacks its legitimate action baseline",
            )
            if identifier == "request_replay":
                require(
                    a == b
                    and any(
                        row["original_execution_id"] == legal[0]["body"]["execution_id"]
                        and row["denial_execution_id"] == denied[0]["body"]["execution_id"]
                        for row in record["after"]["replay_denials"]
                    ),
                    "request replay lacks a separately persisted denial attempt",
                )
            else:
                require(
                    a["request_id"] != b["request_id"]
                    and a["canonical_parameters"] != b["canonical_parameters"],
                    "idempotency conflict did not change parameters with a fresh request",
                )


def collect_nodeids() -> list[str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("AGENTGUARD_")
    }
    environment.update(
        {name: f"http://127.0.0.1:{port}" for name, port in support.ISOLATED_PORTS.items()}
    )
    environment.update(
        {
            "AGENTGUARD_DATABASE_URL": "postgresql://127.0.0.1/agentguard_test_backend_aabbcc",
            "AGENTGUARD_AUDIT_DATABASE_URL": "postgresql://127.0.0.1/agentguard_audit_test_backend_aabbcc",
            "AGENTGUARD_HOLDER_PRIVATE_KEY_FILE": "collection-only-no-key-read",
            "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE": "collection-only-no-key-read",
            "AGENTGUARD_SECURITY_LEDGER_PATH": "collection-only-no-ledger-written",
            "AGENTGUARD_SOURCE_SNAPSHOT_SHA256": "a" * 64,
            "AGENTGUARD_TEST_DEPLOYMENT": "native",
            "AGENTGUARD_CLOUD_LLM_ENABLED": "false",
            "PYTEST_ADDOPTS": "",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            support.TEST_MODULE,
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=45,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    require(
        result.returncode == 0,
        f"pytest nodeid collection failed: {result.stdout[-2000:]} {result.stderr[-1000:]}",
    )
    nodeids = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.startswith(support.TEST_MODULE + "::")
    ]
    expected = {support.test_ref(identifier) for identifier in support.SCENARIO_IDS}
    require(
        len(nodeids) == 36 and set(nodeids) == expected,
        "pytest did not actually collect the 36 unique matrix nodeids",
    )
    return nodeids


def validate_records(
    records: list[dict[str, Any]],
    *,
    expected_source_snapshot_sha256: str,
    nodeids: list[str],
    scenarios: list[dict[str, Any]] | None = None,
) -> None:
    """Validate the evidence contract only; this API does not certify live integration."""
    require(
        bool(_SHA256.fullmatch(expected_source_snapshot_sha256)), "missing parent source SHA256"
    )
    scenarios = support.read_matrix() if scenarios is None else scenarios
    matrix = {item["id"]: item for item in scenarios}
    require(len(records) == len(matrix) == 36, "ledger must contain exactly 36 records")
    require(
        len({record["scenario_id"] for record in records}) == 36
        and {record["scenario_id"] for record in records} == set(matrix),
        "duplicate or missing scenario records",
    )
    require(
        len(nodeids) == 36
        and len(set(nodeids)) == 36
        and set(nodeids) == {scenario["test_ref"] for scenario in scenarios},
        "matrix is not bound to actual pytest collection",
    )
    require(
        len({record["nodeid"] for record in records}) == 36
        and {record["nodeid"] for record in records} == set(nodeids),
        "duplicate or fake ledger nodeid",
    )
    identifiers = {record["run_id"] for record in records}
    require(
        len(identifiers) == 1
        and all(isinstance(value, str) and value.strip() for value in identifiers),
        "mixed or missing run IDs",
    )
    declared = os.getenv("AGENTGUARD_SECURITY_LEDGER_RUN_ID") or os.getenv("AGENTGUARD_RUN_ID")
    require(
        not declared or identifiers == {declared},
        "ledger run ID differs from the parent's current run",
    )
    manifests = []
    owned_execution_ids: set[str] = set()
    owned_task_ids: set[str] = set()
    for record in records:
        require(
            record["source_snapshot_sha256"]
            == record["source_snapshot"]["sha256"]
            == expected_source_snapshot_sha256,
            "source snapshot mismatch",
        )
        files = record["source_snapshot"]["input_files"]
        digest = hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        require(
            digest == record["source_snapshot"]["input_files_sha256"],
            "source input manifest hash mismatch",
        )
        require(
            all(
                isinstance(path, str) and bool(_SHA256.fullmatch(value))
                for path, value in files.items()
            ),
            "invalid source file reference",
        )
        manifests.append(files)
        validate_record(record, matrix[record["scenario_id"]])
        executions = {row["execution_id"] for row in record["after"]["executions"]}
        tasks = set(record["after"]["scope"]["task_ids"])
        require(
            not owned_execution_ids.intersection(executions)
            and not owned_task_ids.intersection(tasks),
            "aggregate evidence was copied across scenarios",
        )
        owned_execution_ids |= executions
        owned_task_ids |= tasks
    require(all(files == manifests[0] for files in manifests), "sources changed between scenarios")


def _validate_source(
    records: list[dict[str, Any]], expected: str, source_manifest: Path | dict[str, Any] | None
) -> dict[str, Any]:
    from scripts import source_manifest as source

    manifest = source.snapshot() if source_manifest is None else source_manifest
    if isinstance(manifest, Path):
        manifest = json.loads(manifest.read_text(encoding="utf-8-sig"))
    require(
        isinstance(manifest, dict) and manifest.get("snapshot_sha256") == expected,
        "parent source manifest SHA256 differs from the ledger/environment",
    )
    current = source.verify(manifest)
    inputs = support.source_inputs()
    require(
        all(record["source_snapshot"]["input_files"] == inputs for record in records),
        "current source files differ from scenario execution",
    )
    require(
        all(
            current["files"].get(path, {}).get("sha256") == digest
            for path, digest in inputs.items()
        ),
        "scenario source references are outside the parent manifest",
    )
    return current


def _validate_junit(path: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    root = ElementTree.parse(path).getroot()
    require(
        not root.findall(".//failure") and not root.findall(".//error"),
        "JUnit contains failures/errors; no publication",
    )
    cases = [
        case
        for case in root.iter("testcase")
        if case.get("classname", "").replace("/", ".").endswith("test_scenario_ledger_postgres")
    ]
    require(
        len(cases) == 36 and not any(case.find("skipped") is not None for case in cases),
        "JUnit does not contain 36 executed ledger scenarios",
    )
    names = [case.get("name") for case in cases]
    require(
        len(set(names)) == 36
        and set(names) == {"test_scenario[" + record["scenario_id"] + "]" for record in records},
        "JUnit/nodeid mapping mismatch",
    )
    for prop in root.iter("property"):
        if prop.get("name") in {"AGENTGUARD_SECURITY_LEDGER_RUN_ID", "run_id"}:
            require(prop.get("value") == records[0]["run_id"], "JUnit run ID mismatch")
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "ledger_cases_passed": 36,
    }


def verify_live_postgres(
    records: list[dict[str, Any]], database_url: str, audit_database_url: str
) -> dict[str, Any]:
    from backend.audit.service import AuditService
    from backend.identity.key_registry import PostgresKeyRegistry

    main = support.database_target(database_url)
    audit = support.database_target(audit_database_url, audit=True)
    require(
        main["name"].split("backend_", 1)[1] == audit["name"].split("backend_", 1)[1],
        "live main/audit databases belong to different isolated stacks",
    )
    for record in records:
        require(
            record["configuration"]["database"] == main
            and record["configuration"]["audit_database"] == audit,
            "live readback target differs from scenario configuration",
        )
        saved = record["after"]
        actual = support.snapshot(database_url, saved["scope"])
        for field in (*_TABLES, "budget", "revocations", "audit_events", "counts"):
            require(
                saved[field] == actual[field],
                f"{record['scenario_id']}: live PostgreSQL {field} differs from recorded evidence",
            )
        if "dispatch_cancellations" in saved:
            require(saved["dispatch_cancellations"] == actual["dispatch_cancellations"], f"{record['scenario_id']}: live cancellation evidence differs")
        if "gateway_signature" in record:
            recorded = record["gateway_signature"]
            key = PostgresKeyRegistry(database_url).get(recorded["key_id"])
            require(
                key.public_key_hex == recorded["public_key_hex"]
                and key.purpose.value == recorded["purpose"],
                "Tool envelope signer is not the actual PostgreSQL key",
            )
        if "key_lifecycle" in record:
            recorded = record["key_lifecycle"]
            key = PostgresKeyRegistry(database_url).get(recorded["key_id"])
            require(
                key.status.value == recorded["status"] == "COMPROMISED"
                and key.compromised_at == recorded["compromised_at"],
                "compromised-key scenario did not persist a real dedicated key compromise",
            )
    report = AuditService(database_url, audit_database_url=audit_database_url).verify()
    require(
        report["valid"] is True and report["rollback_detected"] is False,
        "live audit chain/checkpoint signature verification failed",
    )
    require(
        all(
            event["event_sequence"] <= report["latest_event_sequence"]
            for record in records
            for event in record["after"]["audit_events"]
        ),
        "ledger audit evidence is outside the verified live prefix",
    )
    return {
        "postgresql": "live_readback",
        "main": support.database_probe(database_url),
        "audit": support.database_probe(audit_database_url, audit=True),
        "audit_verification": report,
    }


_RECEIPT_PAYLOAD_FIELDS = (
    "schema_version",
    "receipt_id",
    "receipt_type",
    "execution_id",
    "request_id",
    "request_hash",
    "credential_chain_hash",
    "tenant_id",
    "task_id",
    "tool_service",
    "tool_name",
    "tool_version",
    "parameter_hash",
    "decision",
    "reason_code",
    "business_action_id",
    "business_idempotency_key",
    "business_effect_id",
    "business_result_hash",
    "budget_reserved",
    "budget_committed",
    "started_at",
    "finished_at",
    "decision_at",
    "business_effect_finalized_at",
    "receipt_issued_at",
    "receipt_signing_key_id",
)
_REQUEST_FIELDS = (
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
_RESPONSE_FIELDS = (
    "status",
    "decision",
    "reason_code",
    "state",
    "execution_id",
    "receipt_id",
    "task_id",
    "request_id",
    "request_hash",
    "admission_outcome",
    "business_action_id",
    "business_effect_id",
    "business_result_hash",
    "tool_outcome",
    "recovered",
    "skipped",
)


def _public_signature(signature: dict[str, Any]) -> dict[str, Any]:
    from backend.crypto.sm import sm3_hex

    result = {
        key: signature[key]
        for key in ("algorithm", "key_id", "key_purpose", "signed_at")
        if key in signature
    }
    if isinstance(signature.get("value"), str):
        result["fingerprint_sm3"] = sm3_hex(signature["value"].encode("ascii"))
    return result


def _public_receipt(receipt: Any) -> Any:
    from backend.crypto.sm import signed_object_hash

    if receipt is None:
        return None
    require(isinstance(receipt, dict) and "payload" in receipt, "not a validated signed receipt")
    return {
        "payload": {key: receipt["payload"][key] for key in _RECEIPT_PAYLOAD_FIELDS},
        "signature": _public_signature(receipt["signature"]),
        "receipt_hash": signed_object_hash(receipt),
        "signature_verified": True,
    }


def _public_request(call: dict[str, Any]) -> Any:
    from backend.crypto.canonical_json import canonicalize
    from backend.crypto.sm import sm3_hex

    body = call["request"]["json"]
    if not isinstance(body, dict) or _is_na(body):
        return support.not_applicable(
            "raw HTTP bytes did not establish a RequestContext; "
            "consult server-side RejectedAuditEvent"
        )
    projected = {
        key: body[key] for key in (*_REQUEST_FIELDS, "execution_id", "receipt_id") if key in body
    }
    if "canonical_parameters" in body:
        projected["parameter_hash"] = sm3_hex(canonicalize(body["canonical_parameters"]))
    if "credential_chain" in body:
        projected["credential_chain_hash"] = sm3_hex(canonicalize(body["credential_chain"]))
        projected["request_hash"] = sm3_hex(canonicalize(body))
    if "payload" in body and "signature" in body:
        projected = {
            key: body["payload"][key]
            for key in (
                "execution_id",
                "task_id",
                "tenant_id",
                "tool_service",
                "tool_name",
                "tool_version",
                "execution_attempt_id",
                "parameter_hash",
                "business_action_id",
                "issued_at",
                "expires_at",
            )
            if key in body["payload"]
        }
        projected["gateway_signature"] = _public_signature(body["signature"])
    return projected


def _public_response(body: Any) -> Any:
    if not isinstance(body, dict):
        return None
    result = {key: body[key] for key in _RESPONSE_FIELDS if key in body}
    if isinstance(body.get("detail"), dict):
        result["detail"] = {
            key: body["detail"][key] for key in ("reason_code", "status") if key in body["detail"]
        }
    if "receipt" in body:
        result["receipt"] = _public_receipt(body["receipt"])
    if isinstance(body.get("decisions"), list):
        result["decisions"] = [_public_response(decision) for decision in body["decisions"]]
    return result


def _public_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "scope": {
            "kind": value["scope"]["kind"],
            "task_ids": value["scope"]["task_ids"],
            "credential_levels": value["scope"]["credential_chains"],
            "raw_request_hashes": value["scope"]["raw_request_hashes"],
        },
        "counts": value["counts"],
        "global_counts": value["global_counts"],
        "budgets": value["budget"],
    }


def public_record(record: dict[str, Any]) -> dict[str, Any]:
    """Stable browser projection; never return raw request bytes or signed credentials."""
    requests = {call["call_id"]: call for call in record["requests"]}
    projected = {
        key: record[key]
        for key in (
            "schema_version",
            "run_id",
            "scenario_id",
            "nodeid",
            "test_ref",
            "status",
            "execution_layer",
            "evidence_scope",
            "expected_effect_delta",
            "source_snapshot_sha256",
            "started_at",
            "finished_at",
            "execution_ids",
            "receipt_ids",
        )
    }
    projected["source_snapshot"] = {
        "sha256": record["source_snapshot"]["sha256"],
        "input_files_sha256": record["source_snapshot"]["input_files_sha256"],
        "reference": record["source_snapshot"]["reference"],
    }
    projected["task_ids"] = record["after"]["scope"]["task_ids"]
    projected["before"], projected["after"] = (
        _public_snapshot(record[side]) for side in ("before", "after")
    )
    projected["delta"] = {
        "scope": record["evidence_scope"]["measurement"],
        "counts": {
            table: record["after"]["counts"][table] - record["before"]["counts"][table]
            for table in _TABLES
        },
        "global_counts": {
            table: record["after"]["global_counts"][table]
            - record["before"]["global_counts"][table]
            for table in record["before"]["global_counts"]
        },
    }
    projected["assertions"] = []
    for assertion in record["assertions"]:
        safe = {key: assertion[key] for key in ("name", "result")}
        for key in ("observed", "expected"):
            value = assertion.get(key)
            if value is None or isinstance(value, (str, bool, int)):
                safe[key] = value
            else:
                safe[key + "_sha256"] = hashlib.sha256(
                    json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
        projected["assertions"].append(safe)
    projected["observations"] = []
    for observed in record["observations"]:
        call = requests[observed["call_id"]]
        body = _public_response(observed["body"])
        projected["observations"].append(
            {
                **{key: observed[key] for key in ("kind", "label", "call_id", "status_code")},
                "request": _public_request(call),
                "body": body,
                "raw_request_hash": call["request"]["raw_request_hash"],
                "decision": body.get("decision"),
                "reason_code": body.get("reason_code", body.get("detail", {}).get("reason_code")),
                "execution_id": body.get("execution_id"),
                "receipt_id": body.get("receipt", {}).get("payload", {}).get("receipt_id")
                if body.get("receipt")
                else body.get("receipt_id"),
                "task_id": body.get("task_id") or _public_request(call).get("task_id"),
            }
        )
    projected["requests"] = [
        {
            key: call[key]
            for key in (
                "call_id",
                "phase",
                "method",
                "url",
                "transport",
                "started_at",
                "finished_at",
            )
            if key in call
        }
        | {
            "request": _public_request(call),
            "raw_request_hash": call["request"]["raw_request_hash"],
            "response": _public_response(call["response"].get("json")),
            **({"error_type": call["error_type"]} if "error_type" in call else {}),
        }
        for call in record["requests"]
    ]
    projected["operation_windows"] = [
        {
            "name": window["name"],
            "measurement": window["measurement"],
            "before": _public_snapshot(window["before"]),
            "after": _public_snapshot(window["after"]),
        }
        for window in record["operation_windows"]
    ]
    projected["receipts"] = [
        _public_receipt(row["signed_receipt"]) for row in record["after"]["receipts"]
    ]
    projected["audit_verification"] = {
        key: record["audit_verification"][key] for key in ("status", "call_id", "checkpoint_scope")
    }
    projected["audit_verification"]["report"] = record["audit_verification"]["response"]["json"]
    projected["audit_events"] = [
        {
            key: event[key]
            for key in (
                "outbox_event_id",
                "execution_id",
                "event_type",
                "payload_hash",
                "status",
                "event_sequence",
                "event_hash",
                "previous_event_hash",
            )
        }
        | {
            "reason_code": event["payload"].get("reason_code"),
            "parser_stage": event["payload"].get("parser_stage"),
            "raw_request_hash": event["payload"].get("raw_request_hash"),
        }
        for event in record["after"]["audit_events"]
    ]
    for key in (
        "legal_baseline",
        "new_receipt_evidence",
        "new_allow_receipt_evidence",
        "key_lifecycle",
    ):
        if key in record:
            projected[key] = record[key]
    if "fault" in record:
        projected["fault"] = {
            key: value
            for key, value in record["fault"].items()
            if key
            in {
                "mode",
                "driver",
                "execution_id",
                "worker_exit_code",
                "error_type",
                "real_tool_call_id",
            }
        }
    assert_public_projection(projected)
    return projected


def assert_public_projection(value: Any, *, parent: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            require(
                key
                not in {
                    "credential_chain",
                    "credential_chains",
                    "holder_proof",
                    "raw_hex",
                    "signed_object",
                    "private_key_inputs",
                },
                "unsafe browser evidence projection",
            )
            require(
                not (parent == "signature" and key == "value"),
                "signature value must not reach the browser",
            )
            assert_public_projection(item, parent=key)
    elif isinstance(value, list):
        for item in value:
            assert_public_projection(item, parent=parent)
    _no_secrets(value)


def _publish(
    summary: dict[str, Any],
    ledger_path: Path,
    records: list[dict[str, Any]],
    source_manifest: Path | dict[str, Any] | None,
) -> None:
    _validate_source(records, summary["source_snapshot_sha256"], source_manifest)
    require(
        hashlib.sha256(ledger_path.read_bytes()).hexdigest() == summary["ledger_sha256"],
        "ledger changed before publication",
    )
    assert_public_projection(summary["records"])
    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = SUMMARY_PATH.with_name("." + SUMMARY_PATH.name + "." + uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(summary, output, ensure_ascii=True, allow_nan=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        require(
            hashlib.sha256(ledger_path.read_bytes()).hexdigest() == summary["ledger_sha256"],
            "ledger changed while publishing",
        )
        _validate_source(records, summary["source_snapshot_sha256"], source_manifest)
        os.replace(temporary, SUMMARY_PATH)
    finally:
        temporary.unlink(missing_ok=True)


def validate_ledger(
    ledger_path: str | Path,
    *,
    source_manifest: str | Path | dict[str, Any] | None = None,
    junit: str | Path | None = None,
    expected_source_snapshot_sha256: str | None = None,
    database_url: str | None = None,
    audit_database_url: str | None = None,
    publish: bool = False,
) -> dict[str, Any]:
    """Certify real retained PostgreSQL evidence, returning only the public summary."""
    path = Path(ledger_path).resolve(strict=True)
    ledger_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = expected_source_snapshot_sha256 or os.getenv("AGENTGUARD_SOURCE_SNAPSHOT_SHA256")
    require(
        isinstance(expected, str) and bool(_SHA256.fullmatch(expected)),
        "AGENTGUARD_SOURCE_SNAPSHOT_SHA256 is required",
    )
    injected = os.getenv("AGENTGUARD_SOURCE_SNAPSHOT_SHA256")
    require(
        not injected or injected == expected,
        "explicit source SHA256 conflicts with the parent environment",
    )
    if isinstance(source_manifest, str):
        source_manifest = Path(source_manifest)
    records = read_jsonl(path)
    nodeids = collect_nodeids()
    validate_records(records, expected_source_snapshot_sha256=expected, nodeids=nodeids)
    _validate_source(records, expected, source_manifest)
    junit_report = _validate_junit(Path(junit), records) if junit is not None else None
    main = database_url or os.getenv("AGENTGUARD_DATABASE_URL")
    audit = audit_database_url or os.getenv("AGENTGUARD_AUDIT_DATABASE_URL")
    require(
        bool(main) and bool(audit),
        "retained isolated PostgreSQL URLs are required; "
        "stub/contract-only certification is forbidden",
    )
    validation = verify_live_postgres(records, main, audit)
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == ledger_sha256,
        "ledger changed during verification",
    )
    _validate_source(records, expected, source_manifest)
    summary = {
        "schema_version": "agentguard-security-ledger-summary-1.0",
        "status": "VERIFIED",
        "run_id": records[0]["run_id"],
        "source_snapshot_sha256": expected,
        "ledger_sha256": ledger_sha256,
        "ledger_path": str(path),
        "verified_at": support.utc_now(),
        "records": [public_record(record) for record in records],
        "validation": validation
        | {
            "nodeids": "pytest_collect_only",
            "junit": junit_report
            or support.not_applicable(
                "JUnit was not supplied; actual per-scenario PostgreSQL evidence was verified"
            ),
        },
    }
    assert_public_projection(summary["records"])
    if publish:
        _publish(summary, path, records, source_manifest)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify 36 real isolated HTTP/PostgreSQL security scenarios."
    )
    parser.add_argument("--ledger", type=Path, default=os.getenv("AGENTGUARD_SECURITY_LEDGER_PATH"))
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--junit", type=Path)
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Atomically publish the safe current-ledger summary only after all checks pass.",
    )
    arguments = parser.parse_args()
    if arguments.ledger is None:
        parser.error("--ledger or AGENTGUARD_SECURITY_LEDGER_PATH is required")
    try:
        summary = validate_ledger(
            arguments.ledger,
            source_manifest=arguments.source_manifest,
            junit=arguments.junit,
            publish=arguments.publish,
        )
    except Exception as exc:
        print(f"SECURITY_LEDGER=FAIL {support.sanitize(str(exc))}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "status",
                    "run_id",
                    "source_snapshot_sha256",
                    "ledger_sha256",
                    "ledger_path",
                    "verified_at",
                )
            }
            | {"records": len(summary["records"]), "published": bool(arguments.publish)},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
