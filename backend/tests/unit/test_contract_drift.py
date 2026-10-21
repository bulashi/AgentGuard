from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from pglast import parse_sql

from backend.common.enums import ExecutionState, KeyState, ReceiptStatus
from backend.common.error_codes import ReasonCode

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def load_json(relative: str) -> dict:
    return json.loads((PROJECT_ROOT / relative).read_text(encoding="utf-8"))


def sql_enum_values(sql: str, enum_name: str) -> set[str]:
    match = re.search(
        rf"CREATE TYPE\s+{re.escape(enum_name)}\s+AS ENUM\s*\((.*?)\);",
        sql,
        flags=re.DOTALL | re.IGNORECASE,
    )
    assert match, f"missing SQL enum {enum_name}"
    return set(re.findall(r"'([^']+)'", match.group(1)))


def test_state_sets_do_not_drift() -> None:
    manifest = load_json("protocol/manifest.json")
    machines = load_json("protocol/state-machines.json")
    sql = (PROJECT_ROOT / "database/migrations/main/0001_initial.sql").read_text(encoding="utf-8")
    openapi = yaml.safe_load((PROJECT_ROOT / "protocol/openapi.yaml").read_text(encoding="utf-8"))

    execution = {item.value for item in ExecutionState}
    assert execution == set(manifest["execution_states"])
    assert execution == set(machines["execution"]["states"])
    assert execution == sql_enum_values(sql, "execution_state")
    assert execution == set(
        openapi["components"]["schemas"]["ExecutionDecisionResponse"]["properties"]["state"]["enum"]
    )

    receipts = {item.value for item in ReceiptStatus}
    assert receipts == set(manifest["receipt_statuses"])
    assert receipts == set(machines["receipt"]["states"])
    assert receipts == sql_enum_values(sql, "receipt_status")

    keys = {item.value for item in KeyState}
    assert keys == set(manifest["key_states"])
    assert keys == set(machines["key"]["states"])
    assert keys == sql_enum_values(sql, "key_state")


def test_error_codes_do_not_drift() -> None:
    document = load_json("protocol/error-codes.json")
    openapi = yaml.safe_load((PROJECT_ROOT / "protocol/openapi.yaml").read_text(encoding="utf-8"))
    expected_errors = set(document["error_codes"])
    expected_success = set(document["success_codes"])
    actual = {item.value for item in ReasonCode}
    assert actual == expected_errors | expected_success
    assert set(openapi["components"]["schemas"]["ReasonCode"]["enum"]) == expected_errors


def test_api_surface_and_schema_inventory_are_frozen() -> None:
    openapi = yaml.safe_load((PROJECT_ROOT / "protocol/openapi.yaml").read_text(encoding="utf-8"))
    required_paths = {
        "/tasks",
        "/tasks/{task_id}/authorize",
        "/credentials/{credential_id}/delegate",
        "/gateway/execute",
        "/gateway/admit",
        "/gateway/dispatch",
        "/credentials/{credential_id}/revoke",
        "/gateway/results/retrieve",
        "/gateway/receipts/retrieve",
        "/audit/verify",
        "/security-tests/{scenario}",
        "/benchmarks/run",
        "/agents/run",
    }
    assert required_paths <= set(openapi["paths"])
    assert "/executions/{execution_id}" not in openapi["paths"]
    assert "/receipts/{receipt_id}" not in openapi["paths"]

    required_schemas = {
        "capability-credential.schema.json",
        "delegation-credential.schema.json",
        "business-action.schema.json",
        "request-envelope.schema.json",
        "request-context.schema.json",
        "holder-proof.schema.json",
        "validated-tool-command.schema.json",
        "gateway-execution-envelope.schema.json",
        "result-retrieval-request.schema.json",
        "execution-receipt.schema.json",
        "rejected-audit-event.schema.json",
        "audit-event.schema.json",
        "audit-checkpoint.schema.json",
    }
    actual = {path.name for path in (PROJECT_ROOT / "protocol/schemas").glob("*.schema.json")}
    assert required_schemas <= actual


def test_required_unique_constraints_exist() -> None:
    sql = (PROJECT_ROOT / "database/migrations/main/0001_initial.sql").read_text(encoding="utf-8")
    for table, column in (
        ("credentials", "credential_id"),
        ("execution_requests", "request_id"),
        ("business_actions", "business_action_id"),
        ("business_actions", "action_scope_key"),
        ("idempotency_records", "business_idempotency_key"),
        ("tool_execution_attempts", "execution_attempt_id"),
        ("execution_receipts", "receipt_id"),
        ("audit_outbox", "outbox_event_id"),
        ("audit_events", "outbox_event_id"),
        ("refunds", "business_idempotency_key"),
        ("notifications", "business_idempotency_key"),
    ):
        table_match = re.search(
            rf"CREATE TABLE\s+{table}\s*\((.*?)\n\);",
            sql,
            flags=re.DOTALL | re.IGNORECASE,
        )
        assert table_match, f"missing table {table}"
        body = table_match.group(1)
        assert re.search(
            rf"\b{column}\b[^\n]*(PRIMARY KEY|UNIQUE)|UNIQUE\s*\(\s*{column}\s*\)",
            body,
            flags=re.IGNORECASE,
        ), f"missing unique constraint {table}.{column}"

    retrieval_sql = (
        PROJECT_ROOT / "database/migrations/main/0010_result_retrieval_requests.sql"
    ).read_text(encoding="utf-8")
    assert re.search(
        r"CREATE TABLE\s+result_retrieval_requests\s*\(.*?\brequest_id\b[^\n]*PRIMARY KEY",
        retrieval_sql,
        flags=re.DOTALL | re.IGNORECASE,
    )


def test_postgresql_migrations_parse() -> None:
    migration_root = PROJECT_ROOT / "database/migrations"
    migrations = sorted(migration_root.rglob("*.sql"))
    assert migrations
    for migration in migrations:
        statements = parse_sql(migration.read_text(encoding="utf-8"))
        assert statements, f"migration parsed to no statements: {migration}"


def test_security_semantics_cover_every_protocol_object() -> None:
    semantics = load_json("protocol/security-semantics.json")["objects"]
    schema_names = {entry["schema"] for entry in semantics.values()}
    expected = {
        "capability-credential.schema.json",
        "delegation-credential.schema.json",
        "business-action.schema.json",
        "request-envelope.schema.json",
        "request-context.schema.json",
        "holder-proof.schema.json",
        "validated-tool-command.schema.json",
        "gateway-execution-envelope.schema.json",
        "result-retrieval-request.schema.json",
        "execution-receipt.schema.json",
        "rejected-audit-event.schema.json",
        "audit-event.schema.json",
        "audit-checkpoint.schema.json",
    }
    assert len(semantics) == 13
    assert schema_names == expected
    for entry in semantics.values():
        assert (PROJECT_ROOT / "protocol/schemas" / entry["schema"]).is_file()
        if entry["signed"]:
            assert entry["key_purpose"] is not None
            assert entry["domain_separator"].startswith("AGENTGUARD|")


def test_exactly_sixteen_invariants_and_attenuation_rules() -> None:
    invariants = load_json("protocol/invariants.json")["invariants"]
    assert [item["id"] for item in invariants] == [f"INV-{number:02d}" for number in range(1, 17)]
    rules = load_json("protocol/attenuation-rules.json")
    assert rules["failure_reason_code"] == "DELEGATION_ESCALATION"
    fields = {rule["field"] for rule in rules["rules"]}
    assert {"tenant_id", "task_id", "expires_at", "delegation_depth"} <= fields


def test_crypto_profile_is_frozen_and_matches_manifest() -> None:
    manifest = load_json("protocol/manifest.json")
    profile = load_json(f"protocol/{manifest['crypto_profile']}")
    assert profile["python_crypto_library"] == "gmssl"
    assert profile["python_crypto_library_version"] == "3.2.2"
    assert profile["sm2_user_id_utf8"] == manifest["sm2_user_id_utf8"]
    assert profile["signature_encoding"] == manifest["signature_encoding"]
    assert profile["hash_encoding"] == manifest["hash_encoding"]
    assert profile["database_private_key_material"] == "FORBIDDEN"
