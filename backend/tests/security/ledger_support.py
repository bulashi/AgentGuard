from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = ROOT / "attacks/deterministic_scenarios/scenarios.json"
TEST_MODULE = "backend/tests/security/test_scenario_ledger_postgres.py"
LEDGER_SCHEMA = "agentguard-security-ledger-1.0"
SCENARIO_IDS = (
    "malformed_json",
    "invalid_utf8",
    "duplicate_json_key",
    "unknown_field",
    "credential_tampering",
    "wrong_holder",
    "wrong_holder_key",
    "cross_tenant",
    "cross_task",
    "wrong_audience",
    "wrong_service",
    "tool_version_mismatch",
    "child_privilege_escalation",
    "parent_hash_tampering",
    "invalid_delegation_signer",
    "ancestor_revoked",
    "expired_credential",
    "stale_request",
    "request_replay",
    "negative_amount",
    "integer_overflow",
    "parameter_tampering_after_signature",
    "budget_overflow",
    "concurrent_double_spend",
    "same_action_same_params_retry",
    "same_action_different_params",
    "different_action_same_params",
    "crash_after_tool_success",
    "timeout_retry",
    "revocation_race",
    "gateway_envelope_replay",
    "expired_gateway_envelope",
    "compromised_holder_key",
    "result_retrieval_after_revocation",
    "result_retrieval_replay",
    "prompt_injection_out_of_scope",
)
PARSE_REASONS = {
    "malformed_json": "MALFORMED_JSON",
    "invalid_utf8": "INVALID_UTF8",
    "duplicate_json_key": "DUPLICATE_FIELD",
    "unknown_field": "UNKNOWN_FIELD",
    "integer_overflow": "REQUEST_SCHEMA_INVALID",
}
DELEGATION_SCENARIOS = {"child_privilege_escalation", "invalid_delegation_signer"}
TOOL_SCENARIOS = {"gateway_envelope_replay", "expired_gateway_envelope"}
RETRIEVAL_SCENARIOS = {"result_retrieval_after_revocation", "result_retrieval_replay"}
RECOVERY_SCENARIOS = {"crash_after_tool_success", "timeout_retry"}
POSITIVE_SCENARIOS = {
    "same_action_same_params_retry",
    "different_action_same_params",
    "concurrent_double_spend",
    *RECOVERY_SCENARIOS,
}
ISOLATED_PORTS = {
    "AGENTGUARD_AUTHORITY_URL": 28001,
    "AGENTGUARD_GATEWAY_URL": 28003,
    "AGENTGUARD_RECOVERY_URL": 28004,
    "AGENTGUARD_REVOCATION_URL": 28005,
    "AGENTGUARD_RECEIPT_SERVICE_URL": 28006,
    "AGENTGUARD_AUDIT_SERVICE_URL": 28007,
    "AGENTGUARD_CHECKPOINT_SERVICE_URL": 28008,
    "AGENTGUARD_COORDINATOR_DELEGATION_URL": 28101,
    "AGENTGUARD_CASE_DELEGATION_URL": 28102,
    "AGENTGUARD_REFUND_DELEGATION_URL": 28103,
    "AGENTGUARD_REFUND_TOOL_URL": 28303,
}
REQUIRED_ENVIRONMENT = (
    *ISOLATED_PORTS,
    "AGENTGUARD_DATABASE_URL",
    "AGENTGUARD_AUDIT_DATABASE_URL",
    "AGENTGUARD_HOLDER_PRIVATE_KEY_FILE",
    "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE",
)
_OMITTED_KEYS = {
    "headers",
    "authorization",
    "proxy-authorization",
    "x-agentguard-internal",
    "cookie",
    "set-cookie",
    "password",
    "passphrase",
    "api_key",
    "access_token",
    "private_key",
    "private_key_hex",
    "holder_private_key",
    "gateway_private_key",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def run_id() -> str:
    return (
        os.getenv("AGENTGUARD_SECURITY_LEDGER_RUN_ID")
        or os.getenv("AGENTGUARD_RUN_ID")
        or datetime.now(UTC).strftime("security-%Y%m%dT%H%M%SZ-") + uuid4().hex
    )


def not_applicable(reason: str) -> dict[str, str]:
    return {"status": "N/A", "reason": reason}


def test_ref(scenario_id: str) -> str:
    return f"{TEST_MODULE}::test_scenario[{scenario_id}]"


def scenario_contract(identifier: str) -> dict[str, Any]:
    if identifier not in SCENARIO_IDS:
        raise ValueError(f"unknown scenario: {identifier}")
    layer = "gateway_http_admission"
    limits = ["no_live_llm", "no_external_audit_custody_claim"]
    if identifier in PARSE_REASONS:
        layer = "gateway_http_parse"
    elif identifier in DELEGATION_SCENARIOS:
        layer = "delegation_http"
    elif identifier in TOOL_SCENARIOS:
        layer = "protected_tool_http_with_postgres_admission"
        limits.append("production_dispatch_transition_in_test_process; no_gateway_settlement")
    elif identifier in RETRIEVAL_SCENARIOS:
        layer = "gateway_http_result_retrieval"
    elif identifier in RECOVERY_SCENARIOS:
        layer = "http_postgres_recovery_with_owned_fault_driver"
        limits.append("production_dispatch_transition_in_owned_test_driver")
    elif identifier == "revocation_race":
        layer = "http_admission_revocation_with_postgres_lock_order"
    elif identifier in POSITIVE_SCENARIOS or identifier in {
        "request_replay",
        "same_action_different_params",
    }:
        layer = "gateway_http_dispatch"
    if identifier == "prompt_injection_out_of_scope":
        limits.append("deterministic_untrusted_tool_intent; not_llm_susceptibility")
    if identifier == "wrong_audience":
        limits.append(
            "submitted_audience_substitution; frozen_schema_rejects_before_signature_verification"
        )
    refund_delta = 0
    if identifier in POSITIVE_SCENARIOS:
        refund_delta = 2 if identifier == "different_action_same_params" else 1
    return {
        "test_ref": test_ref(identifier),
        "execution_layer": layer,
        "evidence_scope": {
            "measurement": "scenario_window"
            if identifier in POSITIVE_SCENARIOS or identifier == "revocation_race"
            else "attack_window",
            "budget": "every_quota_at_every_credential_level",
            "business": "scenario_tasks_and_isolated_database_global_deltas",
            "legal_baseline_effects": "counted_before_attack; never_unauthorized",
            "limits": limits,
        },
        "expected_effect_delta": {"refunds": refund_delta, "notifications": 0},
    }


def read_matrix(path: Path = MATRIX_PATH) -> list[dict[str, Any]]:
    matrix = json.loads(path.read_text(encoding="utf-8"))
    scenarios = matrix["scenarios"]
    ids = [item["id"] for item in scenarios]
    if len(ids) != 36 or len(set(ids)) != 36 or set(ids) != set(SCENARIO_IDS):
        raise ValueError("security ledger requires the exact 36 unique baseline scenarios")
    for item in scenarios:
        for field, expected in scenario_contract(item["id"]).items():
            if item.get(field) != expected:
                raise ValueError(
                    f"{item['id']}: matrix {field} differs from the execution contract"
                )
    return scenarios


def source_inputs(root: Path = ROOT) -> dict[str, str]:
    paths = [
        path
        for name in ("backend", "database", "protocol", "attacks", "scripts")
        for path in (root / name).rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix in {".py", ".sql", ".json", ".yaml", ".yml", ".ps1", ".ts"}
    ]
    paths.extend(root / name for name in ("pyproject.toml", "requirements.lock"))
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paths)
    }


def source_snapshot(root: Path = ROOT) -> dict[str, Any]:
    files = source_inputs(root)
    return {
        "sha256": os.getenv("AGENTGUARD_SOURCE_SNAPSHOT_SHA256"),
        "reference": "AGENTGUARD_SOURCE_SNAPSHOT_SHA256 (parent-owned source manifest)",
        "input_files": files,
        "input_files_sha256": hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def sanitize(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): sanitize(item, secrets)
            for key, item in value.items()
            if str(key).lower() not in _OMITTED_KEYS
            and not str(key).lower().endswith(("_password", "_api_key", "_private_key_hex"))
        }
    if isinstance(value, (list, tuple)):
        return [sanitize(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret:
                value = value.replace(secret, "[REDACTED]")
        value = re.sub(r"(?i)(postgres(?:ql)?(?:\+psycopg)?://)[^/\s@]+@", r"\1[REDACTED]@", value)
        value = re.sub(r"(?i)Bearer\s+\S+", "[REDACTED_AUTH]", value)
        return value
    return value


def append_record(path: Path, record: dict[str, Any], secrets: tuple[str, ...] = ()) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(sanitize(record, secrets), ensure_ascii=True, allow_nan=False) + "\n"
    with path.open("a", encoding="utf-8", newline="\n") as destination:
        destination.write(line)
        destination.flush()
        os.fsync(destination.fileno())


def database_target(url: str, *, audit: bool = False) -> dict[str, Any]:
    target = urlsplit(url)
    prefix = "agentguard_audit_test_backend_" if audit else "agentguard_test_backend_"
    name = unquote(target.path.removeprefix("/"))
    if (
        target.scheme not in {"postgresql", "postgresql+psycopg"}
        or target.hostname
        not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }
        or not re.fullmatch(prefix + r"[a-f0-9]+", name)
    ):
        raise ValueError("ledger refuses a non-parent-owned disposable local PostgreSQL database")
    if target.query or target.fragment:
        raise ValueError("ledger database URL must not have routing overrides")
    return {"kind": "postgresql", "name": name, "host": target.hostname, "port": target.port}


def check_environment(environment: Mapping[str, str]) -> dict[str, Any]:
    missing = [name for name in REQUIRED_ENVIRONMENT if not environment.get(name)]
    if missing:
        raise ValueError(f"inactive ledger integration environment: {', '.join(missing)}")
    main = database_target(environment["AGENTGUARD_DATABASE_URL"])
    audit = database_target(environment["AGENTGUARD_AUDIT_DATABASE_URL"], audit=True)
    if main["name"].split("backend_", 1)[1] != audit["name"].split("backend_", 1)[1]:
        raise ValueError("main and audit databases do not belong to the same isolated stack")
    services = {}
    for name, port in ISOLATED_PORTS.items():
        target = urlsplit(environment[name])
        if (
            target.scheme != "http"
            or target.hostname not in {"127.0.0.1", "localhost"}
            or target.port != port
            or target.path not in {"", "/"}
            or target.username
            or target.password
            or target.query
            or target.fragment
        ):
            raise ValueError(f"{name} is not the verify_native_backend.stack isolated endpoint")
        services[name] = environment[name].rstrip("/")
    if environment.get("AGENTGUARD_TEST_DEPLOYMENT") != "native":
        raise ValueError("ledger requires the native PostgreSQL test deployment")
    if environment.get("AGENTGUARD_CLOUD_LLM_ENABLED", "false").lower() != "false":
        raise ValueError("cloud LLM must be disabled for the deterministic ledger")
    if environment.get("PYTEST_XDIST_WORKER"):
        raise ValueError("ledger global deltas require the parent's serial security run")
    return {
        "reference": "scripts/verify_native_backend.py::stack",
        "deployment": "native",
        "database": main,
        "audit_database": audit,
        "services": services,
        "http_transport": "httpx.HTTPTransport",
        "stub_used": False,
        "cloud_llm_enabled": False,
        "private_key_inputs": {
            "holder": environment["AGENTGUARD_HOLDER_PRIVATE_KEY_FILE"],
            "gateway": environment["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"],
        },
    }


def database_probe(database_url: str, *, audit: bool = False) -> dict[str, Any]:
    from backend.state.database import connect

    expected = database_target(database_url, audit=audit)
    with connect(database_url) as connection:
        row = connection.execute(
            "SELECT current_database(), current_setting('server_version'), pg_backend_pid(), "
            "floor(EXTRACT(EPOCH FROM clock_timestamp()))::bigint"
        ).fetchone()
    if row is None or row[0] != expected["name"]:
        raise ValueError("live PostgreSQL identity differs from the isolated database URL")
    return {
        "database_name": row[0],
        "server_version": row[1],
        "backend_pid": row[2],
        "observed_at": row[3],
        "driver": "psycopg",
    }


def _rows(connection: Any, query: str, parameters: tuple[Any, ...]) -> list[dict[str, Any]]:
    from psycopg.rows import dict_row

    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(query, parameters)
        return list(cursor.fetchall())


def snapshot(database_url: str, scope: dict[str, Any]) -> dict[str, Any]:
    from backend.state.database import connect

    tasks = scope["task_ids"]
    credential_ids = sorted(
        {identifier for chain in scope["credential_chains"] for identifier in chain}
    )
    value: dict[str, Any] = {"scope": scope, "database_probe": database_probe(database_url)}
    with connect(database_url) as connection, connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        value["budget"] = _rows(
            connection,
            'SELECT credential_id, quota_type, limit_value AS "limit", reserved_value AS reserved, '
            "committed_value AS committed, version FROM credential_budget_state "
            "WHERE credential_id = ANY(%s) ORDER BY credential_id, quota_type",
            (credential_ids,),
        )
        value["executions"] = _rows(
            connection,
            "SELECT execution_id, initial_request_id, request_hash, credential_chain_hash, "
            "tenant_id, task_id, tool_service, tool_name, tool_version, parameter_hash, "
            "state::text, decision::text, reason_code, business_action_id, business_effect_id, "
            "business_result_hash, result, created_at, decision_at, terminal_at, "
            "terminal_state::text "
            "FROM execution_records WHERE task_id = ANY(%s) ORDER BY execution_id",
            (tasks,),
        )
        executions = [row["execution_id"] for row in value["executions"]]
        queries = {
            "refunds": (
                "SELECT refund_id, execution_id, business_action_id, business_idempotency_key, "
                "parameter_hash, tenant_id, task_id, ticket_id, customer_id, amount_fen, status "
                "FROM refunds WHERE task_id = ANY(%s) ORDER BY refund_id",
                tasks,
            ),
            "notifications": (
                "SELECT notification_id, execution_id, business_action_id, "
                "business_idempotency_key, parameter_hash, tenant_id, task_id, status "
                "FROM notifications WHERE task_id = ANY(%s) ORDER BY notification_id",
                tasks,
            ),
            "credentials": (
                "SELECT credential_id, task_id, parent_credential_id, parent_credential_hash, "
                "signed_object_hash, holder_key_id, delegation_depth, expires_at "
                "FROM credentials WHERE task_id = ANY(%s) ORDER BY credential_id",
                tasks,
            ),
            "requests": (
                "SELECT request_id, execution_id, request_hash, admission_outcome "
                "FROM execution_requests WHERE execution_id = ANY(%s) ORDER BY request_id",
                executions,
            ),
            "tool_attempts": (
                "SELECT execution_attempt_id, execution_id, envelope_hash, "
                "status, tool_outcome::text FROM tool_execution_attempts "
                "WHERE execution_id = ANY(%s) ORDER BY execution_attempt_id",
                executions,
            ),
            "reservations": (
                "SELECT execution_id, credential_id, quota_type, amount, status "
                "FROM execution_budget_reservations WHERE execution_id = ANY(%s) "
                "ORDER BY execution_id, credential_id, quota_type",
                executions,
            ),
            "receipts": (
                "SELECT r.receipt_id, r.execution_id, r.decision::text, r.reason_code, "
                "r.signed_receipt, r.receipt_hash, k.key_id, k.public_key_hex, k.purpose::text "
                "FROM execution_receipts r JOIN key_registry k "
                "ON k.key_id = r.signed_receipt->'signature'->>'key_id' "
                "WHERE r.execution_id = ANY(%s) ORDER BY r.receipt_id",
                executions,
            ),
            "retrievals": (
                "SELECT request_id, request_hash, task_id, target_type, target_id, "
                "execution_id, receipt_id, outcome, reason_code FROM result_retrieval_requests "
                "WHERE task_id = ANY(%s) ORDER BY request_id",
                tasks,
            ),
            "replay_denials": (
                "SELECT attempt_id, request_id, original_execution_id, denial_execution_id, "
                "reason_code FROM replay_denial_attempts WHERE original_execution_id = ANY(%s) "
                "OR denial_execution_id = ANY(%s) ORDER BY attempt_id",
                executions,
            ),
        }
        for name, (query, params) in queries.items():
            value[name] = _rows(
                connection, query, (params, params) if name == "replay_denials" else (params,)
            )
        value["dispatch_cancellations"] = _rows(
            connection,
            "SELECT cancellation_id, execution_id, denial_execution_id, request_id, request_hash, "
            "credential_chain_hash, reason_code, cancelled_at, evidence "
            "FROM dispatch_cancellations WHERE execution_id = ANY(%s) ORDER BY cancellation_id",
            (executions,),
        )
        value["revocations"] = _rows(
            connection,
            "SELECT credential_id, revoked_at, revocation_reason, revoked_by "
            "FROM credential_revocations WHERE credential_id = ANY(%s) ORDER BY credential_id",
            (credential_ids,),
        )
        value["audit_events"] = _rows(
            connection,
            "SELECT o.outbox_event_id, o.execution_id, o.event_type, o.payload, o.payload_hash, "
            "o.status::text, e.event_sequence, e.event_hash, e.previous_event_hash "
            "FROM audit_outbox o LEFT JOIN audit_events e USING (outbox_event_id) "
            "WHERE o.execution_id = ANY(%s) OR o.payload->>'task_id' = ANY(%s) "
            "OR o.payload->>'raw_request_hash' = ANY(%s) "
            "OR o.payload->>'retrieval_request_id' = ANY(%s) "
            "ORDER BY o.outbox_event_id",
            (
                executions,
                tasks,
                scope["raw_request_hashes"],
                [row["request_id"] for row in value["retrievals"]],
            ),
        )
        global_row = connection.execute(
            "SELECT (SELECT count(*) FROM refunds), (SELECT count(*) FROM notifications), "
            "(SELECT count(*) FROM execution_records), (SELECT count(*) FROM execution_requests), "
            "(SELECT count(*) FROM execution_receipts), "
            "(SELECT count(*) FROM tool_execution_attempts)"
        ).fetchone()
    value["counts"] = {name: len(value[name]) for name in queries}
    value["counts"]["executions"] = len(value["executions"])
    value["global_counts"] = dict(
        zip(
            ("refunds", "notifications", "executions", "requests", "receipts", "tool_attempts"),
            global_row,
            strict=True,
        )
    )
    return value


class ScenarioLedger:
    def __init__(
        self,
        scenario: dict[str, Any],
        nodeid: str,
        identifier: str,
        path: Path,
    ) -> None:
        self.scenario = scenario
        self.path = path
        self.secrets: tuple[str, ...] = ()
        self.phase = "setup"
        self.allowed_proxy_ports: set[int] = set()
        self.lock = threading.Lock()
        self.scope: dict[str, Any] = {
            "kind": "scenario_tasks_and_credential_chains",
            "task_ids": [],
            "credential_chains": [],
            "raw_request_hashes": [],
        }
        self.record: dict[str, Any] = {
            "schema_version": LEDGER_SCHEMA,
            "run_id": identifier,
            "scenario_id": scenario["id"],
            "nodeid": nodeid,
            **scenario_contract(scenario["id"]),
            "source_snapshot": source_snapshot(),
            "source_snapshot_sha256": os.getenv("AGENTGUARD_SOURCE_SNAPSHOT_SHA256"),
            "started_at": utc_now(),
            "status": "NOT_RUN",
            "configuration": not_applicable("integration has not been prepared"),
            "requests": [],
            "observations": [],
            "operation_windows": [],
            "assertions": [],
            "fixture_operations": [],
            "before": not_applicable("scenario operation has not started"),
            "after": not_applicable("scenario operation has not finished"),
            "audit_verification": not_applicable("audit has not been verified"),
            "execution_ids": not_applicable("no observed execution yet"),
            "receipt_ids": not_applicable("no observed signed receipt yet"),
        }

    def check(self, name: str, passed: bool, *, observed: Any = None, expected: Any = True) -> None:
        entry = {
            "name": name,
            "result": "PASS" if passed else "FAIL",
            "expected": expected,
            "observed": passed if observed is None else observed,
        }
        self.record["assertions"].append(entry)
        if not passed:
            raise AssertionError(name)

    def equal(self, name: str, observed: Any, expected: Any) -> None:
        self.check(name, observed == expected, observed=observed, expected=expected)

    def prepare(self) -> None:
        configuration = check_environment(os.environ)
        self.record["configuration"] = configuration
        self.check(
            "pytest nodeid equals unique matrix test_ref",
            self.record["nodeid"] == self.scenario["test_ref"],
        )
        self.check(
            "parent source snapshot is a SHA256",
            bool(re.fullmatch(r"[a-f0-9]{64}", self.record["source_snapshot_sha256"] or "")),
        )
        for name in ("AGENTGUARD_DATABASE_URL", "AGENTGUARD_AUDIT_DATABASE_URL"):
            password = urlsplit(os.environ[name]).password
            if password:
                self.secrets += (unquote(password),)
        for name in ("AGENTGUARD_HOLDER_PRIVATE_KEY_FILE", "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"):
            private = Path(os.environ[name]).read_text(encoding="ascii").strip()
            self.secrets += (private, private.encode().hex())
        configuration["database_probe"] = database_probe(os.environ["AGENTGUARD_DATABASE_URL"])
        configuration["audit_database_probe"] = database_probe(
            os.environ["AGENTGUARD_AUDIT_DATABASE_URL"],
            audit=True,
        )
        configuration["health"] = {}
        with httpx.Client(timeout=10, trust_env=False) as client:
            for name, url in configuration["services"].items():
                response = client.get(f"{url}/health")
                body = response.json()
                self.check(
                    f"live HTTP health {name}",
                    response.status_code == 200 and body.get("status") == "ok",
                )
                configuration["health"][name] = body

    @contextmanager
    def capture_http(self, monkeypatch: Any) -> Iterator[None]:
        from backend.crypto.sm import sm3_hex
        from backend.crypto.strict_json import StrictJsonError, parse_strict_json

        original = httpx.Client.send
        ledger = self

        def send(client: httpx.Client, request: httpx.Request, **kwargs: Any) -> httpx.Response:
            target = request.url
            transport = client._transport_for_url(target)
            transport_name = f"{type(transport).__module__}.{type(transport).__name__}"
            if not isinstance(transport, httpx.HTTPTransport):
                raise AssertionError("security ledger refuses stub/ASGI HTTP transports")
            if (
                target.scheme != "http"
                or target.host not in {"127.0.0.1", "localhost"}
                or target.port not in {*ISOLATED_PORTS.values(), *ledger.allowed_proxy_ports}
            ):
                raise AssertionError(
                    "security ledger HTTP call escaped the parent-owned isolated stack"
                )
            raw = request.content
            try:
                parsed: Any = parse_strict_json(raw) if raw else None
            except StrictJsonError:
                parsed = not_applicable("raw bytes do not establish an unambiguous RequestContext")
            with ledger.lock:
                call_id = f"HTTP-{len(ledger.record['requests']) + 1:04d}"
                call = {
                    "call_id": call_id,
                    "phase": ledger.phase,
                    "method": request.method,
                    "url": str(target),
                    "transport": transport_name,
                    "started_at": utc_now(),
                    "started_monotonic_ns": time.monotonic_ns(),
                    "request": {
                        "raw_hex": raw.hex(),
                        "raw_request_hash": sm3_hex(raw),
                        "json": parsed,
                    },
                    "response": not_applicable("HTTP response has not arrived"),
                }
                ledger.record["requests"].append(call)
            try:
                response = original(client, request, **kwargs)
                response.read()
                try:
                    body = response.json()
                except ValueError:
                    body = {"text": response.text}
                call["response"] = {"status_code": response.status_code, "json": body}
                response.extensions["security_ledger_call_id"] = call_id
                return response
            except BaseException as exc:
                call["error_type"] = type(exc).__name__
                raise
            finally:
                call["finished_at"] = utc_now()
                call["finished_monotonic_ns"] = time.monotonic_ns()

        with monkeypatch.context() as patch:
            patch.setattr(httpx.Client, "send", send)
            yield

    def add_chain(self, task_id: str, credential_ids: list[str]) -> None:
        if task_id not in self.scope["task_ids"]:
            self.scope["task_ids"].append(task_id)
            self.scope["task_ids"].sort()
        if credential_ids not in self.scope["credential_chains"]:
            self.scope["credential_chains"].append(list(credential_ids))

    def take_snapshot(self) -> dict[str, Any]:
        scope = json.loads(json.dumps(self.scope))
        return snapshot(os.environ["AGENTGUARD_DATABASE_URL"], scope)

    @contextmanager
    def window(self, name: str, *, primary: bool = False) -> Iterator[dict[str, Any]]:
        previous = self.phase
        self.phase = name
        entry = {
            "name": name,
            "measurement": "primary" if primary else "step",
            "before": self.take_snapshot(),
            "after": not_applicable("window is running"),
        }
        self.record["operation_windows"].append(entry)
        if primary:
            self.record["before"] = entry["before"]
        try:
            yield entry
        finally:
            try:
                entry["after"] = self.take_snapshot()
                if primary:
                    self.record["after"] = entry["after"]
            except BaseException as exc:
                entry["snapshot_error"] = type(exc).__name__
                self.record["snapshot_error"] = type(exc).__name__
                raise
            finally:
                self.phase = previous

    def observe(self, response: httpx.Response, *, kind: str, label: str) -> dict[str, Any]:
        body = response.json()
        self.record["observations"].append(
            {
                "kind": kind,
                "label": label,
                "call_id": response.extensions["security_ledger_call_id"],
                "status_code": response.status_code,
                "body": body,
            }
        )
        return body

    def verify_audit(self) -> None:
        from backend.tests.security.test_deterministic_security import (
            _append_audit,
            _checkpoint,
            _verify_audit,
        )

        previous = self.phase
        self.phase = "audit_verification"
        try:
            _append_audit()
            _checkpoint()
            _verify_audit()
            call = next(
                call
                for call in reversed(self.record["requests"])
                if call["url"].endswith("/audit/verify")
            )
            self.record["audit_verification"] = {
                "status": "VERIFIED",
                "call_id": call["call_id"],
                "response": call["response"],
                "checkpoint_scope": "local_isolated_audit_database",
            }
            if self.scope["task_ids"]:
                self.record["after"] = self.take_snapshot()
        finally:
            self.phase = previous

    def finish(self, status: str, error: BaseException | None = None) -> None:
        self.record["status"] = status
        if error is not None:
            self.record["failure"] = {
                "type": type(error).__name__,
                "message": sanitize(str(error), self.secrets),
            }
        self.record["finished_at"] = utc_now()
        after = self.record["after"]
        if "executions" in after:
            execution_ids = [row["execution_id"] for row in after["executions"]]
            receipt_ids = [row["receipt_id"] for row in after["receipts"]]
            self.record["execution_ids"] = execution_ids or not_applicable(
                "this boundary rejected the request without creating an execution"
            )
            self.record["receipt_ids"] = receipt_ids or not_applicable(
                "this boundary has no terminal Gateway receipt; no receipt was manufactured"
            )
        self.record["source_inputs_unchanged"] = (
            source_inputs() == self.record["source_snapshot"]["input_files"]
        )

    def persist(self) -> None:
        append_record(self.path, self.record, self.secrets)


def write_not_run(
    scenarios: list[dict[str, Any]],
    path: Path,
    identifier: str,
    reason: str,
) -> None:
    for scenario in scenarios:
        ledger = ScenarioLedger(scenario, scenario["test_ref"], identifier, path)
        ledger.finish("NOT_RUN")
        ledger.record["not_run_reason"] = reason
        ledger.persist()


def make_dispatched_envelope(body: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    from backend.admission.service import AdmissionService
    from backend.gateway.contracts import ValidatedToolCommandModel
    from backend.gateway.dispatch import GatewayDispatchService
    from backend.gateway.service import SecureGatewayService

    check_environment(os.environ)
    gateway = SecureGatewayService(database_url=os.environ["AGENTGUARD_DATABASE_URL"])
    service = GatewayDispatchService(
        gateway,
        AdmissionService(gateway),
        tool_urls={("refund-service", "refund.create"): os.environ["AGENTGUARD_REFUND_TOOL_URL"]},
        gateway_key_id="gateway-key-01",
        gateway_private_key_file=os.environ["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"],
    )
    command = ValidatedToolCommandModel.model_validate(body["validated_command"])
    envelope = service._mark_dispatched(command, request_hash=body["request_hash"])
    if envelope is None:
        raise AssertionError("real admitted execution did not enter DISPATCHED")
    return service, envelope.model_dump(mode="json")


def crash_worker() -> None:
    import sys

    from backend.crypto.sm import sm3_hex

    check_environment(os.environ)
    body = json.loads(sys.stdin.read())
    _service, envelope = make_dispatched_envelope(body)
    started_at = utc_now()
    started = time.monotonic_ns()
    with httpx.Client(timeout=20, trust_env=False) as client:
        response = client.post(
            os.environ["AGENTGUARD_REFUND_TOOL_URL"] + "/internal/execute", json=envelope
        )
    raw = response.request.content
    packet = {
        "execution_id": body["execution_id"],
        "fault_mode": "process_exit_after_real_tool_success",
        "envelope": envelope,
        "call": {
            "call_id": f"CRASH-HTTP-{uuid4().hex}",
            "phase": "crash_boundary",
            "method": "POST",
            "url": str(response.request.url),
            "transport": "httpx.HTTPTransport",
            "started_at": started_at,
            "finished_at": utc_now(),
            "started_monotonic_ns": started,
            "finished_monotonic_ns": time.monotonic_ns(),
            "request": {"raw_hex": raw.hex(), "raw_request_hash": sm3_hex(raw), "json": envelope},
            "response": {"status_code": response.status_code, "json": response.json()},
        },
    }
    print(json.dumps(packet, ensure_ascii=True, allow_nan=False), flush=True)
    os._exit(86 if response.status_code == 200 else 87)


def timeout_after_real_tool_response(
    ledger: ScenarioLedger, envelope: dict[str, Any]
) -> dict[str, Any]:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    done = threading.Event()
    release = threading.Event()
    forwarded: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def do_POST(self) -> None:
            try:
                if self.path != "/internal/execute":
                    raise AssertionError("unexpected fault-proxy path")
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                with httpx.Client(timeout=20, trust_env=False) as client:
                    response = client.post(
                        os.environ["AGENTGUARD_REFUND_TOOL_URL"] + self.path,
                        content=raw,
                        headers={"Content-Type": "application/json"},
                    )
                forwarded["call_id"] = response.extensions["security_ledger_call_id"]
                forwarded["status_code"] = response.status_code
                forwarded["body"] = response.json()
            except BaseException as exc:
                forwarded["error_type"] = type(exc).__name__
            finally:
                done.set()
                # Withhold the real response until the caller's TCP read times out.
                release.wait(25)
                self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    ledger.allowed_proxy_ports.add(port)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    error_type = None
    try:
        with httpx.Client(timeout=httpx.Timeout(5, read=0.5), trust_env=False) as client:
            try:
                client.post(f"http://127.0.0.1:{port}/internal/execute", json=envelope)
            except httpx.ReadTimeout as exc:
                error_type = type(exc).__name__
        if not done.wait(20):
            raise AssertionError("real downstream Tool response did not arrive at the fault proxy")
        if error_type != "ReadTimeout" or forwarded.get("status_code") != 200:
            raise AssertionError(
                "fault proxy did not observe a real successful Tool call and TCP ReadTimeout"
            )
        return {
            "mode": "withheld_real_http_response",
            "error_type": error_type,
            "proxy_url": f"http://127.0.0.1:{port}",
            "real_tool_call_id": forwarded["call_id"],
            "real_tool_response": forwarded["body"],
        }
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    crash_worker()
