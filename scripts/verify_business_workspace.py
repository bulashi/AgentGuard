from __future__ import annotations

import argparse
import importlib.metadata
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import psycopg
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from backend.agent_runtime.knowledge_attacks import forged_approval_addendum
from backend.business_action.contracts import RawBusinessFacts
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.state.database import connect, psycopg_url
from backend.ui_api.store import UiReadStore
from scripts.native_runtime import (
    CONFIG,
    PYTHON,
    ROOT,
    RUNTIME,
    STATE,
    clean_environment,
    database_urls,
    matching_process,
    read_json,
    write_json,
)
from scripts.source_manifest import snapshot
from scripts.verify_native import audit_check, verify_receipts

AGENTS = {"agent-coordinator", "agent-knowledge", "agent-case", "agent-refund"}
STAGES = {"coordinate", "knowledge_read", "knowledge_summary", "case_read", "refund", "case_notify"}
CORE_TABLES = (
    "tasks",
    "credentials",
    "credential_budget_state",
    "key_registry",
    "business_actions",
    "execution_records",
    "execution_receipts",
    "audit_outbox",
    "refunds",
    "notifications",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def public_only(value: Any) -> None:
    if isinstance(value, dict):
        require(
            not (
                {
                    "workflow_token",
                    "observation_token_hash",
                    "private_key",
                    "api_key",
                    "credential_chain",
                    "holder_proof",
                    "reasoning_content",
                    "response_content",
                }
                & set(value)
            ),
            "browser projection exposed restricted fields",
        )
        signature = value.get("signature")
        require(
            not isinstance(signature, dict) or "value" not in signature,
            "browser projection exposed reusable signature material",
        )
        for item in value.values():
            public_only(item)
    elif isinstance(value, list):
        for item in value:
            public_only(item)


def command(
    command: list[str],
    directory: Path,
    name: str,
    *,
    env: dict[str, str] | None = None,
    cwd: Path = ROOT,
) -> dict:
    started = time.time()
    with (directory / f"{name}.txt").open("w", encoding="utf-8") as log:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=clean_environment({"PYTHONIOENCODING": "utf-8"} | (env or {})),
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    report = {
        "command": [
            str(Path(command[0]).relative_to(ROOT))
            if Path(command[0]).is_relative_to(ROOT)
            else command[0],
            *command[1:],
        ],
        "cwd": str(cwd.relative_to(ROOT)) or ".",
        "exit_code": result.returncode,
        "duration_seconds": round(time.time() - started, 3),
        "log": f"{name}.txt",
    }
    if any(item.startswith("--junitxml=") for item in command):
        junit = Path(
            next(item.split("=", 1)[1] for item in command if item.startswith("--junitxml="))
        )
        suites = ET.parse(junit).getroot()
        report |= {
            key: sum(int(suite.get(key, "0")) for suite in suites)
            for key in ("tests", "failures", "errors", "skipped")
        }
    write_json(directory / f"{name}.command.json", report)
    require(report.get("skipped", 0) == 0, f"{name} skipped required checks")
    require(result.returncode == 0, f"{name} failed; inspect {name}.txt")
    return report


def regression_environment(urls: dict[str, str]) -> dict[str, str]:
    return {
        "AGENTGUARD_DATABASE_URL": urls["main"],
        "AGENTGUARD_AUDIT_DATABASE_URL": urls["audit"],
        "AGENTGUARD_AUTHORITY_URL": "http://127.0.0.1:18001",
        "AGENTGUARD_COORDINATOR_DELEGATION_URL": "http://127.0.0.1:18101",
        "AGENTGUARD_CASE_DELEGATION_URL": "http://127.0.0.1:18102",
        "AGENTGUARD_REFUND_DELEGATION_URL": "http://127.0.0.1:18103",
        "AGENTGUARD_COORDINATOR_AGENT_URL": "http://127.0.0.1:18201",
        "AGENTGUARD_REFUND_AGENT_URL": "http://127.0.0.1:18204",
        "AGENTGUARD_GATEWAY_URL": "http://127.0.0.1:18003",
        "AGENTGUARD_HOLDER_PRIVATE_KEY_FILE": str(RUNTIME / "keys/private/agent-refund.private"),
        "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE": str(RUNTIME / "keys/private/gateway.private"),
        "AGENTGUARD_TICKET_TOOL_URL": "http://127.0.0.1:18301",
        "AGENTGUARD_KNOWLEDGE_TOOL_URL": "http://127.0.0.1:18302",
        "AGENTGUARD_REFUND_TOOL_URL": "http://127.0.0.1:18303",
        "AGENTGUARD_NOTIFICATION_TOOL_URL": "http://127.0.0.1:18304",
        "AGENTGUARD_RECOVERY_URL": "http://127.0.0.1:18004",
        "AGENTGUARD_REVOCATION_URL": "http://127.0.0.1:18005",
        "AGENTGUARD_RECEIPT_SERVICE_URL": "http://127.0.0.1:18006",
        "AGENTGUARD_AUDIT_SERVICE_URL": "http://127.0.0.1:18007",
        "AGENTGUARD_CHECKPOINT_SERVICE_URL": "http://127.0.0.1:18008",
    }


def permissions(urls: dict[str, str], state: dict) -> dict:
    result: dict[str, Any] = {}
    with psycopg.connect(psycopg_url(urls["ui"]), autocommit=True) as connection:
        result["ui_default_transaction_read_only"] = connection.execute(
            "SHOW default_transaction_read_only"
        ).fetchone()[0]
        require(
            result["ui_default_transaction_read_only"] == "on",
            "UI default transaction is not read-only",
        )
        for table in CORE_TABLES:
            require(
                not connection.execute(
                    "SELECT has_table_privilege(current_user, %s, 'INSERT,UPDATE,DELETE')", (table,)
                ).fetchone()[0],
                f"UI has write access to {table}",
            )
        try:
            with connection.transaction():
                connection.execute("SET TRANSACTION READ WRITE")
                connection.execute("UPDATE tasks SET updated_at=updated_at WHERE false")
        except psycopg.errors.InsufficientPrivilege:
            result["ui_write_rejected_after_readonly_override"] = True
        else:
            raise RuntimeError("UI role can write after overriding read-only default")
    with connect(urls["workflow"]) as connection:
        for table in CORE_TABLES:
            require(
                not connection.execute(
                    "SELECT has_table_privilege(current_user, %s, 'SELECT,INSERT,UPDATE,DELETE')",
                    (table,),
                ).fetchone()[0],
                f"workflow writer has authority access to {table}",
            )
        for table, grants in (
            ("agent_workflow_runs", ("SELECT", "INSERT", "UPDATE")),
            ("agent_workflow_events", ("SELECT", "INSERT")),
        ):
            for privilege in grants:
                require(
                    connection.execute(
                        "SELECT has_table_privilege(current_user, %s, %s)", (table, privilege)
                    ).fetchone()[0],
                    "workflow observation grants are missing",
                )
        require(
            not connection.execute(
                "SELECT has_table_privilege(current_user, 'agent_workflow_events', 'UPDATE,DELETE')"
            ).fetchone()[0],
            "workflow events are not append-only for the runtime role",
        )
        result["workflow_role_core_table_access"] = False
        result["workflow_events_update_delete"] = False
    result["agent_process_boundaries"] = []
    for item in state["processes"]:
        if item.get("name") not in {
            "coordinator-agent",
            "knowledge-agent",
            "case-agent",
            "refund-agent",
            "ui-api",
        }:
            continue
        process = matching_process(item)
        require(process is not None, "managed process identity changed")
        environment = process.environ()
        require(
            not any(
                key in environment
                for key in ("AGENTGUARD_DATABASE_URL", "AGENTGUARD_AUDIT_DATABASE_URL")
            ),
            "runtime inherited authority database credentials",
        )
        if item["name"] == "ui-api":
            require(
                not any("PRIVATE_KEY" in key or "CLOUD_LLM_API_KEY" in key for key in environment),
                "BFF inherited signing or provider credentials",
            )
        elif item["name"] != "coordinator-agent":
            require(
                not environment.get("AGENTGUARD_WORKFLOW_DATABASE_URL"),
                "child role inherited workflow database writer",
            )
        result["agent_process_boundaries"].append(
            {
                "service": item["name"],
                "authority_database_environment": False,
                "identity_verified": True,
            }
        )
    require(
        len(result["agent_process_boundaries"]) == 5,
        "required native process boundaries were not checked",
    )
    return result


def knowledge_state(url: str) -> list:
    with connect(url) as connection:
        return [
            list(row)
            for row in connection.execute(
                "SELECT document_id, content FROM knowledge_documents ORDER BY document_id"
            ).fetchall()
        ]


def business_rows(url: str, task_id: str) -> dict:
    with connect(url) as connection:
        refunds = connection.execute(
            "SELECT tenant_id, ticket_id, customer_id, amount_fen, status, refund_id "
            "FROM refunds WHERE task_id=%s ORDER BY refund_id",
            (task_id,),
        ).fetchall()
        notices = connection.execute(
            "SELECT tenant_id, customer_id, template_id, status, related_business_effect_id "
            "FROM notifications WHERE task_id=%s ORDER BY notification_id",
            (task_id,),
        ).fetchall()
    return {
        "refunds": [list(row) for row in refunds],
        "notifications": [list(row) for row in notices],
    }


def validate_refund_ticket_input(ticket: Any, task: dict) -> None:
    require(
        isinstance(ticket, dict) and ticket.get("ticket_id") == task["ticket_id"],
        "actual ticket result did not reach the refund role",
    )
    if "business_facts" in ticket or "facts_hash" in ticket:
        require(
            set(ticket)
            == {
                "ticket_id",
                "tenant_id",
                "customer_id",
                "status",
                "facts_hash",
                "business_facts",
            }
            and ticket["tenant_id"] == task["tenant_id"]
            and ticket["customer_id"] == task["customer_id"]
            and isinstance(ticket["status"], str)
            and bool(ticket["status"].strip()),
            "fact ticket contains a precomputed verdict, missing source fields or mismatched scope",
        )
        facts = ticket["business_facts"]
        require(isinstance(facts, dict) and bool(facts), "refund raw business facts are missing")
        try:
            RawBusinessFacts.model_validate(facts)
        except ValidationError:
            raise RuntimeError("refund raw business facts or claim text are invalid") from None
        facts_hash = ticket["facts_hash"]
        require(
            isinstance(facts_hash, str)
            and len(facts_hash) == 64
            and all(character in "0123456789abcdef" for character in facts_hash)
            and facts_hash == sm3_hex(canonicalize(facts)),
            "refund raw business facts hash is missing, invalid or inconsistent",
        )
    else:
        description = ticket.get("description")
        require(
            isinstance(description, str) and bool(description.strip()),
            "actual fixture ticket description did not reach the refund role",
        )


def validate_workflow(value: dict, urls: dict[str, str], mode: str, scenario: str) -> dict:
    task = value["task"]
    run = value["workflow_runs"][0]
    schema = read_json(ROOT / "protocol/schemas/workflow-run.schema.json")
    Draft202012Validator(schema).validate(run)
    public_only(value)
    events = run["events"]
    require(
        [event["sequence"] for event in events] == list(range(1, len(events) + 1)),
        "operational sequences are not contiguous",
    )
    require(
        run["runtime_mode"] == mode and run["scenario"] == scenario,
        "stored mode or scenario changed",
    )
    require(
        all(event["recorded_at_ms"] >= event["timestamp_ms"] for event in events),
        "operational timestamps are inconsistent",
    )
    plans = [
        event for event in events if event["action"] == "plan" and event["status"] == "COMPLETED"
    ]
    started = [event for event in events if event["action"] == "plan_started"]
    inputs = {event["details"]["stage"]: event["details"]["input"] for event in started}
    actual = business_rows(urls["main"], value["task"]["task_id"])
    require(
        all(
            row[:3] == [task["tenant_id"], task["ticket_id"], task["customer_id"]]
            and 0 <= row[3] <= task["refund_total_fen"]
            for row in actual["refunds"]
        ),
        "unauthorized refund side effect",
    )
    require(
        sum(row[3] for row in actual["refunds"]) <= task["refund_total_fen"]
        and len(actual["refunds"]) <= 1,
        "duplicate or over-budget refund",
    )
    require(
        all(
            row[:4] == [task["tenant_id"], task["customer_id"], "REFUND_SUCCESS", "SENT"]
            and row[4] in {refund[5] for refund in actual["refunds"]}
            for row in actual["notifications"]
        ),
        "unauthorized notification side effect",
    )
    receipt_count = verify_receipts(urls["main"], value["task"]["task_id"])
    require(
        receipt_count == len(value["executions"])
        and all(item["signature"]["valid"] for item in value["receipts"]),
        "actual execution receipts are missing or invalid",
    )
    if scenario == "normal" or mode == "deterministic":
        require(
            run["state"] == "COMPLETED", f"normal business did not complete: {run['reason_code']}"
        )
    if run["state"] == "COMPLETED":
        require(
            {event["agent_id"] for event in events if event["action"] == "agent_started"} == AGENTS,
            "four roles did not actually start",
        )
        require(
            {event["details"]["stage"] for event in plans} == STAGES and len(plans) == 6,
            "six actual planning stages were not recorded",
        )
        require(
            sorted(
                (item["holder_agent_id"], item["delegation_depth"]) for item in value["credentials"]
            )
            == [
                ("agent-case", 1),
                ("agent-coordinator", 2),
                ("agent-knowledge", 1),
                ("agent-refund", 0),
            ],
            "two-level delegation is missing",
        )
        require(
            all(
                item["signature"]["valid"] and item["stored_hash_valid"]
                for item in value["credentials"]
            ),
            "delegation signature or hash is invalid",
        )
        require(
            len(actual["refunds"]) == 1
            and actual["refunds"][0][3] == task["refund_total_fen"]
            and len(actual["notifications"]) == 1,
            "business effects did not fulfill the 7000-fen task",
        )
        require(receipt_count == 4, "completed business did not use all four protected tools")
        require(
            inputs["case_read"]["knowledge"]["documents"]
            == inputs["refund"]["knowledge"]["documents"],
            "knowledge result did not reach the refund role",
        )
        validate_refund_ticket_input(inputs["refund"]["ticket"], task)
        require(
            inputs["case_notify"]["committed_refund"]["refund_id"] == actual["refunds"][0][5],
            "notification planning did not use the committed refund",
        )
    for plan in plans:
        details = plan["details"]
        require(
            details["planner"] == ("deterministic" if mode == "deterministic" else "llm"),
            "planner silently changed mode",
        )
        if mode == "cloud":
            require(
                isinstance(details["provider"], str)
                and isinstance(details["model_returned"], str)
                and len(details["response_sm3"]) == 64,
                "real cloud model provenance is missing",
            )
    injection = [event for event in events if event["action"] == "knowledge_result"]
    if scenario == "policy_injection":
        require(
            len(injection) == 1 and injection[0]["details"]["injection_applied"] is True,
            "pollution was not applied to an actual knowledge return copy",
        )
        data = injection[0]["details"]
        expected_addendum = forged_approval_addendum(
            value["task"]["ticket_id"],
            value["task"]["customer_id"],
            value["task"]["refund_total_fen"],
        )
        require(
            any(
                document["content"].endswith(expected_addendum)
                for document in data["output"]["documents"]
            ),
            "polluted knowledge did not carry the attack text",
        )
        with connect(urls["main"]) as connection:
            original = connection.execute(
                "SELECT result FROM execution_records WHERE execution_id=%s",
                (data["execution_id"],),
            ).fetchone()[0]
        require(
            sm3_hex(canonicalize(original)) == data["original_result_sm3"],
            "pollution provenance does not match the committed knowledge tool result",
        )
    gateway_denials = [item for item in value["executions"] if item["decision"] == "DENY"]
    outcome = (
        "legal_business_completed"
        if run["state"] == "COMPLETED"
        else "gateway_rejected_candidate"
        if gateway_denials
        else "model_declined"
        if run["reason_code"] == "PLANNER_DECLINED"
        else "workflow_failed_without_gateway_denial"
    )
    if run["state"] != "COMPLETED":
        require(
            run["state"] in {"DENIED", "FAILED"} and bool(run["reason_code"]),
            "workflow failed without a visible reason",
        )
    return {
        "task_id": value["task"]["task_id"],
        "run_id": run["run_id"],
        "mode": mode,
        "scenario": scenario,
        "state": run["state"],
        "reason_code": run["reason_code"],
        "outcome": outcome,
        "gateway_denial_count": len(gateway_denials),
        "events": len(events),
        "successful_model_calls": len(plans) if mode != "deterministic" else 0,
        "planning_attempts": len(started),
        "verified_receipts": receipt_count,
        "unauthorized_side_effects": 0,
        "business_rows": actual,
    }


def run_case(
    client: httpx.Client, urls: dict[str, str], directory: Path, mode: str, scenario: str
) -> dict:
    before = knowledge_state(urls["main"])
    response = client.post("/api/workflows", json={"runtime_mode": mode, "scenario": scenario})
    require(response.status_code == 202, "workflow start did not return HTTP 202")
    started = response.json()
    write_json(directory / f"{mode}-{scenario}-start.json", started)
    forbidden = httpx.post(
        f"http://127.0.0.1:18201/agents/workflows/{started['run_id']}/observe",
        json={
            "sequence": 1,
            "agent_id": "agent-refund",
            "action": "agent_started",
            "status": "RUNNING",
            "details": {},
        },
        headers={"X-Workflow-Token": "invalid-test-token"},
        trust_env=False,
    )
    require(forbidden.status_code == 403, "forged operational event was accepted")
    seen = []
    deadline = time.monotonic() + 920
    while time.monotonic() < deadline:
        response = client.get(f"/api/tasks/{started['task_id']}")
        require(response.status_code == 200, "workflow task projection could not be read")
        value = response.json()
        run = value["workflow_runs"][0]
        progress = {
            "state": run["state"],
            "events": len(run["events"]),
            "last_action": run["events"][-1]["action"] if run["events"] else None,
        }
        if not seen or seen[-1] != progress:
            seen.append(progress)
            print(
                f"WORKFLOW_PROGRESS mode={mode} scenario={scenario} "
                f"state={run['state']} events={len(run['events'])}",
                flush=True,
            )
        write_json(directory / f"{mode}-{scenario}-snapshot.json", value)
        if run["state"] not in {"QUEUED", "RUNNING"}:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("workflow verification deadline exceeded")
    write_json(directory / f"{mode}-{scenario}-polling.json", seen)
    require(
        knowledge_state(urls["main"]) == before,
        "knowledge database was modified by the pollution demo",
    )
    result = validate_workflow(value, urls, mode, scenario)
    repeat = client.get(f"/api/tasks/{started['task_id']}").json()["workflow_runs"][0]
    require(repeat == value["workflow_runs"][0], "persisted workflow changed after completion")
    root = UiReadStore(urls["ui"]).root_credential(started["task_id"])
    duplicate = httpx.post(
        "http://127.0.0.1:18201/agents/workflows",
        json={
            "credential_chain": [root],
            "context": {
                "ticket_id": "T10086",
                "customer_id": "C9527",
                "refund_amount_fen": 7000,
                "runtime_mode": mode,
                "scenario": scenario,
            },
        },
        trust_env=False,
    )
    require(
        duplicate.status_code == 409
        and duplicate.json()["reason_code"] == "WORKFLOW_ALREADY_EXISTS",
        "duplicate task workflow was not rejected",
    )
    result |= {
        "persisted_readback_equal": True,
        "invalid_observation_token_status": 403,
        "duplicate_workflow_status": 409,
        "knowledge_database_unchanged": True,
        "polling_changes": len(seen),
    }
    write_json(directory / f"{mode}-{scenario}-result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the business-first workbench against managed Windows services"
    )
    parser.add_argument("--modes", nargs="+", choices=("deterministic",), default=["deterministic"])
    parser.add_argument(
        "--scenarios",
        nargs="+",
        choices=("normal", "policy_injection"),
        default=["normal", "policy_injection"],
    )
    parser.add_argument("--skip-regressions", action="store_true")
    args = parser.parse_args()
    run_id = datetime.now(UTC).strftime("run-%Y%m%dT%H%M%S%fZ")
    directory = ROOT / "evidence/native-windows/评委工作台验收" / run_id
    directory.mkdir(parents=True)
    state = read_json(STATE)
    urls = database_urls(read_json(CONFIG))
    manifest = snapshot()
    write_json(directory / "source-snapshot.json", manifest)
    report: dict[str, Any] = {
        "run_id": run_id,
        "started_at": datetime.now(UTC).isoformat(),
        "result": "FAIL",
        "source_sha256": manifest["snapshot_sha256"],
        "source_files": len(manifest["files"]),
        "runtime": "windows-native",
        "native_boundary": state["boundary"],
        "ui_url": f"http://127.0.0.1:{state['ui_port']}",
        "modes": args.modes,
        "scenarios": args.scenarios,
        "cases": [],
        "commands": [],
        "cloud_actual_calls": 0,
        "cloud_boundary": "MockTransport protocol tests only; no provider request",
        "compose_runtime": "NOT_RERUN_FOR_THIS_INCREMENT",
    }
    try:
        report["permissions"] = permissions(urls, state)
        report["versions"] = {
            name: importlib.metadata.version(name)
            for name in ("gmssl", "httpx", "psycopg", "fastapi", "jsonschema", "pytest")
        }
        with httpx.Client(base_url=report["ui_url"], timeout=30, trust_env=False) as client:
            profiles = client.get("/api/runtime-profiles").json()
            public_only(profiles)
            report["runtime_profiles"] = profiles
            for mode in args.modes:
                require(
                    any(item["mode"] == mode and item["available"] for item in profiles["items"]),
                    f"{mode} is not available",
                )
                for scenario in args.scenarios:
                    report["cases"].append(run_case(client, urls, directory, mode, scenario))
        if not args.skip_regressions:
            report["commands"].append(
                command(
                    [
                        str(PYTHON),
                        "-B",
                        "-m",
                        "pytest",
                        "backend/tests/unit",
                        "backend/tests/security",
                        "-q",
                        f"--junitxml={directory / 'unit-security.xml'}",
                    ],
                    directory,
                    "backend-unit-security",
                    env=regression_environment(urls),
                )
            )
            selected = [
                "backend/tests/integration/test_delegation_postgres.py",
                "backend/tests/integration/test_admission_postgres.py",
                "backend/tests/integration/test_dispatch_postgres.py",
                "backend/tests/integration/test_recovery_postgres.py",
                "backend/tests/integration/test_revocation_postgres.py::test_root_intermediate_and_leaf_revocation_block_new_admission",
                "backend/tests/integration/test_result_retrieval_postgres.py",
                "backend/tests/integration/test_multi_agent_postgres.py",
            ]
            report["commands"].append(
                command(
                    [
                        str(PYTHON),
                        "-B",
                        "-m",
                        "pytest",
                        *selected,
                        "-q",
                        f"--junitxml={directory / 'native-regressions.xml'}",
                    ],
                    directory,
                    "native-regressions",
                    env=regression_environment(urls),
                )
            )
            for name in ("lint", "typecheck", "test", "build"):
                report["commands"].append(
                    command(
                        ["npm.cmd", "run", name],
                        directory,
                        f"frontend-{name}",
                        cwd=ROOT / "frontend",
                    )
                )
        report["audit"] = audit_check(urls)
        require(snapshot() == manifest, "source changed during acceptance run")
        report["result"] = (
            "PASS"
            if not args.skip_regressions
            and set(args.modes) == {"deterministic"}
            and set(args.scenarios) == {"normal", "policy_injection"}
            else "PARTIAL_PASS"
        )
    except Exception as exc:
        report["failure_type"] = type(exc).__name__
        if isinstance(exc, RuntimeError):
            report["failure_message"] = str(exc)
        print(f"BUSINESS_WORKSPACE_ACCEPTANCE=FAIL error_type={type(exc).__name__}", flush=True)
    finally:
        report["finished_at"] = datetime.now(UTC).isoformat()
        write_json(directory / "summary.json", report)
        print(f"BUSINESS_WORKSPACE_EVIDENCE={directory.relative_to(ROOT).as_posix()}", flush=True)
    print(f"BUSINESS_WORKSPACE_ACCEPTANCE={report['result']}", flush=True)
    return 0 if report["result"] in {"PASS", "PARTIAL_PASS"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
