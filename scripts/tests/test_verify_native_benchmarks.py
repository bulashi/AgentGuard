from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from urllib.parse import urlsplit

import httpx
import psycopg
import pytest

from scripts import verify_native_benchmarks as verify


@pytest.fixture(autouse=True)
def forbid_live_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("unit tests must not start processes or contact HTTP/PostgreSQL")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "check_output", forbidden)
    monkeypatch.setattr(httpx.Client, "request", forbidden)
    monkeypatch.setattr(psycopg, "connect", forbidden)
    monkeypatch.setattr(verify.socket, "socket", forbidden)


@pytest.fixture
def isolated_root(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    spec = {
        "version": "16.15-1",
        "directory": "postgresql-16.15-1",
        "executable": "pgsql/bin/pg_ctl.exe",
    }
    (root / "scripts").mkdir()
    (root / "scripts/native-dependencies.lock.json").write_text(
        json.dumps({"postgresql": spec}), encoding="utf-8"
    )
    dependency = root / ".native/deps" / spec["directory"]
    (dependency / "pgsql/bin").mkdir(parents=True)
    for name in ("pg_ctl.exe", "initdb.exe", "postgres.exe"):
        (dependency / "pgsql/bin" / name).touch()
    (dependency / "native-install.json").write_text(json.dumps(spec), encoding="utf-8")
    monkeypatch.setattr(verify, "ROOT", root)
    monkeypatch.setattr(verify.platform, "system", lambda: "Windows")
    source = {
        "schema_version": "1.0",
        "files": {
            f"{name}/example": {"bytes": 1, "sha256": "b" * 64}
            for name in ("backend", "scripts", "frontend", "protocol")
        },
        "snapshot_sha256": "a" * 64,
    }
    monkeypatch.setattr(
        verify.NativeBenchmarkRunner, "_read_source_snapshot", lambda config: source
    )
    monkeypatch.setattr(verify, "snapshot", lambda: source)
    return root, source


def args_for(root, *extra):
    return verify.build_parser().parse_args(
        [
            "--allow-isolated",
            "--run-id",
            "native-20261004-unit",
            "--artifact-root",
            str(root / "artifacts"),
            "--validate-only",
            *extra,
        ]
    )


def cloud_report(root: Path, source: dict, *, attack_status="COMPLETED") -> Path:
    # Synthetic contract fixtures only, never used as runtime benchmark evidence.
    report = {
        "schema_version": "native-cloud-1.0",
        "run_id": "native-20261004-unit",
        "source_snapshot_sha256": source["snapshot_sha256"],
        "tested_at": datetime.now(UTC).isoformat(),
        "mock_used": False,
        "fallback_used": False,
        "provider": "unit-contract",
        "model_requested": "unit-model",
        "attempted_samples": 2,
        "samples": [
            {
                "sample_id": "workflow-success",
                "http_status": 200,
                "wall_ms": 19.25,
                "model_returned": "unit-model",
                "passed": True,
                "input_tokens": 7,
                "output_tokens": 3,
            },
            {
                "sample_id": "workflow-failed",
                "http_status": 0,
                "wall_ms": 21.75,
                "passed": False,
                "failure_type": "HTTP_STATUS_UNKNOWN",
            },
        ],
        "live_llm": {
            "normal": {
                "task_id": "unit-normal",
                "http_status": 200,
                "status": "COMPLETED",
                "planner": "llm",
                "reason_code": None,
                "committed_effects": 2,
                "unauthorized_side_effects": 0,
            },
            "prompt_injection": {
                "task_id": "unit-attack",
                "http_status": 200,
                "status": attack_status,
                "planner": "llm",
                "reason_code": None,
                "committed_effects": 0,
                "unauthorized_side_effects": 0,
            },
        },
    }
    path = root / "cloud-fixture.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_plan_is_isolated_and_reuses_native_specs(isolated_root):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    assert verify.POSTGRES_PORT == 25432
    assert len(plan.names) == 3
    for dsn in plan.urls.values():
        parsed = urlsplit(dsn)
        assert parsed.hostname == "127.0.0.1" and parsed.port == 25432
        assert parsed.username and parsed.password
    assert plan.runtime == root / "artifacts/native-benchmark-runtime/native-20261004-unit"
    assert not plan.runtime.exists()
    assert plan.config.private_key_root == plan.runtime / "keys/private"
    assert plan.config.coordinator_agent_url == plan.config.live_refund_agent_url == ""
    services = {service.name: service for group in plan.groups for service in group}
    assert len(services) == 23
    assert all(
        "agent_runtime" not in service.module and "ui_api" not in service.module
        for service in services.values()
    )
    assert services["secure-gateway"].port == 38003
    gateway = services["secure-gateway"].environment
    assert gateway["AGENTGUARD_REFUND_TOOL_URL"] == "http://127.0.0.1:38303"
    assert gateway["AGENTGUARD_RECEIPT_SERVICE_URL"] == "http://127.0.0.1:38006"
    assert gateway["AGENTGUARD_AUDIT_SERVICE_URL"] == "http://127.0.0.1:38007"
    for kind, port in (
        ("ticket", 39301),
        ("knowledge", 39302),
        ("refund", 39303),
        ("notification", 39304),
    ):
        assert services[f"baseline-{kind}-tool"].port == port
        assert (
            services[f"baseline-{kind}-tool"].environment["AGENTGUARD_DATABASE_URL"]
            == (plan.urls["baseline"])
        )
        assert services[f"{kind}-tool"].environment["AGENTGUARD_DATABASE_URL"] == plan.urls["main"]
    for name, mode, port in (
        ("static", "shared_static_credential", 39001),
        ("rbac", "conventional_rbac", 39002),
    ):
        service = services["baseline-" + name]
        assert service.module == "backend.benchmark.baseline_app:app" and service.port == port
        assert service.environment["AGENTGUARD_BENCHMARK_MODE"] == mode
        assert service.environment["AGENTGUARD_DATABASE_URL"] == plan.urls["baseline"]
        assert service.environment["AGENTGUARD_BENCHMARK_REFUND_TOOL_URL"] == (
            "http://127.0.0.1:39303"
        )
        assert service.environment["AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE"] == (
            str(plan.runtime / "keys/private/gateway.private")
        )
    assert services["audit-worker"].environment["AGENTGUARD_AUDIT_SERVICE_URL"] == (
        "http://127.0.0.1:38007"
    )
    assert services["checkpoint-worker"].environment["AGENTGUARD_CHECKPOINT_SERVICE_URL"] == (
        "http://127.0.0.1:38008"
    )


def test_database_names_obey_63_byte_limit_and_resist_truncation_collisions():
    first = "native-" + "a" * 79
    second = first[:-1] + "b"
    names = verify.database_names(first)
    assert len(set(names.values())) == 3
    assert all(
        "native_bench" in name and len(name.encode("ascii")) <= 63 for name in names.values()
    )
    assert not set(names.values()) & set(verify.database_names(second).values())
    assert names == verify.database_names(first)


@pytest.mark.parametrize(
    "extra",
    [
        ["--port-offset", "0"],
        ["--port-offset", "100"],
        ["--port-offset", "50000"],
        ["--latency-samples", "0"],
        ["--warmup-samples", "-1"],
        ["--run-id", "../unsafe"],
    ],
)
def test_unsafe_parameters_rejected(isolated_root, extra):
    root, _ = isolated_root
    with pytest.raises(ValueError):
        verify.build_plan(args_for(root, *extra))


def test_windows_opt_in_and_fresh_paths_required(isolated_root, monkeypatch):
    root, _ = isolated_root
    args = args_for(root)
    args.allow_isolated = False
    with pytest.raises(ValueError):
        verify.build_plan(args)
    args.allow_isolated = True
    monkeypatch.setattr(verify.platform, "system", lambda: "Linux")
    with pytest.raises(ValueError):
        verify.build_plan(args)
    monkeypatch.setattr(verify.platform, "system", lambda: "Windows")
    plan = verify.build_plan(args)
    plan.runtime.mkdir(parents=True)
    with pytest.raises(FileExistsError):
        verify.build_plan(args)


def test_planning_preserves_current_summary_and_rejects_historical_evidence_paths(isolated_root):
    root, _ = isolated_root
    current = root / "artifacts/benchmarks/current-cloud-summary.json"
    current.parent.mkdir(parents=True)
    current.write_text("untouched", encoding="utf-8")
    plan = verify.build_plan(args_for(root, "--publish-current-summary"))
    assert plan.config.publish_current_summary is True
    assert plan.public()["current_summary_publication"] == (
        "archive existing bytes by SHA256, then atomic replace"
    )
    assert not plan.runtime.exists()
    assert not (root / "artifacts/benchmarks/current-summary-history").exists()
    assert current.read_text("utf-8") == "untouched"
    with pytest.raises(ValueError):
        verify.build_plan(args_for(root, "--artifact-root", str(root / "evidence")))


@pytest.mark.parametrize("status", ["COMPLETED", "DENIED", "FAILED"])
def test_workflow_cloud_fields_parse_without_inventing_http_or_digests(isolated_root, status):
    root, source = isolated_root
    path = cloud_report(root, source, attack_status=status)
    original = path.read_bytes()
    plan = verify.build_plan(args_for(root, "--cloud-report", str(path)))
    assert plan.cloud["status"] == "IMPORTED"
    assert plan.cloud["samples"][1]["http_status"] == 0
    assert plan.cloud["samples"][1]["wall_ms"] == 21.75
    assert plan.cloud["samples"][1]["passed"] is False
    assert plan.cloud["live_llm"]["prompt_injection"]["status"] == status
    assert plan.cloud["live_llm"]["normal"]["reason_code"] is None
    assert all(
        "response_sha256" not in sample and "response_length_bytes" not in sample
        for sample in plan.cloud["samples"]
    )
    assert plan.raw_cloud == original == path.read_bytes()
    assert plan.cloud["sha256"] == hashlib.sha256(original).hexdigest()
    assert not plan.runtime.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_snapshot_sha256", "b" * 64),
        ("run_id", "native-other"),
        ("schema_version", "connectivity-probe"),
        ("mock_used", True),
    ],
)
def test_cloud_binding_and_contract_not_weakened(isolated_root, field, value):
    root, source = isolated_root
    path = cloud_report(root, source)
    report = json.loads(path.read_text("utf-8"))
    report[field] = value
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError):
        verify.build_plan(args_for(root, "--cloud-report", str(path)))
    assert not (root / "artifacts").exists()


def test_execution_requires_real_cloud_report(isolated_root):
    root, _ = isolated_root
    args = args_for(root)
    args.validate_only = False
    with pytest.raises(ValueError):
        verify.build_plan(args)


def test_prepared_binaries_are_read_only_and_not_downloaded(isolated_root):
    root, _ = isolated_root
    receipt = root / ".native/deps/postgresql-16.15-1/native-install.json"
    receipt.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        verify.build_plan(args_for(root))


def test_child_environment_never_inherits_production_or_cloud_credentials(
    isolated_root, monkeypatch
):
    root, _ = isolated_root
    bad = {
        "AGENTGUARD_DATABASE_URL": "production-dsn",
        "AGENTGUARD_CLOUD_LLM_API_KEY": "secret",
        "OPENAI_API_KEY": "secret",
        "PGPASSWORD": "secret",
        "PGSERVICE": "production",
        "HTTP_PROXY": "remote",
        "DATABASE_URL": "production-dsn",
        "PYTHONPATH": "external",
    }
    for key, value in bad.items():
        monkeypatch.setenv(key, value)
    result = verify.child_environment(root / "runtime", {"AGENTGUARD_DATABASE_URL": "isolated"})
    assert result["AGENTGUARD_DATABASE_URL"] == "isolated"
    assert result["PYTHONPATH"] == str(root)
    assert result["AGENTGUARD_CLOUD_LLM_ENABLED"] == "false"
    for key in bad.keys() - {"AGENTGUARD_DATABASE_URL", "PYTHONPATH"}:
        assert key not in result


def test_cloud_stdin_launcher_control_removed_during_specs_and_restored(isolated_root, monkeypatch):
    root, _ = isolated_root
    monkeypatch.setenv("AGENTGUARD_NATIVE_CLOUD_KEY_STDIN", "1")
    monkeypatch.setenv("AGENTGUARD_CLOUD_LLM_ENABLED", "true")
    monkeypatch.setenv("AGENTGUARD_CLOUD_LLM_API_KEY", "not-for-benchmarks")
    verify.build_plan(args_for(root))
    assert os.environ["AGENTGUARD_NATIVE_CLOUD_KEY_STDIN"] == "1"
    assert os.environ["AGENTGUARD_CLOUD_LLM_ENABLED"] == "true"
    assert os.environ["AGENTGUARD_CLOUD_LLM_API_KEY"] == "not-for-benchmarks"


def test_validate_only_reports_unmeasured_and_has_no_filesystem_side_effects(isolated_root, capsys):
    root, source = isolated_root
    before = set(root.rglob("*"))
    assert (
        verify.main(
            [
                "--allow-isolated",
                "--run-id",
                "native-20261004-unit",
                "--artifact-root",
                str(root / "artifacts"),
                "--validate-only",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PLAN_VALIDATED"
    assert result["benchmark_executed"] is False
    assert result["benchmark_verified"] is False
    assert result["runtime_configuration_validated"] is False
    assert result["cloud_report_status"] == "NOT_MEASURED"
    assert result["cloud_source_bound"] is False
    assert result["source_snapshot_sha256"] == source["snapshot_sha256"]
    assert set(root.rglob("*")) == before


def test_public_metadata_and_errors_never_expose_secrets(isolated_root, monkeypatch, capsys):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    text = json.dumps(plan.public())
    for secret in (
        *plan.urls.values(),
        *plan.passwords.values(),
        plan.config.benchmark_admin_token,
    ):
        assert secret not in text
        assert secret not in runtime.redact(secret)
    monkeypatch.setattr(verify, "build_plan", Mock(side_effect=RuntimeError("SECRET_DSN")))
    assert verify.main(["--run-id", "native-test", "--validate-only"]) == 1
    output = capsys.readouterr().out
    assert "SECRET_DSN" not in output
    assert json.loads(output)["status"] == "REJECTED"


@pytest.mark.parametrize(
    "failing_stage",
    ["prepare", "start_postgres", "initialize_databases", "start_services", "run_benchmark"],
)
def test_finally_always_cleans_owned_runtime_on_stage_failure(
    isolated_root, monkeypatch, failing_stage
):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = Mock(spec=verify.IsolatedRuntime)
    runtime.created = True
    for name in ("prepare", "start_postgres", "initialize_databases", "start_services"):
        getattr(runtime, name).return_value = None
    runtime.run_benchmark.return_value = (1, {"status": "FAILED"})
    getattr(runtime, failing_stage).side_effect = RuntimeError("redact-my-secret")
    runtime.cleanup.return_value = []
    runtime.events = []
    monkeypatch.setattr(verify, "IsolatedRuntime", lambda _: runtime)
    monkeypatch.setattr(verify, "assert_free_ports", lambda ports: None)
    code, report = verify.execute(plan)
    assert code == 1 and report["benchmark_verified"] is False
    assert report["current_summary_published"] is False
    assert report["cleanup_succeeded"] is True
    runtime.cleanup.assert_called_once()
    assert [call.args[0] for call in runtime.save.call_args_list] == [
        "processes.json",
        "orchestration.json",
    ]
    assert "redact-my-secret" not in json.dumps(report)


def test_cleanup_attempts_every_service_and_pg_after_one_stop_failure(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    first, second = [Mock(spec=verify.OwnedProcess) for _ in range(2)]
    postgres = Mock(spec=verify.OwnedPostgres)
    first.name, second.name, postgres.name = "first", "second", "postgres-server"
    postgres.process = Mock()
    postgres.process.is_running.return_value = True
    second.stop.side_effect = RuntimeError("stop failure")
    runtime.processes = [first, second]
    runtime.postgres = postgres
    command = Mock(return_value=0)
    monkeypatch.setattr(runtime, "command", command)
    errors = runtime.cleanup()
    first.stop.assert_called_once()
    second.stop.assert_called_once()
    postgres.stop.assert_called_once()
    assert errors == [{"name": "second", "error_type": "RuntimeError"}]
    assert command.call_args.args[0] == "postgres-stop"
    assert str(plan.runtime / "postgres/data") in command.call_args.args[1]
    assert str(root / ".native/postgres/data") not in command.call_args.args[1]


def test_runner_command_forwards_cloud_snapshot_counts_and_publication_only(
    isolated_root, monkeypatch
):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root, "--publish-current-summary"))
    runtime = verify.IsolatedRuntime(plan)
    summary_path = (
        plan.config.artifact_root / "benchmarks/runs" / plan.config.run_id / "summary.json"
    )
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(
        json.dumps(
            {
                "run_id": plan.config.run_id,
                "status": "VERIFIED",
                "acceptance_target": verify.NativeBenchmarkRunner.ACCEPTANCE_TARGET,
                "environment": {"deployment": "native_windows"},
                "acceptance": {"passed": True},
            }
        ),
        encoding="utf-8",
    )
    current = plan.config.artifact_root / "benchmarks/current-cloud-summary.json"
    current.write_bytes(summary_path.read_bytes())
    command = Mock(return_value=0)
    monkeypatch.setattr(runtime, "command", command)
    code, _ = runtime.run_benchmark()
    assert code == 0
    arguments = command.call_args.args[1]
    environment = command.call_args.args[2]
    assert arguments[:4] == [verify.sys.executable, "-B", "-m", "scripts.run_native_benchmarks"]
    assert "--publish-current-summary" in arguments
    assert arguments[arguments.index("--cloud-report") + 1] == (
        str(plan.runtime / "input-cloud-report.json")
    )
    assert arguments[arguments.index("--source-snapshot") + 1] == str(plan.config.source_snapshot)
    for name, count in verify.COUNTS.items():
        assert arguments[arguments.index("--" + name.replace("_", "-")) + 1] == str(count)
    assert environment["AGENTGUARD_BENCHMARK_MAIN_DATABASE_URL"] == plan.urls["main"]
    assert environment["AGENTGUARD_BENCHMARK_PRIVATE_KEY_ROOT"] == (
        str(plan.runtime / "keys/private")
    )
    assert all(url not in arguments for url in plan.urls.values())


def test_cleanup_failure_does_not_report_success(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = Mock(spec=verify.IsolatedRuntime)
    runtime.created = False
    runtime.run_benchmark.return_value = (1, {"status": "FAILED"})
    runtime.cleanup.return_value = [{"name": "owned", "error_type": "RuntimeError"}]
    monkeypatch.setattr(verify, "IsolatedRuntime", lambda _: runtime)
    monkeypatch.setattr(verify, "assert_free_ports", lambda ports: None)
    code, report = verify.execute(plan)
    assert code == 1 and report["status"] == "FAILED"
    assert report["cleanup_succeeded"] is False


def test_subprocesses_have_hidden_windows_and_sanitized_logs(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    (plan.runtime / "logs").mkdir(parents=True)
    process = Mock()
    process.pid = 12345
    process.stdout = io.StringIO(plan.urls["main"] + "\n" + plan.passwords["admin"] + "\n")
    process.poll.return_value = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(subprocess, "Popen", popen)
    owned = runtime.start("unit-child", ["python.exe", "unit-child"])
    owned.stop()
    assert popen.call_args.kwargs["creationflags"] & subprocess.CREATE_NO_WINDOW
    assert popen.call_args.kwargs["stdin"] == subprocess.DEVNULL
    assert popen.call_args.kwargs["cwd"] == root
    log = (plan.runtime / "logs/unit-child.log").read_text("utf-8")
    assert plan.urls["main"] not in log and plan.passwords["admin"] not in log
    assert "REDACTED" in log


def test_initialization_only_targets_new_databases_and_keys(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    private = plan.runtime / "keys/private"
    private.mkdir(parents=True)
    for name in ("agent-case.private", "agent-refund.private"):
        (private / name).write_text("SYNTHETIC_UNIT_KEY_NOT_A_RUNTIME_KEY", encoding="ascii")
    connection = MagicMock()
    connect = Mock(return_value=connection)
    roles, databases, command = Mock(), Mock(), Mock(return_value=0)
    monkeypatch.setattr(verify, "connect", connect)
    monkeypatch.setattr(verify, "ensure_role", roles)
    monkeypatch.setattr(verify, "ensure_database", databases)
    monkeypatch.setattr(runtime, "command", command)
    runtime.initialize_databases()
    connect.assert_called_once_with(plan.urls["admin"])
    assert [call.args[1] for call in roles.call_args_list] == list(plan.names.values())
    assert [call.args[1] for call in databases.call_args_list] == list(plan.names.values())
    migrations = [call for call in command.call_args_list if call.args[0].startswith("migrate-")]
    assert len(migrations) == 4
    assert [call.args[1][-1] for call in migrations] == [
        "database/migrations/main",
        "database/migrations/audit",
        "database/migrations/main",
        "database/migrations/benchmark",
    ]
    for call in migrations:
        assert call.args[2]["AGENTGUARD_DATABASE_URL"] in plan.urls.values()
        assert all(url not in call.args[1] for url in plan.urls.values())
    generation = next(call for call in command.call_args_list if call.args[0] == "generate-keys")
    assert generation.args[1][-1] == str(plan.runtime / "keys")
    assert str(root / ".native/keys") not in generation.args[1]


def test_pg_stop_failure_still_terminates_owned_pg_handle(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    postgres = Mock()
    postgres.name = "postgres-server"
    postgres.process.is_running.return_value = True
    runtime.postgres = postgres
    monkeypatch.setattr(runtime, "command", Mock(side_effect=RuntimeError("pg_ctl failure")))
    errors = runtime.cleanup()
    postgres.stop.assert_called_once()
    assert errors == [{"name": "postgres-stop", "error_type": "RuntimeError"}]


def test_source_change_stops_before_runtime_creation(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    monkeypatch.setattr(verify, "assert_free_ports", lambda ports: None)
    monkeypatch.setattr(verify, "snapshot", lambda: {"snapshot_sha256": "new"})
    code, report = verify.execute(plan)
    assert code == 1 and report["error_type"] == "ValueError"
    assert not plan.runtime.exists()
    assert report["benchmark_executed"] is False


def test_pg_identity_mismatch_is_not_retried_or_accepted(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    (plan.runtime / "tmp").mkdir(parents=True)
    monkeypatch.setattr(runtime, "command", Mock(return_value=0))
    child = Mock()
    child.process.is_running.return_value = True
    runtime.postgres = child
    monkeypatch.setattr(runtime, "capture_postgres", lambda: None)
    monkeypatch.setattr(verify, "assert_free_ports", lambda ports: None)
    connection = MagicMock()
    connection.__enter__.return_value.execute.return_value.fetchone.return_value = (
        str(root / ".native/postgres/data"),
        "15432",
        "16.15",
    )
    connect = Mock(return_value=connection)
    monkeypatch.setattr(verify, "connect", connect)
    with pytest.raises(RuntimeError, match="identity mismatch"):
        runtime.start_postgres()
    connect.assert_called_once_with(plan.urls["admin"])
    assert not (plan.runtime / "tmp/init-password.tmp").exists()


def test_keyboard_interrupt_runs_cleanup_and_returns_130(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = Mock(spec=verify.IsolatedRuntime)
    runtime.created = False
    runtime.start_postgres.side_effect = KeyboardInterrupt()
    runtime.cleanup.return_value = []
    monkeypatch.setattr(verify, "IsolatedRuntime", lambda _: runtime)
    monkeypatch.setattr(verify, "assert_free_ports", lambda ports: None)
    code, report = verify.execute(plan)
    assert code == 130 and report["status"] == "INTERRUPTED"
    runtime.cleanup.assert_called_once()


@pytest.mark.parametrize("identity", ["owned", "production-directory", "old-process", "other-exe"])
def test_postmaster_adoption_requires_this_run_identity(isolated_root, monkeypatch, identity):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    runtime.postgres_start_attempted_at = 1000
    data = plan.runtime / "postgres/data"
    data.mkdir(parents=True)
    (data / "postmaster.pid").write_text(
        "12345\n" + str(data) + "\n1000\n25432\n", encoding="utf-8"
    )
    process = Mock()
    process.pid = 12345
    process.create_time.return_value = 1000 if identity != "old-process" else 500
    process.exe.return_value = str(
        plan.pg_ctl.with_name("postgres.exe") if identity != "other-exe" else root / "other.exe"
    )
    process.cmdline.return_value = [
        process.exe(),
        "-D",
        str(data if identity != "production-directory" else root / ".native/postgres/data"),
    ]
    monkeypatch.setattr(verify.psutil, "Process", lambda _: process)
    if identity == "owned":
        runtime.capture_postgres()
        assert runtime.postgres.process is process
        assert runtime.events[-1]["pid"] == 12345
    else:
        with pytest.raises(RuntimeError, match="unowned"):
            runtime.capture_postgres()
        assert runtime.postgres is None


def test_failed_pg_start_can_be_adopted_and_stopped_in_finally(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    runtime.postgres_start_attempted_at = 1000
    pg = Mock(spec=verify.OwnedPostgres)
    pg.process = Mock()
    pg.process.is_running.return_value = True

    def adopt():
        runtime.postgres = pg

    capture = Mock(side_effect=adopt)
    monkeypatch.setattr(runtime, "capture_postgres", capture)
    monkeypatch.setattr(runtime, "command", Mock(return_value=0))
    assert runtime.cleanup() == []
    capture.assert_called_once()
    pg.stop.assert_called_once()


def test_unadopted_pg_start_falls_back_to_this_run_data_directory(isolated_root, monkeypatch):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    runtime.postgres_start_attempted_at = 1000
    monkeypatch.setattr(runtime, "capture_postgres", Mock(side_effect=RuntimeError("identity")))
    command = Mock(return_value=0)
    monkeypatch.setattr(runtime, "command", command)
    errors = runtime.cleanup()
    assert errors == [{"name": "postgres-identity", "error_type": "RuntimeError"}]
    call = command.call_args
    assert call.args[0] == "postgres-stop-unadopted"
    assert str(plan.runtime / "postgres/data") in call.args[1]
    assert str(root / ".native/postgres/data") not in call.args[1]


def test_temporary_postgres_log_is_redacted_and_only_new_raw_log_removed(isolated_root):
    root, _ = isolated_root
    plan = verify.build_plan(args_for(root))
    runtime = verify.IsolatedRuntime(plan)
    (plan.runtime / "logs").mkdir(parents=True)
    (plan.runtime / "tmp").mkdir()
    raw = plan.runtime / "tmp/postgres-server.raw.log"
    raw.write_text(plan.passwords["admin"] + "\n" + plan.urls["main"], encoding="utf-8")
    production = root / ".native/postgres.log"
    production.write_text("existing-log-untouched", encoding="utf-8")
    assert runtime.cleanup() == []
    log = (plan.runtime / "logs/postgres-server.log").read_text("utf-8")
    assert "REDACTED" in log and plan.passwords["admin"] not in log
    assert plan.urls["main"] not in log and not raw.exists()
    assert production.read_text("utf-8") == "existing-log-untouched"


@pytest.fixture
def health_probe(isolated_root, monkeypatch):
    root, _ = isolated_root
    runtime = verify.IsolatedRuntime(verify.build_plan(args_for(root)))
    launcher = Mock()
    launcher.pid = 22296
    launcher.poll.return_value = None
    owned = verify.OwnedProcess("ticket-tool", launcher)
    wrapper, child = Mock(), Mock()
    wrapper.pid, child.pid = 22296, 36236
    wrapper.children.return_value = [child]
    wrapper.net_connections.return_value = []
    child.net_connections.return_value = [
        SimpleNamespace(status=verify.psutil.CONN_LISTEN, laddr=("127.0.0.1", 38301))
    ]
    process_lookup = Mock(return_value=wrapper)
    monkeypatch.setattr(verify.psutil, "Process", process_lookup)
    clock = [0]
    monkeypatch.setattr(verify.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(verify.time, "sleep", lambda _: clock.__setitem__(0, clock[0] + 120))
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"status": "ok", "tool_service": "ticket-service"}
    client = MagicMock()
    client.__enter__.return_value = client
    client.get.return_value = response
    constructor = Mock(return_value=client)
    monkeypatch.setattr(verify.httpx, "Client", constructor)
    return SimpleNamespace(
        runtime=runtime,
        owned=owned,
        wrapper=wrapper,
        child=child,
        client=client,
        response=response,
        clock=clock,
        process_lookup=process_lookup,
        constructor=constructor,
    )


def test_health_accepts_owned_venv_wrapper_descendant_listener(health_probe):
    probe = health_probe
    probe.runtime.wait_health(probe.owned, 38301)
    probe.process_lookup.assert_called_once_with(22296)
    probe.wrapper.children.assert_called_once_with(recursive=True)
    probe.wrapper.net_connections.assert_called_once_with(kind="tcp")
    probe.child.net_connections.assert_called_once_with(kind="tcp")
    probe.client.get.assert_called_once_with("http://127.0.0.1:38301/health")
    probe.constructor.assert_called_once_with(timeout=3, trust_env=False)


def test_health_also_accepts_listener_on_launcher_itself(health_probe):
    probe = health_probe
    probe.wrapper.net_connections.return_value = probe.child.net_connections.return_value
    probe.runtime.wait_health(probe.owned, 38301)
    probe.child.net_connections.assert_not_called()
    probe.client.get.assert_called_once()


def test_health_never_probes_unrelated_listener_when_owned_tree_does_not_listen(health_probe):
    probe = health_probe
    probe.wrapper.children.return_value = []
    with pytest.raises(RuntimeError, match="timed out"):
        probe.runtime.wait_health(probe.owned, 38301)
    probe.process_lookup.assert_called_once_with(probe.owned.process.pid)
    probe.child.net_connections.assert_not_called()
    probe.client.get.assert_not_called()


@pytest.mark.parametrize(
    "status,address",
    [
        (verify.psutil.CONN_LISTEN, ("127.0.0.1", 38302)),
        (verify.psutil.CONN_LISTEN, ("0.0.0.0", 38301)),
        ("ESTABLISHED", ("127.0.0.1", 38301)),
    ],
)
def test_health_requires_exact_owned_loopback_listening_socket(health_probe, status, address):
    probe = health_probe
    probe.child.net_connections.return_value = [SimpleNamespace(status=status, laddr=address)]
    with pytest.raises(RuntimeError, match="timed out"):
        probe.runtime.wait_health(probe.owned, 38301)
    probe.client.get.assert_not_called()


@pytest.mark.parametrize(
    "status,body",
    [
        (503, {"status": "ok"}),
        (200, {"status": "degraded"}),
        (200, {"healthy": True}),
        (200, []),
        (200, None),
        (200, "ok"),
    ],
)
def test_health_response_still_requires_http_200_and_ok_json_object(health_probe, status, body):
    probe = health_probe
    probe.response.status_code = status
    probe.response.json.return_value = body
    with pytest.raises(RuntimeError, match="timed out"):
        probe.runtime.wait_health(probe.owned, 38301)
    probe.client.get.assert_called_once()


def test_health_invalid_json_is_retryable_not_a_pass(health_probe):
    probe = health_probe
    probe.response.json.side_effect = ValueError("invalid JSON")
    with pytest.raises(RuntimeError, match="timed out"):
        probe.runtime.wait_health(probe.owned, 38301)


def test_health_exited_wrapper_does_not_authorize_child_or_http(health_probe):
    probe = health_probe
    probe.owned.process.poll.side_effect = [None, 0, 0]
    probe.clock[0] = 0
    with pytest.raises(RuntimeError, match="timed out"):
        probe.runtime.wait_health(probe.owned, 38301)
    probe.client.get.assert_not_called()


def test_health_healthy_response_is_not_accepted_after_wrapper_exits(health_probe):
    probe = health_probe
    probe.owned.process.poll.side_effect = [None, None, 0]
    with pytest.raises(RuntimeError, match="timed out"):
        probe.runtime.wait_health(probe.owned, 38301)
    probe.client.get.assert_called_once()


def test_cleanup_waits_for_pg_inherited_stdout_only_after_postgres_shutdown(
    isolated_root, monkeypatch
):
    root, _ = isolated_root
    runtime = verify.IsolatedRuntime(verify.build_plan(args_for(root)))
    process = Mock()
    process.poll.return_value = 0
    thread = Mock()
    launcher = verify.OwnedProcess("postgres-start", process, thread)
    service = Mock(spec=verify.OwnedProcess)
    service.name = "ticket-tool"
    runtime.processes = [launcher, service]
    postgres = Mock(spec=verify.OwnedPostgres)
    postgres.process = Mock()
    postgres.process.is_running.return_value = True
    runtime.postgres = postgres
    shutdown = [False]
    thread.is_alive.side_effect = lambda: not shutdown[0]

    def join(*args, **kwargs):
        assert shutdown[0], "pg_ctl stdout EOF cannot precede PostgreSQL shutdown"

    thread.join.side_effect = join

    def stop_command(name, arguments, **kwargs):
        service.stop.assert_called_once_with(join_log=False)
        assert name == "postgres-stop"
        shutdown[0] = True
        return 0

    monkeypatch.setattr(runtime, "command", Mock(side_effect=stop_command))
    assert runtime.cleanup() == []
    postgres.stop.assert_called_once()
    thread.join.assert_called_once_with(timeout=5)
    service.finish_log.assert_called_once()


def test_cleanup_log_join_failure_is_reported_after_all_processes_stopped(
    isolated_root, monkeypatch
):
    root, _ = isolated_root
    runtime = verify.IsolatedRuntime(verify.build_plan(args_for(root)))
    process = Mock()
    process.poll.return_value = 0
    thread = Mock()
    thread.is_alive.return_value = True
    runtime.processes = [verify.OwnedProcess("postgres-start", process, thread)]
    postgres = Mock(spec=verify.OwnedPostgres)
    postgres.process = Mock()
    postgres.process.is_running.return_value = True
    runtime.postgres = postgres
    command = Mock(return_value=0)
    monkeypatch.setattr(runtime, "command", command)

    def join(*args, **kwargs):
        postgres.stop.assert_called_once()
        command.assert_called_once()

    thread.join.side_effect = join
    assert runtime.cleanup() == [{"name": "postgres-start", "error_type": "RuntimeError"}]


def test_cleanup_joins_stop_command_streams_on_unadopted_pg_failure(isolated_root, monkeypatch):
    root, _ = isolated_root
    runtime = verify.IsolatedRuntime(verify.build_plan(args_for(root)))
    runtime.postgres_start_attempted_at = 1000
    monkeypatch.setattr(runtime, "capture_postgres", lambda: None)
    stop_command = Mock(spec=verify.OwnedProcess)
    stop_command.name = "postgres-stop-unadopted"

    def command(*args, **kwargs):
        runtime.processes.append(stop_command)
        raise RuntimeError("pg_ctl failed")

    monkeypatch.setattr(runtime, "command", command)
    assert runtime.cleanup() == [{"name": "postgres-stop-unadopted", "error_type": "RuntimeError"}]
    stop_command.stop.assert_called_once_with(join_log=False)
    stop_command.finish_log.assert_called_once()


def test_owned_stop_can_defer_log_join_until_inherited_writer_is_stopped():
    process = Mock()
    process.poll.return_value = 0
    thread = Mock()
    thread.is_alive.return_value = False
    owned = verify.OwnedProcess("postgres-start", process, thread)
    owned.stop(join_log=False)
    thread.join.assert_not_called()
    owned.finish_log()
    thread.join.assert_called_once_with(timeout=5)


def test_owned_stop_does_not_terminate_unrelated_processes(monkeypatch):
    process = Mock()
    process.pid = 22296
    process.poll.return_value = None
    root, child = Mock(), Mock()
    root.children.return_value = [child]
    lookup = Mock(return_value=root)
    monkeypatch.setattr(verify.psutil, "Process", lookup)
    monkeypatch.setattr(verify.psutil, "wait_procs", Mock(return_value=([], [])))
    verify.OwnedProcess("ticket-tool", process).stop(join_log=False)
    lookup.assert_called_once_with(22296)
    root.children.assert_called_once_with(recursive=True)
    child.terminate.assert_called_once()
    process.terminate.assert_called_once()
