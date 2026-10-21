from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
import psutil
import psycopg

ROOT = Path(__file__).resolve().parents[1]
POSTGRES_PORT = 25432
FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
    subprocess, "CREATE_NEW_PROCESS_GROUP", 0
)
COUNTS = {
    "warmup_samples": 2,
    "latency_samples": 10,
    "throughput_requests": 20,
    "concurrency": 4,
    "normal_task_samples": 2,
    "crypto_samples": 20,
}

if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

# Keep direct-script execution compatible with the documented module entry point.
from backend.benchmark.internal_security import (  # noqa: E402
    INTERNAL_AUTH_KEYS_ENV,
    INTERNAL_AUTH_REQUIRED_ENV,
    flatten_keys,
    public_auth_policy,
)
from backend.benchmark.native_app import (  # noqa: E402
    INSTANCE_ENV,
    ISOLATED_APP,
    NONCE_ROOT_ENV,
    TARGET_ENV,
    TARGET_IDENTITIES,
)
from backend.benchmark.runner import (  # noqa: E402
    BenchmarkConfig,
    NativeBenchmarkConfig,
    NativeBenchmarkRunner,
)
from scripts.native_database import connect, ensure_database, ensure_role, role_url  # noqa: E402
from scripts.native_security import generate_keys, service_identity  # noqa: E402
from scripts.run_native_benchmarks import REQUIRED_ENVIRONMENT  # noqa: E402
from scripts.source_manifest import snapshot  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Isolated Windows NativeBenchmarkRunner orchestration. Uses a NEW PostgreSQL "
            "cluster on 25432; imports cloud samples and never calls models."
        )
    )
    parser.add_argument("--allow-isolated", action="store_true")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--cloud-report", type=Path)
    parser.add_argument("--artifact-root", type=Path, default=ROOT / "artifacts")
    parser.add_argument("--port-offset", type=int, default=20000)
    parser.add_argument("--publish-current-summary", action="store_true")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Read-only validation; no directories, keys, sockets or processes created.",
    )
    for name, default in COUNTS.items():
        parser.add_argument("--" + name.replace("_", "-"), type=int, default=default)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def database_names(run_id: str) -> dict[str, str]:
    slug = run_id.lower().replace("-", "_")
    digest = hashlib.sha256(run_id.encode("ascii")).hexdigest()[:12]
    result = {}
    for kind in ("main", "audit", "baseline"):
        prefix = f"native_bench_{kind}_"
        limit = 63 - len(prefix) - len(digest) - 1
        result[kind] = f"{prefix}{slug[:limit]}_{digest}"
    return result


def prepared_postgres() -> Path:
    spec = json.loads((ROOT / "scripts/native-dependencies.lock.json").read_text("utf-8"))[
        "postgresql"
    ]
    dependency_root = (ROOT / ".native/deps").resolve()
    directory = (dependency_root / spec["directory"]).resolve()
    pg_ctl = (directory / spec["executable"]).resolve()
    if not pg_ctl.is_relative_to(dependency_root) or not pg_ctl.is_relative_to(directory):
        raise ValueError("PostgreSQL binary path escapes the prepared dependency directory")
    receipt = directory / "native-install.json"
    if not receipt.is_file() or json.loads(receipt.read_text("utf-8-sig")) != spec:
        raise ValueError("prepared PostgreSQL install receipt does not match the native lock")
    if any(
        not pg_ctl.with_name(name).is_file()
        for name in ("pg_ctl.exe", "initdb.exe", "postgres.exe")
    ):
        raise ValueError("prepared native PostgreSQL binaries are missing; no download attempted")
    return pg_ctl


@contextmanager
def offline_specs_environment():
    # native_config can consume stdin on import. Never inherit its cloud launcher controls.
    controls = {
        "AGENTGUARD_NATIVE_CLOUD_KEY_STDIN": None,
        "AGENTGUARD_CLOUD_LLM_API_KEY": None,
        "AGENTGUARD_CLOUD_LLM_ENABLED": "false",
    }
    previous = {name: os.environ.get(name) for name in controls}
    try:
        for name, value in controls.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def service_groups(
    urls: dict[str, str],
    keys: Path,
    tokens: dict[str, str],
    offset: int,
    *,
    internal_keys: dict[str, dict[str, str]],
    nonce_root: Path,
):
    flatten_keys(internal_keys)
    with offline_specs_environment():
        from scripts.native_config import Service, service_specs

        original = service_specs(
            urls["main"],
            urls["audit"],
            "",
            keys,
            with_llm=False,
            internal_keys=internal_keys,
        )
    selected = [
        [
            service
            for service in group
            if service.module not in {"backend.agent_runtime.app:app", "backend.ui_api.app:app"}
        ]
        for group in original
    ]
    selected = [group for group in selected if group]
    port_map = {service.port: service.port + offset for group in selected for service in group}

    def remap(value: str) -> str:
        if not value.startswith("http://"):
            return value
        parsed = urlsplit(value)
        if parsed.hostname != "127.0.0.1" or parsed.port not in port_map:
            raise ValueError("service_specs contains an unexpected service URL")
        return urlunsplit(parsed._replace(netloc=f"127.0.0.1:{port_map[parsed.port]}"))

    groups = [
        [
            replace(
                service,
                port=port_map[service.port],
                environment={name: remap(value) for name, value in service.environment.items()},
            )
            for service in group
        ]
        for group in selected
    ]
    for index, group in enumerate(groups):
        isolated = []
        for service in group:
            identity = service_identity(service.name)
            if (
                service.environment.get("AGENTGUARD_INTERNAL_AUTH_REQUIRED") != "true"
                or service.environment.get("AGENTGUARD_INTERNAL_AUTH_SERVICE_ID") != identity
                or json.loads(service.environment.get("AGENTGUARD_INTERNAL_AUTH_KEYS", "{}"))
                != internal_keys.get(identity, {})
            ):
                raise ValueError("native benchmark service authentication was downgraded")
            if service.module in TARGET_IDENTITIES:
                service = replace(
                    service,
                    module=ISOLATED_APP,
                    environment=service.environment
                    | {
                        TARGET_ENV: service.module,
                        NONCE_ROOT_ENV: str(nonce_root),
                        INSTANCE_ENV: service.name,
                    },
                )
            isolated.append(service)
        groups[index] = isolated
    baseline_tools = [
        replace(
            service,
            name="baseline-" + service.name,
            port=service.port + 1000,
            environment=service.environment
            | {
                "AGENTGUARD_DATABASE_URL": urls["baseline"],
                INSTANCE_ENV: "baseline-" + service.name,
            },
        )
        for service in groups[0]
    ]
    baseline_environment = {
        "AGENTGUARD_ENV": "benchmark",
        "AGENTGUARD_DATABASE_URL": urls["baseline"],
        "AGENTGUARD_AUDIT_DATABASE_URL": urls["audit"],
        "AGENTGUARD_GATEWAY_AUDIENCE": "secure-tool-gateway",
        "AGENTGUARD_GATEWAY_KEY_ID": "gateway-key-01",
        "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE": str(keys / "private/gateway.private"),
        "AGENTGUARD_INTERNAL_AUTH_REQUIRED": "true",
        "AGENTGUARD_INTERNAL_AUTH_KEYS": "{}",
        **{
            "AGENTGUARD_BENCHMARK_" + name.upper() + "_TOKEN": token
            for name, token in tokens.items()
        },
        **{
            "AGENTGUARD_BENCHMARK_"
            + service.environment["AGENTGUARD_TOOL_KIND"].upper()
            + "_TOOL_URL": f"http://127.0.0.1:{service.port}"
            for service in baseline_tools
        },
    }
    baselines = [
        Service(
            "baseline-" + name,
            "backend.benchmark.baseline_app:app",
            port + offset,
            baseline_environment
            | {
                "AGENTGUARD_BENCHMARK_MODE": mode,
                "AGENTGUARD_INTERNAL_AUTH_SERVICE_ID": "baseline-" + name,
            },
        )
        for name, mode, port in (
            ("static", "shared_static_credential", 19001),
            ("rbac", "conventional_rbac", 19002),
        )
    ]
    groups.extend((baseline_tools, baselines))
    ports = [service.port for group in groups for service in group]
    forbidden = {
        POSTGRES_PORT,
        15432,
        5432,
        5433,
        8090,
        8088,
        11434,
        *range(18001, 18011),
        *range(18101, 18104),
        *range(18201, 18206),
        *range(18301, 18305),
    }
    if (
        offset <= 0
        or len(ports) != len(set(ports))
        or any(port < 1024 or port > 65535 or port in forbidden for port in ports)
    ):
        raise ValueError("service remapping must use distinct non-production loopback ports")
    return groups


@dataclass(repr=False)
class Plan:
    config: NativeBenchmarkConfig
    runtime: Path
    pg_ctl: Path
    names: dict[str, str]
    urls: dict[str, str]
    passwords: dict[str, str]
    groups: list
    source: dict
    cloud: dict
    raw_cloud: bytes | None
    validate_only: bool

    def public(self) -> dict:
        return {
            "run_id": self.config.run_id,
            "acceptance_target": NativeBenchmarkRunner.ACCEPTANCE_TARGET,
            "deployment": "native_windows",
            "postgres_port": POSTGRES_PORT,
            "database_names": self.names,
            "services": [
                {
                    "name": service.name,
                    "module": service.module,
                    "url": f"http://127.0.0.1:{service.port}",
                }
                for group in self.groups
                for service in group
            ],
            "runtime": str(self.runtime),
            "runner_artifacts": str(
                self.config.artifact_root / "benchmarks/runs" / self.config.run_id
            ),
            "source_snapshot_sha256": self.source["snapshot_sha256"],
            "cloud_report_status": self.cloud["status"],
            "cloud_source_bound": self.cloud["status"] == "IMPORTED",
            "publication_requested": self.config.publish_current_summary,
            "model_calls": 0,
            "isolation_boundary": "loopback_and_separate_databases_not_os_or_network_sandbox",
            "internal_authentication": public_auth_policy(),
            "current_summary_publication": "archive existing bytes by SHA256, then atomic replace",
        }


def build_plan(args: argparse.Namespace) -> Plan:
    if not args.allow_isolated or platform.system() != "Windows":
        raise ValueError("explicit --allow-isolated and a Windows host are required")
    if re.fullmatch(r"native-[A-Za-z0-9][A-Za-z0-9_-]{0,79}", args.run_id) is None:
        raise ValueError("run-id must match NativeBenchmarkConfig's safe native- identifier")
    artifact_root = args.artifact_root.resolve()
    if not artifact_root.is_relative_to((ROOT / "artifacts").resolve()):
        raise ValueError("artifact-root must remain inside this project's artifacts directory")
    runtime = artifact_root / "native-benchmark-runtime" / args.run_id
    run_dir = artifact_root / "benchmarks/runs" / args.run_id
    if runtime.exists() or run_dir.exists():
        raise FileExistsError("fresh runtime and benchmark run directories are required")
    if not str(runtime).isascii():
        raise ValueError("temporary PostgreSQL requires an ASCII path; no drive mapping attempted")
    cloud_path = args.cloud_report.resolve() if args.cloud_report is not None else None
    if cloud_path is not None and (
        cloud_path.suffix.lower() != ".json"
        or any(cloud_path.is_relative_to((ROOT / name).resolve()) for name in (".native", "keys"))
    ):
        raise ValueError("cloud-report must be JSON outside production runtime/key directories")
    if cloud_path is None and not args.validate_only:
        raise ValueError("execution requires the main thread's --cloud-report")
    pg_ctl = prepared_postgres()
    names = database_names(args.run_id)
    passwords = {kind: secrets.token_urlsafe(32) for kind in ("admin", *names)}
    admin = f"postgresql://postgres:{passwords['admin']}@127.0.0.1:{POSTGRES_PORT}/postgres"
    urls = {"admin": admin} | {
        kind: role_url(admin, name, passwords[kind], name) for kind, name in names.items()
    }
    tokens = {name: secrets.token_urlsafe(32) for name in ("admin", "static", "rbac")}
    internal_keys = generate_keys()
    keys = runtime / "keys"
    groups = service_groups(
        urls,
        keys,
        tokens,
        args.port_offset,
        internal_keys=internal_keys,
        nonce_root=runtime / "internal-auth",
    )
    by_name = {service.name: service for group in groups for service in group}
    fields = {
        "authority_url": "authorization-authority",
        "coordinator_delegation_url": "coordinator-delegation-agent",
        "case_delegation_url": "case-delegation-agent",
        "gateway_url": "secure-gateway",
        "registry_url": "business-action-registry",
        "revocation_url": "revocation-authority",
        "audit_service_url": "audit-append-authority",
        "checkpoint_service_url": "checkpoint-service",
        "baseline_static_url": "baseline-static",
        "baseline_rbac_url": "baseline-rbac",
    }
    config = NativeBenchmarkConfig(
        run_id=args.run_id,
        artifact_root=artifact_root,
        main_database_url=urls["main"],
        audit_database_url=urls["audit"],
        benchmark_database_url=urls["baseline"],
        private_key_root=keys / "private",
        **{field: f"http://127.0.0.1:{by_name[name].port}" for field, name in fields.items()},
        coordinator_agent_url="",
        live_refund_agent_url="",
        benchmark_admin_token=tokens["admin"],
        benchmark_static_token=tokens["static"],
        benchmark_rbac_token=tokens["rbac"],
        internal_auth_required=True,
        internal_auth_keys=flatten_keys(internal_keys),
        allow_isolated=True,
        cloud_report=cloud_path,
        source_snapshot=runtime / "source-snapshot.json",
        publish_current_summary=args.publish_current_summary,
        **{name: getattr(args, name) for name in COUNTS},
        random_seed=args.seed,
    )
    # Full NativeBenchmarkConfig validation follows NEW key generation, never dummy keys.
    BenchmarkConfig.validate(config)
    source = NativeBenchmarkRunner._read_source_snapshot(replace(config, source_snapshot=None))
    cloud = NativeBenchmarkRunner._read_cloud_report(config)
    NativeBenchmarkRunner._validate_cloud_source(cloud, source)
    raw_cloud = cloud_path.read_bytes() if cloud_path is not None else None
    if raw_cloud is not None and hashlib.sha256(raw_cloud).hexdigest() != cloud["sha256"]:
        raise ValueError("cloud-report changed while validating it")
    return Plan(
        config,
        runtime,
        pg_ctl,
        names,
        urls,
        passwords,
        groups,
        source,
        cloud,
        raw_cloud,
        args.validate_only,
    )


def child_environment(runtime: Path, values: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith(("AGENTGUARD_", "PG", "PYTEST_"))
        and not name.upper().endswith(("_API_KEY", "_TOKEN"))
        and name.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "DATABASE_URL"}
    }
    environment.update(
        {
            "PYTHONPATH": str(ROOT),
            "PYTHONUNBUFFERED": "1",
            "PYTHONUTF8": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "TEMP": str(runtime / "tmp"),
            "TMP": str(runtime / "tmp"),
            "AGENTGUARD_CLOUD_LLM_ENABLED": "false",
            "AGENTGUARD_LLM_MODE": "deterministic",
        }
    )
    environment.update(values or {})
    return environment


def assert_free_ports(ports: list[int]) -> None:
    for port in ports:
        with socket.socket() as probe:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            probe.bind(("127.0.0.1", port))


@dataclass
class OwnedProcess:
    name: str
    process: subprocess.Popen
    log_thread: threading.Thread | None = None

    def stop(self, *, join_log: bool = True) -> None:
        if self.process.poll() is None:
            # Only descendants of our still-live Popen handle may be terminated.
            subject = psutil.Process(self.process.pid)
            children = subject.children(recursive=True)
            for child in reversed(children):
                try:
                    child.terminate()
                except psutil.NoSuchProcess:
                    pass
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
            _, alive = psutil.wait_procs(children, timeout=5)
            for child in alive:
                child.kill()
            if psutil.wait_procs(alive, timeout=5)[1]:
                raise RuntimeError("an owned child process did not stop")
        if join_log:
            self.finish_log()

    def finish_log(self) -> None:
        if self.log_thread is not None:
            self.log_thread.join(timeout=5)
            if self.log_thread.is_alive():
                raise RuntimeError("an owned process log stream did not close")


@dataclass
class OwnedPostgres:
    process: psutil.Process
    name: str = "postgres-server"

    def stop(self) -> None:
        if not self.process.is_running():
            return
        subjects = [*reversed(self.process.children(recursive=True)), self.process]
        for subject in subjects:
            try:
                subject.terminate()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(subjects, timeout=10)
        for subject in alive:
            subject.kill()
        if psutil.wait_procs(alive, timeout=5)[1]:
            raise RuntimeError("owned temporary PostgreSQL did not stop")


class IsolatedRuntime:
    def __init__(self, plan: Plan) -> None:
        self.plan = plan
        self.processes: list[OwnedProcess] = []
        self.postgres: OwnedPostgres | None = None
        self.postgres_start_attempted_at: float | None = None
        self.secrets = [
            *plan.passwords.values(),
            *plan.urls.values(),
            plan.config.benchmark_admin_token,
            plan.config.benchmark_static_token,
            plan.config.benchmark_rbac_token,
            *json.loads(plan.config.internal_auth_keys).values(),
        ]
        self.events: list[dict] = []
        self.created = False

    def redact(self, value: str) -> str:
        for secret in sorted(set(self.secrets), key=len, reverse=True):
            value = value.replace(secret, "REDACTED") if secret else value
        return re.sub(r"postgres(?:ql)?(?:\+psycopg)?://[^\s\"']+", "REDACTED_DSN", value)

    def save(self, name: str, value: Any) -> None:
        path = self.plan.runtime / name
        with path.open("x", encoding="utf-8") as handle:
            handle.write(self.redact(json.dumps(value, indent=2, ensure_ascii=True)) + "\n")

    def start(self, name: str, command: list[str], values: dict[str, str] | None = None):
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=child_environment(self.plan.runtime, values),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=FLAGS,
        )
        owned = OwnedProcess(name, process)
        self.processes.append(owned)
        self.events.append(
            {
                "name": name,
                "pid": process.pid,
                "started_at": datetime.now(UTC).isoformat(),
                "command": [self.redact(item) for item in command],
            }
        )

        def collect_log() -> None:
            with (self.plan.runtime / "logs" / f"{name}.log").open("x", encoding="utf-8") as log:
                for line in process.stdout:
                    log.write(self.redact(line))
                    log.flush()
            process.stdout.close()

        owned.log_thread = threading.Thread(target=collect_log, daemon=True)
        owned.log_thread.start()
        return owned

    def command(
        self,
        name: str,
        arguments: list[str],
        values: dict[str, str] | None = None,
        *,
        timeout: int = 180,
        check: bool = True,
    ) -> int:
        owned = self.start(name, arguments, values)
        code = owned.process.wait(timeout=timeout)
        self.events[-1]["exit_code"] = code
        if code and check:
            raise RuntimeError(f"isolated {name} command failed; see its sanitized log")
        return code

    def prepare(self) -> None:
        self.plan.runtime.mkdir(parents=True, exist_ok=False)
        self.created = True
        # Restrict the fresh directory BEFORE placing passwords or private keys inside it.
        sid = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            ],
            text=True,
            creationflags=FLAGS,
        ).strip()
        if re.fullmatch(r"S-1-[0-9-]+", sid) is None:
            raise ValueError("unable to establish the current Windows account SID")
        subprocess.run(
            [
                "icacls.exe",
                str(self.plan.runtime),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=FLAGS,
        )
        for name in ("logs", "tmp", "postgres"):
            (self.plan.runtime / name).mkdir()
        self.save("plan.json", self.plan.public())
        self.save("source-snapshot.json", self.plan.source)
        (self.plan.runtime / "input-cloud-report.json").write_bytes(self.plan.raw_cloud)

    def start_postgres(self) -> None:
        data = self.plan.runtime / "postgres/data"
        password_file = self.plan.runtime / "tmp/init-password.tmp"
        with password_file.open("x", encoding="ascii") as handle:
            handle.write(self.plan.passwords["admin"])
        try:
            self.command(
                "postgres-init",
                [
                    str(self.plan.pg_ctl.with_name("initdb.exe")),
                    "-D",
                    str(data),
                    "-U",
                    "postgres",
                    "--pwfile",
                    str(password_file),
                    "--encoding=UTF8",
                    "--locale=C",
                    "--auth-local=scram-sha-256",
                    "--auth-host=scram-sha-256",
                ],
            )
        finally:
            password_file.unlink(missing_ok=True)
        assert_free_ports([POSTGRES_PORT])
        self.postgres_start_attempted_at = time.time()
        # pg_ctl uses PostgreSQL's Windows launcher rather than a direct admin-token server.
        self.command(
            "postgres-start",
            [
                str(self.plan.pg_ctl),
                "-D",
                str(data),
                "-l",
                str(self.plan.runtime / "tmp/postgres-server.raw.log"),
                "-o",
                f"-p {POSTGRES_PORT} -h 127.0.0.1",
                "-w",
                "-t",
                "60",
                "start",
            ],
            timeout=75,
        )
        self.capture_postgres()
        if self.postgres is None:
            raise RuntimeError("temporary PostgreSQL has no owned postmaster identity")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if not self.postgres.process.is_running():
                raise RuntimeError("temporary PostgreSQL exited")
            try:
                with connect(self.plan.urls["admin"]) as connection:
                    actual_data, port, version = connection.execute(
                        "SELECT current_setting('data_directory'), current_setting('port'), "
                        "current_setting('server_version')"
                    ).fetchone()
                if (
                    Path(actual_data).resolve() != data.resolve()
                    or int(port) != POSTGRES_PORT
                    or not str(version).startswith("16.")
                ):
                    raise RuntimeError("temporary PostgreSQL identity mismatch")
                self.save(
                    "postgres-identity.json",
                    {"data_directory": str(data), "port": int(port), "server_version": version},
                )
                return
            except psycopg.OperationalError:
                pass
            time.sleep(0.25)
        raise RuntimeError("temporary PostgreSQL startup timed out")

    def capture_postgres(self) -> None:
        data = (self.plan.runtime / "postgres/data").resolve()
        pidfile = data / "postmaster.pid"
        if not pidfile.is_file():
            return
        lines = pidfile.read_text("utf-8").splitlines()
        if len(lines) < 4:
            raise RuntimeError("temporary postmaster PID file is incomplete")
        process = psutil.Process(int(lines[0]))
        command = process.cmdline()
        if (
            self.postgres_start_attempted_at is None
            or Path(lines[1]).resolve() != data
            or int(lines[3]) != POSTGRES_PORT
            or process.create_time() < self.postgres_start_attempted_at - 1
            or Path(process.exe()).resolve() != self.plan.pg_ctl.with_name("postgres.exe")
            or "-D" not in command
            or Path(command[command.index("-D") + 1]).resolve() != data
        ):
            raise RuntimeError("refusing to adopt an unowned PostgreSQL process")
        self.postgres = OwnedPostgres(process)
        self.events.append(
            {
                "name": "postgres-server",
                "pid": process.pid,
                "created_at": process.create_time(),
                "command": command,
            }
        )

    def initialize_databases(self) -> None:
        with connect(self.plan.urls["admin"]) as connection:
            for kind, name in self.plan.names.items():
                ensure_role(connection, name, self.plan.passwords[kind])
                ensure_database(connection, name, name)
        # Reuse migrate.main without exposing its DSN in the OS command line.
        migrate = (
            "import os, sys\nfrom scripts.migrate import main\n"
            "sys.argv = ['migrate', '--database-url', os.environ['AGENTGUARD_DATABASE_URL'], "
            "'--directory', sys.argv[1]]\nmain()\n"
        )
        for kind, directories in {
            "main": ("main",),
            "audit": ("audit",),
            "baseline": ("main", "benchmark"),
        }.items():
            for directory in directories:
                self.command(
                    f"migrate-{kind}-{directory}",
                    [
                        sys.executable,
                        "-B",
                        "-c",
                        migrate,
                        f"database/migrations/{directory}",
                    ],
                    {"AGENTGUARD_DATABASE_URL": self.plan.urls[kind]},
                )
        self.command(
            "generate-keys",
            [
                sys.executable,
                "-B",
                "-m",
                "scripts.generate_dev_keys",
                "--root",
                str(self.plan.runtime / "keys"),
            ],
        )
        self.secrets.extend(
            path.read_text("ascii").strip()
            for path in (self.plan.runtime / "keys/private").glob("*.private")
        )
        for kind in ("main", "baseline"):
            values = {"AGENTGUARD_DATABASE_URL": self.plan.urls[kind]}
            self.command(
                f"register-keys-{kind}",
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "scripts.register_dev_keys",
                    "--public-root",
                    str(self.plan.runtime / "keys/public"),
                ],
                values,
            )
            self.command(f"seed-{kind}", [sys.executable, "-B", "-m", "scripts.seed_demo"], values)
        self.plan.config.validate()

    def wait_health(self, owned: OwnedProcess, port: int) -> None:
        deadline = time.monotonic() + 120
        with httpx.Client(timeout=3, trust_env=False) as client:
            while time.monotonic() < deadline:
                if owned.process.poll() is not None:
                    raise RuntimeError("an isolated service exited during startup")
                # Windows venv launchers can put the Uvicorn listener in a child process.
                root = psutil.Process(owned.process.pid)
                listening = False
                try:
                    subjects = [root, *root.children(recursive=True)]
                except psutil.NoSuchProcess:
                    subjects = []
                for subject in subjects:
                    try:
                        listening = any(
                            item.status == psutil.CONN_LISTEN and item.laddr == ("127.0.0.1", port)
                            for item in subject.net_connections(kind="tcp")
                        )
                    except psutil.NoSuchProcess:
                        continue
                    if listening:
                        break
                if listening and owned.process.poll() is None:
                    try:
                        response = client.get(f"http://127.0.0.1:{port}/health")
                        if response.status_code == 200:
                            body = response.json()
                            if (
                                isinstance(body, dict)
                                and body.get("status") == "ok"
                                and owned.process.poll() is None
                            ):
                                return
                    except (httpx.HTTPError, ValueError):
                        pass
                time.sleep(0.25)
        raise RuntimeError("an isolated service health check timed out")

    def start_services(self) -> None:
        for group in self.plan.groups:
            started = []
            for service in group:
                assert_free_ports([service.port])
                owned = self.start(
                    service.name,
                    [
                        sys.executable,
                        "-B",
                        "-m",
                        "uvicorn",
                        service.module,
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(service.port),
                        "--no-access-log",
                        *(["--factory"] if service.module == ISOLATED_APP else []),
                    ],
                    service.environment,
                )
                started.append((owned, service.port))
            for owned, port in started:
                self.wait_health(owned, port)

    def run_benchmark(self) -> tuple[int, dict]:
        config = self.plan.config
        values = {name: str(getattr(config, field)) for field, name in REQUIRED_ENVIRONMENT.items()}
        values |= {
            INTERNAL_AUTH_REQUIRED_ENV: "true",
            INTERNAL_AUTH_KEYS_ENV: config.internal_auth_keys,
        }
        arguments = [
            sys.executable,
            "-B",
            "-m",
            "scripts.run_native_benchmarks",
            "--allow-isolated",
            "--artifact-root",
            str(config.artifact_root),
            "--run-id",
            config.run_id,
            "--source-snapshot",
            str(config.source_snapshot),
            "--cloud-report",
            str(self.plan.runtime / "input-cloud-report.json"),
            "--seed",
            str(config.random_seed),
        ]
        for name in COUNTS:
            arguments.extend(("--" + name.replace("_", "-"), str(getattr(config, name))))
        if config.publish_current_summary:
            arguments.append("--publish-current-summary")
        code = self.command("benchmark-runner", arguments, values, timeout=7200, check=False)
        path = config.artifact_root / "benchmarks/runs" / config.run_id / "summary.json"
        summary = json.loads(path.read_text("utf-8")) if path.is_file() else {}
        if code == 0 and (
            summary.get("run_id") != config.run_id
            or summary.get("status") != "VERIFIED"
            or summary.get("acceptance_target") != NativeBenchmarkRunner.ACCEPTANCE_TARGET
            or summary.get("environment", {}).get("deployment") != "native_windows"
            or summary.get("acceptance", {}).get("passed") is not True
        ):
            raise RuntimeError("runner exit code and run-local summary disagree")
        if code == 0 and config.publish_current_summary:
            current = config.artifact_root / "benchmarks/current-cloud-summary.json"
            if not current.is_file() or json.loads(current.read_text("utf-8")) != summary:
                raise RuntimeError("runner did not publish the exact run-local current summary")
        return code, summary

    def cleanup(self) -> list[dict]:
        errors = []
        initial_count = len(self.processes)
        for owned in reversed(self.processes.copy()):
            try:
                owned.stop(join_log=False)
            except Exception as exc:
                errors.append({"name": owned.name, "error_type": type(exc).__name__})
        if self.postgres is None and self.postgres_start_attempted_at is not None:
            try:
                self.capture_postgres()
            except Exception as exc:
                errors.append({"name": "postgres-identity", "error_type": type(exc).__name__})
            if self.postgres is None:
                try:
                    self.command(
                        "postgres-stop-unadopted",
                        [
                            str(self.plan.pg_ctl),
                            "-D",
                            str(self.plan.runtime / "postgres/data"),
                            "-w",
                            "-t",
                            "30",
                            "stop",
                            "-m",
                            "fast",
                        ],
                        timeout=45,
                    )
                except Exception as exc:
                    errors.append(
                        {"name": "postgres-stop-unadopted", "error_type": type(exc).__name__}
                    )
        if self.postgres is not None:
            try:
                if self.postgres.process.is_running():
                    self.command(
                        "postgres-stop",
                        [
                            str(self.plan.pg_ctl),
                            "-D",
                            str(self.plan.runtime / "postgres/data"),
                            "-w",
                            "-t",
                            "30",
                            "stop",
                            "-m",
                            "fast",
                        ],
                        timeout=45,
                    )
            except Exception as exc:
                errors.append({"name": "postgres-stop", "error_type": type(exc).__name__})
            finally:
                try:
                    self.postgres.stop()
                except Exception as exc:
                    errors.append({"name": "postgres-server", "error_type": type(exc).__name__})
        for owned in self.processes[initial_count:]:
            try:
                owned.stop(join_log=False)
            except Exception as exc:
                errors.append({"name": owned.name, "error_type": type(exc).__name__})
        # pg_ctl descendants can inherit its stdout pipe until PostgreSQL has stopped.
        for owned in reversed(self.processes):
            try:
                owned.finish_log()
            except Exception as exc:
                errors.append({"name": owned.name, "error_type": type(exc).__name__})
        raw_log = self.plan.runtime / "tmp/postgres-server.raw.log"
        if raw_log.is_file():
            try:
                text = self.redact(raw_log.read_text("utf-8", errors="replace"))
                with (self.plan.runtime / "logs/postgres-server.log").open(
                    "x", encoding="utf-8"
                ) as log:
                    log.write(text)
                raw_log.unlink()
            except Exception as exc:
                errors.append({"name": "postgres-log", "error_type": type(exc).__name__})
        return errors


def execute(plan: Plan) -> tuple[int, dict]:
    runtime = IsolatedRuntime(plan)
    report = plan.public() | {
        "status": "FAILED",
        "benchmark_executed": False,
        "benchmark_verified": False,
        "current_summary_published": False,
    }
    code = 1
    try:
        ports = [POSTGRES_PORT, *(service.port for group in plan.groups for service in group)]
        assert_free_ports(ports)
        if snapshot() != plan.source:
            raise ValueError("source changed after plan/report validation")
        runtime.prepare()
        runtime.start_postgres()
        runtime.initialize_databases()
        runtime.start_services()
        report["benchmark_executed"] = True
        code, summary = runtime.run_benchmark()
        report["runner_exit_code"] = code
        report["status"] = summary.get("status", "FAILED")
        report["benchmark_verified"] = code == 0 and report["status"] == "VERIFIED"
        report["current_summary_published"] = (
            report["benchmark_verified"] and plan.config.publish_current_summary
        )
    except KeyboardInterrupt:
        code = 130
        report["status"] = "INTERRUPTED"
    except Exception as exc:
        code = 1
        report["error_type"] = type(exc).__name__
    finally:
        errors = runtime.cleanup()
        report["cleanup_errors"] = errors
        report["cleanup_succeeded"] = not errors
        if errors:
            code = 1
            report["status"] = "FAILED"
        report["finished_at"] = datetime.now(UTC).isoformat()
        if runtime.created:
            runtime.save("processes.json", runtime.events)
            runtime.save("orchestration.json", report)
    return code, report


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = build_plan(args)
        if args.validate_only:
            result = plan.public() | {
                "status": "PLAN_VALIDATED",
                "benchmark_executed": False,
                "benchmark_verified": False,
                "runtime_configuration_validated": False,
            }
            code = 0
        else:
            code, result = execute(plan)
    except Exception as exc:
        # Never print exception messages/libpq errors, environment values or credentials.
        code, result = (
            1,
            {
                "status": "REJECTED",
                "error_type": type(exc).__name__,
                "benchmark_executed": False,
                "benchmark_verified": False,
            },
        )
    print(json.dumps(result, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
