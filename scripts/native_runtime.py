from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import quote

import httpx
import psutil

from scripts.native_config import cloud_configuration, prepare_model_profiles, service_specs
from scripts.native_database import (
    AUDIT_DATABASE,
    AUDIT_ROLE,
    MAIN_DATABASE,
    MAIN_ROLE,
    UI_ROLE,
    WORKFLOW_ROLE,
    connect,
    ensure_database,
    ensure_role,
    provision_ui,
    provision_workflow,
    role_url,
)
from scripts.native_security import generate_keys, save_keys
from scripts.provision_ui_reader import READ_TABLES

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".native"
STATE = RUNTIME / "processes.json"
CONFIG = RUNTIME / "config.json"
LOCK = ROOT / "scripts" / "native-dependencies.lock.json"
PYTHON = ROOT / ".runtime" / "python" / "python.exe"
if not PYTHON.exists():
    PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
    subprocess, "CREATE_NEW_PROCESS_GROUP", 0
)


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if path.absolute() == CONFIG.absolute() or "native_secret_storage" in value:
        from scripts.native_windows_dpapi import decode_database_document

        return decode_database_document(value)
    return value


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def layout() -> None:
    for name in ("logs", "downloads", "deps", "home", "tmp"):
        (RUNTIME / name).mkdir(parents=True, exist_ok=True)
    # This protects local credentials from other Windows accounts, not sibling processes.
    if os.name == "nt":
        system_directory = Path(os.environ["SystemRoot"]) / "System32"
        sid = json.loads(
            subprocess.check_output(
                [
                    str(system_directory / "WindowsPowerShell/v1.0/powershell.exe"),
                    "-NoProfile",
                    "-Command",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value "
                    "| ConvertTo-Json",
                ],
                text=True,
            )
        )
        subprocess.run(
            [
                str(system_directory / "icacls.exe"),
                str(RUNTIME),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )


def clean_environment(values: dict[str, str] | None = None) -> dict[str, str]:
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("AGENTGUARD_")}
    for key in list(environment):
        if key.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}:
            environment.pop(key)
    environment.update({"PYTHONPATH": str(ROOT), "PYTHONUNBUFFERED": "1"})
    environment.update(values or {})
    return environment


def run(
    command: list[str],
    *,
    environment: dict[str, str] | None = None,
    log_name: str = "initialization",
    cwd: Path = ROOT,
) -> None:
    log_path = RUNTIME / "logs" / f"{log_name}.log"
    with log_path.open("a", encoding="utf-8") as log:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=clean_environment(environment),
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=FLAGS,
        )
    if result.returncode:
        raise RuntimeError(f"{log_name} failed with exit {result.returncode}; see {log_path}")


def hash_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def safe_extract(archive: Path, destination: Path, *, postgresql_server_only: bool = False) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        for member in members:
            if not (destination / member.filename).resolve().is_relative_to(root):
                raise RuntimeError("dependency archive contains an unsafe path")
        if postgresql_server_only:
            # pgAdmin is unused and its bundled Python paths can exceed Windows MAX_PATH.
            prefixes = ("pgsql/bin/", "pgsql/lib/", "pgsql/share/")
            licenses = {
                "pgsql/server_license.txt",
                "pgsql/commandlinetools_3rd_party_licenses.txt",
            }
            members = [
                member
                for member in members
                if member.filename.startswith(prefixes) or member.filename in licenses
            ]
        source.extractall(destination, members=members)


def dependency(name: str, *, prepared_only: bool = False) -> Path:
    spec = read_json(LOCK)[name]
    directory = RUNTIME / "deps" / spec["directory"]
    executable = directory / spec["executable"]
    receipt = directory / "native-install.json"
    if executable.exists() and receipt.exists() and read_json(receipt) == spec:
        return executable
    if prepared_only:
        raise RuntimeError(
            f"prepared dependency is missing or not locked: {name}; run native-up.ps1 explicitly"
        )
    archive = RUNTIME / "downloads" / spec["archive"]
    if not archive.exists() or hash_file(archive) != spec["sha256"]:
        print(f"NATIVE_DOWNLOAD={name} version={spec['version']}", flush=True)
        curl = shutil.which("curl.exe")
        if not curl:
            raise RuntimeError("Windows curl.exe is required to download portable dependencies")
        command = [curl, "-fL", "--retry", "3", "--connect-timeout", "30"]
        proxy = os.getenv("AGENTGUARD_NATIVE_DOWNLOAD_PROXY")
        if proxy:
            command.extend(["--proxy", proxy])
        command.extend(["--output", str(archive), spec["url"]])
        run(command, log_name=f"download-{name}")
    if hash_file(archive) != spec["sha256"]:
        raise RuntimeError(f"SHA256 verification failed: {archive.name}; refusing execution")
    directory.mkdir(parents=True, exist_ok=True)
    safe_extract(archive, directory, postgresql_server_only=name == "postgresql")
    if not executable.exists():
        raise RuntimeError(f"unexpected dependency layout: {executable}")
    write_json(receipt, spec)
    print(f"NATIVE_DEPENDENCY=PASS name={name} version={spec['version']}", flush=True)
    return executable


def matching_process(item: dict) -> psutil.Process | None:
    try:
        process = psutil.Process(int(item["pid"]))
        if abs(process.create_time() - float(item["created_at"])) > 0.01:
            return None
        if os.path.normcase(process.exe()) != os.path.normcase(item["executable"]):
            return None
        if process.cmdline() != item["command"]:
            return None
        return process
    except (psutil.Error, KeyError, TypeError, ValueError):
        return None


def spawn(
    name: str,
    command: list[str],
    port: int,
    state: dict,
    environment: dict[str, str] | None = None,
    cwd: Path = ROOT,
) -> dict:
    log_path = RUNTIME / "logs" / f"{name}.log"
    with log_path.open("a", encoding="utf-8") as log:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=clean_environment(environment),
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=FLAGS,
        )
    subject = psutil.Process(process.pid)
    item = {
        "name": name,
        "pid": process.pid,
        "port": port,
        "created_at": subject.create_time(),
        "executable": subject.exe(),
        "command": subject.cmdline(),
        "log": str(log_path),
    }
    state["processes"].append(item)
    write_json(STATE, state)
    return item


def wait_http(item: dict, path: str = "/health", timeout: int = 120) -> dict:
    deadline = time.monotonic() + timeout
    with httpx.Client(timeout=3, trust_env=False) as client:
        while time.monotonic() < deadline:
            if matching_process(item) is None:
                raise RuntimeError(f"{item['name']} exited; see {item['log']}")
            try:
                response = client.get(f"http://127.0.0.1:{item['port']}{path}")
                if response.status_code == 200:
                    body = response.json()
                    if path != "/health" or body.get("status") == "ok":
                        print(f"NATIVE_HEALTH=PASS service={item['name']}", flush=True)
                        return body
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(0.5)
    raise RuntimeError(f"{item['name']} health timeout; see {item['log']}")


def free_port(port: int) -> bool:
    with socket.socket() as connection:
        connection.settimeout(0.2)
        return connection.connect_ex(("127.0.0.1", port)) != 0


def select_ui_port(requested: int, reserved: set[int]) -> int:
    for port in [requested] if requested else [8088, 8099, 8100, 8101]:
        if port not in reserved and free_port(port):
            return port
    raise RuntimeError("no free UI port; specify a free -UiPort")


def config(postgres_port: int) -> dict:
    from scripts.native_windows_dpapi import PASSWORD_FIELDS, config_lock, save_database_config

    with config_lock(CONFIG):
        original = CONFIG.read_bytes() if CONFIG.exists() else None
        if original is not None:
            value = read_json(CONFIG)
            if value["postgres_port"] != postgres_port:
                raise RuntimeError("existing native database uses a different -PostgresPort")
            if "workflow_password" not in value:
                value["workflow_password"] = secrets.token_urlsafe(32)
                save_database_config(CONFIG, value, expected=original)
            return value
        value = {name: secrets.token_urlsafe(32) for name in PASSWORD_FIELDS}
        value["postgres_port"] = postgres_port
        save_database_config(CONFIG, value, expected=None)
        return value


def prepared_config(postgres_port: int) -> dict:
    if not str(ROOT).isascii():
        raise RuntimeError(
            "prepared startup requires an English project path; no drive mapping is created"
        )
    if not CONFIG.is_file():
        raise RuntimeError(
            "native configuration is missing; initialize explicitly with native-up.ps1"
        )
    value = read_json(CONFIG)
    required = (
        "admin_password",
        "main_password",
        "audit_password",
        "ui_password",
        "workflow_password",
    )
    if any(not isinstance(value.get(name), str) or not value[name] for name in required):
        raise RuntimeError("prepared native database configuration is incomplete")
    if value.get("postgres_port") != postgres_port:
        raise RuntimeError("prepared startup cannot change the configured PostgreSQL port")
    files = [
        RUNTIME / "seeded.json",
        RUNTIME / "postgres/data/PG_VERSION",
        RUNTIME / "postgres/data/global/pg_control",
    ]
    for name in (
        "authorization",
        "agent-coordinator",
        "agent-knowledge",
        "agent-case",
        "agent-refund",
        "gateway",
        "receipt",
        "audit",
    ):
        files.extend(
            (RUNTIME / f"keys/private/{name}.private", RUNTIME / f"keys/public/{name}.public")
        )
    if any(not path.is_file() for path in files) or any(
        not (RUNTIME / name).is_dir() for name in ("logs", "tmp")
    ):
        raise RuntimeError(
            "prepared data, key or runtime files are missing; no initialization was attempted"
        )
    if (RUNTIME / "postgres/data/PG_VERSION").read_text(encoding="ascii").strip() != "16":
        raise RuntimeError("prepared startup requires the existing PostgreSQL 16 data directory")
    dependency("postgresql", prepared_only=True)
    return value


def ascii_project_root(value: dict, state: dict) -> Path:
    if str(ROOT).isascii():
        return ROOT
    raise RuntimeError(
        "Extract AgentGuard into an English path before initialization; no drive mapping is created"
    )


def database_urls(value: dict) -> dict[str, str]:
    from scripts.native_windows_dpapi import decode_database_document

    value = decode_database_document(value)
    password = quote(value["admin_password"], safe="")
    admin = f"postgresql://postgres:{password}@127.0.0.1:{value['postgres_port']}/postgres"
    return {
        "admin": admin,
        "main": role_url(admin, MAIN_ROLE, value["main_password"], MAIN_DATABASE),
        "audit": role_url(admin, AUDIT_ROLE, value["audit_password"], AUDIT_DATABASE),
        "ui": role_url(admin, UI_ROLE, value["ui_password"], MAIN_DATABASE),
        "workflow": role_url(admin, WORKFLOW_ROLE, value["workflow_password"], MAIN_DATABASE)
        if value.get("workflow_password")
        else "",
    }


def postgres_start(value: dict, state: dict, *, prepared_only: bool = False) -> None:
    installed = dependency("postgresql", prepared_only=prepared_only)
    ascii_root = ascii_project_root(value, state)
    pg_ctl = ascii_root / installed.relative_to(ROOT)
    data = ascii_root / ".native" / "postgres" / "data"
    if not prepared_only:
        data.parent.mkdir(exist_ok=True)
    if not (data / "PG_VERSION").exists():
        if prepared_only:
            raise RuntimeError("prepared PostgreSQL data is missing; initdb was not attempted")
        password_file = ascii_root / ".native" / "postgres" / "init-password.tmp"
        password_file.write_text(value["admin_password"], encoding="ascii")
        try:
            run(
                [
                    str(pg_ctl.with_name("initdb.exe")),
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
                log_name="postgres-init",
                cwd=ascii_root,
                environment={
                    "TEMP": str(ascii_root / ".native/tmp"),
                    "TMP": str(ascii_root / ".native/tmp"),
                },
            )
        finally:
            password_file.unlink(missing_ok=True)
    state["postgres"] = {"data": str(data), "pg_ctl": str(pg_ctl), "port": value["postgres_port"]}
    write_json(STATE, state)
    status = subprocess.run(
        [str(pg_ctl), "-D", str(data), "status"], capture_output=True, creationflags=FLAGS
    )
    if status.returncode != 0:
        if not free_port(value["postgres_port"]):
            raise RuntimeError("managed PostgreSQL port is owned by another process")
        run(
            [
                str(pg_ctl),
                "-D",
                str(data),
                "-l",
                str(ascii_root / ".native/logs/postgres.log"),
                "-o",
                f"-p {value['postgres_port']} -h 127.0.0.1",
                "-w",
                "start",
            ],
            log_name="postgres-start",
            cwd=ascii_root,
        )
    with connect(database_urls(value)["admin"]) as connection:
        version = connection.execute("SHOW server_version").fetchone()[0]
        actual_data = Path(connection.execute("SHOW data_directory").fetchone()[0]).resolve()
    if not actual_data.samefile(data) or not str(version).startswith("16."):
        raise RuntimeError("native PostgreSQL identity or major version mismatch")
    print(f"NATIVE_POSTGRES=PASS version={version} port={value['postgres_port']}", flush=True)


def initialize(value: dict) -> dict[str, str]:
    urls = database_urls(value)
    with connect(urls["admin"]) as connection:
        ensure_role(connection, MAIN_ROLE, value["main_password"])
        ensure_role(connection, AUDIT_ROLE, value["audit_password"])
        ensure_database(connection, MAIN_DATABASE, MAIN_ROLE)
        ensure_database(connection, AUDIT_DATABASE, AUDIT_ROLE)
    for name in ("main", "audit"):
        run(
            [
                str(PYTHON),
                "scripts/migrate.py",
                "--database-url",
                urls[name],
                "--directory",
                f"database/migrations/{name}",
            ],
            log_name="migrations",
        )
    keys = RUNTIME / "keys"
    run([str(PYTHON), "scripts/generate_dev_keys.py", "--root", str(keys)])
    environment = {"AGENTGUARD_DATABASE_URL": urls["main"]}
    run(
        [str(PYTHON), "scripts/register_dev_keys.py", "--public-root", str(keys / "public")],
        environment=environment,
    )
    if not (RUNTIME / "seeded.json").exists():
        run([str(PYTHON), "scripts/seed_demo.py"], environment=environment)
        write_json(RUNTIME / "seeded.json", {"seeded_at": time.time()})
    run([str(PYTHON), "scripts/seed_demo.py", "--chinese-only"], environment=environment)
    run([str(PYTHON), "scripts/refresh_business_materials.py"], environment=environment)
    provision_ui(urls["admin"], value["ui_password"])
    provision_workflow(urls["admin"], value["workflow_password"])
    print("NATIVE_INITIALIZATION=PASS migrations=main,audit keys=8", flush=True)
    return urls


def prepared_urls(value: dict) -> dict[str, str]:
    urls = database_urls(value)
    # Read existing schema checksums and grants; never repair or provision during a model switch.
    for name in ("main", "audit"):
        with connect(urls[name]) as connection:
            rows = dict(
                connection.execute(
                    "SELECT version, checksum_sha256 FROM schema_migrations"
                ).fetchall()
            )
        migrations = sorted((ROOT / f"database/migrations/{name}").glob("*.sql"))
        if not migrations:
            raise RuntimeError(f"prepared schema has no source migrations: {name}")
        for migration in migrations:
            checksum = hashlib.sha256(
                migration.read_text(encoding="utf-8").encode("utf-8")
            ).hexdigest()
            if rows.get(migration.name) != checksum:
                raise RuntimeError(
                    f"prepared schema differs: {name}/{migration.name}; "
                    "apply initialization explicitly"
                )
    for name in ("ui", "workflow"):
        with connect(urls[name]) as connection:
            role = connection.execute(
                "SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user"
            ).fetchone()
            if role is None or any(role):
                raise RuntimeError(f"prepared {name} role has unsafe administrative privileges")
            tables = (
                READ_TABLES if name == "ui" else ("agent_workflow_runs", "agent_workflow_events")
            )
            for table in tables:
                if not connection.execute(
                    "SELECT has_table_privilege(current_user, %s, 'SELECT')", (f"public.{table}",)
                ).fetchone()[0]:
                    raise RuntimeError(f"prepared {name} role is missing read access: {table}")
                if (
                    name == "ui"
                    and connection.execute(
                        "SELECT has_table_privilege(current_user, %s, "
                        "'INSERT,UPDATE,DELETE,TRUNCATE')",
                        (f"public.{table}",),
                    ).fetchone()[0]
                ):
                    raise RuntimeError(f"prepared UI role has write access: {table}")
            if name == "workflow":
                for table, privileges in (
                    ("agent_workflow_runs", ("INSERT", "UPDATE")),
                    ("agent_workflow_events", ("INSERT",)),
                ):
                    for privilege in privileges:
                        if not connection.execute(
                            "SELECT has_table_privilege(current_user, %s, %s)",
                            (f"public.{table}", privilege),
                        ).fetchone()[0]:
                            raise RuntimeError(
                                f"prepared workflow role is missing operational access: {table}"
                            )
    print("NATIVE_PREPARED_ENVIRONMENT=READY no_migrations_no_seed_no_key_generation", flush=True)
    return urls


def stop(state: dict) -> None:
    for item in reversed(state["processes"]):
        process = matching_process(item)
        if process is None:
            print(
                f"NATIVE_STOP_SKIPPED={item['name']} reason=exited_or_identity_changed", flush=True
            )
            continue
        subjects = [*reversed(process.children(recursive=True)), process]
        for subject in subjects:
            try:
                subject.terminate()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(subjects, timeout=10)
        for subject in alive:
            subject.kill()
        _, alive = psutil.wait_procs(alive, timeout=5)
        if alive:
            raise RuntimeError(f"unable to stop native process: {item['name']}")
    pg = state.get("postgres")
    if pg:
        pg_ctl, data = Path(pg["pg_ctl"]), Path(pg["data"])
        if not data.resolve().is_relative_to(RUNTIME.resolve()):
            raise RuntimeError(
                "refusing to stop PostgreSQL outside this project's .native directory"
            )
        status = subprocess.run(
            [str(pg_ctl), "-D", str(data), "status"], capture_output=True, creationflags=FLAGS
        )
        if status.returncode == 0:
            run(
                [str(pg_ctl), "-D", str(data), "-w", "stop", "-m", "fast"], log_name="postgres-stop"
            )
    STATE.unlink(missing_ok=True)
    drive = state.get("ascii_drive")
    if drive and Path(f"{drive}/").exists() and Path(f"{drive}/").samefile(ROOT):
        subprocess.run(["subst.exe", drive, "/D"], check=True, creationflags=FLAGS)
    print("NATIVE_STOP_RESULT=PASS", flush=True)


def prerequisites() -> None:
    if os.name != "nt":
        raise RuntimeError("this entry point requires Windows x64")
    if not str(ROOT).isascii():
        raise RuntimeError("Use an English project path; no drive mapping is created")
    if not PYTHON.exists():
        raise RuntimeError(
            "Python runtime is missing; use the complete Windows release or bootstrap.ps1"
        )
    if not (ROOT / "frontend/dist/index.html").is_file():
        raise RuntimeError(
            "built frontend is missing; build frontend before starting the native runtime"
        )


def managed_state() -> dict:
    value = read_json(STATE)
    if (
        value.get("schema_version") != 1
        or os.path.normcase(value.get("project_root", "")) != os.path.normcase(str(ROOT))
        or not isinstance(value.get("processes"), list)
    ):
        raise RuntimeError(
            "managed state does not belong to this project; no lifecycle change was attempted"
        )
    return value


def up(args: argparse.Namespace) -> None:
    from scripts.native_windows_isolation import select_mode

    if select_mode(getattr(args, "isolation_mode", None)) == "scm-virtual-account":
        scm_runtime(args, "up")
        return
    if getattr(args, "isolation_root", None) is not None:
        raise RuntimeError("an isolation root requires explicit scm-virtual-account selection")
    prerequisites()
    if args.with_llm:
        raise RuntimeError(
            "local model startup is retired; use start-cloud-native.ps1 for DeepSeek"
        )
    model_configurations_path = RUNTIME / "model-configurations.json"
    prepare_model_profiles(model_configurations_path)
    try:
        cloud_requested, _, cloud_model, _ = cloud_configuration(model_configurations_path)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from None
    approval_setting = os.getenv("AGENTGUARD_COAUTHORIZATION_REQUIRED", "false").lower()
    if approval_setting not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise RuntimeError("AGENTGUARD_COAUTHORIZATION_REQUIRED must be an explicit boolean")
    value = prepared_config(args.postgres_port) if args.prepared_only else None
    if STATE.exists():
        previous = managed_state()
        if any(matching_process(item) for item in previous["processes"]):
            if previous.get("with_llm") or any(
                item.get("name") == "ollama" for item in previous["processes"]
            ):
                raise RuntimeError(
                    "recorded runtime includes a retired local model; stop it before cloud startup"
                )
            if previous.get("cloud_configured", False) != cloud_requested:
                raise RuntimeError(
                    "model configuration changed; use start-cloud-native.ps1 to confirm a restart"
                )
            if args.ui_port and args.ui_port != previous["ui_port"]:
                raise RuntimeError(
                    "native UI is already using another port; stop before changing it"
                )
            doctor(args)
            print("NATIVE_START_RESULT=PASS_ALREADY_RUNNING", flush=True)
            return
    if not args.prepared_only:
        layout()
    ports = {
        8090,
        *range(18001, 18011),
        *range(18101, 18104),
        *range(18201, 18205),
        *range(18301, 18305),
    }
    busy = sorted(port for port in ports if not free_port(port))
    if busy:
        raise RuntimeError(f"native service ports are occupied: {busy}")
    ui_port = select_ui_port(args.ui_port, ports | {args.postgres_port})
    value = value if value is not None else config(args.postgres_port)
    state = {
        "schema_version": 1,
        "project_root": str(ROOT),
        "started_at": time.time(),
        "ui_port": ui_port,
        "with_llm": False,
        "cloud_configured": cloud_requested,
        "coauthorization_required": approval_setting in {"true", "1", "yes", "on"},
        "model": cloud_model if cloud_requested else None,
        "prepared_only": args.prepared_only,
        "operator_auth_required": True,
        "processes": [],
        "boundary": "authenticated_native_application_not_windows_account_isolation",
        "internal_auth_required": True,
    }
    write_json(STATE, state)
    try:
        postgres_start(value, state, prepared_only=args.prepared_only)
        urls = prepared_urls(value) if args.prepared_only else initialize(value)
        from backend.config.model_profiles import WindowsCredentialCipher

        operator_session_secret = secrets.token_hex(32)
        (RUNTIME / "operator-session.dpapi").write_text(
            WindowsCredentialCipher().encrypt(operator_session_secret), encoding="ascii"
        )
        internal_keys = generate_keys()
        save_keys(RUNTIME / "internal-service-keys.dpapi", internal_keys)
        for group in service_specs(
            urls["main"],
            urls["audit"],
            urls["ui"],
            RUNTIME / "keys",
            with_llm=False,
            workflow_url=urls["workflow"],
            model_configurations_path=model_configurations_path,
            internal_keys=internal_keys,
            operator_session_secret=operator_session_secret,
        ):
            items = [
                spawn(
                    service.name,
                    [
                        str(PYTHON),
                        "-m",
                        "uvicorn",
                        service.module,
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(service.port),
                    ],
                    service.port,
                    state,
                    service.environment,
                )
                for service in group
            ]
            for item in items:
                wait_http(item)
        spawn(
            "web-ui",
            [
                str(PYTHON),
                "-B",
                "-m",
                "scripts.native_web",
                "--port",
                str(ui_port),
            ],
            ui_port,
            state,
            cwd=ROOT,
        )
        wait_http(state["processes"][-1], "/healthz")
        print(f"NATIVE_UI=http://127.0.0.1:{ui_port}", flush=True)
        print("NATIVE_LOCAL_MODEL=DISABLED", flush=True)
        print(f"NATIVE_CLOUD_REVIEW_ENABLED={cloud_requested} configuration_only=True", flush=True)
        print("NATIVE_START_RESULT=PASS", flush=True)
    except Exception:
        stop(state)
        raise


def doctor(args: argparse.Namespace) -> None:
    from scripts.native_windows_isolation import select_mode

    if select_mode(getattr(args, "isolation_mode", None)) == "scm-virtual-account":
        scm_runtime(args, "doctor")
        return
    prerequisites()
    print(f"NATIVE_PYTHON={sys.version.split()[0]}")
    print("NATIVE_WEB=BUILT_STATIC_UI node_required_for_startup=False")
    if STATE.exists():
        state = managed_state()
        if any(item.get("name") == "ollama" for item in state["processes"]):
            raise RuntimeError(
                "recorded runtime includes a retired local model; stop it before cloud startup"
            )
        for item in state["processes"]:
            if matching_process(item) is None:
                raise RuntimeError(f"managed process is not alive: {item['name']}")
            wait_http(
                item,
                "/healthz" if item["name"] == "web-ui" else "/health",
                timeout=10,
            )
        with connect(database_urls(read_json(CONFIG))["admin"]) as connection:
            print(
                f"NATIVE_POSTGRES_VERSION={connection.execute('SHOW server_version').fetchone()[0]}"
            )
        print(f"NATIVE_UI=http://127.0.0.1:{state['ui_port']}")
    else:
        print("NATIVE_RUNTIME=NOT_STARTED portable_dependencies_prepared_on_first_up")
    print("NATIVE_DOCTOR_RESULT=PASS")


def scm_runtime(args: argparse.Namespace, operation: str) -> None:
    from scripts.native_windows_api import WindowsIsolationError, require_admin
    from scripts.native_windows_isolation import (
        doctor_deployment,
        install_deployment,
        read_manifest,
        start_deployment,
        stop_deployment,
        validate_deployment,
    )

    require_admin()
    root = getattr(args, "isolation_root", None)
    if root is None:
        raise WindowsIsolationError("EXPLICIT_ISOLATION_ROOT_REQUIRED")
    if operation == "install":
        if not getattr(args, "confirm_service_install", False):
            raise WindowsIsolationError("EXPLICIT_SERVICE_INSTALL_CONFIRMATION_REQUIRED")
        result = install_deployment(ROOT, root, getattr(args, "service_python", None) or PYTHON,
                                    ui_port=args.ui_port or 8088, postgres_port=args.postgres_port)
    elif operation == "down":
        stop_deployment(root, project_root=ROOT)
        result = {"result": "STOPPED", "services_removed": False}
    elif operation == "status":
        from scripts.native_windows_api import Scm

        manifest = read_manifest(root, project_root=ROOT)
        with Scm() as scm:
            services = []
            for record in manifest["services"].values():
                scm.assert_owned(record["service_name"], record["command"])
                services.append({"role": record["role"], "service_name": record["service_name"],
                                 **scm.status(record["service_name"])})
        result = {"services": services, "isolation_mode": "scm-virtual-account",
                  "trusted_boundary": "administrators_and_SYSTEM", "external_custody_proven": False}
    elif operation == "doctor":
        result = doctor_deployment(root, project_root=ROOT)
    else:
        prerequisites()
        if args.with_llm:
            raise WindowsIsolationError("SCM_LOCAL_MODELS_RETIRED")
        if STATE.exists() and any(matching_process(item) for item in managed_state()["processes"]):
            raise WindowsIsolationError("STOP_CURRENT_USER_RUNTIME_BEFORE_SCM_START")
        manifest = validate_deployment(root, project_root=ROOT)
        model_path = RUNTIME / "model-configurations.json"
        model_source = model_path.read_bytes() if model_path.is_file() else b""
        if hashlib.sha256(model_source).hexdigest() != manifest.get("model_source_sha256"):
            raise WindowsIsolationError("SCM_MODEL_CONFIGURATION_REPROVISION_REQUIRED")
        if args.ui_port and args.ui_port != manifest["ui_port"]:
            raise WindowsIsolationError("SCM_UI_PORT_CHANGE_REQUIRES_NEW_DEPLOYMENT")
        value = prepared_config(args.postgres_port)
        # PostgreSQL is a separately prepared trusted dependency. Never initialize/migrate it here.
        prepared_urls(value)
        for record in manifest["services"].values():
            if not free_port(record["port"]):
                raise WindowsIsolationError("SCM_SERVICE_PORT_OCCUPIED")
        start_deployment(root, project_root=ROOT)
        result = {"result": "STARTED", "services": len(manifest["services"]),
                  "ui": f"http://127.0.0.1:{manifest['ui_port']}",
                  "trusted_boundary": "administrators_and_SYSTEM", "external_custody_proven": False}
    print(json.dumps(result, ensure_ascii=True), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Project-local Windows AgentGuard runtime")
    parser.add_argument("operation", choices=("up", "down", "doctor", "status", "install",
                                              "verify-isolation", "migrate-config"))
    parser.add_argument("--ui-port", type=int, default=0)
    parser.add_argument("--postgres-port", type=int, default=15432)
    parser.add_argument("--with-llm", action="store_true")
    parser.add_argument("--prepared-only", action="store_true")
    parser.add_argument("--isolation-mode", choices=("current-user", "scm-virtual-account"))
    parser.add_argument("--isolation-root", type=Path)
    parser.add_argument("--service-python", type=Path)
    parser.add_argument("--confirm-service-install", action="store_true")
    parser.add_argument("--confirm-config-migration", action="store_true")
    parser.add_argument("--allow-scoped-probe", action="store_true")
    args = parser.parse_args()
    try:
        from scripts.native_windows_isolation import select_mode

        mode = select_mode(args.isolation_mode)
        if args.operation == "verify-isolation":
            from scripts.native_windows_probe import run_probe

            result = run_probe(ROOT, verify_requested=args.allow_scoped_probe)
            print(json.dumps({"result": result["result"], "receipt": result["receipt_path"]}))
            return 0 if result["result"] == "PASS" else 2
        if args.operation == "migrate-config":
            if not args.confirm_config_migration:
                raise RuntimeError("explicit --confirm-config-migration is required")
            from scripts.native_windows_dpapi import migrate_database_config

            print(json.dumps(migrate_database_config(CONFIG)))
        elif args.operation == "install":
            if mode != "scm-virtual-account":
                raise RuntimeError(
                    "SCM installation requires explicit scm-virtual-account selection"
                )
            scm_runtime(args, "install")
        elif args.operation in {"down", "status"} and mode == "scm-virtual-account":
            scm_runtime(args, args.operation)
        elif args.operation == "status":
            result = {"isolation_mode": "current-user", "boundary": "no_windows_account_isolation",
                      "state_present": STATE.exists()}
            if STATE.exists():
                result["processes"] = [
                    {"name": item["name"], "pid": item["pid"],
                     "alive": matching_process(item) is not None}
                    for item in managed_state()["processes"]
                ]
            print(json.dumps(result))
        elif args.operation == "up":
            up(args)
        elif args.operation == "doctor":
            doctor(args)
        elif STATE.exists():
            stop(managed_state())
        else:
            print("NATIVE_STOP_RESULT=NO_STATE")
        return 0
    except Exception as exc:
        # Do not print exception strings or command arguments containing connection credentials.
        print(f"NATIVE_RUNTIME_RESULT=FAIL error_type={type(exc).__name__}", file=sys.stderr)
        if isinstance(exc, RuntimeError):
            print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
