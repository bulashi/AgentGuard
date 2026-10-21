from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.native_windows_dpapi import read_database_config  # noqa: E402

RUN_ID = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8]
EVIDENCE = ROOT / "artifacts/native-acceptance" / ("current-cloud-" + RUN_ID)
PYTHON = ROOT / ".venv/Scripts/python.exe"
PREFIX = "backend-" + RUN_ID
CONFIG = read_database_config(ROOT / ".native/config.json")
STATE = json.loads((ROOT / ".native/processes.json").read_text(encoding="utf-8-sig"))
SECRETS = [v for k, v in CONFIG.items() if "password" in k and isinstance(v, str)]
for directory in (ROOT / ".native/keys/private", ROOT / "keys/private"):
    if directory.is_dir():
        for path in directory.glob("*.private"):
            SECRETS.append(path.read_text(encoding="ascii").strip())
SECRETS += [v for k, v in os.environ.items() if k.endswith("_API_KEY") and len(v) > 6]
PROCESSES: list[dict] = []
CREATED_DATABASES: list[str] = []
REPORT: dict = {
    "run_id": RUN_ID,
    "root": str(ROOT),
    "phases": [],
    "created_databases": CREATED_DATABASES,
}
FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def redact(value: str) -> str:
    for secret in sorted(set(SECRETS), key=len, reverse=True):
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(
        r"(postgres(?:ql)?(?:\+psycopg)?://[^:/\s]+:)[^@\s]+(@)", r"\1[REDACTED]\2", value
    )
    value = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9_.:/+=-]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(api_key[\"']?\s*[:=]\s*[\"'])[^\"']+", r"\1[REDACTED]", value)
    return value.replace("TEST_ONLY_NOT_A_REAL_KEY", "[REDACTED_TEST_KEY]").replace(
        "TEST_NOT_A_REAL_KEY", "[REDACTED_TEST_KEY]"
    )


def emit(value: object) -> None:
    print(
        redact(value if isinstance(value, str) else json.dumps(value, ensure_ascii=True)),
        flush=True,
    )


def save(name: str, value: object) -> Path:
    path = EVIDENCE / f"{PREFIX}-{name}"
    text = (
        value
        if isinstance(value, str)
        else json.dumps(value, indent=2, ensure_ascii=True, default=str)
    )
    path.write_text(redact(text), encoding="utf-8")
    return path


def environment(extra: dict[str, str] | None = None, *, guarded: bool = True) -> dict[str, str]:
    values = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith("AGENTGUARD_")
        and not k.upper().endswith("_API_KEY")
        and k.upper()
        not in {
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGDATABASE",
            "PGPASSWORD",
            "PYTEST_ADDOPTS",
        }
    }
    temp = EVIDENCE / f"{PREFIX}-temp"
    temp.mkdir(exist_ok=True)
    values.update(
        {
            "PYTHONPATH": os.pathsep.join((str(ROOT / "scripts/native_test_guard"), str(ROOT))),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "TEMP": str(temp),
            "TMP": str(temp),
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "AGENTGUARD_LLM_MODE": "deterministic",
            "AGENTGUARD_TEST_DEPLOYMENT": "native",
            "AGENTGUARD_CLOUD_LLM_ENABLED": "false",
            "AGENTGUARD_BACKEND_GUARD_ENABLED": "1" if guarded else "0",
            "AGENTGUARD_BACKEND_PROJECT_ROOT": str(ROOT),
            "AGENTGUARD_BACKEND_EVIDENCE_ROOT": str(EVIDENCE),
            "AGENTGUARD_BACKEND_BLOCKED_PORTS": ",".join(
                map(
                    str,
                    [
                        8090,
                        8088,
                        *range(18001, 18011),
                        *range(18101, 18104),
                        *range(18201, 18206),
                        *range(18301, 18305),
                    ],
                )
            ),
            "AGENTGUARD_BACKEND_ALLOWED_DATABASES": ",".join(CREATED_DATABASES),
            "npm_config_cache": str(EVIDENCE / f"{PREFIX}-npm-cache"),
            "npm_config_update_notifier": "false",
        }
    )
    values.update(extra or {})
    return values


def command(name: str, arguments: list[str], env: dict[str, str], *, timeout: int = 1800) -> dict:
    start = time.monotonic()
    emit({"start": name, "command": [redact(a) for a in arguments]})
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=FLAGS,
    )
    path = save(name + ".log", result.stdout + result.stderr)
    item = {
        "name": name,
        "command": [redact(a) for a in arguments],
        "exit_code": result.returncode,
        "seconds": round(time.monotonic() - start, 3),
        "log": str(path),
    }
    REPORT["phases"].append(item)
    emit(item)
    emit("\n".join(redact(result.stdout + result.stderr).splitlines()[-9:]))
    return item


def pytest_phase(name: str, selected: list[str], extra: dict[str, str] | None = None) -> dict:
    junit = EVIDENCE / f"{PREFIX}-{name}.xml"
    basetemp = EVIDENCE / ("t" + str(len(REPORT["phases"])))
    if basetemp.exists() or junit.exists():
        raise RuntimeError("refusing to reuse an evidence or basetemp path")
    item = command(
        name,
        [
            str(PYTHON),
            "-B",
            "-m",
            "pytest",
            *selected,
            "-q",
            "-ra",
            "--tb=short",
            "-p",
            "no:cacheprovider",
            "-p",
            "pytest_asyncio.plugin",
            "-p",
            "testids",
            f"--log-file={EVIDENCE / (PREFIX + '-' + name + '-pytest.log')}",
            f"--basetemp={basetemp}",
            f"--junitxml={junit}",
        ],
        environment(extra),
    )
    if junit.exists():
        junit.write_text(redact(junit.read_text(encoding="utf-8")), encoding="utf-8")
        tree = ET.parse(junit).getroot()
        cases = tree.findall(".//testcase")
        item.update(
            {
                "tests": len(cases),
                "failed": sum(c.find("failure") is not None for c in cases),
                "errors": sum(c.find("error") is not None for c in cases),
                "skipped": sum(c.find("skipped") is not None for c in cases),
                "junit": str(junit),
                "failures": [
                    {
                        "case": c.get("classname", "") + "." + c.get("name", ""),
                        "message": (
                            c.find("failure") if c.find("failure") is not None else c.find("error")
                        ).get("message", ""),
                    }
                    for c in cases
                    if c.find("failure") is not None or c.find("error") is not None
                ],
                "skip_reasons": [
                    {
                        "case": c.get("classname", "") + "." + c.get("name", ""),
                        "reason": c.find("skipped").get("message", ""),
                    }
                    for c in cases
                    if c.find("skipped") is not None
                ],
            }
        )
        item["passed"] = item["tests"] - item["failed"] - item["errors"] - item["skipped"]
    save("report.json", REPORT)
    emit({k: v for k, v in item.items() if k not in {"command", "failures"}})
    return item


def fingerprint_sources() -> dict:
    paths = [
        p
        for name in ("backend", "database", "protocol", "attacks", "scripts")
        for p in (ROOT / name).rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.suffix in {".py", ".sql", ".json", ".yaml", ".yml", ".ps1", ".ts"}
    ]
    paths += [ROOT / "pyproject.toml", ROOT / "requirements.lock"]
    return {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)
    }


def snapshot() -> dict:
    import psycopg
    from psycopg import sql

    from scripts.native_runtime import database_urls

    urls = database_urls(CONFIG)
    value: dict = {"files": {}, "databases": {}}
    paths = [
        ROOT / ".native/config.json",
        ROOT / ".native/processes.json",
        ROOT / ".native/seeded.json",
    ]
    for directory in (ROOT / ".native/keys", ROOT / "keys"):
        if directory.is_dir():
            paths += [p for p in directory.rglob("*") if p.is_file()]
    for path in paths:
        value["files"][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for label in ("main", "audit"):
        with psycopg.connect(
            urls[label].replace("postgresql+psycopg://", "postgresql://"), connect_timeout=5
        ) as connection:
            connection.execute("SET TRANSACTION READ ONLY")
            identity = connection.execute("SELECT current_database(), current_user").fetchone()
            tables = connection.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
            ).fetchall()
            digests = {}
            for (table,) in tables:
                row = connection.execute(
                    sql.SQL(
                        "SELECT count(*), md5(COALESCE(string_agg(value, '' ORDER BY value), '')) "
                        "FROM (SELECT row_to_json(t)::text AS value FROM {} t) s"
                    ).format(sql.Identifier(table))
                ).fetchone()
                digests[table] = {"count": row[0], "content_md5": row[1]}
            value["databases"][label] = {
                "name": identity[0],
                "role": identity[1],
                "tables": digests,
            }
    with psycopg.connect(urls["admin"], connect_timeout=5) as connection:
        connection.execute("SET TRANSACTION READ ONLY")
        value["postgres"] = dict(
            zip(
                ("version", "port", "data_directory"),
                connection.execute(
                    "SELECT current_setting('server_version'), current_setting('port'), "
                    "current_setting('data_directory')"
                ).fetchone(),
                strict=False,
            )
        )
        role_rows = connection.execute(
            "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, md5(rolpassword) "
            "FROM pg_authid ORDER BY rolname"
        ).fetchall()
        role_settings = connection.execute(
            "SELECT setdatabase, setrole, setconfig FROM pg_db_role_setting "
            "ORDER BY setdatabase,setrole"
        ).fetchall()
        value["roles_sha256"] = hashlib.sha256(
            json.dumps([role_rows, role_settings], default=str).encode()
        ).hexdigest()
    return value


def preflight() -> None:
    import httpx
    import psutil

    from scripts.source_manifest import snapshot as source_snapshot

    inventory = []
    with httpx.Client(timeout=5, trust_env=False) as client:
        for service in STATE["processes"]:
            if service["name"] == "web-ui":
                continue
            try:
                response = client.get(f"http://127.0.0.1:{service['port']}/health")
                body = response.json() if response.status_code == 200 else {}
                item = {
                    "name": service["name"],
                    "port": service["port"],
                    "pid": service["pid"],
                    "alive": psutil.pid_exists(service["pid"]),
                    "http_status": response.status_code,
                    "status": body.get("status"),
                }
            except Exception as exc:
                item = {
                    "name": service["name"],
                    "port": service["port"],
                    "error_type": type(exc).__name__,
                }
            inventory.append(item)
    REPORT["preflight"] = {
        "python": sys.version,
        "backend_services": inventory,
        "with_llm": STATE.get("with_llm"),
        "dependencies": {
            name: importlib.metadata.version(name)
            for name in (
                "pytest",
                "pytest-asyncio",
                "fastapi",
                "httpx",
                "psycopg",
                "gmssl",
                "pydantic",
                "jsonschema",
            )
        },
        "git": "not_a_git_checkout",
        "source_manifest": str(save("source-before.json", fingerprint_sources())),
        "full_source_manifest": str(save("full-source-before.json", source_snapshot())),
    }
    before = snapshot()
    REPORT["before_snapshot"] = str(save("boundary-before.json", before))
    REPORT["preflight"]["postgres"] = before["postgres"]
    emit(REPORT["preflight"])


def create_database(kind: str, label: str) -> tuple[str, str]:
    import psycopg
    from psycopg import sql

    from scripts.native_database import role_url
    from scripts.native_runtime import database_urls

    db_prefix = {
        "main": "agentguard_test_backend_",
        "audit": "agentguard_audit_test_backend_",
        "coauth": "agentguard_coauth_test_backend_",
    }[kind]
    database_run = hashlib.sha256((RUN_ID + ":" + label).encode("ascii")).hexdigest()[:16]
    name = db_prefix + database_run
    role = "audit" if kind == "audit" else "agentguard"
    password = CONFIG["audit_password" if kind == "audit" else "main_password"]
    if not re.fullmatch(r"agentguard_(?:audit_test|test|coauth_test)_backend_[a-zA-Z0-9_]+", name):
        raise RuntimeError("invalid disposable database name")
    if len(name.encode("ascii")) > 63:
        raise RuntimeError("disposable database name exceeds PostgreSQL identifier limit")
    admin = database_urls(CONFIG)["admin"]
    with psycopg.connect(admin, autocommit=True, connect_timeout=5) as connection:
        if connection.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
            raise RuntimeError("disposable database already exists; refusing reuse")
        connection.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(name), sql.Identifier(role)
            )
        )
    CREATED_DATABASES.append(name)
    url = role_url(admin, role, password, name)
    with psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://")) as connection:
        if connection.execute("SELECT current_database()").fetchone() != (name,):
            raise RuntimeError("disposable database identity mismatch")
    migration_kind = "audit" if kind == "audit" else "main"
    item = command(
        label + "-migrate-" + kind,
        [
            str(PYTHON),
            "-B",
            "scripts/migrate.py",
            "--database-url",
            url,
            "--directory",
            f"database/migrations/{migration_kind}",
        ],
        environment(),
    )
    if item["exit_code"]:
        raise RuntimeError("isolated migration failed")
    if kind == "main":
        for action, args in (
            (
                "register",
                [
                    "scripts/register_dev_keys.py",
                    "--public-root",
                    str(ROOT / ".native/keys/public"),
                ],
            ),
            ("seed", ["scripts/seed_demo.py"]),
        ):
            item = command(
                label + "-" + action,
                [str(PYTHON), "-B", *args],
                environment({"AGENTGUARD_DATABASE_URL": url}),
            )
            if item["exit_code"]:
                raise RuntimeError("isolated seed failed")
    save("report.json", REPORT)
    emit({"created_test_database": name, "existing_role_reused": role})
    return name, url


def stop_services() -> None:
    for item in reversed(PROCESSES):
        process = item["process"]
        if process.poll() is None:
            process.terminate()
    for item in PROCESSES:
        process = item["process"]
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        item["thread"].join(timeout=5)
    PROCESSES.clear()
    cleanup_cloud_model_profile()


def stage_cloud_model_profile() -> Path:
    """Copy configured DPAPI ciphertext into this run's writable evidence boundary."""
    from backend.config.model_profiles import ModelProfileStore

    source = ModelProfileStore(ROOT / ".native/model-configurations.json").path
    raw = source.read_bytes()
    evidence = EVIDENCE.resolve()
    if not evidence.is_relative_to((ROOT / "artifacts/native-acceptance").resolve()):
        raise RuntimeError("cloud profile runtime must belong to native acceptance evidence")
    runtime_directory = evidence / f"{PREFIX}-private-runtime"
    runtime_directory.mkdir(exist_ok=False)
    runtime_path = runtime_directory / "model-configurations.json"
    info = {
        "source_profile_path": str(source),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime_directory": str(runtime_directory),
        "runtime_profile_path": str(runtime_path),
        "credential_storage": "Windows_DPAPI_current_user_ciphertext_copy",
        "cleanup_status": "pending",
    }
    REPORT["cloud_model_profile_runtime"] = info
    with runtime_path.open("xb") as output:
        output.write(raw)
    info["runtime_sha256"] = hashlib.sha256(runtime_path.read_bytes()).hexdigest()
    info["copy_byte_identical"] = info["source_sha256"] == info["runtime_sha256"]
    if not info["copy_byte_identical"]:
        raise RuntimeError("isolated model profile copy differs from the configured source")
    public_profiles = ModelProfileStore(runtime_path).public().get("items", [])
    info["public_profiles"] = public_profiles
    save("cloud-model-profile-public.json", info)
    configured = [
        item
        for item in public_profiles
        if item.get("is_default") is True
        and item.get("enabled") is True
        and item.get("has_key") is True
        and item.get("model") == "deepseek-flash"
    ]
    if len(configured) != 1:
        raise RuntimeError("the configured default DeepSeek Flash profile is unavailable")
    return runtime_path


def cleanup_cloud_model_profile() -> None:
    """Remove only this run's secret copy after every test service has stopped."""
    import shutil

    info = REPORT.get("cloud_model_profile_runtime")
    if info is None or info.get("cleanup_status") == "removed":
        return
    if PROCESSES:
        raise RuntimeError("cannot remove the cloud profile before test services stop")
    evidence = EVIDENCE.resolve()
    directory = Path(info["runtime_directory"])
    if (
        directory.is_symlink()
        or directory.is_junction()
        or directory.resolve() != evidence / f"{PREFIX}-private-runtime"
        or not directory.resolve().is_relative_to(evidence)
    ):
        raise RuntimeError("refusing to remove a cloud profile outside its owned runtime")
    shutil.rmtree(directory)
    info["cleanup_status"] = "removed"
    info["source_sha256_after"] = hashlib.sha256(
        Path(info["source_profile_path"]).read_bytes()
    ).hexdigest()
    info["source_profile_unchanged"] = info["source_sha256_after"] == info["source_sha256"]
    save("cloud-model-profile-public.json", info)


def cloud_agent_guard_environment(
    service_name: str,
    model_configurations_path: Path | None,
    *,
    explicit_cloud: bool = False,
) -> dict[str, str]:
    """Grant only a real configured endpoint to the four explicit-cloud model agents."""
    from urllib.parse import urlsplit

    from backend.config.model_profiles import ModelProfileStore, normalized_endpoint

    if not explicit_cloud or service_name not in {
        "coordinator-agent",
        "knowledge-agent",
        "case-agent",
        "refund-agent",
    }:
        return {}
    if model_configurations_path is None or not model_configurations_path.resolve().is_relative_to(
        EVIDENCE.resolve()
    ):
        raise RuntimeError("cloud endpoint permission requires an evidence-owned model profile")
    profiles = ModelProfileStore(model_configurations_path).public()["items"]
    configured = [
        item
        for item in profiles
        if item["is_default"]
        and item["enabled"]
        and item["has_key"]
        and item["model"] == "deepseek-flash"
    ]
    if len(configured) != 1:
        raise RuntimeError("the configured default DeepSeek Flash profile is unavailable")
    endpoint = urlsplit(normalized_endpoint(configured[0]["base_url"]))
    return {
        "AGENTGUARD_BACKEND_ACCEPTANCE_MODE": "cloud",
        "AGENTGUARD_BACKEND_CLOUD_SERVICE": service_name,
        "AGENTGUARD_BACKEND_CLOUD_HOST": endpoint.hostname,
        "AGENTGUARD_BACKEND_CLOUD_PORT": str(endpoint.port or 443),
    }


def stack(
    label: str,
    *,
    authenticated: bool = False,
    model_configurations_path: Path | None = None,
    include_audit_workers: bool = False,
    allow_cloud_endpoint: bool = False,
) -> dict[str, str]:
    import httpx
    import psycopg
    from psycopg import sql

    from scripts.native_config import service_specs
    from scripts.native_database import role_url
    from scripts.native_runtime import database_urls
    from scripts.native_security import generate_keys
    from scripts.provision_ui_reader import READ_TABLES

    if (
        model_configurations_path is not None
        and not model_configurations_path.resolve().is_relative_to(EVIDENCE.resolve())
    ):
        raise RuntimeError("test services must use an evidence-owned model profile copy")
    if allow_cloud_endpoint and (not authenticated or model_configurations_path is None):
        raise RuntimeError(
            "explicit cloud endpoint permission requires an authenticated profile stack"
        )
    internal_keys = generate_keys() if authenticated else None
    operator_secret = uuid.uuid4().hex + uuid.uuid4().hex if authenticated else ""
    if internal_keys is not None:
        SECRETS.extend(value for edges in internal_keys.values() for value in edges.values())
        SECRETS.append(operator_secret)

    main_name, main_url = create_database("main", label)
    _, audit_url = create_database("audit", label)
    admin = database_urls(CONFIG)["admin"]
    admin_main = role_url(admin, "postgres", CONFIG["admin_password"], main_name)
    with psycopg.connect(
        admin_main.replace("postgresql+psycopg://", "postgresql://"), autocommit=True
    ) as connection:
        for role in ("agentguard_ui", "agentguard_workflow"):
            connection.execute(
                sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role))
            )
        for table in READ_TABLES:
            connection.execute(
                sql.SQL("GRANT SELECT ON {} TO agentguard_ui").format(sql.Identifier(table))
            )
        connection.execute(
            "GRANT SELECT, INSERT, UPDATE ON agent_workflow_runs TO agentguard_workflow"
        )
        connection.execute("GRANT SELECT, INSERT ON agent_workflow_events TO agentguard_workflow")
    ui_url = role_url(admin, "agentguard_ui", CONFIG["ui_password"], main_name)
    workflow_url = role_url(admin, "agentguard_workflow", CONFIG["workflow_password"], main_name)
    specs = service_specs(
        main_url,
        audit_url,
        ui_url,
        ROOT / ".native/keys",
        with_llm=False,
        workflow_url=workflow_url,
        model_configurations_path=model_configurations_path,
        internal_keys=internal_keys,
        operator_session_secret=operator_secret,
    )
    if not include_audit_workers:
        specs = [
            [
                service
                for service in group
                if service.name not in {"audit-worker", "checkpoint-worker"}
            ]
            for group in specs
        ]
    ports = {s.port: s.port + 10000 for group in specs for s in group}
    for port in ports.values():
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", port))

    def remap(value: str) -> str:
        for old, new in ports.items():
            value = value.replace(f"http://127.0.0.1:{old}", f"http://127.0.0.1:{new}")
        return value

    services = []
    for group in specs:
        started = []
        for service in group:
            extra = {k: remap(v) for k, v in service.environment.items()}
            extra.update(
                {
                    "AGENTGUARD_RECOVERY_AUTORUN": "false",
                    "AGENTGUARD_INTERNAL_AUTH_NONCE_ROOT": str(EVIDENCE / f"{label}-nonces"),
                    "AGENTGUARD_UI_ARTIFACT_ROOT": str(EVIDENCE / f"{label}-ui-artifacts"),
                }
            )
            if model_configurations_path is None:
                extra["AGENTGUARD_CLOUD_LLM_ENABLED"] = "false"
            extra.update(
                cloud_agent_guard_environment(
                    service.name,
                    model_configurations_path,
                    explicit_cloud=allow_cloud_endpoint,
                )
            )
            port = ports[service.port]
            path = EVIDENCE / f"{PREFIX}-{label}-{service.name}.log"
            process = subprocess.Popen(
                [
                    str(PYTHON),
                    "-B",
                    "-m",
                    "uvicorn",
                    service.module,
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=ROOT,
                env=environment(extra),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=FLAGS,
            )

            def capture(proc=process, log=path):
                with log.open("w", encoding="utf-8") as destination:
                    for line in proc.stdout:
                        destination.write(redact(line))
                        destination.flush()

            thread = threading.Thread(target=capture, daemon=True)
            thread.start()
            item = {
                "name": service.name,
                "process": process,
                "thread": thread,
                "port": port,
                "log": str(path),
            }
            PROCESSES.append(item)
            started.append(item)
            services.append(
                {
                    "name": service.name,
                    "port": port,
                    "pid": process.pid,
                    "environment": {k: redact(v) for k, v in extra.items()},
                    "log": str(path),
                }
            )
        with httpx.Client(timeout=3, trust_env=False) as client:
            for item in started:
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if item["process"].poll() is not None:
                        raise RuntimeError(f"isolated {item['name']} exited; see {item['log']}")
                    try:
                        response = client.get(f"http://127.0.0.1:{item['port']}/health")
                        if response.status_code == 200 and response.json().get("status") == "ok":
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.25)
                else:
                    raise RuntimeError(f"isolated {item['name']} health timeout")
        emit({"isolated_group_ready": [s["name"] for s in started]})
    REPORT.setdefault("stacks", []).append(
        {
            "label": label,
            "services": services,
            "recovery_autorun": False,
            "audit_checkpoint_background_workers": include_audit_workers,
            "internal_auth_required": authenticated,
            "operator_auth_required": authenticated,
            "reason": (
                "cloud runs use background audit/checkpoint workers; other tests invoke "
                "recovery, audit append and checkpoints explicitly to avoid fault-injection races"
            ),
        }
    )
    save("report.json", REPORT)
    return {
        "AGENTGUARD_DATABASE_URL": main_url,
        "AGENTGUARD_AUDIT_DATABASE_URL": audit_url,
        "AGENTGUARD_AUTHORITY_URL": "http://127.0.0.1:28001",
        "AGENTGUARD_BUSINESS_ACTION_REGISTRY_URL": "http://127.0.0.1:28002",
        "AGENTGUARD_GATEWAY_URL": "http://127.0.0.1:28003",
        "AGENTGUARD_RECOVERY_URL": "http://127.0.0.1:28004",
        "AGENTGUARD_REVOCATION_URL": "http://127.0.0.1:28005",
        "AGENTGUARD_RECEIPT_SERVICE_URL": "http://127.0.0.1:28006",
        "AGENTGUARD_AUDIT_SERVICE_URL": "http://127.0.0.1:28007",
        "AGENTGUARD_CHECKPOINT_SERVICE_URL": "http://127.0.0.1:28008",
        "AGENTGUARD_COORDINATOR_DELEGATION_URL": "http://127.0.0.1:28101",
        "AGENTGUARD_CASE_DELEGATION_URL": "http://127.0.0.1:28102",
        "AGENTGUARD_REFUND_DELEGATION_URL": "http://127.0.0.1:28103",
        "AGENTGUARD_COORDINATOR_AGENT_URL": "http://127.0.0.1:28201",
        "AGENTGUARD_REFUND_AGENT_URL": "http://127.0.0.1:28204",
        "AGENTGUARD_TICKET_TOOL_URL": "http://127.0.0.1:28301",
        "AGENTGUARD_KNOWLEDGE_TOOL_URL": "http://127.0.0.1:28302",
        "AGENTGUARD_REFUND_TOOL_URL": "http://127.0.0.1:28303",
        "AGENTGUARD_NOTIFICATION_TOOL_URL": "http://127.0.0.1:28304",
        "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE": str(ROOT / ".native/keys/private/gateway.private"),
        "AGENTGUARD_HOLDER_PRIVATE_KEY_FILE": str(
            ROOT / ".native/keys/private/agent-refund.private"
        ),
        "AGENTGUARD_UI_DATABASE_URL": ui_url,
        "AGENTGUARD_WORKFLOW_DATABASE_URL": workflow_url,
        "AGENTGUARD_UI_API_URL": "http://127.0.0.1:18090",
        "AGENTGUARD_UI_ARTIFACT_ROOT": str(EVIDENCE / f"{label}-ui-artifacts"),
        "AGENTGUARD_OPERATOR_AUTH_REQUIRED": str(authenticated).lower(),
        "AGENTGUARD_OPERATOR_SESSION_SECRET": operator_secret,
    }


def finish() -> None:
    from scripts.source_manifest import snapshot as source_snapshot

    stop_services()
    after = snapshot()
    save("boundary-after.json", after)
    before_path = REPORT.get("before_snapshot")
    if before_path:
        before = json.loads(Path(before_path).read_text(encoding="utf-8"))
        REPORT["production_boundary_unchanged"] = before == after
        REPORT["boundary_differences"] = [key for key in before if before[key] != after.get(key)]
    source_before = json.loads(Path(REPORT["preflight"]["source_manifest"]).read_text())
    source_after = fingerprint_sources()
    save("source-after.json", source_after)
    REPORT["backend_source_unchanged"] = source_before == source_after
    REPORT["source_changes"] = sorted(
        k
        for k in set(source_before) | set(source_after)
        if source_before.get(k) != source_after.get(k)
    )
    full_before = json.loads(Path(REPORT["preflight"]["full_source_manifest"]).read_text())
    full_after = source_snapshot()
    save("full-source-after.json", full_after)
    REPORT["full_source_unchanged"] = full_before == full_after
    REPORT["source_snapshot_sha256"] = full_before["snapshot_sha256"]
    REPORT["test_services_stopped"] = True
    REPORT["production_boundary_classification"] = (
        "unchanged_in_this_run"
        if REPORT.get("production_boundary_unchanged")
        else "difference_detected_requires_authorized_increment_or_unexpected_write_review"
    )
    REPORT["test_databases_retained"] = list(CREATED_DATABASES)
    save("report.json", REPORT)
    emit(
        {
            k: REPORT[k]
            for k in (
                "production_boundary_unchanged",
                "boundary_differences",
                "backend_source_unchanged",
                "full_source_unchanged",
                "source_changes",
                "test_services_stopped",
                "test_databases_retained",
            )
        }
    )
    emit({"report": str(EVIDENCE / f"{PREFIX}-report.json")})


def frontend_checks() -> None:
    import shutil

    npm = shutil.which("npm.cmd")
    if npm is None:
        raise RuntimeError("locked frontend acceptance requires npm.cmd")
    junit = EVIDENCE / f"{PREFIX}-frontend.xml"
    steps = [
        ("frontend-typecheck", ["--prefix", "frontend", "run", "typecheck"]),
        ("frontend-lint", ["--prefix", "frontend", "run", "lint"]),
        (
            "frontend-tests",
            [
                "--prefix",
                "frontend",
                "run",
                "test",
                "--",
                "--reporter=default",
                "--reporter=junit",
                "--outputFile=" + str(junit),
            ],
        ),
        ("frontend-build", ["--prefix", "frontend", "run", "build"]),
        ("protocol-check", ["run", "protocol:check"]),
        ("protocol-typecheck", ["run", "typecheck"]),
    ]
    for name, arguments in steps:
        item = command(name, [npm, *arguments], environment())
        if item["exit_code"]:
            raise RuntimeError(f"{name} failed; retain its output before repair")
    cases = ET.parse(junit).getroot().findall(".//testcase")
    totals = {
        "tests": len(cases),
        "failed": sum(case.find("failure") is not None for case in cases),
        "errors": sum(case.find("error") is not None for case in cases),
        "skipped": sum(case.find("skipped") is not None for case in cases),
    }
    totals["passed"] = totals["tests"] - totals["failed"] - totals["errors"] - totals["skipped"]
    REPORT["frontend_totals"] = totals | {"junit": str(junit)}
    if not cases or totals["failed"] or totals["errors"] or totals["skipped"]:
        raise RuntimeError("frontend acceptance has failed, absent or skipped tests")


def scenario_ledger(runtime: dict[str, str]) -> None:
    manifest = Path(REPORT["preflight"]["full_source_manifest"])
    digest = json.loads(manifest.read_text(encoding="utf-8"))["snapshot_sha256"]
    ledger = EVIDENCE / f"{PREFIX}-security-scenarios.jsonl"
    extra = runtime | {
        "AGENTGUARD_SOURCE_SNAPSHOT_SHA256": digest,
        "AGENTGUARD_SECURITY_LEDGER_PATH": str(ledger),
        "AGENTGUARD_SECURITY_LEDGER_RUN_ID": "security-" + RUN_ID,
    }
    item = pytest_phase(
        "security-scenario-ledger",
        ["backend/tests/security/test_scenario_ledger_postgres.py"],
        extra,
    )
    if item["exit_code"] or item.get("passed") != 36 or item.get("skipped"):
        raise RuntimeError("the 36-scenario ledger did not pass; do not publish it")
    verified = command(
        "security-ledger-verify",
        [
            str(PYTHON),
            "-B",
            "scripts/verify_security_ledger.py",
            "--ledger",
            str(ledger),
            "--source-manifest",
            str(manifest),
            "--junit",
            item["junit"],
            "--publish",
        ],
        environment(extra, guarded=False),
    )
    verified["write_scope"] = "trusted publisher: artifacts/security/current-ledger-summary.json"
    if verified["exit_code"]:
        raise RuntimeError("independent ledger verification failed; no current result is certified")
    REPORT["scenario_ledger"] = {
        "path": str(ledger),
        "source_snapshot_sha256": digest,
        "summary": str(ROOT / "artifacts/security/current-ledger-summary.json"),
        "junit": item["junit"],
        "scenarios": 36,
    }


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "unit",
            "full",
            "proof",
            "browser",
            "ledger",
            "revocation",
            "handoff",
            "cloud",
            "preflight",
        ),
    )
    parser.add_argument("--run-id", help="required benchmark run ID for the isolated cloud mode")
    parser.add_argument("--confirm-cloud-calls", action="store_true")
    parser.add_argument("--confirm-create-business-cases", action="store_true")
    args = parser.parse_args()
    if args.mode == "cloud" and (
        args.run_id is None or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args.run_id)
    ):
        parser.error("cloud mode requires a safe --run-id for the matching benchmark")
    if args.mode == "cloud" and not args.confirm_cloud_calls:
        parser.error("cloud mode requires --confirm-cloud-calls")
    if args.mode == "cloud" and not args.confirm_create_business_cases:
        parser.error("cloud mode requires --confirm-create-business-cases")
    EVIDENCE.mkdir(parents=True, exist_ok=False)
    REPORT.update(
        {
            "started_at": datetime.now(UTC).isoformat(),
            "deployment": "native_windows_postgresql_no_local_model",
            "cloud_verification": "separate_explicit_cloud_workflows_required",
        }
    )
    # Imports of the native launcher cannot inherit any cloud key or native mode.
    for key in list(os.environ):
        if key.upper().startswith("AGENTGUARD_"):
            os.environ.pop(key)
    sys.path.insert(0, str(ROOT))
    preflight()
    try:
        if args.mode == "cloud":
            from scripts.verify_current_cloud import run_isolated_cloud

            model_profile_path = stage_cloud_model_profile()
            urls = stack(
                "isolated-cloud",
                authenticated=True,
                model_configurations_path=model_profile_path,
                include_audit_workers=True,
                allow_cloud_endpoint=True,
            )
            cloud_evidence = ROOT / "artifacts" / "native-cloud" / args.run_id
            cloud_report = run_isolated_cloud(
                urls,
                operator_secret=urls["AGENTGUARD_OPERATOR_SESSION_SECRET"],
                run_id=args.run_id,
                evidence_directory=cloud_evidence,
            )
            REPORT["cloud_acceptance"] = {
                "status": cloud_report["status"],
                "run_id": args.run_id,
                "evidence": str(cloud_evidence),
                "benchmark_cloud_report": cloud_report.get("benchmark_cloud_report"),
                "source_snapshot_sha256": (
                    cloud_report.get("source_snapshot_sha256")
                    or json.loads((cloud_evidence / "source-before.json").read_text())[
                        "snapshot_sha256"
                    ]
                ),
                "cases": [
                    {
                        "scenario": item.get("scenario"),
                        "status": item.get("state"),
                        "reason_code": item.get("reason_code"),
                        "committed_effects": len(item.get("business_rows", {}).get("refunds", []))
                        + len(item.get("business_rows", {}).get("notifications", [])),
                        "unauthorized_side_effects": item.get("unauthorized_side_effects"),
                    }
                    for item in cloud_report.get("cases", [])
                ],
                "business_declines": [
                    {
                        "scenario": item.get("scenario"),
                        "status": item.get("state"),
                        "reason_code": item.get("reason_code"),
                    }
                    for item in cloud_report.get("business_declines", [])
                ],
                "test_databases_only": cloud_report.get("database_identity", {}),
            }
            REPORT["cloud_verification"] = "isolated_test_database_real_model_calls"
            if cloud_report["status"] != "PASS":
                raise RuntimeError("isolated current-source cloud acceptance failed")
            stop_services()
        if args.mode == "handoff":
            import shutil

            npm = shutil.which("npm.cmd")
            if npm is None:
                raise RuntimeError("isolated browser acceptance requires npm.cmd")
            built = command(
                "handoff-frontend-build",
                [npm, "--prefix", "frontend", "run", "build"],
                environment(),
            )
            if built["exit_code"]:
                raise RuntimeError("frontend build failed before browser handoff acceptance")
            proof = stack("authenticated-handoff", authenticated=True)
            browser = command(
                "current-task-handoff-browser",
                [
                    str(PYTHON),
                    "-B",
                    "scripts/verify_task_handoff_browser.py",
                    "--output",
                    str(EVIDENCE / "task-handoff-browser"),
                ],
                environment(proof),
                timeout=420,
            )
            REPORT["current_task_handoff"] = {
                "status": "PASS" if browser["exit_code"] == 0 else "FAIL",
                "log": str(EVIDENCE / "task-handoff-browser" / "browser.log"),
                "screenshots": str(EVIDENCE / "task-handoff-browser"),
                "isolated_stack": "authenticated-handoff",
                "demo_ports_touched": [],
            }
            if browser["exit_code"]:
                raise RuntimeError("real browser current-task handoff acceptance failed")
            stop_services()
        if args.mode == "full":
            frontend_checks()
            _, coauth = create_database("coauth", "coauth")
            pytest_phase(
                "coauthorization-postgres",
                ["backend/tests/integration/test_coauthorization_postgres.py"],
                {"AGENTGUARD_COAUTHORIZATION_TEST_DATABASE_URL": coauth},
            )
            coauth_workflow = (
                ROOT / "backend/tests/integration/test_coauthorization_full_workflow_postgres.py"
            )
            if coauth_workflow.is_file():
                _, coauth_workflow_db = create_database("coauth", "coauth_full_workflow")
                pytest_phase(
                    "coauthorization-full-workflow",
                    [str(coauth_workflow)],
                    {"AGENTGUARD_COAUTHORIZATION_TEST_DATABASE_URL": coauth_workflow_db},
                )
        if args.mode in {"unit", "full"}:
            pytest_phase(
                "unit-contract",
                [
                    "backend/tests/unit",
                    "backend/tests/security/test_matrix_contract.py",
                    "scripts/tests",
                ],
            )
        if args.mode == "full":
            runtime = stack("integration")
            modules = [
                "key_registry",
                "root_authorization",
                "delegation",
                "business_action",
                "tool",
                "gateway",
                "execution_decision",
                "execution_terminal",
                "admission",
                "dispatch",
                "recovery",
                "receipt_audit",
                "result_retrieval",
                "multi_agent",
                "revocation",
                "dispatch_revocation",
                "dispatch_holder_lifecycle",
                "notification_binding_locking",
                "recovery_singleflight",
                "runtime_authorization_preflight",
                "runtime_boundary_recovery",
            ]
            for module in modules:
                extra = runtime.copy()
                if module == "gateway":
                    extra["AGENTGUARD_HOLDER_PRIVATE_KEY_FILE"] = str(
                        ROOT / ".native/keys/private/agent-coordinator.private"
                    )
                pytest_phase(
                    "integration-" + module,
                    [f"backend/tests/integration/test_{module}_postgres.py"],
                    extra,
                )
            pytest_phase(
                "integration-workflow-consistency",
                ["backend/tests/integration/test_workflow_consistency_postgres.py"],
                runtime,
            )
            pytest_phase(
                "protocol-typescript",
                ["backend/tests/integration/test_typescript_canonical.py"],
                runtime,
            )
            stop_services()
            security = stack("security")
            pytest_phase(
                "deterministic-security",
                [
                    "backend/tests/security/test_deterministic_security.py",
                    "backend/tests/security/test_native_tool_boundary.py",
                ],
                security,
            )
            scenario_ledger(security)
            stop_services()
        if args.mode == "revocation":
            runtime = stack("dispatch-revocation")
            pytest_phase(
                "integration-dispatch-revocation",
                ["backend/tests/integration/test_dispatch_revocation_postgres.py"],
                runtime,
            )
            stop_services()
        if args.mode == "ledger":
            security = stack("security-ledger")
            scenario_ledger(security)
            stop_services()
        if args.mode == "browser":
            security = stack("browser-current-ledger")
            scenario_ledger(security)
            stop_services()
        if args.mode in {"proof", "browser", "full"}:
            proof = stack("authenticated-proof", authenticated=True)
            pytest_phase(
                "authenticated-security-proof",
                [
                    "backend/tests/integration/test_security_proof_postgres.py",
                    "backend/tests/integration/test_authenticated_runtime_workflow_postgres.py",
                    "backend/tests/integration/test_business_facts_postgres.py",
                    "backend/tests/integration/test_business_fact_workflow_postgres.py",
                ],
                proof,
            )
            if args.mode in {"browser", "full"}:
                browser = command(
                    "security-proof-browser",
                    [
                        str(PYTHON),
                        "-B",
                        "scripts/verify_security_proof_browser.py",
                        "--output",
                        str(EVIDENCE / "security-browser"),
                    ],
                    environment(proof),
                )
                if browser["exit_code"]:
                    raise RuntimeError("real browser proof acceptance failed")
    except Exception as exc:
        REPORT["runner_error"] = {"type": type(exc).__name__, "message": redact(str(exc))}
        emit(REPORT["runner_error"])
    finally:
        finish()
    tests = [p for p in REPORT["phases"] if "tests" in p]
    totals = {
        k: sum(p[k] for p in tests) for k in ("tests", "passed", "failed", "errors", "skipped")
    }
    REPORT["totals"] = totals
    REPORT["finished_at"] = datetime.now(UTC).isoformat()
    save("report.json", REPORT)
    emit(totals)
    nonzero = [p for p in REPORT["phases"] if p["exit_code"] != 0]
    return (
        1
        if REPORT.get("runner_error")
        or nonzero
        or totals["failed"]
        or totals["errors"]
        or totals["skipped"]
        or not REPORT.get("production_boundary_unchanged")
        or not REPORT.get("backend_source_unchanged")
        or not REPORT.get("full_source_unchanged")
        or REPORT.get("cloud_model_profile_runtime", {}).get("cleanup_status")
        not in {None, "removed"}
        or REPORT.get("cloud_model_profile_runtime", {}).get("source_profile_unchanged") is False
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
