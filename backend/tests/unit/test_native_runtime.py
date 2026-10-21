from __future__ import annotations

import os
import zipfile
from pathlib import Path

import psutil
import pytest

from backend.config.settings import Settings
from backend.ui_api.service import UiApiError, UiService
from scripts import native_runtime
from scripts.native_config import service_specs
from scripts.native_database import role_url
from scripts.native_runtime import clean_environment, matching_process, safe_extract


def test_role_url_retains_host_port_and_encodes_credentials() -> None:
    url = role_url(
        "postgresql://postgres:admin@localhost:15432/postgres?sslmode=require",
        "ui@role",
        "p:a@ss%/word",
        "agentguard",
    )
    assert url == (
        "postgresql+psycopg://ui%40role:p%3Aa%40ss%25%2Fword@localhost:15432/agentguard"
        "?sslmode=require"
    )


def test_role_url_retains_ipv6() -> None:
    assert role_url("postgresql://root:x@[::1]:5439/postgres", "audit", "p", "audit") == (
        "postgresql+psycopg://audit:p@[::1]:5439/audit"
    )


def test_native_service_ports_are_unique_and_ui_is_unprivileged(tmp_path: Path) -> None:
    groups = service_specs("MAIN_SECRET", "AUDIT_SECRET", "UI_SECRET", tmp_path, with_llm=False)
    services = [service for group in groups for service in group]
    assert len(services) == len({service.port for service in services}) == 22
    ui = next(service for service in services if service.name == "ui-api")
    assert ui.environment["AGENTGUARD_UI_DATABASE_URL"] == "UI_SECRET"
    assert "AGENTGUARD_DATABASE_URL" not in ui.environment
    assert "AGENTGUARD_AUDIT_DATABASE_URL" not in ui.environment
    assert not any("PRIVATE_KEY" in key for key in ui.environment)
    assert not any(service.name == "refund-agent-live-demo" for service in services)
    assert all(service.environment.get("AGENTGUARD_LLM_MODE") != "ollama" for service in services)


def test_native_launcher_rejects_retired_local_model_without_starting_services(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="Managed local models are retired"):
        service_specs("MAIN_SECRET", "AUDIT_SECRET", "UI_SECRET", tmp_path, with_llm=True)


def test_without_llm_does_not_fake_live_demo(tmp_path: Path) -> None:
    services = [
        service
        for group in service_specs("m", "a", "u", tmp_path, with_llm=False)
        for service in group
    ]
    assert not any(service.name == "refund-agent-live-demo" for service in services)
    ui = next(service for service in services if service.name == "ui-api")
    assert ui.environment["AGENTGUARD_LIVE_REFUND_AGENT_URL"] == ""
    subject = UiService(Settings(live_refund_agent_url=""), object())
    with pytest.raises(UiApiError) as caught:
        subject.run_prompt_injection_demo("untrusted prompt")
    assert caught.value.status_code == 503
    assert caught.value.reason_code == "UPSTREAM_UNAVAILABLE"


def test_native_environment_drops_inherited_authority_and_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_DATABASE_URL", "parent-secret")
    monkeypatch.setenv("AGENTGUARD_AGENT_PRIVATE_KEY_FILE", "parent-key")
    monkeypatch.setenv("AGENTGUARD_LLM_MODE", "mocked-parent-mode")
    monkeypatch.setenv("HTTPS_PROXY", "parent-proxy")
    environment = clean_environment({"AGENTGUARD_UI_DATABASE_URL": "ui-only"})
    assert environment["AGENTGUARD_UI_DATABASE_URL"] == "ui-only"
    assert not any(
        key in environment
        for key in (
            "AGENTGUARD_DATABASE_URL",
            "AGENTGUARD_AGENT_PRIVATE_KEY_FILE",
            "AGENTGUARD_LLM_MODE",
            "HTTPS_PROXY",
        )
    )


def test_reused_or_tampered_pid_is_not_a_managed_process() -> None:
    current = psutil.Process(os.getpid())
    item = {
        "pid": current.pid,
        "created_at": current.create_time(),
        "executable": current.exe(),
        "command": current.cmdline(),
    }
    assert matching_process(item) is not None
    for field, replacement in (
        ("created_at", current.create_time() - 60),
        ("executable", "another.exe"),
        ("command", ["unrelated"]),
    ):
        assert matching_process(item | {field: replacement}) is None


def test_dependency_zip_cannot_escape_runtime(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../escaped.txt", "not allowed")
    destination = tmp_path / "dependency"
    destination.mkdir()
    with pytest.raises(RuntimeError, match="unsafe path"):
        safe_extract(archive, destination)
    assert not (tmp_path / "escaped.txt").exists()


def test_postgresql_extracts_server_and_licenses_without_unused_long_pgadmin_paths(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "postgresql.zip"
    selected = {
        "pgsql/bin/postgres.exe",
        "pgsql/bin/initdb.exe",
        "pgsql/bin/pg_ctl.exe",
        "pgsql/lib/libpq.dll",
        "pgsql/share/timezone/Asia/Hong_Kong",
        "pgsql/share/extension/plpgsql--1.0.sql",
        "pgsql/share/postgresql.conf.sample",
        "pgsql/server_license.txt",
        "pgsql/commandlinetools_3rd_party_licenses.txt",
    }
    ignored = {
        "pgsql/pgAdmin 4/python/Lib/site-packages/azure/" + "component/" * 30 + "unused.py",
        "pgsql/doc/html/index.html",
        "pgsql/StackBuilder/bin/stackbuilder.exe",
    }
    with zipfile.ZipFile(archive, "w") as zipped:
        for name in selected | ignored:
            zipped.writestr(name, b"public fixture")
    destination = tmp_path / "server"
    safe_extract(archive, destination, postgresql_server_only=True)
    actual = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file()
    }
    assert actual == selected
    assert all((destination / name).read_bytes() == b"public fixture" for name in selected)
    assert not (destination / "pgsql/pgAdmin 4").exists()


@pytest.mark.parametrize(
    "unsafe",
    ("../escaped.txt", "pgsql/bin/../../../escaped.txt", "pgsql/pgAdmin 4/../../../escaped.txt"),
)
def test_server_filter_still_validates_every_archive_member_before_writing(
    tmp_path: Path,
    unsafe: str,
) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("pgsql/bin/postgres.exe", b"public fixture")
        zipped.writestr(unsafe, b"not allowed")
    destination = tmp_path / "server"
    with pytest.raises(RuntimeError, match="unsafe path"):
        safe_extract(archive, destination, postgresql_server_only=True)
    assert not destination.exists()
    assert not (tmp_path / "escaped.txt").exists()


def test_dependency_applies_postgresql_server_filter_without_changing_locked_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    archive = runtime / "downloads/postgresql.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("pgsql/bin/pg_ctl.exe", b"public fixture")
        zipped.writestr("pgsql/server_license.txt", b"license fixture")
        zipped.writestr("pgsql/pgAdmin 4/unused.py", b"unused fixture")
    expected_hash = native_runtime.hash_file(archive)
    spec = {
        "version": "16.15-1",
        "directory": "postgresql-16.15-1",
        "archive": archive.name,
        "executable": "pgsql/bin/pg_ctl.exe",
        "sha256": expected_hash,
    }
    lock = tmp_path / "lock.json"
    native_runtime.write_json(lock, {"postgresql": spec})
    monkeypatch.setattr(native_runtime, "RUNTIME", runtime)
    monkeypatch.setattr(native_runtime, "LOCK", lock)
    executable = native_runtime.dependency("postgresql")
    install = runtime / "deps" / spec["directory"]
    assert executable == install / spec["executable"]
    assert executable.read_bytes() == b"public fixture"
    assert (install / "pgsql/server_license.txt").exists()
    assert not (install / "pgsql/pgAdmin 4").exists()
    assert native_runtime.read_json(install / "native-install.json") == spec
    assert native_runtime.hash_file(archive) == expected_hash


@pytest.mark.skipif(os.name != "nt", reason="Windows native ACL setup")
def test_windows_acl_setup_uses_system_executable_paths_without_relying_on_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runtime"
    windows = tmp_path / "Windows"
    calls = []
    monkeypatch.setattr(native_runtime, "RUNTIME", root)
    monkeypatch.setenv("SystemRoot", str(windows))
    monkeypatch.setenv("PATH", "")

    def identity(command, *, text):
        assert text is True
        calls.append(command)
        return '"S-1-5-21-fixture"'

    def acl(command, **kwargs):
        calls.append(command)
        assert kwargs["check"] is True

    monkeypatch.setattr(native_runtime.subprocess, "check_output", identity)
    monkeypatch.setattr(native_runtime.subprocess, "run", acl)
    native_runtime.layout()
    assert calls[0][0] == str(windows / "System32/WindowsPowerShell/v1.0/powershell.exe")
    assert calls[1][0] == str(windows / "System32/icacls.exe")
    assert all((root / name).is_dir() for name in ("logs", "downloads", "deps", "home", "tmp"))
