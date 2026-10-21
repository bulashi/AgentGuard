"""Explicit production SCM deployment; current-user acceptance tools remain separate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import time
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from scripts.native_windows_api import (
    SERVICE_RUNNING,
    SERVICE_START_PENDING,
    SERVICE_STOPPED,
    Scm,
    WindowsIsolationError,
    account_sid,
    acl_entries,
    assert_private_acl,
    assert_trusted_code,
    no_links,
    require_admin,
    send_provisioning,
    set_acl,
    token_identity,
    validate_service_name,
)
from scripts.native_windows_dpapi import (
    UserDpapi,
    atomic_private_write,
    parse_document,
)

MODES = ("current-user", "scm-virtual-account")
SIGNING_PRINCIPALS = {
    "authorization": ("authorization-authority",),
    "gateway": ("secure-gateway",),
    "receipt": ("receipt-service",),
    "audit": ("checkpoint-service",),
    "agent-coordinator": ("coordinator-agent", "coordinator-delegation-agent"),
    "agent-knowledge": ("knowledge-agent",),
    "agent-case": ("case-agent", "case-delegation-agent"),
    "agent-refund": ("refund-agent", "refund-delegation-agent"),
}
ALL_ROLES = (
    "ticket-tool",
    "knowledge-tool",
    "refund-tool",
    "notification-tool",
    "authorization-authority",
    "business-action-registry",
    "secure-gateway",
    "revocation-authority",
    "receipt-service",
    "audit-append-authority",
    "checkpoint-service",
    "coordinator-delegation-agent",
    "case-delegation-agent",
    "refund-delegation-agent",
    "coordinator-agent",
    "knowledge-agent",
    "case-agent",
    "refund-agent",
    "recovery-worker",
    "audit-worker",
    "checkpoint-worker",
    "ui-api",
    "web-ui",
)
AUDIT_DATABASE_ROLES = {"audit-append-authority", "checkpoint-service"}
AGENT_ROLES = {"coordinator-agent", "knowledge-agent", "case-agent", "refund-agent"}
PROBE_ROLES = ("probe-a", "probe-b")


def select_mode(explicit: str | None = None) -> str:
    selected = explicit or os.environ.get("AGENTGUARD_NATIVE_ISOLATION", "current-user")
    if selected not in MODES:
        raise WindowsIsolationError("EXPLICIT_ISOLATION_MODE_INVALID")
    return selected


def service_names(
    deployment_id: str, roles: tuple[str, ...] = ALL_ROLES, *, probe: bool = False
) -> dict[str, str]:
    if len(deployment_id) != 16 or any(char not in "0123456789abcdef" for char in deployment_id):
        raise WindowsIsolationError("DEPLOYMENT_ID_INVALID")
    prefix = "AgentGuardProbe_" if probe else "AgentGuardSvc_"
    result = {role: prefix + deployment_id + "_" + role for role in roles}
    for name in result.values():
        validate_service_name(name)
    return result


def service_command(python: Path, host: Path, root: Path, service_name: str) -> str:
    validate_service_name(service_name)
    return subprocess.list2cmdline(
        [
            str(no_links(python)),
            "-I",
            "-B",
            str(no_links(host)),
            "--root",
            str(no_links(root)),
            "--service-name",
            service_name,
        ]
    )


def scope_service_groups(
    groups: list, root: Path, names: dict[str, str], *, model_revision: str = ""
) -> list:
    root = no_links(root)
    if model_revision and (
        len(model_revision) != 64 or any(char not in "0123456789abcdef" for char in model_revision)
    ):
        raise WindowsIsolationError("MODEL_SNAPSHOT_REVISION_INVALID")
    expected = set(ALL_ROLES) - {"web-ui"}
    if set(names) not in (expected, set(ALL_ROLES)) or len(set(names.values())) != len(names):
        raise WindowsIsolationError("SERVICE_IDENTITY_MAP_INCOMPLETE")
    for name in names.values():
        validate_service_name(name)
    result = []
    for group in groups:
        scoped = []
        for service in group:
            if service.name not in expected:
                raise WindowsIsolationError("SERVICE_ROLE_UNEXPECTED")
            values = dict(service.environment)
            if service.name not in AUDIT_DATABASE_ROLES:
                values.pop("AGENTGUARD_AUDIT_DATABASE_URL", None)
            if service.name in AGENT_ROLES | {"ui-api"}:
                values.pop("AGENTGUARD_DATABASE_URL", None)
            if service.name != "coordinator-agent":
                values.pop("AGENTGUARD_WORKFLOW_DATABASE_URL", None)
            if service.name in AGENT_ROLES:
                if values.get("AGENTGUARD_CLOUD_LLM_ENABLED") == "true" and not model_revision:
                    raise WindowsIsolationError("SCM_CLOUD_PROFILE_SNAPSHOT_REQUIRED")
                values["AGENTGUARD_CLOUD_LLM_API_KEY"] = ""
            if service.name in AGENT_ROLES | {"ui-api"}:
                values["AGENTGUARD_MODEL_CONFIGURATIONS_PATH"] = (
                    str(root / "services" / service.name / "private/model-configurations.json")
                    if model_revision
                    else ""
                )
            state_root = root / "services" / service.name / "state"
            values["AGENTGUARD_INTERNAL_AUTH_NONCE_ROOT"] = str(state_root / "nonces")
            if service.name == "ui-api":
                values["AGENTGUARD_UI_ARTIFACT_ROOT"] = str(state_root / "artifacts")
            for principal, roles in SIGNING_PRINCIPALS.items():
                if service.name not in roles:
                    continue
                private = root / "principals" / principal
                for variable in (
                    "AGENTGUARD_AUTHORIZATION_PRIVATE_KEY_ROOT",
                    "AGENTGUARD_DELEGATION_PRIVATE_KEY_ROOT",
                ):
                    if variable in values:
                        values[variable] = str(private)
                for variable in (
                    "AGENTGUARD_GATEWAY_PRIVATE_KEY_FILE",
                    "AGENTGUARD_RECEIPT_PRIVATE_KEY_FILE",
                    "AGENTGUARD_AUDIT_PRIVATE_KEY_FILE",
                    "AGENTGUARD_AGENT_PRIVATE_KEY_FILE",
                ):
                    if variable in values:
                        values[variable] = str(private / (principal + ".private"))
            for variable in (
                "AGENTGUARD_GATEWAY_PUBLIC_KEY_FILE",
                "AGENTGUARD_RECEIPT_PUBLIC_KEY_FILE",
                "AGENTGUARD_AUDIT_PUBLIC_KEY_FILE",
            ):
                if variable in values:
                    values[variable] = str(root / "public" / Path(values[variable]).name)
            scoped.append(
                replace(
                    service,
                    environment=values,
                    windows_service_name=names[service.name],
                    windows_config_path=root
                    / "services"
                    / service.name
                    / "private"
                    / "config.dpapi",
                )
            )
        result.append(scoped)
    if {item.name for group in result for item in group} != expected:
        raise WindowsIsolationError("SERVICE_ROLE_SET_INCOMPLETE")
    return result


def validate_service_environment(role: str, values: dict[str, str], root: Path) -> None:
    if (
        role not in ALL_ROLES
        or not isinstance(values, dict)
        or any(
            not isinstance(key, str) or not isinstance(value, str) or "\x00" in key + value
            for key, value in values.items()
        )
    ):
        raise WindowsIsolationError("SERVICE_ENVIRONMENT_INVALID")
    if any(not key.startswith("AGENTGUARD_") for key in values):
        raise WindowsIsolationError("SERVICE_ENVIRONMENT_VARIABLE_REJECTED")
    for variable in (
        "AGENTGUARD_DATABASE_URL",
        "AGENTGUARD_AUDIT_DATABASE_URL",
        "AGENTGUARD_WORKFLOW_DATABASE_URL",
        "AGENTGUARD_UI_DATABASE_URL",
    ):
        if variable not in values:
            continue
        allowed = (
            (
                variable == "AGENTGUARD_DATABASE_URL"
                and role not in AGENT_ROLES | {"ui-api", "web-ui"}
            )
            or (variable == "AGENTGUARD_AUDIT_DATABASE_URL" and role in AUDIT_DATABASE_ROLES)
            or (variable == "AGENTGUARD_WORKFLOW_DATABASE_URL" and role == "coordinator-agent")
            or (variable == "AGENTGUARD_UI_DATABASE_URL" and role == "ui-api")
        )
        if not allowed:
            raise WindowsIsolationError("SERVICE_DATABASE_SCOPE_MISMATCH")
    principal = next((name for name, roles in SIGNING_PRINCIPALS.items() if role in roles), None)
    for key, value in values.items():
        if "PRIVATE_KEY" not in key:
            continue
        if principal is None:
            raise WindowsIsolationError("SERVICE_SIGNING_SCOPE_MISMATCH")
        directory = root / "principals" / principal
        target = no_links(Path(value), within=directory)
        if key.endswith("_ROOT") and target != directory.resolve():
            raise WindowsIsolationError("SERVICE_SIGNING_SCOPE_MISMATCH")
        if key.endswith("_FILE") and target != (directory / (principal + ".private")).resolve():
            raise WindowsIsolationError("SERVICE_SIGNING_SCOPE_MISMATCH")
    if values.get("AGENTGUARD_INTERNAL_AUTH_REQUIRED") != "true" and role != "web-ui":
        raise WindowsIsolationError("SCM_INTERNAL_AUTH_REQUIRED")
    if role != "web-ui":
        from scripts.native_security import service_identity

        subject = service_identity(role)
        if values.get("AGENTGUARD_INTERNAL_AUTH_SERVICE_ID") != subject:
            raise WindowsIsolationError("SCM_INTERNAL_AUTH_IDENTITY_MISMATCH")
        try:
            keys = json.loads(values.get("AGENTGUARD_INTERNAL_AUTH_KEYS", ""))
        except (ValueError, TypeError):
            raise WindowsIsolationError("SCM_INTERNAL_AUTH_KEYS_INVALID") from None
        if not isinstance(keys, dict) or any(
            not isinstance(edge, str)
            or len(edge.split("->")) != 2
            or subject not in edge.split("->")
            or not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for edge, value in keys.items()
        ):
            raise WindowsIsolationError("SCM_INTERNAL_AUTH_KEYS_SCOPE_MISMATCH")
    if role == "ui-api" and (
        values.get("AGENTGUARD_OPERATOR_AUTH_REQUIRED") != "true"
        or not values.get("AGENTGUARD_OPERATOR_SESSION_SECRET")
    ):
        raise WindowsIsolationError("SCM_OPERATOR_AUTH_REQUIRED")
    if values.get("AGENTGUARD_CLOUD_LLM_API_KEY"):
        raise WindowsIsolationError("SCM_CLOUD_KEY_MUST_USE_PRIVATE_SNAPSHOT")
    if values.get("AGENTGUARD_CLOUD_LLM_ENABLED", "false") not in {"true", "false"}:
        raise WindowsIsolationError("SCM_CLOUD_SELECTION_INVALID")
    model_path = values.get("AGENTGUARD_MODEL_CONFIGURATIONS_PATH")
    if model_path:
        expected = root / "services" / role / "private/model-configurations.json"
        if role not in AGENT_ROLES | {"ui-api"} or no_links(Path(model_path)) != expected.resolve():
            raise WindowsIsolationError("SCM_MODEL_SNAPSHOT_ROLE_PATH_MISMATCH")
    elif values.get("AGENTGUARD_CLOUD_LLM_ENABLED") == "true":
        raise WindowsIsolationError("SCM_CLOUD_PROFILE_SNAPSHOT_REQUIRED")


def child_environment(values: dict[str, str], state_root: Path, *, project_root: Path) -> dict:
    # SCM's inherited machine environment can contain unrelated credentials. Use an allowlist.
    system_root = os.environ.get("SystemRoot")
    if not system_root or not Path(system_root).is_absolute():
        raise WindowsIsolationError("SYSTEM_ROOT_UNAVAILABLE")
    result = {
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "PATH": str(Path(system_root) / "System32"),
        "TEMP": str(state_root / "tmp"),
        "TMP": str(state_root / "tmp"),
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "USERPROFILE": str(state_root / "home"),
        "HOME": str(state_root / "home"),
        "APPDATA": str(state_root / "home/AppData/Roaming"),
        "LOCALAPPDATA": str(state_root / "home/AppData/Local"),
        "NO_PROXY": "127.0.0.1,localhost,::1",
    }
    result.update(values)
    return result


def read_manifest(
    root: Path, *, project_root: Path | None = None, current_role: str | None = None
) -> dict:
    root = no_links(root)
    manifest = parse_document((root / "manifest.json").read_bytes())
    if (
        manifest.get("schema_version") != 1
        or manifest.get("root") != str(root)
        or manifest.get("kind") not in {"probe", "production"}
        or not isinstance(manifest.get("services"), dict)
    ):
        raise WindowsIsolationError("SCM_MANIFEST_INVALID")
    if project_root is not None and manifest.get("project_root") != str(project_root.resolve()):
        raise WindowsIsolationError("SCM_PROJECT_OWNERSHIP_MISMATCH")
    roles = PROBE_ROLES if manifest["kind"] == "probe" else ALL_ROLES
    names = service_names(
        manifest.get("deployment_id", ""), roles, probe=manifest["kind"] == "probe"
    )
    if set(manifest["services"]) != set(roles):
        raise WindowsIsolationError("SCM_MANIFEST_ROLE_SET")
    if manifest["kind"] == "production":
        groups = manifest.get("groups")
        if (
            not isinstance(groups, list)
            or not groups
            or any(not isinstance(group, list) or not group for group in groups)
            or [role for group in groups for role in group] != list(ALL_ROLES)
            or manifest.get("provisioned_receipt") != str(root / "provisioned.json")
        ):
            raise WindowsIsolationError("SCM_MANIFEST_START_ORDER_INVALID")
    for role, record in manifest["services"].items():
        if record.get("service_name") != names[role] or record.get("role") != role:
            raise WindowsIsolationError("SCM_MANIFEST_IDENTITY_MISMATCH")
        if record.get("sid") != account_sid("NT SERVICE\\" + names[role]):
            raise WindowsIsolationError("SCM_MANIFEST_SID_MISMATCH")
        for field in ("private_root", "state_root", "config_path"):
            if current_role is None or current_role == role:
                no_links(Path(record[field]), within=root)
        expected_private = root / "services" / role / "private"
        if (
            Path(record["private_root"]) != expected_private
            or Path(record["state_root"]) != root / "services" / role / "state"
            or Path(record["config_path"]) != expected_private / "config.dpapi"
        ):
            raise WindowsIsolationError("SCM_MANIFEST_PRIVATE_PATH_MISMATCH")
        if record.get("command") != service_command(
            Path(manifest["python"]), Path(manifest["host"]), root, names[role]
        ):
            raise WindowsIsolationError("SCM_MANIFEST_COMMAND_MISMATCH")
    return manifest


def validate_deployment(root: Path, *, project_root: Path, require_configs: bool = True) -> dict:
    identity = require_admin()
    manifest = read_manifest(root, project_root=project_root)
    if manifest["kind"] != "production":
        raise WindowsIsolationError("PRODUCTION_MANIFEST_REQUIRED")
    all_sids = tuple(record["sid"] for record in manifest["services"].values())
    assert_private_acl(root, readers=all_sids)
    assert_private_acl(root / "manifest.json", readers=all_sids)
    assert_legacy_private_acl(project_root, administrator_sid=identity["user_sid"])
    # Writable source/runtime code defeats file ACL isolation by executing attacker code at startup.
    code_roots = [
        project_root / "scripts",
        project_root / "backend",
        project_root / "protocol",
        project_root / "frontend" / "dist",
        Path(manifest["python"]).parent,
    ]
    if Path(manifest["python"]).parent.name == "Scripts":
        raise WindowsIsolationError("SCM_SELF_CONTAINED_PYTHON_REQUIRED")
    for code_root in code_roots:
        assert_trusted_code(code_root, administrator_sid=identity["user_sid"])
        for path in code_root.rglob("*"):
            assert_trusted_code(path, administrator_sid=identity["user_sid"])
    with Scm() as scm:
        for record in manifest["services"].values():
            scm.assert_owned(record["service_name"], record["command"])
            sid = record["sid"]
            private, state = Path(record["private_root"]), Path(record["state_root"])
            assert_private_acl(private, writers=(sid,))
            assert_private_acl(state, writers=(sid,))
            if require_configs:
                path = Path(record["config_path"])
                assert_private_acl(path, writers=(sid,))
                config = parse_document(path.read_bytes())
                if (
                    config.get("schema_version") != 1
                    or config.get("owner_sid") != sid
                    or config.get("role") != record["role"]
                    or not isinstance(config.get("protected"), str)
                ):
                    raise WindowsIsolationError("SCM_PRIVATE_CONFIGURATION_INVALID")
        for principal, roles in SIGNING_PRINCIPALS.items():
            sids = tuple(manifest["services"][role]["sid"] for role in roles)
            directory = root / "principals" / principal
            assert_private_acl(directory, readers=sids)
            for path in directory.iterdir():
                assert_private_acl(path, readers=sids)
    return manifest


def assert_legacy_private_acl(project_root: Path, *, administrator_sid: str) -> None:
    from scripts.native_windows_api import ADMINISTRATORS_SID, SYSTEM_SID

    trusted = {administrator_sid, ADMINISTRATORS_SID, SYSTEM_SID}
    private = project_root / ".native/keys/private"
    if not private.is_dir():
        raise WindowsIsolationError("LEGACY_PRIVATE_ROOT_MISSING")
    paths = [project_root / ".native", private, *private.glob("*.private")]
    for name in (
        "config.json",
        "model-configurations.json",
        "internal-service-keys.dpapi",
        "operator-session.dpapi",
    ):
        candidate = project_root / ".native" / name
        if candidate.is_file():
            paths.append(candidate)
    for path in paths:
        actual = acl_entries(path)
        if actual["owner"] not in trusted or any(
            entry["allow"] and not entry["flags"] & 8 and entry["sid"] not in trusted
            for entry in actual["entries"]
        ):
            raise WindowsIsolationError("LEGACY_PRIVATE_ACL_EXPOSED")


def seal_config(manifest: dict, record: dict, content: bytes) -> None:
    from scripts.native_windows_api import require_service_identity

    identity = require_service_identity(record["service_name"])
    document = parse_document(content)
    if document.get("role") != record["role"] or document.get("schema_version") != 1:
        raise WindowsIsolationError("SCM_PROVISIONED_ROLE_MISMATCH")
    if manifest["kind"] == "production":
        validate_service_environment(
            record["role"], document.get("environment"), Path(manifest["root"])
        )
        from scripts.native_windows_profiles import MODEL_ROLES, stage_model_snapshot

        if record["role"] in MODEL_ROLES:
            snapshot = document.get("model_snapshot")
            if not isinstance(snapshot, dict) or snapshot.get("source_sha256") != manifest.get(
                "model_source_sha256"
            ):
                raise WindowsIsolationError("SCM_MODEL_SNAPSHOT_MANIFEST_MISMATCH")
            document["model_staged_sha256"] = stage_model_snapshot(snapshot, record)
        elif "model_snapshot" in document:
            raise WindowsIsolationError("MODEL_SNAPSHOT_ROLE_REJECTED")
        content = json.dumps(document, ensure_ascii=True).encode("ascii")
    elif "model_snapshot" in document:
        from scripts.native_windows_profiles import stage_model_snapshot

        model_role = manifest.get("probe_model_roles", {}).get(record["role"])
        if model_role not in AGENT_ROLES:
            raise WindowsIsolationError("PROBE_MODEL_ROLE_REJECTED")
        document["model_staged_sha256"] = stage_model_snapshot(
            document["model_snapshot"], record | {"role": model_role}
        )
        content = json.dumps(document, ensure_ascii=True).encode("ascii")
    path = Path(record["config_path"])
    if path.exists():
        raise WindowsIsolationError("SCM_PRIVATE_CONFIG_ALREADY_EXISTS")
    purpose = "service:" + record["service_name"]
    cipher = UserDpapi()
    protected = cipher.protect(content, purpose=purpose)
    if cipher.unprotect(protected, purpose=purpose) != content:
        raise WindowsIsolationError("SCM_PRIVATE_CONFIG_DPAPI_ROUNDTRIP")
    envelope = {
        "schema_version": 1,
        "owner_sid": identity["user_sid"],
        "role": record["role"],
        "protected": protected,
    }
    atomic_private_write(
        path, json.dumps(envelope).encode("ascii"), expected=None, writers=(identity["user_sid"],)
    )


def load_config(record: dict) -> dict:
    from scripts.native_windows_api import require_service_identity

    identity = require_service_identity(record["service_name"])
    path = Path(record["config_path"])
    assert_private_acl(path, writers=(identity["user_sid"],))
    envelope = parse_document(path.read_bytes())
    if (
        envelope.get("schema_version") != 1
        or envelope.get("owner_sid") != identity["user_sid"]
        or envelope.get("role") != record["role"]
    ):
        raise WindowsIsolationError("SCM_PRIVATE_CONFIG_OWNER_MISMATCH")
    return parse_document(
        UserDpapi().unprotect(
            envelope.get("protected"), purpose="service:" + record["service_name"]
        )
    )


def provision_identity(scm: Scm, record: dict, payload: dict) -> None:
    if scm.status(record["service_name"])["state"] != SERVICE_STOPPED:
        raise WindowsIsolationError("SCM_PROVISIONING_REQUIRES_STOPPED_SERVICE")
    scm.start(record["service_name"], record["command"], ("provision",))
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        status = scm.status(record["service_name"])
        if status["pid"] and status["state"] in (SERVICE_START_PENDING, SERVICE_RUNNING):
            send_provisioning(
                record["service_name"], status["pid"], json.dumps(payload).encode("ascii")
            )
            scm.wait(record["service_name"], SERVICE_STOPPED)
            return
        if status["state"] == SERVICE_STOPPED:
            raise WindowsIsolationError("SCM_PROVISIONER_STOPPED", status["service_exit"])
        time.sleep(0.05)
    raise WindowsIsolationError("SCM_PROVISIONER_PID_TIMEOUT")


def start_deployment(root: Path, *, project_root: Path) -> dict:
    manifest = validate_deployment(root, project_root=project_root)
    validate_provisioned_receipt(manifest)
    with Scm() as scm:
        started = []
        try:
            for group in manifest["groups"]:
                for role in group:
                    record = manifest["services"][role]
                    if scm.status(record["service_name"])["state"] != SERVICE_STOPPED:
                        raise WindowsIsolationError("SCM_SERVICE_ALREADY_RUNNING")
                    scm.start(record["service_name"], record["command"])
                    started.append(record)
                for role in group:
                    record = manifest["services"][role]
                    status = scm.wait(record["service_name"], SERVICE_RUNNING)
                    if token_identity(status["pid"])["user_sid"] != record["sid"]:
                        raise WindowsIsolationError("SCM_RUNNING_TOKEN_MISMATCH")
                    _wait_health(record, scm)
        except Exception:
            for record in reversed(started):
                scm.stop(record["service_name"], record["command"])
            raise
    return manifest


def validate_provisioned_receipt(manifest: dict) -> None:
    from scripts.native_windows_profiles import MODEL_ROLES

    root = Path(manifest["root"])
    path = no_links(root / "provisioned.json", within=root)
    if not path.is_file():
        raise WindowsIsolationError("SCM_PROVISIONING_RECEIPT_REQUIRED")
    assert_private_acl(path)
    document = parse_document(path.read_bytes())
    configurations = {
        role: hashlib.sha256(
            no_links(Path(record["config_path"]), within=root).read_bytes()
        ).hexdigest()
        for role, record in manifest["services"].items()
    }
    models = {
        role: hashlib.sha256(
            no_links(
                Path(record["private_root"]) / "model-configurations.json", within=root
            ).read_bytes()
        ).hexdigest()
        for role, record in manifest["services"].items()
        if role in MODEL_ROLES
    }
    if (
        document.get("schema_version") != 1
        or document.get("deployment_id") != manifest["deployment_id"]
        or document.get("services") != len(ALL_ROLES)
        or document.get("main_runtime_started") is not False
        or document.get("manifest_sha256")
        != hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()
        or document.get("private_config_sha256") != configurations
        or document.get("model_profile_sha256") != models
    ):
        raise WindowsIsolationError("SCM_PROVISIONING_RECEIPT_MISMATCH")


def _wait_health(record: dict, scm: Scm) -> None:
    import httpx

    path = "/healthz" if record["role"] == "web-ui" else "/health"
    deadline = time.monotonic() + 60
    with httpx.Client(timeout=2, trust_env=False) as client:
        while time.monotonic() < deadline:
            if scm.status(record["service_name"])["state"] != SERVICE_RUNNING:
                raise WindowsIsolationError("SCM_SERVICE_EXITED")
            try:
                response = client.get(f"http://127.0.0.1:{record['port']}{path}")
                if response.status_code == 200 and response.json().get("status") == "ok":
                    return
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(0.2)
    raise WindowsIsolationError("SCM_HEALTH_TIMEOUT")


def stop_deployment(root: Path, *, project_root: Path) -> None:
    require_admin()
    manifest = read_manifest(root, project_root=project_root)
    if manifest["kind"] != "production":
        raise WindowsIsolationError("PRODUCTION_MANIFEST_REQUIRED")
    with Scm() as scm:
        for group in reversed(manifest["groups"]):
            for role in reversed(group):
                record = manifest["services"][role]
                scm.stop(record["service_name"], record["command"])


def doctor_deployment(root: Path, *, project_root: Path) -> dict:
    manifest = validate_deployment(root, project_root=project_root)
    validate_provisioned_receipt(manifest)
    services = []
    with Scm() as scm:
        for role, record in manifest["services"].items():
            status = scm.status(record["service_name"])
            if status["state"] != SERVICE_RUNNING:
                raise WindowsIsolationError("SCM_SERVICE_NOT_RUNNING")
            identity = token_identity(status["pid"])
            if (
                identity["user_sid"] != record["sid"]
                or identity["elevated_admin"]
                or identity["system"]
            ):
                raise WindowsIsolationError("SCM_RUNNING_TOKEN_MISMATCH")
            _wait_health(record, scm)
            services.append(
                {
                    "role": role,
                    "service_name": record["service_name"],
                    "pid": status["pid"],
                    "user_sid": identity["user_sid"],
                }
            )
    return {
        "schema_version": 1,
        "boundary": "windows_virtual_service_accounts_admin_system_trusted",
        "services": services,
        "external_custody_proven": False,
    }


def install_deployment(
    project_root: Path, root: Path, python: Path, *, ui_port: int = 8088, postgres_port: int = 15432
) -> dict:
    """Explicit administrative operation, never invoked by ordinary startup or test tooling."""
    require_admin()
    project_root, root, python = no_links(project_root), no_links(root), no_links(python)
    if root.parent != project_root / ".native-windows" or root.exists():
        raise WindowsIsolationError("FRESH_PROJECT_SCOPED_DEPLOYMENT_REQUIRED")
    from scripts import native_runtime as runtime
    from scripts.native_config import service_specs
    from scripts.native_security import generate_keys
    from scripts.native_windows_profiles import MODEL_ROLES, export_model_snapshot

    if project_root != runtime.ROOT:
        raise WindowsIsolationError("SCM_PROJECT_OWNERSHIP_MISMATCH")
    if runtime.STATE.exists() and any(
        runtime.matching_process(item) for item in runtime.managed_state()["processes"]
    ):
        raise WindowsIsolationError("STOP_CURRENT_USER_RUNTIME_BEFORE_SCM_INSTALL")
    identity = require_admin()
    assert_legacy_private_acl(project_root, administrator_sid=identity["user_sid"])
    if python.parent.name == "Scripts":
        raise WindowsIsolationError("SCM_SELF_CONTAINED_PYTHON_REQUIRED")
    for code_root in (
        project_root / "scripts",
        project_root / "backend",
        project_root / "protocol",
        project_root / "frontend/dist",
        python.parent,
    ):
        assert_trusted_code(code_root, administrator_sid=identity["user_sid"])
        for path in code_root.rglob("*"):
            assert_trusted_code(path, administrator_sid=identity["user_sid"])
    value = runtime.prepared_config(postgres_port)
    urls = runtime.prepared_urls(value)  # Existing DB/schema/grants only; no provisioning.
    deployment_id = uuid.uuid4().hex[:16]
    names = service_names(deployment_id)
    model_path = project_root / ".native/model-configurations.json"
    model_snapshot = export_model_snapshot(model_path)
    keys, operator_secret = generate_keys(), secrets.token_hex(32)
    groups = service_specs(
        urls["main"],
        urls["audit"],
        urls["ui"],
        project_root / ".native/keys",
        with_llm=False,
        workflow_url=urls["workflow"],
        internal_keys=keys,
        operator_session_secret=operator_secret,
        isolation_mode="scm-virtual-account",
        isolation_root=root,
        windows_service_names=names,
        model_configurations_path=model_path,
        windows_model_revision=model_snapshot["source_sha256"],
    )
    host = project_root / "scripts/native_windows_service.py"
    parent = root.parent
    if not parent.exists():
        parent.mkdir()
        set_acl(parent)
    else:
        assert_private_acl(parent)
    root.mkdir()
    set_acl(root)
    manifest = {
        "schema_version": 1,
        "kind": "production",
        "deployment_id": deployment_id,
        "root": str(root),
        "project_root": str(project_root),
        "python": str(python),
        "host": str(host),
        "created_at": datetime.now(UTC).isoformat(),
        "model_source_sha256": model_snapshot["source_sha256"],
        "services": {},
        "groups": [[service.name for service in group] for group in groups] + [["web-ui"]],
        "ui_port": ui_port,
    }
    with Scm(create=True) as scm:
        for role in ALL_ROLES:
            command = service_command(python, host, root, names[role])
            scm.create(names[role], command)
            sid = account_sid("NT SERVICE\\" + names[role])
            service_root = root / "services" / role
            service_root.mkdir(parents=True)
            set_acl(service_root, readers=(sid,))
            private, state = service_root / "private", service_root / "state"
            for path in (private, state):
                path.mkdir()
                set_acl(path, writers=(sid,))
            for relative in (
                "tmp",
                "home",
                "home/AppData",
                "home/AppData/Roaming",
                "home/AppData/Local",
            ):
                path = state / relative
                path.mkdir()
                set_acl(path, writers=(sid,))
            service = next((item for group in groups for item in group if item.name == role), None)
            manifest["services"][role] = {
                "role": role,
                "service_name": names[role],
                "sid": sid,
                "command": command,
                "private_root": str(private),
                "state_root": str(state),
                "config_path": str(private / "config.dpapi"),
                "module": service.module if service else "scripts.native_web",
                "port": service.port if service else ui_port,
            }
        all_sids = tuple(record["sid"] for record in manifest["services"].values())
        set_acl(root / "services", readers=all_sids)
        for principal, roles in SIGNING_PRINCIPALS.items():
            directory = root / "principals" / principal
            directory.mkdir(parents=True)
            sids = tuple(manifest["services"][role]["sid"] for role in roles)
            set_acl(directory, readers=sids)
            source = project_root / ".native/keys/private" / (principal + ".private")
            no_links(source)
            atomic_private_write(
                directory / source.name, source.read_bytes(), expected=None, readers=sids
            )
        set_acl(root / "principals", readers=all_sids)
        public = root / "public"
        public.mkdir()
        set_acl(public, readers=all_sids)
        for source in (project_root / ".native/keys/public").glob("*.public"):
            no_links(source)
            atomic_private_write(
                public / source.name, source.read_bytes(), expected=None, readers=all_sids
            )
        # Manifest contains no secrets and is immutable to services; it provides their own paths.
        set_acl(root, readers=all_sids)
        manifest_path = root / "manifest.json"
        manifest["provisioned_receipt"] = str(root / "provisioned.json")
        atomic_private_write(
            manifest_path, json.dumps(manifest).encode("ascii"), expected=None, readers=all_sids
        )
        for group in groups:
            for service in group:
                payload = {
                    "schema_version": 1,
                    "role": service.name,
                    "environment": service.environment,
                }
                if service.name in MODEL_ROLES:
                    payload["model_snapshot"] = model_snapshot
                provision_identity(scm, manifest["services"][service.name], payload)
        provision_identity(
            scm,
            manifest["services"]["web-ui"],
            {"schema_version": 1, "role": "web-ui", "environment": {}},
        )
    receipt = {
        "schema_version": 1,
        "deployment_id": deployment_id,
        "provisioned_at": datetime.now(UTC).isoformat(),
        "services": len(ALL_ROLES),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "private_config_sha256": {
            role: hashlib.sha256(Path(record["config_path"]).read_bytes()).hexdigest()
            for role, record in manifest["services"].items()
        },
        "model_profile_sha256": {
            role: hashlib.sha256(
                (Path(record["private_root"]) / "model-configurations.json").read_bytes()
            ).hexdigest()
            for role, record in manifest["services"].items()
            if role in MODEL_ROLES
        },
        "main_runtime_started": False,
        "external_custody_proven": False,
    }
    atomic_private_write(
        root / "provisioned.json", json.dumps(receipt).encode("ascii"), expected=None
    )
    # The UI token is operator-user DPAPI; no service can read this operator-only record.
    atomic_private_write(
        root / "operator-session.dpapi",
        UserDpapi()
        .protect(operator_secret.encode("ascii"), purpose="scm-operator:" + deployment_id)
        .encode("ascii"),
        expected=None,
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicit AgentGuard virtual service installation")
    parser.add_argument("operation", choices=("install", "check"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--confirm-service-install", action="store_true")
    parser.add_argument("--ui-port", type=int, default=8088)
    parser.add_argument("--postgres-port", type=int, default=15432)
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    try:
        if args.operation == "install":
            if not args.confirm_service_install or args.python is None:
                raise WindowsIsolationError("EXPLICIT_SERVICE_INSTALL_CONFIRMATION_REQUIRED")
            result = install_deployment(
                project_root,
                args.root,
                args.python,
                ui_port=args.ui_port,
                postgres_port=args.postgres_port,
            )
        else:
            manifest = validate_deployment(args.root, project_root=project_root)
            result = {"result": "PASS", "services": len(manifest["services"])}
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except WindowsIsolationError as exc:
        print(json.dumps({"result": "FAIL", "reason": exc.code, "winerror": exc.winerror}))
        return 2
    except Exception as exc:
        print(json.dumps({"result": "FAIL", "error_type": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
