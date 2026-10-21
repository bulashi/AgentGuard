from __future__ import annotations

import hashlib
import json
from argparse import Namespace

import pytest

from scripts import native_config
from scripts import native_windows_isolation as isolation
from scripts.native_security import generate_keys, service_identity
from scripts.native_windows_api import Scm, WindowsIsolationError, acl_sddl, validate_service_name


@pytest.fixture
def scoped(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_CLOUD_LLM_ENABLED", "false")
    monkeypatch.setenv("AGENTGUARD_COAUTHORIZATION_REQUIRED", "false")
    root = tmp_path / "isolated"
    names = isolation.service_names("1234567890abcdef")
    groups = native_config.service_specs(
        "postgresql://main:synthetic@127.0.0.1:15432/main",
        "postgresql://audit:synthetic@127.0.0.1:15432/audit",
        "postgresql://ui:synthetic@127.0.0.1:15432/main",
        tmp_path / "old-keys",
        with_llm=False,
        workflow_url="postgresql://workflow:synthetic@127.0.0.1:15432/main",
        internal_keys=generate_keys(),
        operator_session_secret="a" * 64,
        isolation_mode="scm-virtual-account",
        isolation_root=root,
        windows_service_names=names,
    )
    return root, {item.name: item for group in groups for item in group}


def test_distinct_service_identity_config_and_nonce_per_role(scoped):
    root, services = scoped
    assert len({item.windows_service_name for item in services.values()}) == len(services)
    assert len({item.windows_config_path for item in services.values()}) == len(services)
    assert len(
        {item.environment["AGENTGUARD_INTERNAL_AUTH_NONCE_ROOT"] for item in services.values()}
    ) == len(services)
    for name, item in services.items():
        assert item.windows_config_path == root / "services" / name / "private/config.dpapi"


def test_signing_key_roots_are_per_principal_not_global(scoped):
    root, services = scoped
    for principal, roles in isolation.SIGNING_PRINCIPALS.items():
        for role in roles:
            variables = {
                key: value
                for key, value in services[role].environment.items()
                if "PRIVATE_KEY" in key
            }
            assert len(variables) == 1
            for key, value in variables.items():
                expected = root / "principals" / principal
                if key.endswith("_FILE"):
                    expected /= principal + ".private"
                assert value == str(expected)
    for role in set(services) - {
        role for roles in isolation.SIGNING_PRINCIPALS.values() for role in roles
    }:
        assert not any("PRIVATE_KEY" in key for key in services[role].environment)


def test_database_credentials_are_role_scoped(scoped):
    _, services = scoped
    for role, item in services.items():
        values = item.environment
        assert ("AGENTGUARD_AUDIT_DATABASE_URL" in values) == (
            role in isolation.AUDIT_DATABASE_ROLES
        )
        assert ("AGENTGUARD_DATABASE_URL" in values) == (
            role not in isolation.AGENT_ROLES | {"ui-api"}
        )
        assert ("AGENTGUARD_WORKFLOW_DATABASE_URL" in values) == (role == "coordinator-agent")
        assert ("AGENTGUARD_UI_DATABASE_URL" in values) == (role == "ui-api")


def test_internal_hmac_keys_only_cover_role_edges(scoped):
    _, services = scoped
    for role, item in services.items():
        identity = service_identity(role)
        assert item.environment["AGENTGUARD_INTERNAL_AUTH_SERVICE_ID"] == identity
        keys = json.loads(item.environment["AGENTGUARD_INTERNAL_AUTH_KEYS"])
        assert all(identity in edge.split("->") for edge in keys)


def test_bff_revocation_url_matches_current_port_in_both_modes(scoped, tmp_path):
    _, services = scoped
    assert services["ui-api"].environment["AGENTGUARD_REVOCATION_URL"] == "http://127.0.0.1:18005"
    normal = native_config.service_specs("main", "audit", "ui", tmp_path, with_llm=False)
    ui = next(item for group in normal for item in group if item.name == "ui-api")
    assert ui.environment["AGENTGUARD_REVOCATION_URL"] == "http://127.0.0.1:18005"
    assert not ui.windows_service_name and ui.windows_config_path is None


def test_service_repr_does_not_include_environment():
    subject = native_config.Service("safe-name", "safe-module", 1, {"SECRET": "synthetic"})
    assert "synthetic" not in repr(subject) and "SECRET" not in repr(subject)


@pytest.mark.parametrize("mode", ["", "auto", "folder-only", "SCM", "current-user "])
def test_unknown_explicit_selection_is_fail_closed(mode, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_NATIVE_ISOLATION", mode)
    with pytest.raises(WindowsIsolationError, match="EXPLICIT_ISOLATION_MODE_INVALID"):
        isolation.select_mode()


def test_incomplete_scm_selection_never_returns_insecure_specs(tmp_path):
    with pytest.raises(ValueError, match="SCM isolation requires"):
        native_config.service_specs(
            "main", "audit", "ui", tmp_path, with_llm=False, isolation_mode="scm-virtual-account"
        )


def test_cloud_request_without_snapshot_is_refused_not_disabled(scoped, monkeypatch):
    root, services = scoped
    group = list(services.values())
    values = services["coordinator-agent"].environment
    values["AGENTGUARD_CLOUD_LLM_ENABLED"] = "true"
    with pytest.raises(WindowsIsolationError, match="SCM_CLOUD_PROFILE_SNAPSHOT_REQUIRED"):
        isolation.scope_service_groups([group], root, isolation.service_names("1234567890abcdef"))


def test_cloud_snapshot_paths_are_private_for_all_four_agents_and_bff(scoped):
    root, services = scoped
    services["coordinator-agent"].environment["AGENTGUARD_CLOUD_LLM_ENABLED"] = "true"
    groups = isolation.scope_service_groups(
        [list(services.values())],
        root,
        isolation.service_names("1234567890abcdef"),
        model_revision="f" * 64,
    )
    for item in groups[0]:
        if item.name in isolation.AGENT_ROLES | {"ui-api"}:
            assert item.environment["AGENTGUARD_MODEL_CONFIGURATIONS_PATH"] == str(
                root / "services" / item.name / "private/model-configurations.json"
            )
            assert not item.environment.get("AGENTGUARD_CLOUD_LLM_API_KEY")
    coordinator = next(item for item in groups[0] if item.name == "coordinator-agent")
    assert coordinator.environment["AGENTGUARD_CLOUD_LLM_ENABLED"] == "true"


def test_scoped_service_environment_accepts_expected_roles(scoped):
    root, services = scoped
    for role, item in services.items():
        isolation.validate_service_environment(role, item.environment, root)


@pytest.mark.parametrize(
    "role,field,value",
    [
        ("refund-agent", "AGENTGUARD_DATABASE_URL", "forbidden"),
        ("secure-gateway", "AGENTGUARD_AUDIT_DATABASE_URL", "forbidden"),
        ("ui-api", "AGENTGUARD_WORKFLOW_DATABASE_URL", "forbidden"),
        ("refund-agent", "PYTHONPATH", "forbidden"),
        ("refund-agent", "AGENTGUARD_CLOUD_LLM_API_KEY", "synthetic"),
        (
            "refund-agent",
            "AGENTGUARD_INTERNAL_AUTH_KEYS",
            '{"ui-api->revocation-authority":"' + "a" * 64 + '"}',
        ),
    ],
)
def test_inappropriate_role_credentials_rejected(scoped, role, field, value):
    root, services = scoped
    values = services[role].environment | {field: value}
    with pytest.raises(WindowsIsolationError):
        isolation.validate_service_environment(role, values, root)


def test_foreign_signing_key_reference_is_rejected(scoped):
    root, services = scoped
    values = services["refund-agent"].environment | {
        "AGENTGUARD_AGENT_PRIVATE_KEY_FILE": str(
            root / "principals/authorization/authorization.private"
        )
    }
    with pytest.raises(WindowsIsolationError):
        isolation.validate_service_environment("refund-agent", values, root)


def test_child_environment_does_not_inherit_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path / "Windows"))
    for name in ("PGPASSWORD", "HTTP_PROXY", "AGENTGUARD_CLOUD_LLM_API_KEY", "UNRELATED_API_KEY"):
        monkeypatch.setenv(name, "synthetic-credential")
    values = isolation.child_environment(
        {"AGENTGUARD_INTERNAL_AUTH_SERVICE_ID": "agent-refund"},
        tmp_path / "state",
        project_root=tmp_path,
    )
    assert "synthetic-credential" not in values.values()
    assert not any(name in values for name in ("PGPASSWORD", "HTTP_PROXY", "UNRELATED_API_KEY"))
    assert values["TEMP"] == str(tmp_path / "state/tmp")
    assert values["USERPROFILE"] == str(tmp_path / "state/home")


@pytest.mark.parametrize(
    "name",
    ["AgentGuard", "postgresql", "AgentGuardProbe_bad_x", "AgentGuardSvc_1234567890abcdef_/other"],
)
def test_non_owned_service_names_are_rejected(name):
    with pytest.raises(WindowsIsolationError, match="SCOPED_SERVICE_NAME_REQUIRED"):
        validate_service_name(name)


def test_production_services_cannot_be_deleted_by_probe_cleanup():
    subject = Scm.__new__(Scm)
    with pytest.raises(WindowsIsolationError, match="EPHEMERAL_SERVICE_REQUIRED"):
        subject.delete_ephemeral("AgentGuardSvc_1234567890abcdef_receipt-service", "command")


@pytest.mark.parametrize(
    "field,value",
    [
        ("binary", "foreign command"),
        ("account", "LocalSystem"),
        ("sid_type", 0),
        ("required_privileges", ["SeImpersonatePrivilege"]),
    ],
)
def test_scm_ownership_checks_account_command_and_privileges(field, value):
    name = "AgentGuardProbe_1234567890abcdef_probe-a"
    subject = Scm.__new__(Scm)
    configuration = {
        "binary": "owned",
        "account": "NT SERVICE\\" + name,
        "service_type": 16,
        "start_type": 3,
        "sid_type": 1,
        "required_privileges": ["SeChangeNotifyPrivilege"],
    }
    configuration[field] = value
    subject.configuration = lambda _: configuration
    with pytest.raises(WindowsIsolationError, match="SERVICE_OWNERSHIP_MISMATCH"):
        subject.assert_owned(name, "owned")


def test_private_acl_template_has_only_explicit_trusted_and_scoped_sids():
    value = acl_sddl(("S-1-5-80-1-2-3-4-5",))
    assert value.startswith("D:P")
    assert "S-1-5-80-1-2-3-4-5" in value
    assert "BA" not in value and "AU" not in value and "BU" not in value
    assert "S-1-5-18" in value and "S-1-5-32-544" in value


def test_probe_does_nothing_without_explicit_authorization(tmp_path, monkeypatch):
    from scripts import native_windows_probe

    monkeypatch.setattr(
        native_windows_probe, "require_admin", lambda: pytest.fail("must not query SCM")
    )
    with pytest.raises(WindowsIsolationError, match="EXPLICIT_SCOPED_SCM_PROBE_REQUIRED"):
        native_windows_probe.run_probe(tmp_path, verify_requested=False)
    assert not list(tmp_path.iterdir())


def test_guarded_launcher_never_falls_back_to_current_user(monkeypatch):
    from scripts import native_runtime

    args = Namespace(isolation_mode="scm-virtual-account", isolation_root=None)

    def fail(*_):
        raise WindowsIsolationError("EXPLICIT_ISOLATION_ROOT_REQUIRED")

    monkeypatch.setattr(native_runtime, "scm_runtime", fail)
    monkeypatch.setattr(native_runtime, "prerequisites", lambda: pytest.fail("insecure startup"))
    with pytest.raises(WindowsIsolationError, match="EXPLICIT_ISOLATION_ROOT_REQUIRED"):
        native_runtime.up(args)


@pytest.mark.parametrize("revision", ["x" * 64, "f" * 63, "F" * 64])
def test_bad_cloud_snapshot_revision_is_not_accepted(scoped, revision):
    root, services = scoped
    with pytest.raises(WindowsIsolationError, match="MODEL_SNAPSHOT_REVISION_INVALID"):
        isolation.scope_service_groups(
            [list(services.values())],
            root,
            isolation.service_names("1234567890abcdef"),
            model_revision=revision,
        )


@pytest.mark.parametrize("alteration", [None, "manifest", "config", "model", "identity", "count"])
def test_provisioning_receipt_binds_manifest_and_private_configs(tmp_path, monkeypatch, alteration):
    monkeypatch.setattr(isolation, "assert_private_acl", lambda *_args, **_kwargs: {})
    config = tmp_path / "config.dpapi"
    config.write_bytes(b"synthetic-encrypted-config")
    models = tmp_path / "model-configurations.json"
    models.write_bytes(b"synthetic-encrypted-models")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(b"synthetic-manifest")
    manifest = {
        "root": str(tmp_path),
        "deployment_id": "1234567890abcdef",
        "services": {
            "coordinator-agent": {"config_path": str(config), "private_root": str(tmp_path)}
        },
    }
    receipt = {
        "schema_version": 1,
        "deployment_id": manifest["deployment_id"],
        "services": len(isolation.ALL_ROLES),
        "main_runtime_started": False,
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "private_config_sha256": {
            "coordinator-agent": hashlib.sha256(config.read_bytes()).hexdigest()
        },
        "model_profile_sha256": {
            "coordinator-agent": hashlib.sha256(models.read_bytes()).hexdigest()
        },
    }
    if alteration == "manifest":
        manifest_path.write_bytes(b"changed-manifest")
    elif alteration == "config":
        config.write_bytes(b"changed-config")
    elif alteration == "model":
        models.write_bytes(b"changed-models")
    elif alteration == "identity":
        receipt["deployment_id"] = "0" * 16
    elif alteration == "count":
        receipt["services"] = 0
    (tmp_path / "provisioned.json").write_text(json.dumps(receipt), encoding="utf-8")
    if alteration is None:
        isolation.validate_provisioned_receipt(manifest)
    else:
        with pytest.raises(WindowsIsolationError, match="SCM_PROVISIONING_RECEIPT_MISMATCH"):
            isolation.validate_provisioned_receipt(manifest)


def test_missing_provisioning_receipt_refuses_start(tmp_path):
    with pytest.raises(WindowsIsolationError, match="SCM_PROVISIONING_RECEIPT_REQUIRED"):
        isolation.validate_provisioned_receipt({"root": str(tmp_path)})
