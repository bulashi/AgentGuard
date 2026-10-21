"""Offline lifecycle checks; no installed credentials, services or cloud calls are used."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.config.model_profiles import ModelProfileStore, WindowsCredentialCipher

REPOSITORY = Path(__file__).resolve().parents[2]


@pytest.fixture
def runtime(tmp_path: Path) -> dict:
    # Load only the tested functions: importing the CLI reads installed config/private keys.
    source = REPOSITORY / "scripts/verify_native_backend.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    names = {
        "stage_cloud_model_profile",
        "cleanup_cloud_model_profile",
        "stop_services",
        "stack",
        "cloud_agent_guard_environment",
    }
    functions = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    root = tmp_path / "project"
    evidence = root / "artifacts/native-acceptance/test-profile-run"
    evidence.mkdir(parents=True)
    (root / ".native").mkdir()
    namespace = {
        "Path": Path,
        "hashlib": hashlib,
        "subprocess": subprocess,
        "ROOT": root,
        "EVIDENCE": evidence,
        "PREFIX": "backend-test-profile-run",
        "REPORT": {},
        "PROCESSES": [],
        "create_database": lambda *_args: pytest.fail("must reject before allocating databases"),
    }

    def save(name: str, value: object) -> Path:
        destination = evidence / (namespace["PREFIX"] + "-" + name)
        destination.write_text(json.dumps(value), encoding="utf-8")
        return destination

    namespace["save"] = save
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)
    profile = {
        "schema_version": "model-profiles-v1",
        "default_id": "primary",
        "items": {
            "primary": {
                "name": "Synthetic isolated profile",
                "provider_id": "deepseek",
                "base_url": "https://api.deepseek.com",
                "api_mode": "chat_completions",
                "model": "deepseek-flash",
                "timeout_seconds": 120,
                "enabled": True,
                "credential": "opaque-synthetic-record",
            }
        },
    }
    installed = root / ".native/model-configurations.json"
    installed.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    namespace["installed"] = installed
    namespace["profile"] = profile
    return namespace


def public_record(runtime: dict) -> dict:
    path = runtime["EVIDENCE"] / (runtime["PREFIX"] + "-cloud-model-profile-public.json")
    return json.loads(path.read_text(encoding="utf-8"))


def test_copy_preserves_configured_bytes_and_public_identity_without_credentials(runtime):
    before = runtime["installed"].read_bytes()
    path = runtime["stage_cloud_model_profile"]()
    record = public_record(runtime)

    assert path.is_relative_to(runtime["EVIDENCE"])
    assert path.read_bytes() == before == runtime["installed"].read_bytes()
    assert record["source_sha256"] == record["runtime_sha256"] == hashlib.sha256(before).hexdigest()
    assert record["copy_byte_identical"] is True
    assert record["public_profiles"] == ModelProfileStore(runtime["installed"]).public()["items"]
    assert record["public_profiles"][0]["provider_id"] == "deepseek"
    assert record["public_profiles"][0]["model"] == "deepseek-flash"
    assert "opaque-synthetic-record" not in json.dumps(record)
    assert "credential" not in record["public_profiles"][0]
    assert record["cleanup_status"] == "pending"


def test_stop_services_removes_copy_locks_and_temporary_files_but_retains_public_evidence(runtime):
    path = runtime["stage_cloud_model_profile"]()
    path.with_suffix(".lock").write_bytes(b"\0")
    path.with_suffix(".tmp").write_bytes(path.read_bytes())
    events = []

    class Process:
        stopped = False

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            assert path.is_file()
            events.append("terminate")

        def wait(self, *, timeout):
            assert path.is_file() and timeout == 10
            self.stopped = True
            events.append("wait")

    def join(*, timeout):
        assert path.is_file() and timeout == 5
        events.append("join")

    runtime["PROCESSES"].append({"process": Process(), "thread": SimpleNamespace(join=join)})
    runtime["stop_services"]()

    assert events == ["terminate", "wait", "join"]
    assert not path.parent.exists()
    assert runtime["installed"].is_file()
    assert public_record(runtime)["cleanup_status"] == "removed"
    assert public_record(runtime)["source_profile_unchanged"] is True
    runtime["stop_services"]()  # Finalization after the explicit cloud stop is idempotent.


def test_cleanup_refuses_live_services(runtime):
    path = runtime["stage_cloud_model_profile"]()
    runtime["PROCESSES"].append({"process": object()})
    with pytest.raises(RuntimeError, match="before test services stop"):
        runtime["cleanup_cloud_model_profile"]()
    assert path.is_file()


def test_cleanup_refuses_an_unowned_directory(runtime):
    path = runtime["stage_cloud_model_profile"]()
    runtime["REPORT"]["cloud_model_profile_runtime"]["runtime_directory"] = str(
        runtime["ROOT"] / ".native"
    )
    with pytest.raises(RuntimeError, match="outside its owned runtime"):
        runtime["cleanup_cloud_model_profile"]()
    assert runtime["installed"].is_file() and path.is_file()


def test_staging_refuses_to_reuse_an_existing_private_runtime(runtime):
    directory = runtime["EVIDENCE"] / (runtime["PREFIX"] + "-private-runtime")
    directory.mkdir()
    sentinel = directory / "previous-owner"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        runtime["stage_cloud_model_profile"]()
    runtime["stop_services"]()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_unavailable_model_is_not_replaced_and_failed_staging_is_cleaned(runtime):
    runtime["profile"]["items"]["primary"]["model"] = "different-model"
    runtime["installed"].write_text(json.dumps(runtime["profile"]), encoding="utf-8")
    with pytest.raises(RuntimeError, match="default DeepSeek Flash profile is unavailable"):
        runtime["stage_cloud_model_profile"]()
    assert public_record(runtime)["public_profiles"][0]["model"] == "different-model"
    path = Path(runtime["REPORT"]["cloud_model_profile_runtime"]["runtime_profile_path"])
    runtime["stop_services"]()
    assert not path.parent.exists()


def test_stack_rejects_installed_profile_before_database_or_service_creation(runtime):
    with pytest.raises(RuntimeError, match="evidence-owned model profile copy"):
        runtime["stack"]("cloud", model_configurations_path=runtime["installed"])


@pytest.mark.parametrize(
    "service", ["coordinator-agent", "knowledge-agent", "case-agent", "refund-agent"]
)
def test_only_explicit_cloud_model_agents_receive_the_configured_endpoint(runtime, service):
    path = runtime["stage_cloud_model_profile"]()
    guard = runtime["cloud_agent_guard_environment"]
    assert guard(service, path) == {}
    assert guard(service, path, explicit_cloud=True) == {
        "AGENTGUARD_BACKEND_ACCEPTANCE_MODE": "cloud",
        "AGENTGUARD_BACKEND_CLOUD_SERVICE": service,
        "AGENTGUARD_BACKEND_CLOUD_HOST": "api.deepseek.com",
        "AGENTGUARD_BACKEND_CLOUD_PORT": "443",
    }


@pytest.mark.parametrize("service", ["ui-api", "gateway", "refund-tool", "audit-worker"])
def test_explicit_cloud_does_not_grant_external_network_to_other_services(runtime, service):
    path = runtime["stage_cloud_model_profile"]()
    assert runtime["cloud_agent_guard_environment"](service, path, explicit_cloud=True) == {}


def test_cloud_endpoint_permission_rejects_installed_profile_and_unconfigured_stack(runtime):
    with pytest.raises(RuntimeError, match="evidence-owned model profile"):
        runtime["cloud_agent_guard_environment"](
            "coordinator-agent",
            runtime["installed"],
            explicit_cloud=True,
        )
    with pytest.raises(RuntimeError, match="authenticated profile stack"):
        runtime["stack"]("cloud", allow_cloud_endpoint=True)


@pytest.mark.skipif(os.name != "nt", reason="actual current-user Windows DPAPI is required")
def test_actual_dpapi_copy_locks_and_decrypts_inside_the_native_write_guard(runtime):
    synthetic_key = "synthetic-no-network-provider-key"
    runtime["profile"]["items"]["primary"]["credential"] = WindowsCredentialCipher().encrypt(
        synthetic_key
    )
    runtime["installed"].write_text(json.dumps(runtime["profile"]), encoding="utf-8")
    path = runtime["stage_cloud_model_profile"]()
    script = """
import sys
from pathlib import Path
from backend.config.model_profiles import ModelProfileStore

store = ModelProfileStore(Path(sys.argv[1]))
with store.lock():
    profile, key = store.configured()
    assert profile['provider_id'] == 'deepseek'
    assert profile['model'] == 'deepseek-flash'
    assert key == 'synthetic-no-network-provider-key'
try:
    Path(sys.argv[2]).with_suffix('.lock').open('a+b')
except PermissionError:
    pass
else:
    raise AssertionError('installed profile lock must remain unwritable')
print('isolated DPAPI and lock: PASS')
"""
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("AGENTGUARD_")
    }
    environment.update(
        {
            "PYTHONPATH": os.pathsep.join(
                (str(REPOSITORY / "scripts/native_test_guard"), str(REPOSITORY))
            ),
            "PYTHONDONTWRITEBYTECODE": "1",
            "AGENTGUARD_BACKEND_GUARD_ENABLED": "1",
            "AGENTGUARD_BACKEND_PROJECT_ROOT": str(runtime["ROOT"]),
            "AGENTGUARD_BACKEND_EVIDENCE_ROOT": str(runtime["EVIDENCE"]),
            "AGENTGUARD_BACKEND_BLOCKED_PORTS": "8088,8090",
            "AGENTGUARD_BACKEND_ALLOWED_DATABASES": "",
        }
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", script, str(path), str(runtime["installed"])],
        env=environment,
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "isolated DPAPI and lock: PASS"
    assert path.with_suffix(".lock").is_file()
    assert not runtime["installed"].with_suffix(".lock").exists()
    runtime["stop_services"]()
    assert not path.parent.exists()
    assert public_record(runtime)["source_profile_unchanged"] is True
