from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from backend.config import model_profiles
from scripts import native_windows_profiles as profiles
from scripts.native_windows_api import WindowsIsolationError, token_identity


class ProfileTestCipher:
    def __init__(self):
        self.records = {}

    def encrypt(self, value):
        identifier = "opaque-test-record-" + str(len(self.records))
        self.records[identifier] = value
        return identifier

    def decrypt(self, value):
        if value not in self.records:
            raise model_profiles.ModelConfigurationError("MODEL_CREDENTIAL_UNAVAILABLE", "test")
        return self.records[value]


@pytest.fixture
def snapshot():
    return {
        "schema_version": 1,
        "source_sha256": "a" * 64,
        "default_id": "primary",
        "profiles": {
            "primary": {
                "name": "Synthetic profile",
                "provider_id": "probe",
                "base_url": "https://scm-probe.invalid",
                "api_mode": "chat_completions",
                "model": "probe-deterministic",
                "timeout_seconds": 5,
                "enabled": True,
                "api_key": "synthetic-profile-secret",
            },
            "secondary": {
                "name": "Synthetic secondary",
                "provider_id": "probe",
                "base_url": "https://scm-probe.invalid",
                "api_mode": "chat_completions",
                "model": "probe-deterministic",
                "timeout_seconds": 5,
                "enabled": True,
                "api_key": "synthetic-secondary-secret",
            },
        },
    }


@pytest.fixture
def staged(tmp_path, monkeypatch, snapshot):
    private = tmp_path / "private"
    private.mkdir()
    record = {
        "role": "coordinator-agent",
        "service_name": "AgentGuardProbe_1234567890abcdef_probe-a",
        "private_root": str(private),
        "sid": token_identity()["user_sid"] if os.name == "nt" else "S-1-0-0",
    }
    cipher = ProfileTestCipher()
    monkeypatch.setattr(profiles, "require_service_identity", lambda _: {"user_sid": record["sid"]})
    monkeypatch.setattr(model_profiles, "WindowsCredentialCipher", lambda: cipher)
    monkeypatch.setattr(
        model_profiles, "require_public_resolution", lambda _: pytest.fail("network")
    )
    digest = profiles.stage_model_snapshot(snapshot, record)
    config = {
        "environment": {
            "AGENTGUARD_MODEL_CONFIGURATIONS_PATH": str(private / "model-configurations.json"),
        },
        "model_snapshot": snapshot,
        "model_staged_sha256": digest,
    }
    return record, config, cipher


def test_staging_uses_existing_backend_schema_without_plaintext_key(staged):
    record, config, cipher = staged
    path = Path(record["private_root"]) / "model-configurations.json"
    content = path.read_bytes()
    document = json.loads(content)
    assert document["schema_version"] == "model-profiles-v1"
    assert document["default_id"] == "primary"
    assert b"synthetic-profile-secret" not in content
    assert "api_key" not in document["items"]["primary"]
    assert hashlib.sha256(content).hexdigest() == config["model_staged_sha256"]
    assert cipher.decrypt(document["items"]["primary"]["credential"]) == "synthetic-profile-secret"


def test_activated_snapshot_delivers_same_provider_and_key(staged, monkeypatch):
    record, config, _ = staged
    original = model_profiles.ModelProfileStore
    monkeypatch.setattr(model_profiles, "ModelProfileStore", original)
    profiles.activate_model_snapshot(record, config)
    path = Path(record["private_root"]) / "model-configurations.json"
    profile, key = model_profiles.ModelProfileStore(path).configured()
    assert profile["provider_id"] == "probe" and profile["model"] == "probe-deterministic"
    assert key == "synthetic-profile-secret"


@pytest.mark.parametrize("operation", ["select", "save", "delete"])
def test_bff_changes_require_reprovision_not_silent_agent_divergence(
    staged, monkeypatch, operation
):
    record, config, _ = staged
    original = model_profiles.ModelProfileStore
    monkeypatch.setattr(model_profiles, "ModelProfileStore", original)
    profiles.activate_model_snapshot(record, config)
    path = Path(record["private_root"]) / "model-configurations.json"
    before = path.read_bytes()
    store = model_profiles.ModelProfileStore(path)
    with pytest.raises(model_profiles.ModelConfigurationError) as raised:
        if operation == "select":
            store.select("primary")
        elif operation == "save":
            store.save(
                "another",
                model_profiles.ProfileInput.model_validate(
                    config["model_snapshot"]["profiles"]["primary"]
                ),
            )
        else:
            store.delete("secondary")
    assert raised.value.reason_code == "MODEL_SNAPSHOT_REPROVISION_REQUIRED"
    assert raised.value.status_code == 409
    assert path.read_bytes() == before


def test_snapshot_tamper_after_activation_is_fail_closed(staged, monkeypatch):
    record, config, _ = staged
    original = model_profiles.ModelProfileStore
    monkeypatch.setattr(model_profiles, "ModelProfileStore", original)
    profiles.activate_model_snapshot(record, config)
    path = Path(record["private_root"]) / "model-configurations.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(model_profiles.ModelConfigurationError) as raised:
        model_profiles.ModelProfileStore(path).configured()
    assert raised.value.reason_code == "MODEL_SNAPSHOT_REVISION_MISMATCH"
    assert raised.value.status_code == 503


@pytest.mark.parametrize(
    "alteration", ["default", "revision", "endpoint", "missing-key", "extra", "role", "path"]
)
def test_invalid_or_inappropriately_scoped_snapshot_is_rejected(staged, alteration):
    record, original, _ = staged
    config = copy.deepcopy(original)
    if alteration == "default":
        config["model_snapshot"]["default_id"] = []
    elif alteration == "revision":
        config["model_staged_sha256"] = "0" * 64
    elif alteration == "endpoint":
        config["model_snapshot"]["profiles"]["primary"]["base_url"] = "http://localhost"
    elif alteration == "missing-key":
        config["model_snapshot"]["profiles"]["primary"]["api_key"] = ""
    elif alteration == "extra":
        config["model_snapshot"]["unexpected"] = True
    elif alteration == "role":
        record = record | {"role": "secure-gateway"}
    else:
        config["environment"]["AGENTGUARD_MODEL_CONFIGURATIONS_PATH"] = "foreign"
    with pytest.raises(WindowsIsolationError):
        profiles.activate_model_snapshot(record, config)


def test_staging_refuses_existing_snapshot_without_overwrite(staged):
    record, config, _ = staged
    path = Path(record["private_root"]) / "model-configurations.json"
    before = path.read_bytes()
    with pytest.raises(WindowsIsolationError, match="MODEL_SNAPSHOT_ALREADY_STAGED"):
        profiles.stage_model_snapshot(config["model_snapshot"], record)
    assert path.read_bytes() == before


def test_export_is_read_only_and_keeps_secret_in_memory(staged):
    record, _, _ = staged
    path = Path(record["private_root"]) / "model-configurations.json"
    before = path.read_bytes()
    result = profiles.export_model_snapshot(path)
    assert result["profiles"]["primary"]["api_key"] == "synthetic-profile-secret"
    assert result["source_sha256"] == hashlib.sha256(before).hexdigest()
    assert path.read_bytes() == before


def test_export_checks_empty_and_inconsistent_legacy_configuration(tmp_path, monkeypatch):
    path = tmp_path / "missing-models.json"
    assert profiles.export_model_snapshot(path)["profiles"] == {}
    assert not path.exists()
    monkeypatch.setattr(
        model_profiles.ModelProfileStore,
        "_read",
        lambda _: {
            "schema_version": "model-profiles-v1",
            "default_id": "missing",
            "items": {},
        },
    )
    with pytest.raises(WindowsIsolationError, match="MODEL_SNAPSHOT_DEFAULT_INVALID"):
        profiles.export_model_snapshot(path)


@pytest.mark.parametrize("role", sorted(profiles.MODEL_ROLES))
def test_all_four_agents_and_bff_can_stage_separate_profiles(staged, tmp_path, role):
    record, config, _ = staged
    private = tmp_path / role / "private"
    private.mkdir(parents=True)
    digest = profiles.stage_model_snapshot(
        config["model_snapshot"], record | {"role": role, "private_root": str(private)}
    )
    assert digest and (private / "model-configurations.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="actual Windows credential DPAPI is required")
def test_backend_provider_cipher_works_under_current_user_without_network():
    cipher = model_profiles.WindowsCredentialCipher()
    protected = cipher.encrypt("synthetic-provider-roundtrip")
    assert cipher.decrypt(protected) == "synthetic-provider-roundtrip"
    assert "synthetic-provider-roundtrip" not in protected
