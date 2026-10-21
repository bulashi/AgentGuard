"""Stage provider secrets under each SCM user's DPAPI; enforce one immutable revision."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.native_windows_api import WindowsIsolationError, no_links, require_service_identity
from scripts.native_windows_dpapi import atomic_private_write

MODEL_ROLES = {"coordinator-agent", "knowledge-agent", "case-agent", "refund-agent", "ui-api"}


def export_model_snapshot(path: Path) -> dict:
    """Read/decrypt only, using the installer's user token. Never contacts a provider."""
    from backend.config.model_profiles import ModelProfileStore

    path = no_links(path)
    source = path.read_bytes() if path.is_file() else None
    store = ModelProfileStore(path)
    document = store._read()
    profiles = {}
    for identifier, row in document["items"].items():
        key = store.cipher.decrypt(row["credential"]) if row["credential"] else ""
        profiles[identifier] = {name: value for name, value in row.items() if name != "credential"}
        profiles[identifier]["api_key"] = key
    if (path.read_bytes() if path.is_file() else None) != source:
        raise WindowsIsolationError("MODEL_CONFIGURATION_CHANGED_DURING_EXPORT")
    snapshot = {
        "schema_version": 1,
        "source_sha256": hashlib.sha256(source or b"").hexdigest(),
        "default_id": document["default_id"],
        "profiles": profiles,
    }
    validate_model_snapshot(snapshot)
    return snapshot


def validate_model_snapshot(snapshot: dict) -> None:
    from backend.config.model_profiles import PROFILE_ID, ProfileInput

    if (
        not isinstance(snapshot, dict)
        or set(snapshot) != {"schema_version", "source_sha256", "default_id", "profiles"}
        or snapshot["schema_version"] != 1
        or not isinstance(snapshot["source_sha256"], str)
        or len(snapshot["source_sha256"]) != 64
        or any(char not in "0123456789abcdef" for char in snapshot["source_sha256"])
        or not isinstance(snapshot["profiles"], dict)
        or len(snapshot["profiles"]) > 32
    ):
        raise WindowsIsolationError("MODEL_SNAPSHOT_INVALID")
    profiles = snapshot["profiles"]
    if snapshot["default_id"] is not None and (
        not isinstance(snapshot["default_id"], str)
        or not PROFILE_ID.fullmatch(snapshot["default_id"])
        or snapshot["default_id"] not in profiles
    ):
        raise WindowsIsolationError("MODEL_SNAPSHOT_DEFAULT_INVALID")
    for identifier, row in profiles.items():
        if not isinstance(identifier, str) or not PROFILE_ID.fullmatch(identifier):
            raise WindowsIsolationError("MODEL_SNAPSHOT_IDENTIFIER_INVALID")
        if not isinstance(row, dict) or set(row) != {
            "name",
            "provider_id",
            "base_url",
            "api_mode",
            "model",
            "timeout_seconds",
            "enabled",
            "api_key",
        }:
            raise WindowsIsolationError("MODEL_SNAPSHOT_PROFILE_INVALID")
        try:
            request = ProfileInput.model_validate(row)
        except ValueError:
            raise WindowsIsolationError("MODEL_SNAPSHOT_PROFILE_INVALID") from None
        if request.enabled and not request.api_key:
            raise WindowsIsolationError("MODEL_SNAPSHOT_ENABLED_CREDENTIAL_MISSING")


def stage_model_snapshot(snapshot: dict, record: dict) -> str:
    from backend.config.model_profiles import WindowsCredentialCipher

    require_service_identity(record["service_name"])
    if record["role"] not in MODEL_ROLES:
        raise WindowsIsolationError("MODEL_SNAPSHOT_ROLE_REJECTED")
    validate_model_snapshot(snapshot)
    path = Path(record["private_root"]) / "model-configurations.json"
    if path.exists():
        raise WindowsIsolationError("MODEL_SNAPSHOT_ALREADY_STAGED")
    cipher, profiles = WindowsCredentialCipher(), {}
    for identifier, row in snapshot["profiles"].items():
        credential = cipher.encrypt(row["api_key"]) if row["api_key"] else ""
        if row["api_key"] and cipher.decrypt(credential) != row["api_key"]:
            raise WindowsIsolationError("MODEL_SNAPSHOT_DPAPI_ROUNDTRIP_MISMATCH")
        profiles[identifier] = {name: value for name, value in row.items() if name != "api_key"}
        profiles[identifier]["credential"] = credential
    document = {
        "schema_version": "model-profiles-v1",
        "default_id": snapshot["default_id"],
        "items": profiles,
    }
    content = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    atomic_private_write(path, content, expected=None, writers=(record["sid"],))
    return hashlib.sha256(content).hexdigest()


def activate_model_snapshot(record: dict, config: dict) -> None:
    """Host-local adapter: backend files remain unchanged; changes require all-role reprovision."""
    import backend.config.model_profiles as profiles_module

    if record["role"] not in MODEL_ROLES:
        if "model_snapshot" in config:
            raise WindowsIsolationError("MODEL_SNAPSHOT_ROLE_REJECTED")
        return
    snapshot = config.get("model_snapshot")
    validate_model_snapshot(snapshot)
    path = no_links(Path(record["private_root"]) / "model-configurations.json")
    if config["environment"].get("AGENTGUARD_MODEL_CONFIGURATIONS_PATH") != str(path):
        raise WindowsIsolationError("MODEL_SNAPSHOT_ROLE_PATH_MISMATCH")
    expected_hash = config.get("model_staged_sha256")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
        raise WindowsIsolationError("MODEL_SNAPSHOT_STAGED_REVISION_MISMATCH")
    original = profiles_module.ModelProfileStore

    class StagedModelProfileStore(original):
        def _read(self) -> dict:
            if self.path != path or hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                raise profiles_module.ModelConfigurationError(
                    "MODEL_SNAPSHOT_REVISION_MISMATCH",
                    "MODEL_SNAPSHOT_REVISION_MISMATCH: restart with a newly provisioned revision",
                    status_code=503,
                )
            return super()._read()

        def _write(self, _document: dict) -> None:
            raise profiles_module.ModelConfigurationError(
                "MODEL_SNAPSHOT_REPROVISION_REQUIRED",
                "MODEL_SNAPSHOT_REPROVISION_REQUIRED: configure and reprovision all SCM identities",
                status_code=409,
            )

    profiles_module.ModelProfileStore = StagedModelProfileStore
    store = StagedModelProfileStore(path)
    if snapshot["default_id"] is not None:
        configured = store.configured()
        if configured is None or configured[0]["id"] != snapshot["default_id"]:
            raise WindowsIsolationError("MODEL_SNAPSHOT_DEFAULT_MISMATCH")
        original_row = snapshot["profiles"][snapshot["default_id"]]
        if original_row["enabled"] and configured[1] != original_row["api_key"]:
            raise WindowsIsolationError("MODEL_SNAPSHOT_CREDENTIAL_MISMATCH")
