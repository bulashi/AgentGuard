from __future__ import annotations

from pathlib import Path

import pytest

from backend.benchmark.internal_security import flatten_keys
from backend.benchmark.runner import NativeBenchmarkConfig
from scripts.native_security import generate_keys


def native_config(tmp_path: Path, **overrides: object) -> NativeBenchmarkConfig:
    key_root = tmp_path / "keys"
    key_root.mkdir()
    for name in ("agent-refund.private", "agent-case.private"):
        (key_root / name).write_text("a" * 64, encoding="ascii")
    values: dict[str, object] = {
        "run_id": "native-unit-test",
        "artifact_root": tmp_path / "artifacts",
        "main_database_url": "postgresql://bench:secret@127.0.0.1:25432/native_bench_main",
        "audit_database_url": "postgresql://bench:secret@127.0.0.1:25433/native_bench_audit",
        "benchmark_database_url": "postgresql://bench:secret@127.0.0.1:25434/native_bench_baseline",
        "private_key_root": key_root,
        "authority_url": "http://127.0.0.1:28401",
        "coordinator_delegation_url": "http://127.0.0.1:28402",
        "case_delegation_url": "http://127.0.0.1:28403",
        "gateway_url": "http://127.0.0.1:28404",
        "registry_url": "http://127.0.0.1:28405",
        "revocation_url": "http://127.0.0.1:28406",
        "coordinator_agent_url": "",
        "live_refund_agent_url": "",
        "audit_service_url": "http://127.0.0.1:28407",
        "checkpoint_service_url": "http://127.0.0.1:28408",
        "baseline_static_url": "http://127.0.0.1:28409",
        "baseline_rbac_url": "http://127.0.0.1:28410",
        "benchmark_admin_token": "admin-secret",
        "benchmark_static_token": "static-secret",
        "benchmark_rbac_token": "rbac-secret",
        "allow_isolated": True,
        "internal_auth_required": True,
        "internal_auth_keys": flatten_keys(generate_keys()),
    }
    values.update(overrides)
    return NativeBenchmarkConfig(**values)  # type: ignore[arg-type]


def test_native_configuration_requires_explicit_opt_in(tmp_path: Path) -> None:
    config = native_config(tmp_path, allow_isolated=False)
    with pytest.raises(ValueError, match="allow-isolated"):
        config.validate()


def test_native_configuration_rejects_project_native_postgres_port(tmp_path: Path) -> None:
    config = native_config(
        tmp_path,
        main_database_url="postgresql://bench:secret@127.0.0.1:15432/native_bench_main",
    )
    with pytest.raises(ValueError, match="DSNs"):
        config.validate()


def test_native_configuration_rejects_default_service_origin(tmp_path: Path) -> None:
    config = native_config(tmp_path, gateway_url="http://127.0.0.1:18003")
    with pytest.raises(ValueError, match="service URLs"):
        config.validate()


def test_native_configuration_uses_distinct_database_names_and_ports(tmp_path: Path) -> None:
    config = native_config(tmp_path)
    config.validate()
    assert len(config.service_urls()) == 10
    assert len({value.rsplit(":", 1)[-1] for value in config.service_urls().values()}) == 10


def test_native_repr_does_not_include_configuration_secrets(tmp_path: Path) -> None:
    config = native_config(tmp_path)
    rendered = repr(config)
    assert "secret" not in rendered
    assert "admin-secret" not in rendered
    assert "REDACTED" in rendered
    assert config.internal_auth_keys not in rendered


def test_native_configuration_rejects_authentication_downgrade(tmp_path: Path) -> None:
    config = native_config(tmp_path, internal_auth_required=False)
    with pytest.raises(ValueError, match="must not disable"):
        config.validate()


def test_native_configuration_requires_all_native_edge_secrets(tmp_path: Path) -> None:
    config = native_config(tmp_path, internal_auth_keys="{}")
    with pytest.raises(ValueError, match="complete distinct native edge"):
        config.validate()


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://bench:secret@127.0.0.1:25432/agentguard",
        "postgresql://bench:secret@main-db:25432/native_bench_main",
        "postgresql://bench:secret@192.168.1.2:25432/native_bench_main",
        "postgresql://bench:secret@127.0.0.1/native_bench_main",
        "postgresql://bench:secret@127.0.0.1:5432/native_bench_main",
        "postgresql://bench:secret@127.0.0.1:0/native_bench_main",
        "postgresql://bench@127.0.0.1:25432/native_bench_main",
        "postgresql://bench:secret@127.0.0.1:25432/native_bench_main?host=production",
        "postgresql://bench:secret@127.0.0.1:25432/native_bench_main#fragment",
    ],
)
def test_native_rejects_unsafe_dsns_before_client_creation(tmp_path: Path, dsn: str) -> None:
    config = native_config(tmp_path, main_database_url=dsn)
    with pytest.raises(ValueError):
        config.validate()
    assert not config.artifact_root.exists()


@pytest.mark.parametrize(
    "url",
    [
        "https://api.deepseek.com:28404",
        "http://gateway:28404",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://user:secret@127.0.0.1:28404",
        "http://127.0.0.1:28404/gateway",
        "http://127.0.0.1:28404?key=secret",
        "http://127.0.0.1:28404#fragment",
        "http://127.0.0.1:11434",
    ],
)
def test_native_rejects_external_default_or_credential_urls(tmp_path: Path, url: str) -> None:
    config = native_config(tmp_path, gateway_url=url)
    with pytest.raises(ValueError):
        config.validate()


@pytest.mark.parametrize("run_id", ["phase17-old", "native-../old", "native-a/b", "native-a:1"])
def test_native_rejects_unsafe_or_historical_run_ids(tmp_path: Path, run_id: str) -> None:
    config = native_config(tmp_path, run_id=run_id)
    with pytest.raises(ValueError, match="run_id"):
        config.validate()


def test_native_requires_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("backend.benchmark.runner.platform.system", lambda: "Linux")
    config = native_config(tmp_path)
    with pytest.raises(ValueError, match="Windows"):
        config.validate()


def test_native_rejects_shared_database_or_service_port(tmp_path: Path) -> None:
    config = native_config(
        tmp_path,
        audit_database_url="postgresql://bench:secret@127.0.0.1:25433/native_bench_main",
    )
    with pytest.raises(ValueError, match="distinct isolated names"):
        config.validate()


def test_native_rejects_existing_evidence_output(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[3]
    config = native_config(tmp_path, artifact_root=project / "evidence" / "native-output")
    with pytest.raises(ValueError, match="historical"):
        config.validate()


def test_native_rejects_model_and_agent_endpoint_even_when_loopback(tmp_path: Path) -> None:
    config = native_config(tmp_path, coordinator_agent_url="http://127.0.0.1:28411")
    with pytest.raises(ValueError, match="agent runtime"):
        config.validate()
