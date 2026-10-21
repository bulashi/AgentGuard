from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from backend.benchmark.runner import NativeBenchmarkRunner
from scripts.source_manifest import snapshot

from .test_native_benchmark_config import native_config


def cloud_report(*, run_id: str = "native-unit-test", **overrides: object) -> dict[str, object]:
    # These are parser-test fixtures, never evidence files or performance measurements.
    report: dict[str, object] = {
        "schema_version": "native-cloud-1.0",
        "run_id": run_id,
        "tested_at": datetime.now(UTC).isoformat(),
        "provider": "test-provider",
        "model_requested": "test-model",
        "mock_used": False,
        "fallback_used": False,
        "source_snapshot_sha256": snapshot()["snapshot_sha256"],
        "attempted_samples": 1,
        "samples": [
            {
                "sample_id": "cloud-1",
                "http_status": 200,
                "wall_ms": 12.5,
                "model_returned": "test-model",
                "passed": True,
                "response_sha256": "a" * 64,
            }
        ],
    }
    report.update(overrides)
    return report


def write_report(tmp_path: Path, report: dict[str, object]) -> Path:
    path = tmp_path / "cloudreport.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_cloud_report_accepts_only_current_run_actual_sample_contract(tmp_path: Path) -> None:
    config = native_config(tmp_path, cloud_report=write_report(tmp_path, cloud_report()))
    loaded = NativeBenchmarkRunner._read_cloud_report(config)
    assert loaded["status"] == "IMPORTED"
    assert loaded["samples"][0]["passed"] is True
    assert "response_sha256" in loaded["samples"][0]


def test_cloud_report_rejects_old_probe_schema(tmp_path: Path) -> None:
    report = cloud_report(schema_version="1.0", checks=[{"name": "official_api", "passed": True}])
    config = native_config(tmp_path, cloud_report=write_report(tmp_path, report))
    with pytest.raises(ValueError, match=r"native-cloud-1\.0"):
        NativeBenchmarkRunner._read_cloud_report(config)


def test_cloud_report_rejects_stale_or_incomplete_samples(tmp_path: Path) -> None:
    report = cloud_report(
        tested_at=(datetime.now(UTC) - timedelta(days=2)).isoformat(),
        attempted_samples=2,
    )
    config = native_config(tmp_path, cloud_report=write_report(tmp_path, report))
    with pytest.raises(ValueError, match="last 24 hours"):
        NativeBenchmarkRunner._read_cloud_report(config)


def test_cloud_report_rejects_secret_bearing_fields(tmp_path: Path) -> None:
    report = cloud_report(api_key="must-not-be-imported")
    config = native_config(tmp_path, cloud_report=write_report(tmp_path, report))
    with pytest.raises(ValueError, match="unsupported or sensitive"):
        NativeBenchmarkRunner._read_cloud_report(config)


def test_redaction_removes_dsn_token_and_private_key_values() -> None:
    runner = object.__new__(NativeBenchmarkRunner)
    runner._secrets = ["postgres-secret", "bearer-secret", "private-secret"]
    redacted = runner._redact(
        {
            "database_url": "postgresql://bench:postgres-secret@127.0.0.1:25432/native_bench_main",
            "token": "bearer-secret",
            "private_key": "private-secret",
            "safe": "measured",
        }
    )
    assert redacted["database_url"] == "REDACTED"
    assert redacted["token"] == "REDACTED"
    assert redacted["private_key"] == "REDACTED"
    assert redacted["safe"] == "measured"


@pytest.mark.parametrize(
    "overrides",
    [
        {"run_id": "native-other-run"},
        {"tested_at": datetime.now().isoformat()},
        {"tested_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
        {"mock_used": True},
        {"fallback_used": True},
        {"attempted_samples": 2},
        {"samples": []},
        {"model_requested": None},
        {"generation_parameters": {"api_key": "unsafe"}},
    ],
)
def test_report_rejects_unverifiable_inputs(tmp_path: Path, overrides: dict[str, object]) -> None:
    path = write_report(tmp_path, cloud_report(**overrides))
    config = native_config(tmp_path, cloud_report=path)
    with pytest.raises(ValueError):
        NativeBenchmarkRunner._read_cloud_report(config)


@pytest.mark.parametrize(
    "overrides",
    [
        {"wall_ms": float("nan")},
        {"wall_ms": float("inf")},
        {"wall_ms": -1},
        {"wall_ms": True},
        {"passed": "true"},
        {"http_status": True},
        {"http_status": 401},
        {"model_returned": None},
        {"input_tokens": -1},
        {"request_length_bytes": 1.5},
        {"response_sha256": "not-a-digest"},
        {"api_key": "unsafe"},
    ],
)
def test_report_rejects_invalid_samples(tmp_path: Path, overrides: dict[str, object]) -> None:
    report = cloud_report()
    report["samples"][0].update(overrides)
    config = native_config(tmp_path, cloud_report=write_report(tmp_path, report))
    with pytest.raises(ValueError):
        NativeBenchmarkRunner._read_cloud_report(config)


def test_report_preserves_failed_attempts_without_substituting_a_model(tmp_path: Path) -> None:
    report = cloud_report()
    report["samples"].append(
        {
            "sample_id": "failed-2",
            "http_status": 429,
            "wall_ms": 5.5,
            "passed": False,
            "failure_type": "rate_limited",
        }
    )
    report["attempted_samples"] = 2
    config = native_config(tmp_path, cloud_report=write_report(tmp_path, report))
    loaded = NativeBenchmarkRunner._read_cloud_report(config)
    runner = object.__new__(NativeBenchmarkRunner)
    runner._cloud = loaded
    recorded = []
    runner._record_structured_sample = lambda *args: recorded.append(args)
    result = runner._measure_model_inference()
    assert result["passed"] is False
    assert result["sample_count"] == 2
    assert result["failed_samples"] == 1
    assert result["model"] == "test-model"
    assert len(recorded) == 2
    assert recorded[1][2] is False


def test_report_rejects_duplicate_fields(tmp_path: Path) -> None:
    path = tmp_path / "cloudreport.json"
    path.write_text(
        '{"schema_version":"native-cloud-1.0","schema_version":"native-cloud-1.0"}',
        encoding="utf-8",
    )
    config = native_config(tmp_path, cloud_report=path)
    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        NativeBenchmarkRunner._read_cloud_report(config)


def test_missing_cloud_report_has_no_fabricated_timing(tmp_path: Path) -> None:
    runner = object.__new__(NativeBenchmarkRunner)
    runner._cloud = NativeBenchmarkRunner._read_cloud_report(native_config(tmp_path))
    result = runner._measure_model_inference()
    assert result["status"] == "NOT_MEASURED"
    assert result["passed"] is False
    assert result["latency_ms"] is None
    assert result["sample_count"] == 0
