from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

import backend.benchmark.provenance as provenance_module
from backend.benchmark.provenance import source_provenance
from backend.config.settings import Settings
from backend.ui_api.service import UiService
from backend.ui_api.store import UiReadStore
from scripts.source_manifest import snapshot


@pytest.fixture
def source_root(tmp_path: Path) -> Path:
    (tmp_path / "frontend").mkdir()
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "example.py").write_text("value = 1\n", encoding="utf-8")
    return tmp_path


def _summary(digest: str) -> dict:
    return {
        "status": "VERIFIED",
        "run_id": "native-historical-01",
        "generated_at": "2026-10-08T00:00:00Z",
        "acceptance_target": "native_windows_cloud_20261004",
        "acceptance": {"passed": True},
        "metrics": {"latency_p95_ms": 19},
        "environment": {
            "deployment": "native_windows",
            "source_snapshot": {"snapshot_sha256": digest},
            "code_version": {"git_commit": None, "source_sha256": {}},
        },
    }


def test_source_comparison_tracks_actual_content_changes_without_relabeling_measurements(
    source_root,
):
    digest = snapshot(source_root)["snapshot_sha256"]
    summary = _summary(digest)
    before = deepcopy(summary)
    assert source_provenance(summary, source_root) == {
        "status": "MATCH",
        "recorded_snapshot_sha256": digest,
        "current_snapshot_sha256": digest,
    }
    (source_root / "backend" / "example.py").write_text("value = 2\n", encoding="utf-8")
    compared = source_provenance(summary, source_root)
    assert compared["status"] == "SOURCE_CHANGED"
    assert compared["recorded_snapshot_sha256"] == digest
    assert compared["current_snapshot_sha256"] != digest
    assert summary == before


@pytest.mark.parametrize(
    "metadata", [None, {}, [], {"snapshot_sha256": "unknown"}, {"snapshot_sha256": 12}]
)
def test_missing_or_malformed_recorded_snapshot_is_never_current(source_root, metadata):
    summary = _summary("1" * 64)
    summary["environment"]["source_snapshot"] = metadata
    result = source_provenance(summary, source_root)
    assert result["status"] == "UNVERIFIED"
    assert result["recorded_snapshot_sha256"] is None
    assert result["current_snapshot_sha256"] == snapshot(source_root)["snapshot_sha256"]


def test_legacy_nested_snapshot_is_supported_when_direct_snapshot_is_absent(source_root):
    digest = snapshot(source_root)["snapshot_sha256"]
    summary = _summary(digest)
    summary["environment"]["code_version"]["source_snapshot"] = summary["environment"].pop(
        "source_snapshot"
    )
    assert source_provenance(summary, source_root)["status"] == "MATCH"


@pytest.mark.parametrize("nested", ["1" * 64, "2" * 64, "malformed", None])
def test_two_recorded_sources_must_both_be_valid_and_agree(source_root, nested):
    summary = _summary("1" * 64)
    summary["environment"]["code_version"]["source_snapshot"] = {
        "snapshot_sha256": nested,
    }
    result = source_provenance(summary, source_root)
    if nested == "1" * 64:
        assert result["status"] == "SOURCE_CHANGED"
        assert result["recorded_snapshot_sha256"] == "1" * 64
    else:
        assert result["status"] == "UNVERIFIED"
        assert result["recorded_snapshot_sha256"] is None


def test_unreadable_source_does_not_turn_historical_acceptance_into_current_proof(monkeypatch):
    def unreadable(_root):
        raise OSError("source is unavailable")

    monkeypatch.setattr(provenance_module, "snapshot", unreadable)
    assert source_provenance(_summary("1" * 64), Path("unused")) == {
        "status": "UNVERIFIED",
        "recorded_snapshot_sha256": "1" * 64,
        "current_snapshot_sha256": None,
    }


def test_ui_projection_preserves_historical_summary_and_refreshes_source_status(source_root):
    digest = snapshot(source_root)["snapshot_sha256"]
    summary = _summary(digest)
    artifact_root = source_root / "artifacts"
    evidence = artifact_root / "benchmarks" / "current-cloud-summary.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text(json.dumps(summary), encoding="utf-8")
    original_bytes = evidence.read_bytes()
    service = UiService(
        Settings(),
        cast(UiReadStore, object()),
        protocol_root=source_root / "protocol",
        artifact_root=artifact_root,
    )
    first = service.benchmark_summary()
    assert first["source_provenance"]["status"] == "MATCH"
    (source_root / "backend" / "example.py").write_text("value = 2\n", encoding="utf-8")
    latest = service.benchmark_summary()
    assert latest["source_provenance"]["status"] == "SOURCE_CHANGED"
    assert {key: value for key, value in latest.items() if key != "source_provenance"} == summary
    assert evidence.read_bytes() == original_bytes
