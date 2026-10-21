from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.verify_current_cloud import benchmark_cloud_report


def test_cloud_export_preserves_all_actual_attempts_including_failure(tmp_path: Path) -> None:
    events = [
        {
            "action": "plan",
            "details": {
                "http_status": 200,
                "duration_ms": 1234,
                "model_returned": "test-model",
                "prompt_eval_count": 100,
                "eval_count": 50,
                "request_length_bytes": 456,
                "response_length_bytes": 789,
                "response_sha256": "a" * 64,
            },
        },
        {
            "action": "plan",
            "details": {
                "http_status": 429,
                "duration_ms": 789,
                "failure_type": "HTTPStatusError",
                "request_length_bytes": 456,
            },
        },
    ]
    (tmp_path / "cloud-normal-snapshot.json").write_text(
        json.dumps({"workflow_runs": [{"events": events}]}), encoding="utf-8"
    )
    report = benchmark_cloud_report(tmp_path, [], {"snapshot_sha256": "b" * 64}, "native-test")
    assert report["attempted_samples"] == 2
    assert [sample["passed"] for sample in report["samples"]] == [True, False]
    assert report["samples"][1]["http_status"] == 429
    assert report["samples"][1]["wall_ms"] == 789
    assert "model_returned" not in report["samples"][1]
    assert "live_llm" not in report
    assert report["source_snapshot_sha256"] == "b" * 64
    assert report["mock_used"] is False and report["fallback_used"] is False


def test_cloud_export_does_not_fabricate_missing_call_metadata(tmp_path: Path) -> None:
    (tmp_path / "cloud-normal-snapshot.json").write_text(
        json.dumps({"workflow_runs": [{"events": [{"action": "plan", "details": {}}]}]}),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="metadata is incomplete"):
        benchmark_cloud_report(tmp_path, [], {"snapshot_sha256": "b" * 64}, "native-test")


def test_cloud_export_only_publishes_business_results_checked_for_both_scenarios(
    tmp_path: Path,
) -> None:
    results = [
        {
            "scenario": scenario,
            "task_id": task_id,
            "state": "COMPLETED",
            "reason_code": None,
            "providers": ["test-provider"],
            "requested_models": ["test-model"],
            "business_rows": {"refunds": [[1]], "notifications": [[2]]},
            "unauthorized_side_effects": 0,
        }
        for scenario, task_id in (("normal", "TASK-1"), ("policy_injection", "TASK-2"))
    ]
    report = benchmark_cloud_report(tmp_path, results, {"snapshot_sha256": "b" * 64}, "native-test")
    assert report["provider"] == "test-provider"
    assert report["model_requested"] == "test-model"
    assert report["live_llm"]["normal"]["committed_effects"] == 2
    assert report["live_llm"]["prompt_injection"]["task_id"] == "TASK-2"
    assert report["live_llm"]["prompt_injection"]["unauthorized_side_effects"] == 0
