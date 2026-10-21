from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from backend.benchmark.agentguard_client import (
    AgentGuardBenchmarkClient,
    AgentGuardChain,
    HttpObservation,
)
from backend.benchmark.baseline_client import BaselineBenchmarkClient
from backend.benchmark.internal_security import INTERNAL_AUTH_KEYS_ENV, INTERNAL_AUTH_REQUIRED_ENV
from backend.benchmark.runner import (
    BenchmarkRunner,
    ModeMeasurement,
    NativeBenchmarkRunner,
    evaluate_acceptance,
)
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import EXECUTION_RECEIPT
from backend.crypto.sm import derive_public_key, sign_payload, verify_payload
from scripts.run_native_benchmarks import REQUIRED_ENVIRONMENT, main
from scripts.source_manifest import snapshot

from .test_native_benchmark_config import native_config

# Fixed public test vector, never a runtime or production signing key.
RECEIPT_TEST_PRIVATE_KEY = "0" * 63 + "1"
RECEIPT_TEST_PUBLIC_KEY = (
    "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
    "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
)


def signed_receipt(decision: str, **changes: object) -> dict:
    payload = {
        "schema_version": "1.0",
        "receipt_id": "REC-export-" + decision,
        "receipt_type": "EXECUTION_RESULT" if decision == "ALLOW" else "AUTHORIZATION_DENIAL",
        "execution_id": "EXEC-export-" + decision,
        "request_id": "REQ-export-" + decision,
        "request_hash": "b" * 64,
        "credential_chain_hash": "c" * 64,
        "tenant_id": "tenant-export",
        "task_id": "TASK-export",
        "tool_service": "ticket-service",
        "tool_name": "ticket.read",
        "tool_version": "v1",
        "parameter_hash": "d" * 64,
        "decision": decision,
        "reason_code": "ALLOWED" if decision == "ALLOW" else "HOLDER_PROOF_INVALID",
        "business_action_id": None,
        "business_idempotency_key": None,
        "business_effect_id": None,
        "business_result_hash": "e" * 64 if decision == "ALLOW" else None,
        "budget_reserved": 0,
        "budget_committed": 0,
        "started_at": 1760000000,
        "finished_at": 1760000001,
        "decision_at": 1760000000,
        "business_effect_finalized_at": None,
        "receipt_issued_at": 1760000002,
        "receipt_signing_key_id": "receipt-key-01",
        **changes,
    }
    signature = sign_payload(
        payload,
        domain_separator=EXECUTION_RECEIPT,
        key_id="receipt-key-01",
        key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
        private_key_hex=RECEIPT_TEST_PRIVATE_KEY,
        public_key_hex=RECEIPT_TEST_PUBLIC_KEY,
        signed_at=1760000002,
        random_hex="0" * 63 + "2",
    )
    return {"payload": payload, "signature": signature}


def seed_public_receipts(runner: NativeBenchmarkRunner) -> None:
    public = runner.config.private_key_root.parent / "public"
    public.mkdir(exist_ok=True)
    (public / "receipt.public").write_text(
        RECEIPT_TEST_PUBLIC_KEY + "\n", encoding="ascii", newline="\n",
    )
    runner.run_dir.mkdir(parents=True, exist_ok=True)
    runner.raw_path = runner.run_dir / "raw_samples.jsonl"
    if not runner.raw_path.exists():
        runner._write_lock = threading.Lock()
        for decision in ("ALLOW", "DENY"):
            runner._append_jsonl(runner.raw_path, {"receipt": signed_receipt(decision)})
    runner._public_receipt_verification = runner._verify_exported_receipts()


@pytest.fixture(autouse=True)
def forbid_external_measurements(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        raise AssertionError("unit tests must not execute HTTP or PostgreSQL measurements")

    monkeypatch.setattr(httpx.Client, "request", unexpected)
    monkeypatch.setattr("backend.benchmark.runner.connect", unexpected)


def test_native_instantiates_mature_clients_without_network_or_existing_run_overwrite(
    tmp_path: Path,
) -> None:
    config = native_config(tmp_path)
    runner = NativeBenchmarkRunner(config)
    assert type(runner.agentguard) is AgentGuardBenchmarkClient
    assert all(type(client) is BaselineBenchmarkClient for client in runner.baselines.values())
    assert NativeBenchmarkRunner._measure_revocation is BenchmarkRunner._measure_revocation
    assert NativeBenchmarkRunner._measure_concurrency is BenchmarkRunner._measure_concurrency
    assert NativeBenchmarkRunner._verify_aec is BenchmarkRunner._verify_aec
    assert (
        NativeBenchmarkRunner._settle_and_verify_audit is BenchmarkRunner._settle_and_verify_audit
    )
    runner.close()
    with pytest.raises(FileExistsError):
        NativeBenchmarkRunner(config)


def test_native_never_writes_shared_summary_and_keeps_failure_structure(tmp_path: Path) -> None:
    config = native_config(tmp_path)
    runner = NativeBenchmarkRunner(config)
    try:
        public = config.artifact_root / "benchmarks" / "summary.json"
        public.write_text("historical-content", encoding="utf-8")
        runner._write_public_summary({"status": "VERIFIED"})
        assert public.read_text(encoding="utf-8") == "historical-content"
        runner._record_failure(
            "unit", RuntimeError(config.main_database_url + " " + config.benchmark_admin_token)
        )
        failure = json.loads(runner.failure_path.read_text(encoding="utf-8"))
        assert failure["stage"] == "unit"
        assert failure["exception_type"] == "RuntimeError"
        assert config.main_database_url not in failure["message"]
        assert config.benchmark_admin_token not in failure["message"]
        with pytest.raises(ValueError, match="newly created run directory"):
            runner._write_json(public, {"status": "VERIFIED"})
    finally:
        runner.close()


def summary_inputs(config: object) -> dict[str, object]:
    # Synthetic gate inputs exercise the serializer only, not the benchmark orchestration.
    measurements = {
        name: ModeMeasurement(
            name=name,
            legitimate_attempts=config.latency_samples,
            legitimate_accepted=config.latency_samples,
            normal_task_attempts=config.normal_task_samples,
            normal_tasks_completed=config.normal_task_samples,
            latency_ms=[1.0] * config.latency_samples,
            throughput_rps=1.0,
            component_timings_ms={},
            task_ids=[],
            workload_ids=[],
        )
        for name in ("shared_static_credential", "conventional_rbac", "agentguard")
    }
    modes = list(measurements)
    inputs = {
        "started_at": datetime.now(UTC),
        "environment": {},
        "health": {},
        "measurements": measurements,
        "attacks": {
            **{name: {"unauthorized_side_effects": 0, "decision": "DENY"} for name in modes},
            "live_llm": {"passed": False},
        },
        "revocation": {name: {"denied": True} for name in modes},
        "concurrency": {name: {"budget_safe": True} for name in modes},
        "credential_size": {},
        "component_latency": {"model_inference": {"passed": False}},
        "storage": {name: {} for name in modes},
        "ablations": [
            {"name": name, "passed": True}
            for name in (
                "paired_multilevel_budget_reservation",
                "no_business_idempotency",
                "no_holder_proof",
                "no_signed_receipt_and_audit_evidence",
            )
        ],
        "audit": {"valid": True},
        "aec": {name: {"passed": True} for name in ("AEC-01", "AEC-02", "AEC-03", "AEC-04")},
    }
    inputs["acceptance"] = evaluate_acceptance(
        **{name: inputs[name] for name in ("measurements", "attacks", "revocation", "concurrency",
                                         "aec", "audit")}
    )
    return inputs


def summary_runner(tmp_path: Path) -> NativeBenchmarkRunner:
    runner = object.__new__(NativeBenchmarkRunner)
    runner.config = native_config(tmp_path)
    runner.run_dir = tmp_path / "run"
    runner._secrets = []
    runner._cloud = {"status": "NOT_MEASURED", "samples": []}
    runner._source_before = {"snapshot_sha256": "a" * 64}
    runner._source_unchanged = True
    seed_public_receipts(runner)
    return runner


def test_paired_multilevel_budget_ablation_runs_30_fresh_matched_trials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backend.benchmark.runner as runner_module

    runner = summary_runner(tmp_path)
    schema_statements: list[tuple[str, str]] = []
    seeded_trials: list[tuple[str, ...]] = []
    atomic_trials: list[dict[str, Any]] = []
    race_trials: list[dict[str, Any]] = []
    recorded_trials: list[tuple[str, bool, dict[str, Any]]] = []

    class FakeConnection:
        def execute(self, query: object, params: object = None) -> None:
            schema_statements.append((runner.config.benchmark_database_url, str(query)))

    from contextlib import contextmanager

    @contextmanager
    def fake_connect(dsn: str):
        yield FakeConnection()

    monkeypatch.setattr(runner_module, "connect", fake_connect)

    def seed(
        _schema: str, _tables: dict, *, credential_ids: list[str], **_limits: int
    ) -> None:
        seeded_trials.append(tuple(credential_ids))

    def safe_trial(_schema: str, _table: object, *, hierarchy: dict, trial: dict) -> dict:
        budgets = [
            {"credential_id": credential_id, "limit_fen": 10_000,
             "reserved_fen": 6_000 if key in {"root", "intermediate", "leaf_a"} else 0,
             "committed_fen": 0}
            for key, credential_id in hierarchy.items()
        ]
        item = {
            **trial, "allowed": 1, "denied": 1, "errors": [],
            "budgets": budgets, "invariant_violations": [], "overcommitted": False,
            "attempts": [
                {"leaf": "leaf_a", "decision": "ALLOW"},
                {"leaf": "leaf_b", "decision": "DENY"},
            ],
        }
        atomic_trials.append(item)
        return item

    def unsafe_trial(_table: object, *, hierarchy: dict, trial: dict) -> dict:
        budgets = [
            {"credential_id": credential_id, "limit_fen": 10_000,
             "reserved_fen": 12_000 if key in {"root", "intermediate"} else 6_000,
             "committed_fen": 0}
            for key, credential_id in hierarchy.items()
        ]
        item = {
            **trial, "allowed": 2, "denied": 0, "errors": [], "budgets": budgets,
            "invariant_violations": [
                {"credential_id": hierarchy["root"]},
                {"credential_id": hierarchy["intermediate"]},
            ], "overcommitted": True,
            "attempts": [
                {"leaf": "leaf_a", "decision": "ALLOW"},
                {"leaf": "leaf_b", "decision": "ALLOW"},
            ],
        }
        race_trials.append(item)
        return item

    runner._seed_budget_ablation_trial = seed
    runner._run_atomic_budget_ablation_trial = safe_trial
    runner._run_read_check_write_budget_ablation_trial = unsafe_trial
    def record_trial(kind: str, _system: str, passed: bool, details: dict[str, Any]) -> None:
        recorded_trials.append((kind, passed, details))

    runner._record_structured_sample = record_trial

    result = runner._ablation_paired_multilevel_budget()

    assert result["name"] == "paired_multilevel_budget_reservation"
    assert result["passed"] is True
    assert result["trial_count"] == 30
    assert result["atomic"]["allowed"] == 30
    assert result["atomic"]["denied"] == 30
    assert result["atomic"]["invariant_violation_trials"] == 0
    assert result["read_check_write"]["allowed"] == 60
    assert result["read_check_write"]["denied"] == 0
    assert result["read_check_write"]["overcommitted_trials"] == 30
    assert len(seeded_trials) == len(atomic_trials) == len(race_trials) == 30
    assert len({credential_id for trial_ids in seeded_trials for credential_id in trial_ids}) == 120
    assert len(recorded_trials) == 60
    assert all(kind == "ablation_budget_trial" for kind, _, _ in recorded_trials)
    assert all(dsn == runner.config.benchmark_database_url for dsn, _ in schema_statements)


def test_paired_multilevel_budget_ablation_fails_when_race_is_not_reproduced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backend.benchmark.runner as runner_module

    runner = summary_runner(tmp_path)

    class FakeConnection:
        def execute(self, _query: object, _params: object = None) -> None:
            return None

    from contextlib import contextmanager

    @contextmanager
    def fake_connect(_dsn: str):
        yield FakeConnection()

    monkeypatch.setattr(runner_module, "connect", fake_connect)
    runner._seed_budget_ablation_trial = lambda *_args, **_kwargs: None
    runner._record_structured_sample = lambda *_args, **_kwargs: None

    def safe_trial(_schema: str, _table: object, *, hierarchy: dict, trial: dict) -> dict:
        return {
            **trial, "allowed": 1, "denied": 1, "errors": [],
            "invariant_violations": [], "overcommitted": False,
        }

    def race_trial(_table: object, *, hierarchy: dict, trial: dict) -> dict:
        return {
            **trial, "allowed": 1, "denied": 1, "errors": [],
            "invariant_violations": [], "overcommitted": False,
        }

    runner._run_atomic_budget_ablation_trial = safe_trial
    runner._run_read_check_write_budget_ablation_trial = race_trial

    result = runner._ablation_paired_multilevel_budget()

    assert result["atomic"]["passed"] is True
    assert result["read_check_write"]["counterexample_reproduced"] is False
    assert result["passed"] is False


@pytest.mark.parametrize("interrupted_at,expected_arms", [
    ("race-first", ["atomic"]),
    ("seed-second", ["atomic", "read_check_write"]),
])
def test_budget_trials_already_finished_remain_on_disk_after_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    interrupted_at: str, expected_arms: list[str],
) -> None:
    from contextlib import contextmanager

    import backend.benchmark.runner as runner_module

    runner = summary_runner(tmp_path)
    statements: list[str] = []
    seeds = 0

    class FakeConnection:
        def execute(self, query: object, _params: object = None) -> None:
            statements.append(str(query))

    @contextmanager
    def fake_connect(_dsn: str):
        yield FakeConnection()

    def seed(*_args: object, **_kwargs: object) -> None:
        nonlocal seeds
        seeds += 1
        if interrupted_at == "seed-second" and seeds == 2:
            raise RuntimeError("injected trial interruption")

    def atomic(*_args: object, trial: dict, **_kwargs: object) -> dict:
        return {
            **trial, "allowed": 1, "denied": 1, "errors": [],
            "invariant_violations": [], "overcommitted": False,
        }

    def race(*_args: object, trial: dict, **_kwargs: object) -> dict:
        if interrupted_at == "race-first":
            raise RuntimeError("injected trial interruption")
        return {
            **trial, "allowed": 2, "denied": 0, "errors": [],
            "invariant_violations": [{"credential_id": "root"}], "overcommitted": True,
        }

    monkeypatch.setattr(runner_module, "connect", fake_connect)
    runner._seed_budget_ablation_trial = seed
    runner._run_atomic_budget_ablation_trial = atomic
    runner._run_read_check_write_budget_ablation_trial = race

    with pytest.raises(RuntimeError, match="injected trial interruption"):
        runner._ablation_paired_multilevel_budget()

    samples = [
        json.loads(line) for line in runner.raw_path.read_text(encoding="utf-8").splitlines()
    ]
    trials = [sample for sample in samples if sample.get("kind") == "ablation_budget_trial"]
    assert [sample["details"]["arm"] for sample in trials] == expected_arms
    assert all(sample["passed"] is True for sample in trials)
    assert {sample["details"]["trial"] for sample in trials} == {1}
    assert len({sample["details"]["trial_id"] for sample in trials}) == 1
    assert not any("DROP SCHEMA" in statement for statement in statements)


@pytest.mark.parametrize(
    "refund_body,ledger_effects,expected_completed",
    [
        ({"receipt": {"payload": {"business_effect_id": "REFUND-test"}}}, 2, True),
        ({"receipt": {"payload": {"business_effect_id": "REFUND-test"}}}, 1, False),
        ({"receipt": {"payload": {"business_effect_id": "REFUND-test"}}}, 3, False),
        ({"receipt": None}, 2, False),
        ({"receipt": {"payload": None}}, 2, False),
        ({"receipt": {"payload": {"business_effect_id": None}}}, 2, False),
        ({"business_effect_id": "unbound-top-level-value"}, 2, False),
    ],
)
def test_native_normal_task_uses_receipt_effect_and_requires_four_steps_and_two_ledger_rows(
    tmp_path: Path, refund_body: dict, ledger_effects: int, expected_completed: bool
) -> None:
    runner = summary_runner(tmp_path)
    calls: list[dict] = []
    resolutions: list[dict] = []

    def dispatch(chain: AgentGuardChain, **kwargs: object) -> HttpObservation:
        calls.append(kwargs)
        body = {"decision": "ALLOW", "state": "COMMITTED"}
        if kwargs["tool_name"] == "refund.create":
            body.update(refund_body)
        return HttpObservation(200, body, 1.0)

    def resolve_notification(
        base: str, method: str, path: str, **kwargs: object
    ) -> HttpObservation:
        assert method == "POST"
        assert path == "/business-actions/notification/resolve"
        resolutions.append(kwargs["json_body"])
        return HttpObservation(200, {"business_action_id": "ACTION-notice"}, 1.0)

    runner.agentguard = SimpleNamespace(
        dispatch=dispatch,
        resolve_refund_action=lambda task_id: HttpObservation(
            200, {"business_action_id": "ACTION-refund"}, 1.0
        ),
        _request=resolve_notification,
    )
    runner._agentguard_effect_count = lambda task_id: ledger_effects
    chain = AgentGuardChain("TASK-test", [], [], "agent-refund", "key-test", "1", "2")
    observation = runner._direct_normal_task(chain, refund_amount_fen=7_000)
    assert (observation.body["status"] == "COMPLETED") is expected_completed
    has_receipt_effect = refund_body.get("receipt") == {
        "payload": {"business_effect_id": "REFUND-test"}
    }
    assert len(calls) == (4 if has_receipt_effect else 3)
    assert len(resolutions) == (1 if has_receipt_effect else 0)
    assert [call["tool_name"] for call in calls[:3]] == [
        "ticket.read", "knowledge.read_associated", "refund.create"
    ]
    if has_receipt_effect:
        assert calls[3]["tool_name"] == "notification.send_template"
        assert calls[3]["parameters"]["related_business_effect_id"] == "REFUND-test"
        assert resolutions[0]["related_business_effect_id"] == "REFUND-test"


@pytest.mark.parametrize(
    "attack_status,attack_effects,unauthorized,normal_effects,expected",
    [
        ("COMPLETED", 2, 0, 2, True),
        ("DENIED", 0, 0, 2, True),
        ("COMPLETED", 2, 1, 2, False),
        ("DENIED", 0, 1, 2, False),
        ("COMPLETED", 1, 0, 2, False),
        ("COMPLETED", 3, 0, 2, False),
        ("DENIED", 2, 0, 2, False),
        ("FAILED", 0, 0, 2, False),
        ("COMPLETED", 2, 0, 1, False),
        ("COMPLETED", None, 0, 2, False),
    ],
)
def test_native_cloud_gate_distinguishes_safe_continuation_from_request_denial(
    tmp_path: Path, attack_status: str, attack_effects: int | None,
    unauthorized: int, normal_effects: int, expected: bool
) -> None:
    runner = summary_runner(tmp_path)
    runner._cloud = {
        "sha256": "a" * 64,
        "live_llm": {
            "normal": {
                "http_status": 200, "status": "COMPLETED", "planner": "llm",
                "committed_effects": normal_effects, "unauthorized_side_effects": 0,
            },
            "prompt_injection": {
                "http_status": 200, "status": attack_status, "planner": "llm",
                "committed_effects": attack_effects,
                "unauthorized_side_effects": unauthorized,
            },
        },
    }
    samples = []
    runner._record_structured_sample = lambda *args: samples.append(args)
    result = runner._measure_live_llm_injection()
    assert result["passed"] is expected
    assert samples[0][2] is expected
    assert result["safe_outcome_kind"] == (
        "LEGAL_BUSINESS_CONTINUED" if expected and attack_status == "COMPLETED"
        else "REQUEST_DENIED" if expected else None
    )


@pytest.mark.parametrize("baseline_count,signed_count", [(0, 3), (4, 0), (4, 3)])
def test_native_receipt_ablation_counts_only_tracked_committed_unsigned_baseline_rows(
    tmp_path: Path, baseline_count: int, signed_count: int
) -> None:
    runner = summary_runner(tmp_path)
    runner._baseline_workload_ids = {
        "shared_static_credential": ["WORK-static"],
        "conventional_rbac": ["WORK-rbac"],
    }
    runner._agentguard_task_ids = ["TASK-test"]
    queries = []

    def scalar(dsn: str, query: str, params: tuple) -> int:
        queries.append((dsn, query, params))
        return baseline_count if len(queries) == 1 else signed_count

    runner._scalar = scalar
    runner._ablation_paired_multilevel_budget = lambda: {
        "name": "paired_multilevel_budget_reservation", "passed": True
    }
    runner._ablation_no_idempotency = lambda: {
        "name": "no_business_idempotency", "duplicate_effect_observed": True
    }
    runner._record_structured_sample = lambda *args: None
    results = runner._run_ablations({
        "shared_static_credential": {"decision": "ALLOW"},
        "agentguard": {"decision": "DENY", "unauthorized_side_effects": 0},
    })
    assert queries[0][0] == runner.config.benchmark_database_url
    assert queries[0][2] == (["WORK-rbac", "WORK-static"],)
    query = queries[0][1]
    for required in (
        "w.workload_id=ANY(%s)", "e.state='COMMITTED'", "e.decision='ALLOW'",
        "e.receipt_status IN ('NOT_REQUIRED', 'PENDING')", "NOT EXISTS",
        "r.execution_id=e.execution_id", "r.receipt_status='SIGNED'",
    ):
        assert required in query
    assert queries[1][0] == runner.config.main_database_url
    assert queries[1][2] == (["TASK-test"],)
    assert results[-1]["passed"] is (baseline_count > 0 and signed_count > 0)
    assert results[-1]["baseline_executions_without_required_receipt"] == baseline_count
    assert results[-1]["agentguard_executions_with_signed_receipt"] == signed_count


def test_missing_cloud_is_unverified_not_pass_and_preserves_bff_keys(tmp_path: Path) -> None:
    runner = summary_runner(tmp_path)
    summary = runner._build_summary(**summary_inputs(runner.config))
    assert summary["status"] == "UNVERIFIED"
    assert summary["acceptance"]["passed"] is False
    assert summary["acceptance"]["native_local_passed"] is True
    assert summary["metrics"]["component_latency_ms"]["model_inference"]["passed"] is False
    assert {"agentguard", "baselines", "aec", "audit", "artifacts", "metrics"} <= set(summary)
    assert summary["artifacts"]["raw_samples"] == "raw_samples.jsonl"
    assert summary["artifacts"]["failures"] == "failures.jsonl"
    assert summary["acceptance_target"] == "native_windows_cloud_20261004"
    assert summary["environment"]["deployment"] == "native_windows"


@pytest.mark.parametrize(
    "check",
    [
        "all_systems_measured",
        "agentguard_legitimate_requests_accepted",
        "agentguard_normal_tasks_completed",
        "agentguard_unauthorized_side_effects_zero",
        "agentguard_revocation_observed",
        "agentguard_concurrent_budget_safe",
        "aec_01",
        "aec_02",
        "aec_03",
        "aec_04",
        "audit_chain_and_checkpoint_valid",
    ],
)
def test_native_gate_does_not_weaken_existing_security_checks(tmp_path: Path, check: str) -> None:
    runner = summary_runner(tmp_path)
    inputs = summary_inputs(runner.config)
    inputs["acceptance"]["checks"][check] = False
    summary = runner._build_summary(**inputs)
    assert summary["status"] == "FAILED"
    assert summary["acceptance"]["checks"][check] is False
    assert summary["acceptance"]["passed"] is False


def verified_serializer_inputs(runner: NativeBenchmarkRunner) -> dict[str, object]:
    # Synthetic state-machine inputs only; no actual acceptance or benchmark is asserted.
    seed_public_receipts(runner)
    runner._source_unchanged = True
    runner._cloud = {
        "status": "IMPORTED",
        "samples": [{"passed": True}],
        "live_llm": {},
        "source_snapshot_sha256": runner._source_before["snapshot_sha256"],
    }
    inputs = summary_inputs(runner.config)
    inputs["attacks"]["live_llm"] = {"passed": True}
    inputs["component_latency"]["model_inference"] = {"passed": True}
    return inputs


def test_cloud_source_binding_is_required_and_no_model_is_retried(tmp_path: Path) -> None:
    runner = summary_runner(tmp_path)
    inputs = verified_serializer_inputs(runner)
    runner._cloud.pop("source_snapshot_sha256")
    summary = runner._build_summary(**inputs)
    assert summary["status"] == "UNVERIFIED"
    assert "cloud_source_snapshot_binding" in summary["acceptance"]["missing_evidence"]


def test_native_source_drift_is_failed_even_with_cloud_samples(tmp_path: Path) -> None:
    runner = summary_runner(tmp_path)
    inputs = verified_serializer_inputs(runner)
    runner._source_unchanged = False
    summary = runner._build_summary(**inputs)
    assert summary["status"] == "FAILED"
    assert summary["acceptance"]["checks"]["source_snapshot_unchanged"] is False


def test_missing_original_gate_cannot_pass(tmp_path: Path) -> None:
    runner = summary_runner(tmp_path)
    inputs = verified_serializer_inputs(runner)
    del inputs["acceptance"]["checks"]["agentguard_concurrent_budget_safe"]
    summary = runner._build_summary(**inputs)
    assert summary["status"] == "FAILED"
    assert summary["acceptance"]["checks"]["agentguard_concurrent_budget_safe"] is False


def test_current_summary_publication_is_idempotent_and_preserves_history(
    tmp_path: Path,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        old = runner.config.artifact_root / "benchmarks" / "summary.json"
        old.write_text("historical-content", encoding="utf-8")
        summary = runner._build_summary(**verified_serializer_inputs(runner))
        assert summary["status"] == "VERIFIED"  # Serializer fixture, not a measured run.
        runner._write_public_summary(summary)
        current = old.with_name("current-cloud-summary.json")
        published_bytes = current.read_bytes()
        published = json.loads(published_bytes)
        assert published["acceptance_target"] == NativeBenchmarkRunner.ACCEPTANCE_TARGET
        assert published["environment"]["deployment"] == "native_windows"
        assert old.read_text(encoding="utf-8") == "historical-content"
        runner._write_public_summary(summary)
        assert current.read_bytes() == published_bytes
        assert list(current.parent.glob("current-cloud-summary.json.*")) == []
    finally:
        runner.close()


def test_current_summary_archives_previous_exact_bytes_before_replacement(tmp_path: Path) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        current = runner.config.artifact_root / "benchmarks/current-cloud-summary.json"
        previous = b'{"run_id":"prior-run","status":"VERIFIED"}\r\n'
        current.write_bytes(previous)
        summary = runner._build_summary(**verified_serializer_inputs(runner))
        digest = hashlib.sha256(previous).hexdigest()
        assert summary["publication"]["previous_current_sha256"] == digest
        runner._write_public_summary(summary)
        archive = current.parent / "current-summary-history" / f"{digest}.json"
        assert archive.read_bytes() == previous
        assert json.loads(current.read_bytes())["run_id"] == runner.config.run_id
    finally:
        runner.close()


def test_current_summary_rejects_corrupt_existing_archive_without_overwrite(tmp_path: Path) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        current = runner.config.artifact_root / "benchmarks/current-cloud-summary.json"
        previous = b"prior signed-run index"
        current.write_bytes(previous)
        history = current.parent / "current-summary-history"
        history.mkdir()
        archive = history / f"{hashlib.sha256(previous).hexdigest()}.json"
        archive.write_bytes(b"corrupted archival bytes")
        summary = runner._build_summary(**verified_serializer_inputs(runner))
        with pytest.raises(ValueError, match="archive failed byte verification"):
            runner._write_public_summary(summary)
        assert current.read_bytes() == previous
        assert archive.read_bytes() == b"corrupted archival bytes"
        assert not list(current.parent.glob("current-cloud-summary.json.*"))
    finally:
        runner.close()


def test_current_summary_exclusive_publisher_lock_does_not_delete_other_lock(
    tmp_path: Path,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        current = runner.config.artifact_root / "benchmarks/current-cloud-summary.json"
        current.write_bytes(b"prior index")
        summary = runner._build_summary(**verified_serializer_inputs(runner))
        lock = current.with_suffix(".json.publish-lock")
        lock.write_text("another-live-publisher", encoding="ascii")
        with pytest.raises(FileExistsError):
            runner._write_public_summary(summary)
        assert current.read_bytes() == b"prior index"
        assert lock.read_text(encoding="ascii") == "another-live-publisher"
    finally:
        runner.close()


def test_current_summary_rejects_changed_current_index_between_build_and_publish(
    tmp_path: Path,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        current = runner.config.artifact_root / "benchmarks/current-cloud-summary.json"
        current.write_bytes(b"first index")
        summary = runner._build_summary(**verified_serializer_inputs(runner))
        current.write_bytes(b"concurrent index")
        with pytest.raises(ValueError, match="changed after measurement"):
            runner._write_public_summary(summary)
        assert current.read_bytes() == b"concurrent index"
        assert not list(current.parent.glob("current-cloud-summary.json.*"))
    finally:
        runner.close()


def test_current_summary_replace_failure_keeps_old_bytes_and_verified_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        current = runner.config.artifact_root / "benchmarks/current-cloud-summary.json"
        previous = b"prior index"
        current.write_bytes(previous)
        summary = runner._build_summary(**verified_serializer_inputs(runner))

        def denied(*args: object) -> None:
            raise PermissionError("injected atomic replace failure")

        monkeypatch.setattr("backend.benchmark.runner.os.replace", denied)
        with pytest.raises(PermissionError, match="injected atomic replace"):
            runner._write_public_summary(summary)
        assert current.read_bytes() == previous
        archive = current.parent / "current-summary-history" / (
            hashlib.sha256(previous).hexdigest() + ".json"
        )
        assert archive.read_bytes() == previous
        assert not list(current.parent.glob("current-cloud-summary.json.*"))
    finally:
        runner.close()


@pytest.mark.parametrize("tamper", ["failed", "unverified", "missing_gate", "false_gate"])
def test_current_summary_rejects_every_incomplete_or_failed_gate(
    tmp_path: Path, tamper: str
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        summary = runner._build_summary(**verified_serializer_inputs(runner))
        if tamper == "missing_gate":
            del summary["acceptance"]["checks"]["aec_03"]
        elif tamper == "false_gate":
            summary["acceptance"]["checks"]["aec_04"] = False
        else:
            summary["status"] = tamper.upper()
        with pytest.raises(ValueError, match="every mandatory"):
            runner._write_public_summary(summary)
        assert not (runner.config.artifact_root / "benchmarks/current-cloud-summary.json").exists()
    finally:
        runner.close()


def test_source_snapshot_covers_current_four_roots_and_is_saved_without_secret_substitutions(
    tmp_path: Path,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path))
    try:
        captured = runner._source_before
        for root in ("backend", "scripts", "frontend", "protocol"):
            assert any(name.startswith(root + "/") for name in captured["files"])
        path = runner.run_dir / "source-snapshot.json"
        runner._write_json(path, captured)
        assert json.loads(path.read_text(encoding="utf-8")) == snapshot()
        runner._verify_source_snapshot()
        assert runner._source_unchanged is True
        assert (
            json.loads((runner.run_dir / "source-after.json").read_text(encoding="utf-8"))
            == captured
        )
    finally:
        runner.close()


def test_current_summary_rechecks_source_before_publication(tmp_path: Path) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        summary = runner._build_summary(**verified_serializer_inputs(runner))
        runner._source_before["snapshot_sha256"] = "0" * 64
        with pytest.raises(ValueError, match="source changed"):
            runner._write_public_summary(summary)
        assert not (runner.config.artifact_root / "benchmarks/current-cloud-summary.json").exists()
    finally:
        runner.close()


def test_supplied_snapshot_must_match_current_source_without_network(tmp_path: Path) -> None:
    path = tmp_path / "source-before.json"
    path.write_text(json.dumps(snapshot()), encoding="utf-8")
    config = native_config(tmp_path, source_snapshot=path)
    assert NativeBenchmarkRunner._read_source_snapshot(config) == snapshot()
    supplied = json.loads(path.read_text())
    supplied["snapshot_sha256"] = "0" * 64
    path.write_text(json.dumps(supplied), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        NativeBenchmarkRunner._read_source_snapshot(config)


def test_cloud_failures_are_failed_not_missing_evidence(tmp_path: Path) -> None:
    runner = summary_runner(tmp_path)
    runner._cloud = {"status": "IMPORTED", "samples": [{"passed": False}]}
    summary = runner._build_summary(**summary_inputs(runner.config))
    assert summary["status"] == "FAILED"


def test_request_lengths_are_real_encoded_bodies_without_secrets(tmp_path: Path) -> None:
    runner = object.__new__(NativeBenchmarkRunner)
    runner._write_lock = threading.Lock()
    runner._request_lengths = []
    request = httpx.Request(
        "POST", "http://127.0.0.1:28404/gateway/dispatch", json={"ticket_id": "T10086"}
    )
    runner._capture_request_length("agentguard", request)
    assert runner._request_lengths == [("agentguard", len(request.content))]


def test_current_host_metadata_captures_cpu_ram_dependencies_and_source_hashes() -> None:
    metadata = NativeBenchmarkRunner.host_metadata()
    assert metadata["cpu"]["physical_model"]
    assert metadata["cpu"]["physical_cores"] > 0
    assert metadata["memory_bytes_visible_to_runner"] > 0
    assert metadata["packages"]["gmssl"] != "NOT_INSTALLED"
    project = Path(__file__).resolve().parents[3]
    actual = hashlib.sha256((project / "backend/benchmark/runner.py").read_bytes()).hexdigest()
    assert metadata["code_version"]["source_sha256"]["backend/benchmark/runner.py"] == actual
    assert "docker" not in metadata
    assert "model" not in metadata


def test_entry_requires_opt_in_and_never_defaults_to_production(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    code = main(["--artifact-root", str(tmp_path / "unused"), "--validate-only"])
    assert code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "REJECTED"
    assert not (tmp_path / "unused").exists()


def test_validate_only_does_not_create_output_or_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    config = native_config(tmp_path)
    for name, variable in REQUIRED_ENVIRONMENT.items():
        monkeypatch.setenv(variable, str(getattr(config, name)))
    monkeypatch.setenv(INTERNAL_AUTH_KEYS_ENV, config.internal_auth_keys)
    monkeypatch.setenv(INTERNAL_AUTH_REQUIRED_ENV, "true")
    code = main(
        [
            "--allow-isolated",
            "--artifact-root",
            str(config.artifact_root),
            "--run-id",
            config.run_id,
            "--validate-only",
        ]
    )
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "CONFIG_VALIDATED"
    assert result["benchmark_executed"] is False
    assert not config.artifact_root.exists()
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("public_value", [
    "AUTHORIZATION_DENIAL", "AUTHORIZATION_ROOT_SIGNING", "AUTHORIZATION_INVALID",
    "authorization-authority", "bearer-token-service", "password-policy-service",
    "api-key-management-service", "authorization", "bearer",
])
def test_redaction_preserves_public_enumerations_and_service_names(public_value: str) -> None:
    runner = object.__new__(NativeBenchmarkRunner)
    runner._secrets = []
    assert runner._redact({"public_value": public_value}) == {"public_value": public_value}


@pytest.mark.parametrize("message,private_value", [
    ("password=opaque-credential", "opaque-credential"),
    ("password opaque-credential", "opaque-credential"),
    ("PASSWORD : 'opaque value with spaces'", "opaque value with spaces"),
    ("api-key: opaque-api-value", "opaque-api-value"),
    ("{'api_key': 'opaque-api-value'}", "opaque-api-value"),
    ('{"api_key": "opaque-api-value"}', "opaque-api-value"),
    ("private_key=opaque-private-value", "opaque-private-value"),
    ("Authorization: Bearer opaque-header-value", "opaque-header-value"),
    ("Authorization Bearer opaque-header-value", "opaque-header-value"),
    ("authorization=Basic opaque-header-value", "opaque-header-value"),
    ("Bearer opaque-header-value", "opaque-header-value"),
    ("bearer: opaque-header-value", "opaque-header-value"),
    ("bearer=opaque-header-value", "opaque-header-value"),
    ("postgresql+psycopg://user:opaque-dsn-value@localhost/db", "opaque-dsn-value"),
])
def test_free_text_secret_assignments_headers_and_dsns_are_redacted(
    message: str, private_value: str,
) -> None:
    runner = object.__new__(NativeBenchmarkRunner)
    runner._secrets = []
    result = runner._redact(message)
    assert private_value not in result
    assert "REDACTED" in result


def test_all_configured_secrets_and_confidential_fields_remain_redacted(tmp_path: Path) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path))
    try:
        for secret in runner._secrets:
            assert secret not in runner._redact("diagnostic: " + secret)
        fields = {key: "opaque-field-value" for key in (
            "password", "private_key", "private-key", "api_key", "api-key", "dsn",
            "main_database_url", "admin_token",
        )}
        assert set(runner._redact(fields).values()) == {"REDACTED"}
        assert runner._redact({"Authorization": "Basic opaque-field-value"}) == {
            "Authorization": "REDACTED",
        }
        service_urls = {"authorization": runner.config.authority_url}
        assert runner._redact(service_urls) == service_urls
    finally:
        runner.close()


@pytest.mark.parametrize("exporter", ["_write_json", "_append_jsonl"])
@pytest.mark.parametrize("decision", ["ALLOW", "DENY"])
def test_exported_receipt_retains_full_schema_canonical_payload_and_fixed_sm2_signature(
    tmp_path: Path, exporter: str, decision: str,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path))
    try:
        receipt = signed_receipt(decision, tool_service="authorization-authority")
        before = canonicalize(receipt)
        value = {
            "body": {"receipt": receipt},
            "password": "opaque-field-value",
            "headers": {"Authorization": "Bearer opaque-header-value"},
            "message": runner.config.main_database_url + " " + runner.config.benchmark_admin_token,
        }
        path = runner.run_dir / ("export.json" if exporter == "_write_json" else "export.jsonl")
        getattr(runner, exporter)(path, value)
        encoded = path.read_text(encoding="utf-8")
        exported = json.loads(encoded)
        actual = exported["body"]["receipt"]
        assert canonicalize(receipt) == before == canonicalize(actual)
        assert canonicalize(actual["payload"]) == canonicalize(receipt["payload"])
        assert actual["signature"] == receipt["signature"]
        SchemaStore().validate("execution-receipt.schema.json", actual)
        assert verify_payload(
            actual["payload"], actual["signature"],
            domain_separator=EXECUTION_RECEIPT, expected_key_id="receipt-key-01",
            expected_key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
            public_key_hex=RECEIPT_TEST_PUBLIC_KEY,
        )
        for secret in ("opaque-field-value", "opaque-header-value", *runner._secrets):
            assert secret not in encoded
    finally:
        runner.close()


@pytest.mark.parametrize("exporter", ["_write_json", "_append_jsonl"])
@pytest.mark.parametrize("secret_kind", ["field", "known", "dsn", "free_text"])
def test_signed_payload_with_confidential_data_fails_before_any_public_file_change(
    tmp_path: Path, exporter: str, secret_kind: str,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path))
    try:
        changes = {
            "field": {"password": "opaque-field-value"},
            "known": {"tenant_id": runner.config.benchmark_admin_token},
            "dsn": {"note": "postgresql://user:opaque-dsn-value@localhost/db"},
            "free_text": {"note": "Authorization: Bearer opaque-header-value"},
        }[secret_kind]
        receipt = signed_receipt("DENY", **changes)
        before = canonicalize(receipt)
        path = runner.run_dir / ("export.json" if exporter == "_write_json" else "export.jsonl")
        prior = b"existing-public-bytes\n"
        path.write_bytes(prior)
        with pytest.raises(ValueError, match="signed evidence contains confidential data"):
            getattr(runner, exporter)(path, {"receipt": receipt})
        assert path.read_bytes() == prior
        assert canonicalize(receipt) == before
        path.unlink()
        with pytest.raises(ValueError, match="refusing public export"):
            getattr(runner, exporter)(path, {"receipt": receipt})
        assert not path.exists()
    finally:
        runner.close()


def test_exported_receipt_gate_records_artifact_bytes_and_both_decisions(tmp_path: Path) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path))
    try:
        seed_public_receipts(runner)
        runner._write_json(
            runner.run_dir / "receipt-copy.json", {"receipt": signed_receipt("DENY")},
        )
        report = runner._verify_exported_receipts()
        assert report["passed"] is True
        assert report["decision_counts"] == {"ALLOW": 1, "DENY": 2}
        assert set(report["artifacts"]) == {"raw_samples.jsonl", "receipt-copy.json"}
        for name, artifact in report["artifacts"].items():
            actual_digest = hashlib.sha256((runner.run_dir / name).read_bytes()).hexdigest()
            assert artifact["sha256"] == actual_digest
        assert report["public_key_sha256"] == hashlib.sha256(
            (RECEIPT_TEST_PUBLIC_KEY + "\n").encode("ascii")
        ).hexdigest()
        runner._write_json(runner.run_dir / "public-receipt-verification.json", report)
        runner._write_json(runner.run_dir / "summary.json", {"public_receipt_verification": report})
        assert runner._verify_exported_receipts() == report
    finally:
        runner.close()


@pytest.mark.parametrize("tamper", ["schema", "payload", "signature", "wrong_signer", "missing"])
def test_exported_receipt_gate_rejects_post_export_corruption_using_fixed_public_key(
    tmp_path: Path, tamper: str,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path))
    try:
        seed_public_receipts(runner)
        rows = [
            json.loads(line) for line in runner.raw_path.read_text(encoding="utf-8").splitlines()
        ]
        receipt = rows[1]["receipt"]
        if tamper == "schema":
            receipt["payload"]["receipt_type"] = "REDACTED_SECRET"
        elif tamper == "payload":
            receipt["payload"]["tenant_id"] = "tenant-tampered"
        elif tamper == "signature":
            receipt["signature"]["value"] = "0" * 128
        elif tamper == "wrong_signer":
            private = "0" * 63 + "3"
            untrusted_public = derive_public_key(private)
            receipt["signature"] = sign_payload(
                receipt["payload"], domain_separator=EXECUTION_RECEIPT,
                key_id="receipt-key-01", key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
                private_key_hex=private, public_key_hex=untrusted_public, signed_at=1760000002,
            )
            rows[1]["untrusted_public_key"] = untrusted_public
        else:
            rows = rows[:1]
        runner.raw_path.write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8",
        )
        with pytest.raises(ValueError, match=r"schema|SM2|ALLOW and DENY"):
            runner._verify_exported_receipts()
    finally:
        runner.close()


def test_missing_public_receipt_verification_cannot_produce_verified_summary(
    tmp_path: Path,
) -> None:
    runner = summary_runner(tmp_path)
    inputs = verified_serializer_inputs(runner)
    runner._public_receipt_verification = {}
    summary = runner._build_summary(**inputs)
    assert summary["status"] == "FAILED"
    assert summary["acceptance"]["passed"] is False
    assert summary["acceptance"]["checks"]["exported_receipts_schema_and_sm2_valid"] is False


def test_publication_rechecks_exported_receipt_bytes_and_preserves_previous_index(
    tmp_path: Path,
) -> None:
    runner = NativeBenchmarkRunner(native_config(tmp_path, publish_current_summary=True))
    try:
        current = runner.config.artifact_root / "benchmarks/current-cloud-summary.json"
        previous = b"prior public index"
        current.write_bytes(previous)
        summary = runner._build_summary(**verified_serializer_inputs(runner))
        # Whitespace keeps Schema and SM2 valid but changes the verified artifact bytes.
        runner.raw_path.write_bytes(runner.raw_path.read_bytes().replace(b"\n", b" \n", 1))
        assert runner._verify_exported_receipts()["passed"] is True
        with pytest.raises(ValueError, match="exported public receipts changed"):
            runner._write_public_summary(summary)
        assert current.read_bytes() == previous
        assert not current.with_suffix(".json.publish-lock").exists()
    finally:
        runner.close()
