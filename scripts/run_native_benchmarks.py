from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from backend.benchmark.runner import NativeBenchmarkConfig, NativeBenchmarkRunner

REQUIRED_ENVIRONMENT = {
    "main_database_url": "AGENTGUARD_BENCHMARK_MAIN_DATABASE_URL",
    "audit_database_url": "AGENTGUARD_BENCHMARK_AUDIT_DATABASE_URL",
    "benchmark_database_url": "AGENTGUARD_BENCHMARK_DATABASE_URL",
    "private_key_root": "AGENTGUARD_BENCHMARK_PRIVATE_KEY_ROOT",
    "authority_url": "AGENTGUARD_BENCHMARK_AUTHORITY_URL",
    "coordinator_delegation_url": "AGENTGUARD_BENCHMARK_COORDINATOR_DELEGATION_URL",
    "case_delegation_url": "AGENTGUARD_BENCHMARK_CASE_DELEGATION_URL",
    "gateway_url": "AGENTGUARD_BENCHMARK_GATEWAY_URL",
    "registry_url": "AGENTGUARD_BENCHMARK_REGISTRY_URL",
    "revocation_url": "AGENTGUARD_BENCHMARK_REVOCATION_URL",
    "audit_service_url": "AGENTGUARD_BENCHMARK_AUDIT_SERVICE_URL",
    "checkpoint_service_url": "AGENTGUARD_BENCHMARK_CHECKPOINT_SERVICE_URL",
    "baseline_static_url": "AGENTGUARD_BENCHMARK_STATIC_URL",
    "baseline_rbac_url": "AGENTGUARD_BENCHMARK_RBAC_URL",
    "benchmark_admin_token": "AGENTGUARD_BENCHMARK_ADMIN_TOKEN",
    "benchmark_static_token": "AGENTGUARD_BENCHMARK_STATIC_TOKEN",
    "benchmark_rbac_token": "AGENTGUARD_BENCHMARK_RBAC_TOKEN",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Opt-in isolated Windows benchmark; cloud samples come from the main thread."
    )
    parser.add_argument("--allow-isolated", action="store_true")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--cloud-report", type=Path, default=None)
    parser.add_argument("--source-snapshot", type=Path, default=None)
    parser.add_argument(
        "--publish-current-summary",
        action="store_true",
        help=(
            "Publish verified current-cloud-summary.json atomically; never replace existing files."
        ),
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate inputs only; no writes, service requests or database connections.",
    )
    parser.add_argument("--warmup-samples", type=int, default=2)
    parser.add_argument("--latency-samples", type=int, default=10)
    parser.add_argument("--throughput-requests", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--normal-task-samples", type=int, default=2)
    parser.add_argument("--crypto-samples", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def configuration(args: argparse.Namespace) -> NativeBenchmarkConfig:
    if not args.allow_isolated:
        raise ValueError("--allow-isolated is required before configuring any benchmark")
    missing = [name for name in REQUIRED_ENVIRONMENT.values() if not os.environ.get(name)]
    if missing:
        raise ValueError("explicit benchmark environment variables are missing")
    values = {field: os.environ[name] for field, name in REQUIRED_ENVIRONMENT.items()}
    values["private_key_root"] = Path(values["private_key_root"])
    config = NativeBenchmarkConfig(
        **values,
        run_id=args.run_id
        or datetime.now(UTC).strftime("native-%Y%m%dT%H%M%SZ-") + uuid4().hex[:8],
        artifact_root=args.artifact_root,
        coordinator_agent_url="",
        live_refund_agent_url="",
        allow_isolated=args.allow_isolated,
        cloud_report=args.cloud_report,
        source_snapshot=args.source_snapshot,
        publish_current_summary=args.publish_current_summary,
        warmup_samples=args.warmup_samples,
        latency_samples=args.latency_samples,
        throughput_requests=args.throughput_requests,
        concurrency=args.concurrency,
        normal_task_samples=args.normal_task_samples,
        crypto_samples=args.crypto_samples,
        random_seed=args.seed,
    )
    config.validate()
    return config


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    stage = "configuration"
    runner = None
    try:
        config = configuration(args)
        if args.validate_only:
            report = NativeBenchmarkRunner._read_cloud_report(config)
            source = NativeBenchmarkRunner._read_source_snapshot(config)
            NativeBenchmarkRunner._validate_cloud_source(report, source)
            run_dir = config.artifact_root / "benchmarks" / "runs" / config.run_id
            if run_dir.exists():
                raise FileExistsError("the run directory already exists")
            print(
                json.dumps(
                    {
                        "status": "CONFIG_VALIDATED",
                        "run_id": config.run_id,
                        "cloud_report_status": report["status"],
                        "source_snapshot_sha256": source["snapshot_sha256"],
                        "acceptance_target": NativeBenchmarkRunner.ACCEPTANCE_TARGET,
                        "publication_requested": config.publish_current_summary,
                        "benchmark_executed": False,
                    }
                )
            )
            return 0
        stage = "execution"
        runner = NativeBenchmarkRunner(config)
        summary = runner.run()
        print(
            json.dumps(
                {
                    "status": summary["status"],
                    "run_id": summary["run_id"],
                    "acceptance_passed": summary["acceptance"]["passed"],
                    "summary": runner._redact(str(runner.run_dir / "summary.json")),
                    "current_summary_published": config.publish_current_summary
                    and summary["status"] == "VERIFIED",
                },
                ensure_ascii=True,
            )
        )
        return {"VERIFIED": 0, "FAILED": 1, "UNVERIFIED": 2}[summary["status"]]
    except Exception as exc:
        # Raw libpq errors can contain credentials; details stay in sanitized run-local files.
        result = {
            "status": "REJECTED" if stage == "configuration" else "FAILED",
            "stage": stage,
            "error_type": type(exc).__name__,
            "benchmark_verified": False,
        }
        if stage == "configuration" and args.allow_isolated:
            result["missing_environment"] = [
                name for name in REQUIRED_ENVIRONMENT.values() if not os.environ.get(name)
            ]
        if runner is not None:
            result["failures"] = runner._redact(str(runner.failure_path))
        print(json.dumps(result, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
