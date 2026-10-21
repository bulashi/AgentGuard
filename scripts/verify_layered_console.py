from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from backend.state.database import connect
from scripts.native_runtime import CONFIG, ROOT, database_urls, read_json, write_json
from scripts.verify_business_workspace import validate_workflow
from scripts.verify_native import audit_check


def main() -> None:
    directory = ROOT / "evidence/native-windows/layered-console-migration-20261003"
    workflows = read_json(directory / "browser-workflows.json")
    urls = database_urls(read_json(CONFIG))
    report: dict = {
        "scope": "persisted_business_and_signature_verification",
        "started_at": datetime.now(UTC).isoformat(),
        "cloud_invoked": False,
        "new_task_created": False,
        "runs": [],
    }
    try:
        with httpx.Client(base_url="http://127.0.0.1:8090", timeout=180, trust_env=False) as client:
            for run in workflows["runs"]:
                response = client.get(f"/api/tasks/{run['task_id']}")
                response.raise_for_status()
                value = response.json()
                result = validate_workflow(value, urls, run["mode"], run["scenario"])
                if run["mode"] == "cloud":
                    plans = [event for event in value["workflow_runs"][0]["events"]
                             if event["action"] == "plan" and event["status"] == "COMPLETED"]
                    if not all(event["details"]["provider"] == "deepseek"
                               and event["details"]["model_requested"] == "deepseek-flash"
                               and event["details"]["model_returned"] == "deepseek-flash"
                               for event in plans):
                        raise RuntimeError("actual cloud invocation model does not match configuration")
                    result["actual_cloud_calls_verified"] = len(plans)
                report["runs"].append(result)
                with connect(urls["main"]) as connection:
                    budget = connection.execute(
                        "SELECT sum(reserved_value), sum(committed_value) "
                        "FROM credential_budget_state JOIN credentials USING (credential_id) "
                        "WHERE task_id=%s", (run["task_id"],),
                    ).fetchone()
                report["runs"][-1]["budget_reserved_sum"] = int(budget[0] or 0)
                report["runs"][-1]["budget_committed_across_levels_sum"] = int(budget[1] or 0)
        report["audit"] = audit_check(urls)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error_type"] = type(error).__name__
        report["error"] = str(error)
    report["finished_at"] = datetime.now(UTC).isoformat()
    write_json(directory / "persisted-workflows.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
