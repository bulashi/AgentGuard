from __future__ import annotations

import json
import platform
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from backend.agent_runtime.contracts import AgentContext
from backend.agent_runtime.planner import PlannerError
from backend.agent_runtime.workflow_planner import WorkflowPlanner
from backend.config.settings import Settings
from backend.crypto.strict_json import parse_strict_json

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "https://api.deepseek.com"
MODEL = "deepseek-flash"


def main() -> int:
    key = sys.stdin.readline(1026).rstrip("\r\n")
    if not key or len(key) > 1024 or any(not 33 <= ord(char) <= 126 for char in key):
        print("DEEPSEEK_VERIFICATION=FAIL invalid_key_input", flush=True)
        return 1
    report: dict = {
        "tested_at": datetime.now(UTC).isoformat(),
        "endpoint": ENDPOINT,
        "model_requested": MODEL,
        "python": platform.python_version(),
        "httpx": httpx.__version__,
        "mock_used": False,
        "fallback_used": False,
        "checks": [],
    }
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = ROOT / "evidence" / "native-windows" / f"deepseek-cloud-{stamp}" / "connection.json"
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=60, trust_env=False, follow_redirects=False) as client:
            response = client.post(
                ENDPOINT + "/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": MODEL,
                    "messages": [
                        {"role": "user", "content": 'Return only the JSON object {"ok":true}.'}
                    ],
                    "response_format": {"type": "json_object"},
                    "thinking": {"type": "disabled"},
                    "temperature": 0,
                    "max_tokens": 32,
                    "stream": False,
                },
            )
            check = {"name": "official_api", "http_status": response.status_code}
            report["checks"].append(check)
            if response.status_code != 200:
                check["passed"] = False
                check["failure"] = {
                    401: "authentication_rejected", 402: "insufficient_balance",
                    429: "rate_limited", 400: "request_or_model_rejected",
                }.get(response.status_code, "upstream_http_error")
                raise RuntimeError("official_api_failed")
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            check |= {
                "passed": parse_strict_json(content.encode("utf-8")) == {"ok": True},
                "model_returned": body.get("model"),
                "usage": body.get("usage"),
                "duration_ms": round((time.perf_counter() - started) * 1000),
            }
            if not check["passed"]:
                raise RuntimeError("unexpected_probe_output")
        settings = Settings(
            cloud_llm_enabled=True,
            cloud_llm_api_key=key,
            cloud_llm_base_url=ENDPOINT,
            cloud_llm_model=MODEL,
        )
        context = AgentContext(
            ticket_id="TICKET-SYNTHETIC-CLOUD-CHECK",
            customer_id="CUSTOMER-SYNTHETIC-CLOUD-CHECK",
            refund_amount_fen=100,
            runtime_mode="cloud",
            cloud_data_confirmed=True,
        )
        planned = WorkflowPlanner(settings).plan("coordinator", context, stage="coordinate")
        report["checks"].append({
            "name": "project_workflow_planner",
            "passed": planned.planner == "llm" and not planned.intents,
            "evidence": planned.evidence,
        })
        report["passed"] = all(item["passed"] for item in report["checks"])
    except PlannerError as exc:
        report["passed"] = False
        report["failure"] = exc.reason_code
    except Exception as exc:
        report["passed"] = False
        report["failure_type"] = type(exc).__name__
    finally:
        key = ""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True, indent=2), flush=True)
    print(f"DEEPSEEK_EVIDENCE={path}", flush=True)
    print(f"DEEPSEEK_VERIFICATION={'PASS' if report['passed'] else 'FAIL'}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
