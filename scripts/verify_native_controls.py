"""Probe strict native control boundaries without authorizing tasks or changing business state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx

from backend.common.internal_auth import InternalAuthenticator
from backend.state.database import connect
from scripts.native_operator import authenticate
from scripts.native_runtime import CONFIG, ROOT, STATE, database_urls, matching_process, read_json
from scripts.native_security import load_keys, service_identity
from scripts.source_manifest import snapshot


def business_counts(url: str) -> list[int]:
    with connect(url) as connection:
        return list(
            connection.execute(
                "SELECT (SELECT count(*) FROM tasks), (SELECT count(*) FROM refunds), "
                "(SELECT count(*) FROM notifications), (SELECT count(*) FROM execution_records)"
            ).fetchone()
        )


def run() -> dict:
    state = read_json(STATE)
    if (
        state.get("internal_auth_required") is not True
        or state.get("operator_auth_required") is not True
    ):
        raise RuntimeError("native strict authentication is not enabled")
    checks = []
    urls = database_urls(read_json(CONFIG))
    before = business_counts(urls["main"])
    with httpx.Client(
        trust_env=False, timeout=20, base_url=f"http://127.0.0.1:{state['ui_port']}"
    ) as browser:
        for method, path, headers in (
            ("GET", "/api/tasks", {}),
            ("POST", "/api/tasks", {}),
            ("PUT", "/api/model-configurations/forbidden", {"X-AgentGuard-Configuration": "1"}),
        ):
            response = browser.request(
                method, path, json={} if method != "GET" else None, headers=headers
            )
            assert response.status_code == 401
            checks.append(
                {"name": "unauthenticated operator " + method + " " + path, "status": 401}
            )
        authenticate(browser)
        assert browser.get("/api/tasks").status_code == 200
        response = browser.get("/api/model-configurations")
        assert response.status_code == 200
        configurations = response.json()
        assert not any(
            name in response.text for name in ('"api_key"', '"credential"', '"ciphertext"')
        )
        assert (
            browser.get("/api/tasks", headers={"Origin": "https://outside.invalid"}).status_code
            == 403
        )
        assert browser.put("/api/model-configurations/forbidden", json={}).status_code == 403
        checks.append(
            {"name": "authenticated operator and redacted model configuration", "passed": True}
        )
    with httpx.Client(trust_env=False, timeout=20) as client:
        targets = (
            (18001, "/tasks", "ui-api"),
            (18002, "/business-actions/refund/resolve", "agent-refund"),
            (18002, "/business-actions/notification/resolve", "agent-case"),
            (18101, "/credentials/ROOT-boundary-probe/delegate", "agent-coordinator"),
            (18005, "/credentials/ROOT-boundary-probe/revoke", "revocation-controller"),
            (18004, "/internal/recovery/run", "recovery-trigger"),
            (18006, "/internal/receipts/issue", "secure-gateway"),
            (18007, "/internal/audit/append", "audit-worker"),
            (18008, "/internal/checkpoint/run", "checkpoint-worker"),
            (18303, "/internal/reconcile", "recovery-worker"),
        )
        for port, path, caller in targets:
            response = client.post(
                f"http://127.0.0.1:{port}{path}", json={}, headers={"X-AgentGuard-Internal": caller}
            )
            assert response.status_code == 403, (path, response.status_code)
            checks.append({"name": "fixed caller string is not identity " + path, "status": 403})
        keys = load_keys(ROOT / ".native/internal-service-keys.dpapi", "agent-case")
        auth = InternalAuthenticator(service_id="agent-case", keys_json=json.dumps(keys))
        body = b"{}"
        proof = auth.request_headers(
            recipient="case-delegation-agent", method="POST", path="/tasks", body=body
        )
        response = client.post("http://127.0.0.1:18001/tasks", content=body, headers=proof)
        assert response.status_code == 403
        checks.append({"name": "limited agent proof cannot call authority", "status": 403})
    for item in state["processes"]:
        if item["name"] in {"postgres-server", "web-ui"}:
            continue
        process = matching_process(item)
        assert process is not None
        env = process.environ()
        assert env["AGENTGUARD_INTERNAL_AUTH_REQUIRED"] == "true"
        assert env["AGENTGUARD_INTERNAL_AUTH_SERVICE_ID"] == service_identity(item["name"])
        if item["name"] in {"coordinator-agent", "knowledge-agent", "case-agent", "refund-agent"}:
            assert (
                "AGENTGUARD_DATABASE_URL" not in env and "AGENTGUARD_AUDIT_DATABASE_URL" not in env
            )
            assert "AGENTGUARD_OPERATOR_SESSION_SECRET" not in env
            assert "ui-api->authorization-authority" not in env["AGENTGUARD_INTERNAL_AUTH_KEYS"]
    assert before == business_counts(urls["main"])
    return {
        "status": "PASS",
        "checks": checks,
        "business_state_unchanged": True,
        "processes_checked": 22,
        "configuration_count": len(configurations["items"]),
        "source_snapshot_sha256": snapshot()["snapshot_sha256"],
        "scope": "native application authentication; not Windows same-user OS isolation",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run()
    except Exception as exc:
        result = {"status": "FAIL", "error_type": type(exc).__name__}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
