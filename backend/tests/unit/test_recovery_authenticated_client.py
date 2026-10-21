from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest

import backend.recovery.service as recovery_module
from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import PROOF_HEADER, InternalAuthError
from backend.recovery.service import RecoveryService
from backend.tests.unit.test_internal_auth import authenticator


def execution_row(kind: str) -> dict:
    return {
        "execution_id": "EXEC-001", "tenant_id": "tenant-A", "task_id": "TASK-001",
        "tool_service": f"{kind}-service",
        "tool_name": "refund.create" if kind == "refund" else "notification.send_template",
        "business_action_id": "ACTION-001", "business_idempotency_key": "a" * 64,
        "parameter_hash": "b" * 64,
    }


def response_body(row: dict, kind: str) -> dict:
    field = "refund_id" if kind == "refund" else "notification_id"
    result = {**row, field: "EFFECT-001"}
    return {
        "schema_version": "1.0", "execution_id": row["execution_id"],
        "status": "ALREADY_EXECUTED", "parameter_hash": row["parameter_hash"],
        "result": result, "business_effect_id": "EFFECT-001", "reason_code": "ALLOWED",
    }


@pytest.mark.parametrize("kind", ["refund", "notification"])
def test_recovery_client_signs_sent_bytes_and_uses_a_new_nonce_each_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    row = execution_row(kind)
    receiver = authenticator(tmp_path, f"{kind}-service")
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.path == "/internal/reconcile"
        assert receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={"recovery-worker"},
        ) == "recovery-worker"
        document = json.loads(request.content)
        assert document == {"schema_version": "1.0"} | {
            name: row[name] for name in (
                "execution_id", "tenant_id", "task_id", "business_action_id",
                "business_idempotency_key", "parameter_hash",
            )
        }
        return httpx.Response(200, json=response_body(row, kind))

    real_client = httpx.Client
    monkeypatch.setattr(
        recovery_module.httpx, "Client",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(handle), **kwargs,
        ),
    )
    subject = RecoveryService(
        "unit-only-database", internal_auth=authenticator(tmp_path, "recovery-worker"),
        tool_urls={(row["tool_service"], row["tool_name"]): "http://tool.invalid"},
    )
    first = subject._query_tool(row)
    second = subject._query_tool(row)
    assert first.status == second.status == "ALREADY_EXECUTED"
    assert first.result == second.result == response_body(row, kind)["result"]
    assert len(requests) == 2
    assert requests[0].headers[PROOF_HEADER] != requests[1].headers[PROOF_HEADER]
    assert all(request.url.path != "/internal/execute" for request in requests)


@pytest.mark.parametrize("status_code", [401, 403, 409, 503])
def test_reconcile_auth_failure_stays_unknown_not_not_executed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status_code: int,
) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(status_code, json={"detail": {"reason_code": "TOOL_NOT_ALLOWED"}})

    real_client = httpx.Client
    monkeypatch.setattr(
        recovery_module.httpx, "Client",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(handle), **kwargs,
        ),
    )
    subject = RecoveryService(
        "unit-only-database", internal_auth=authenticator(tmp_path, "recovery-worker"),
        tool_urls={("refund-service", "refund.create"): "http://tool.invalid"},
    )
    result = subject._query_tool(execution_row("refund"))
    assert result.status == "UNKNOWN"
    assert result.reason_code == ReasonCode.TOOL_EXECUTION_UNKNOWN.value
    assert result.result is None and result.business_effect_id is None
    assert len(requests) == 1 and requests[0].url.path == "/internal/reconcile"


def test_missing_edge_secret_never_falls_back_to_constant_identity_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbid_http(**_kwargs):
        raise AssertionError("no unsigned fallback is permitted")

    monkeypatch.setattr(recovery_module.httpx, "Client", forbid_http)
    subject = RecoveryService(
        "unit-only-database", internal_auth=authenticator(tmp_path, "recovery-worker", keys={}),
        tool_urls={("refund-service", "refund.create"): "http://tool.invalid"},
    )
    assert subject._query_tool(execution_row("refund")).status == "UNKNOWN"


def test_receipt_recovery_signs_only_execution_id_and_preserves_known_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    receiver = authenticator(tmp_path, "receipt-service")
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.path == "/internal/receipts/issue"
        assert json.loads(request.content) == {"execution_id": "EXEC-001"}
        receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={"recovery-worker"},
        )
        return httpx.Response(200, json={"receipt": {"receipt_id": "RECEIPT-UNIT"}})

    real_client = httpx.Client
    monkeypatch.setattr(
        recovery_module.httpx, "Client",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(handle), **kwargs,
        ),
    )
    subject = RecoveryService(
        "unit-only-database", internal_auth=authenticator(tmp_path, "recovery-worker"),
        tool_urls={}, receipt_url="http://receipt.invalid",
    )
    body = {
        "execution_id": "EXEC-001", "state": "COMMITTED",
        "business_effect_id": "REFUND-EXISTING", "result": {"amount_fen": 7000},
    }
    result = subject._with_receipt(body, 0)
    assert result["business_effect_id"] == "REFUND-EXISTING"
    assert result["result"] == body["result"]
    assert result["receipt"] == {"receipt_id": "RECEIPT-UNIT"}
    assert len(requests) == 1


def test_receipt_auth_failure_cannot_erase_committed_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = RecoveryService(
        "unit-only-database", internal_auth=authenticator(tmp_path, "recovery-worker"),
        tool_urls={}, receipt_url="http://receipt.invalid",
    )
    monkeypatch.setattr(
        subject.internal_auth, "request_headers",
        Mock(side_effect=InternalAuthError(ReasonCode.TOOL_NOT_ALLOWED)),
    )
    body = {
        "execution_id": "EXEC-001", "state": "COMMITTED",
        "business_effect_id": "REFUND-EXISTING", "result": {"amount_fen": 7000},
    }
    assert subject._with_receipt(body, 1000) is body
