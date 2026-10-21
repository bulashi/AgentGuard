from __future__ import annotations

import json
from typing import Any, cast

import httpx
import pytest

from backend.config.settings import Settings
from backend.ui_api.contracts import StartWorkflowRequest
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore

# Transport stubs isolate the queue boundary; they do not prove signatures or actual execution.
ACK = {"run_id": "RUN-test", "task_id": "TASK-test", "state": "QUEUED", "runtime_mode": "deterministic"}
TASK = {"task_id": "TASK-test", "ticket_id": "T10086", "customer_id": "C9527", "refund_total_fen": 7000}


def test_custom_text_is_transported_without_editing_task_or_authority(monkeypatch):
    subject, requests = transport_subject(monkeypatch, 202, json.dumps(ACK).encode())
    subject._queue_workflow({"payload": {"task_id": "TASK-test"}}, TASK,
                            StartWorkflowRequest(scenario="policy_injection", custom_injection_text="财务复核样例"))
    context = json.loads(requests[0].content)["context"]
    assert context["custom_injection_text"] == "财务复核样例"
    assert context["refund_amount_fen"] == 7000
    assert context["customer_id"] == "C9527"


def transport_subject(
    monkeypatch: pytest.MonkeyPatch, status: int, raw: bytes, *, timeout: bool = False,
) -> tuple[UiService, list[httpx.Request]]:
    requests = []
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if timeout:
            raise httpx.ReadTimeout("test-only timeout", request=request)
        return httpx.Response(status, content=raw)

    def client(*args: Any, **kwargs: Any) -> httpx.Client:
        assert kwargs["trust_env"] is False
        return real_client(*args, **kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr("backend.ui_api.service.httpx.Client", client)
    subject = UiService(Settings(coordinator_agent_url="http://coordinator.test"), cast(UiReadStore, object()))
    return subject, requests


def test_queue_response_is_bound_and_submission_occurs_once(monkeypatch: pytest.MonkeyPatch) -> None:
    subject, calls = transport_subject(monkeypatch, 202, json.dumps(ACK).encode())
    assert subject._queue_workflow({"source": "server-storage-stub"}, TASK, StartWorkflowRequest()) == ACK
    assert len(calls) == 1 and calls[0].url.path == "/agents/workflows"
    context = json.loads(calls[0].content)["context"]
    assert context["ticket_id"] == TASK["ticket_id"]
    assert context["refund_amount_fen"] == 7000
    assert "workflow_token" not in context


@pytest.mark.parametrize(
    "raw",
    [
        b'{"run_id":"RUN-test","task_id":"TASK-other","task_id":"TASK-test","state":"QUEUED","runtime_mode":"deterministic"}',
        b'[]', b'null', b'{"runtime_mode":1.5}', b'\xff', b' ' * 65_537,
        json.dumps(ACK | {"task_id": "TASK-other"}).encode(),
        json.dumps(ACK | {"state": "COMPLETED"}).encode(),
        json.dumps(ACK | {"runtime_mode": "cloud"}).encode(),
        json.dumps(ACK | {"workflow_token": "must-not-leak"}).encode(),
    ],
    ids=(
        "duplicate_field", "array", "null", "wrong_type", "invalid_utf8", "oversized",
        "wrong_task", "terminal_state", "wrong_mode", "secret_field",
    ),
)
def test_uncheckable_ack_is_unknown_and_never_retried(raw: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    subject, calls = transport_subject(monkeypatch, 202, raw)
    with pytest.raises(UiApiError) as caught:
        subject._queue_workflow({}, TASK, StartWorkflowRequest())
    assert caught.value.reason_code == "WORKFLOW_RESULT_UNCONFIRMED"
    assert caught.value.status_code == 502
    assert "must-not-leak" not in str(caught.value)
    assert len(calls) == 1


@pytest.mark.parametrize("status,code,extra", [
    (500, "WORKFLOW_ALREADY_EXISTS", {}),
    (503, "MODEL_MODE_UNAVAILABLE", {}),
    (403, "OTHER_ERROR", {}),
    (409, "WORKFLOW_ALREADY_EXISTS", {"extra": "not-allowed"}),
])
def test_only_exact_known_error_status_pairs_are_definite_rejections(
    status: int, code: str, extra: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject, calls = transport_subject(monkeypatch, status, json.dumps({"reason_code": code, "message": "test-only"} | extra).encode())
    with pytest.raises(UiApiError) as caught:
        subject._queue_workflow({}, TASK, StartWorkflowRequest())
    assert caught.value.reason_code == "WORKFLOW_RESULT_UNCONFIRMED"
    assert len(calls) == 1


def test_known_existing_run_rejection_remains_a_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    subject, calls = transport_subject(monkeypatch, 409, b'{"reason_code":"WORKFLOW_ALREADY_EXISTS","message":"test-only"}')
    with pytest.raises(UiApiError) as caught:
        subject._queue_workflow({}, TASK, StartWorkflowRequest())
    assert caught.value.reason_code == "WORKFLOW_ALREADY_EXISTS"
    assert caught.value.status_code == 409 and len(calls) == 1


def test_transport_timeout_does_not_claim_no_run_was_created(monkeypatch: pytest.MonkeyPatch) -> None:
    subject, calls = transport_subject(monkeypatch, 202, b"", timeout=True)
    with pytest.raises(UiApiError) as caught:
        subject._queue_workflow({}, TASK, StartWorkflowRequest())
    assert caught.value.reason_code == "WORKFLOW_RESULT_UNCONFIRMED"
    assert caught.value.status_code == 503 and len(calls) == 1
