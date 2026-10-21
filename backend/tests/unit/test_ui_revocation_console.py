from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, cast
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import ValidationError

import backend.common.internal_auth as auth_module
import backend.ui_api.revocation as sidecar
from backend.common.internal_auth import InternalAuthenticator
from backend.common.strict_json_route import StrictJsonRoute
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.ui_api.operator_session import COOKIE_NAME, OperatorSessionGuard
from backend.ui_api.revocation_contracts import UiRevocationResponse, UiRevokeCredentialRequest
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore

TASK = "TASK-revocation-unit"
OPERATOR = "local-operator-unit"
CURRENT = 1000
KEYS = {"ui-api->revocation-authority": "43" * 32}
SECRET = "31" * 32
URL = "http://revocation.invalid"


def snapshot() -> dict[str, Any]:
    return {
        "task": {"task_id": TASK},
        "credentials": [
            {
                "credential_id": identifier,
                "credential_type": kind,
                "parent_credential_id": parent,
                "revoked_at": None,
                "revocation_reason": None,
                "revoked_by": None,
                "signed_object": {"not_for_browser": "reusable-credential-sentinel"},
            }
            for identifier, kind, parent in [
                ("ROOT-1", "ROOT", None),
                ("BRANCH-1", "DELEGATION", "ROOT-1"),
                ("LEAF-1", "DELEGATION", "BRANCH-1"),
                ("LEAF-2", "DELEGATION", "ROOT-1"),
            ]
        ],
        "executions": [],
        "receipts": [],
        "audit_events": [],
        "dispatch_cancellations": [],
    }


class FakeStore:
    def __init__(self) -> None:
        self.saved = snapshot()
        self.reads = 0

    def task_snapshot(self, task_id: str) -> dict[str, Any] | None:
        self.reads += 1
        return deepcopy(self.saved) if task_id == TASK else None

    def apply(self, identifier="ROOT-1", *, reason="Stop this task", operator=OPERATOR) -> dict:
        record = {
            "credential_id": identifier,
            "revoked_at": CURRENT,
            "revocation_reason": reason,
            "revoked_by": operator,
            "status": "REVOKED",
        }
        for credential in self.saved["credentials"]:
            if credential["credential_id"] == identifier:
                credential.update({key: value for key, value in record.items() if key != "status"})
        return record


class MemoryNonces:
    def __init__(self) -> None:
        self.claimed: set[tuple[str, str, str]] = set()

    def claim(self, *, caller, recipient, nonce, **kwargs) -> bool:
        del kwargs
        key = caller, recipient, nonce
        if key in self.claimed:
            return False
        self.claimed.add(key)
        return True


@pytest.fixture
def subject(monkeypatch: pytest.MonkeyPatch) -> tuple[UiService, FakeStore]:
    monkeypatch.setattr(auth_module, "now_unix", lambda: CURRENT)
    monkeypatch.setattr(sidecar, "now_unix", lambda: CURRENT)
    monkeypatch.setattr("backend.ui_api.operator_session.time.time", lambda: CURRENT)
    no_database = Mock(
        side_effect=AssertionError("unit test must not connect to the main database")
    )
    monkeypatch.setattr("backend.ui_api.store.connect", no_database)
    monkeypatch.setattr("backend.revocation.service.connect", no_database)
    store = FakeStore()
    settings = Settings(
        internal_auth_required=True,
        internal_auth_service_id="ui-api",
        internal_auth_keys=json.dumps(KEYS),
        operator_auth_required=True,
        operator_session_secret=SECRET,
    )
    return UiService(settings, cast(UiReadStore, store)), store


def mock_authority(monkeypatch, handler) -> list[httpx.Request]:
    requests: list[httpx.Request] = []
    receiver = InternalAuthenticator(
        service_id="revocation-authority",
        keys_json=json.dumps(KEYS),
        nonce_store=MemoryNonces(),
        clock=lambda: CURRENT,
    )

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        caller = receiver.verify_headers(
            headers=request.headers,
            method="POST",
            path=request.url.path,
            body=request.content,
            allowed_callers={"ui-api"},
        )
        assert caller == "ui-api"
        return handler(request)

    real_client = httpx.Client

    def client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["base_url"] == URL
        return real_client(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(sidecar.httpx, "Client", client)
    return requests


def revoke(ui, identifier="ROOT-1", *, reason="Stop this task", task_id=TASK):
    return sidecar.revoke_credential(
        ui,
        task_id,
        identifier,
        UiRevokeCredentialRequest(confirmed=True, reason=reason),
        operator_id=OPERATOR,
        revocation_url=URL,
    )


@pytest.mark.parametrize(
    ("identifier", "descendants"), [("ROOT-1", 3), ("BRANCH-1", 1), ("LEAF-1", 0)]
)
def test_real_internal_hmac_targets_authority_and_returns_only_safe_projection(
    subject,
    monkeypatch,
    identifier,
    descendants,
):
    ui, store = subject
    reason = "Pause pending review: \u64a4\u9500\u539f\u56e0"

    def reply(request):
        assert request.url.path == f"/credentials/{identifier}/revoke"
        assert request.content == canonicalize({"reason": reason, "revoked_by": OPERATOR})
        return httpx.Response(200, json=store.apply(identifier, reason=reason))

    requests = mock_authority(monkeypatch, reply)
    result = revoke(ui, identifier, reason=reason)
    assert len(requests) == 1 and store.reads == 2
    assert result["credential_id"] == identifier and result["task_id"] == TASK
    assert result["descendant_count"] == descendants and result["already_revoked"] is False
    assert result["revoked_by"] == OPERATOR and result["revocation_reason"] == reason
    assert result["boundary"] == "DISPATCH_BOUNDARY_NO_ROLLBACK"
    assert result["audit_status"] == "PENDING" and result["cancellations"] == []
    assert UiRevocationResponse.model_validate(result).model_dump(mode="json") == result
    serialized = json.dumps(result)
    assert "reusable-credential-sentinel" not in serialized and SECRET not in serialized
    assert "signed_object" not in serialized and "holder_proof" not in serialized


@pytest.mark.parametrize(
    "change",
    [
        "task-mismatch",
        "foreign-credential",
        "duplicate",
        "orphan",
        "cycle",
        "credential-task-mismatch",
    ],
)
def test_inconsistent_or_cross_task_scope_never_contacts_authority(subject, monkeypatch, change):
    ui, store = subject
    identifier = "ROOT-1"
    if change == "task-mismatch":
        store.saved["task"]["task_id"] = "OTHER-task"
    elif change == "foreign-credential":
        identifier = "OTHER-credential"
    elif change == "duplicate":
        store.saved["credentials"].append(deepcopy(store.saved["credentials"][0]))
    elif change == "orphan":
        store.saved["credentials"][1]["parent_credential_id"] = "MISSING-parent"
    elif change == "cycle":
        store.saved["credentials"][1]["parent_credential_id"] = "LEAF-1"
    else:
        store.saved["credentials"][0]["task_id"] = "OTHER-task"
    client = Mock(side_effect=AssertionError("cross-task write must not occur"))
    monkeypatch.setattr(sidecar.httpx, "Client", client)
    with pytest.raises(UiApiError):
        revoke(ui, identifier)
    client.assert_not_called()


@pytest.mark.parametrize("identifier", ["../ROOT-1", "ROOT/1", "ROOT-1\n", "a" * 129])
def test_identifiers_cannot_change_the_authenticated_path(subject, identifier):
    ui, _ = subject
    with pytest.raises(UiApiError) as caught:
        revoke(ui, identifier)
    assert caught.value.reason_code == "REQUEST_SCHEMA_INVALID"


@pytest.mark.parametrize(
    "body",
    [
        {"confirmed": False, "reason": "x"},
        {"confirmed": 1, "reason": "x"},
        {"confirmed": "true", "reason": "x"},
        {"confirmed": True, "reason": ""},
        {"confirmed": True, "reason": " \t\n"},
        {"confirmed": True, "reason": "x" * 257},
        {"confirmed": True, "reason": "x", "revoked_by": "arbitrary-browser-user"},
        {"confirmed": True, "reason": "x", "holder_proof": {}},
    ],
)
def test_browser_contract_requires_confirmation_and_rejects_identity_or_proofs(body):
    with pytest.raises(ValidationError):
        UiRevokeCredentialRequest.model_validate(body)


def test_reason_limit_counts_unicode_codepoints_without_changing_saved_reason():
    reason = "\U0001f512" * 256
    assert UiRevokeCredentialRequest(confirmed=True, reason=reason).reason == reason


@pytest.mark.parametrize("auth_mode", ["disabled", "missing-edge", "wrong-service"])
def test_authentication_configuration_failure_cannot_fall_back_to_unsigned_post(
    subject, monkeypatch, auth_mode
):
    ui, _ = subject
    if auth_mode == "disabled":
        ui.settings.internal_auth_required = False
    elif auth_mode == "missing-edge":
        ui.settings.internal_auth_keys = "{}"
    else:
        ui.settings.internal_auth_service_id = "revocation-controller"
    client = Mock(side_effect=AssertionError("unsigned write must not occur"))
    monkeypatch.setattr(sidecar.httpx, "Client", client)
    with pytest.raises(UiApiError) as caught:
        revoke(ui)
    assert caught.value.reason_code == "INTERNAL_AUTH_UNAVAILABLE"
    client.assert_not_called()


def test_already_revoked_preserves_original_evidence_even_for_another_operator_reason(
    subject, monkeypatch
):
    ui, store = subject
    store.apply(operator="first-trusted-operator", reason="Original reason")
    store.saved["credentials"][0]["revoked_at"] = 0
    client = Mock(side_effect=AssertionError("idempotent read must not mutate"))
    monkeypatch.setattr(sidecar.httpx, "Client", client)
    result = revoke(ui, reason="A new reason that must not replace the original")
    assert result["already_revoked"] is True and result["revoked_at"] == 0
    assert (
        result["revoked_by"] == "first-trusted-operator"
        and result["revocation_reason"] == "Original reason"
    )
    client.assert_not_called()


def test_concurrent_revocation_conflict_is_resolved_from_saved_evidence(subject, monkeypatch):
    ui, store = subject

    def reply(_request):
        store.apply(operator="other-trusted-operator", reason="First committed reason")
        return httpx.Response(
            409, json={"reason_code": "IDEMPOTENCY_CONFLICT", "message": "not public"}
        )

    requests = mock_authority(monkeypatch, reply)
    result = revoke(ui)
    assert len(requests) == 1 and result["already_revoked"] is True
    assert result["revoked_by"] == "other-trusted-operator"
    assert result["revocation_reason"] == "First committed reason"


@pytest.mark.parametrize(
    "change",
    [
        "wrong-credential",
        "wrong-operator",
        "wrong-reason",
        "not-revoked",
        "extra-secret",
        "bool-time",
        "unsafe-time",
    ],
)
def test_malformed_or_mismatched_authority_reply_is_never_success(subject, monkeypatch, change):
    ui, store = subject

    def reply(_request):
        record = store.apply()
        if change == "wrong-credential":
            record["credential_id"] = "OTHER-credential"
        elif change == "wrong-operator":
            record["revoked_by"] = "OTHER-operator"
        elif change == "wrong-reason":
            record["revocation_reason"] = "OTHER-reason"
        elif change == "not-revoked":
            record["status"] = "ACTIVE"
        elif change == "extra-secret":
            record["private_key"] = "private-key-sentinel"
        elif change == "bool-time":
            record["revoked_at"] = True
        else:
            record["revoked_at"] = 2**53
        return httpx.Response(200, json=record)

    mock_authority(monkeypatch, reply)
    with pytest.raises(UiApiError) as caught:
        revoke(ui)
    assert caught.value.reason_code == "CONTROLLED_RESULT_INVALID"
    assert "private-key-sentinel" not in str(caught.value)


@pytest.mark.parametrize("body", [b"not JSON", b"[]", b'{"status":"REVOKED","status":"REVOKED"}'])
def test_invalid_or_duplicate_json_does_not_become_a_success(subject, monkeypatch, body):
    ui, _ = subject
    mock_authority(monkeypatch, lambda _request: httpx.Response(200, content=body))
    with pytest.raises(UiApiError) as caught:
        revoke(ui)
    assert caught.value.reason_code == "CONTROLLED_RESULT_INVALID"


def test_lost_reply_clearly_marks_unknown_and_does_not_automatically_repeat(subject, monkeypatch):
    ui, _ = subject

    def timeout(request):
        raise httpx.ReadTimeout("private-key-sentinel", request=request)

    requests = mock_authority(monkeypatch, timeout)
    with pytest.raises(UiApiError) as caught:
        revoke(ui)
    assert len(requests) == 1 and caught.value.reason_code == "REVOCATION_RESULT_UNCONFIRMED"
    assert "private-key-sentinel" not in str(caught.value)


def test_authority_error_is_projected_without_echoing_private_material(subject, monkeypatch):
    ui, _ = subject
    mock_authority(
        monkeypatch,
        lambda _request: httpx.Response(
            403,
            json={"reason_code": "TOOL_NOT_ALLOWED", "message": "private-key-sentinel"},
        ),
    )
    with pytest.raises(UiApiError) as caught:
        revoke(ui)
    assert caught.value.status_code == 403 and caught.value.reason_code == "TOOL_NOT_ALLOWED"
    assert "private-key-sentinel" not in str(caught.value)


@pytest.mark.parametrize("missing", ["revoked_by", "revoked_at", "revocation_reason"])
def test_missing_persisted_evidence_does_not_claim_the_reply_was_saved(
    subject, monkeypatch, missing
):
    ui, store = subject

    def reply(_request):
        record = store.apply()
        del store.saved["credentials"][0][missing]
        return httpx.Response(200, json=record)

    mock_authority(monkeypatch, reply)
    with pytest.raises(UiApiError) as caught:
        revoke(ui)
    assert caught.value.reason_code == "REVOCATION_RESULT_UNCONFIRMED"


def cancellation_records(
    store: FakeStore,
    *,
    credential_id="ROOT-1",
    reason_code="ANCESTOR_REVOKED",
) -> None:
    hashes = {"request_hash": "a" * 64, "credential_chain_hash": "b" * 64}
    evidence = {
        "schema_version": "1.0",
        "record_type": "DISPATCH_CANCELLED_V1",
        "cancellation_id": "CANCEL-unit",
        "execution_id": "EXEC-original",
        "denial_execution_id": "EXEC-denied",
        "task_id": TASK,
        "request_id": "REQUEST-unit",
        **hashes,
        "admission_decision": "ALLOW",
        "dispatch_decision": "DENY",
        "reason_code": reason_code,
        "cancelled_at": CURRENT,
        "released_budgets": [],
        "revocations": [
            {
                "credential_id": credential_id,
                "revoked_at": CURRENT,
                "reason": "Stop this task",
                "revoked_by": OPERATOR,
            }
        ],
    }
    store.saved.update(
        {
            "executions": [
                {
                    "execution_id": "EXEC-original",
                    "state": "RELEASED",
                    "decision": "ALLOW",
                    **hashes,
                },
                {
                    "execution_id": "EXEC-denied",
                    "state": "DENIED",
                    "decision": "DENY",
                    "reason_code": reason_code,
                    **hashes,
                },
                {"execution_id": "EXEC-dispatched", "state": "DISPATCHED", "decision": "ALLOW"},
                {"execution_id": "EXEC-unknown", "state": "UNKNOWN", "decision": "ALLOW"},
            ],
            "receipts": [
                {
                    "receipt_id": "RECEIPT-denied",
                    "execution_id": "EXEC-denied",
                    "decision": "DENY",
                    "reason_code": reason_code,
                }
            ],
            "audit_events": [
                {
                    "event_id": "AUDIT-released",
                    "execution_id": "EXEC-original",
                    "event_type": "EXECUTION_RELEASED",
                    "evidence_reference": "CANCEL-unit",
                    "payload_hash": sm3_hex(canonicalize(evidence)),
                }
            ],
            "dispatch_cancellations": [
                {
                    "cancellation_id": "CANCEL-unit",
                    "execution_id": "EXEC-original",
                    "denial_execution_id": "EXEC-denied",
                    **hashes,
                    "reason_code": reason_code,
                    "cancelled_at": CURRENT,
                    "evidence": evidence,
                    "private_key": "not projected",
                }
            ],
        }
    )


def test_saved_cancellation_links_preserve_historical_allow_and_keep_dispatched_unknown(
    subject, monkeypatch
):
    ui, store = subject

    def reply(_request):
        record = store.apply()
        cancellation_records(store)
        return httpx.Response(200, json=record)

    mock_authority(monkeypatch, reply)
    result = revoke(ui)
    assert result["cancellations"] == [
        {
            "cancellation_id": "CANCEL-unit",
            "reason_code": "ANCESTOR_REVOKED",
            "original_execution_id": "EXEC-original",
            "denied_execution_id": "EXEC-denied",
            "denied_receipt_id": "RECEIPT-denied",
            "audit_event_ids": ["AUDIT-released"],
        }
    ]
    assert result["audit_status"] == "RECORDED"
    assert result["execution_observation"] == {
        "scope": "TASK_SNAPSHOT",
        "released_count": 1,
        "dispatched_or_unknown_count": 2,
        "admitted_count": 0,
    }
    assert store.saved["executions"][0]["decision"] == "ALLOW"
    assert "private_key" not in json.dumps(result)


@pytest.mark.parametrize(
    ("identifier", "reason_code"),
    [
        ("ROOT-1", "ANCESTOR_REVOKED"),
        ("BRANCH-1", "ANCESTOR_REVOKED"),
        ("LEAF-1", "KEY_REVOKED"),
    ],
)
def test_each_revocation_level_preserves_the_frozen_verifier_reason(
    subject, monkeypatch, identifier, reason_code
):
    ui, store = subject

    def reply(_request):
        record = store.apply(identifier)
        cancellation_records(store, credential_id=identifier, reason_code=reason_code)
        return httpx.Response(200, json=record)

    requests = mock_authority(monkeypatch, reply)
    result = revoke(ui, identifier)
    assert len(requests) == 1
    assert len(result["cancellations"]) == 1
    link = result["cancellations"][0]
    assert link["reason_code"] == reason_code
    assert link["denied_receipt_id"] == "RECEIPT-denied"
    assert link["audit_event_ids"] == ["AUDIT-released"]
    assert store.saved["executions"][0]["decision"] == "ALLOW"
    assert store.saved["executions"][1]["reason_code"] == reason_code


@pytest.mark.parametrize(
    "change",
    [
        "wrong-credential",
        "duplicate-execution",
        "allow-denial",
        "dispatched-original",
        "missing-audit",
        "wrong-request-hash",
        "wrong-audit-hash",
        "row-reason-mismatch",
        "denial-reason-mismatch",
        "unsupported-reason",
        "invalid-reason-type",
    ],
)
def test_unbound_links_are_not_presented_as_recorded_audit(subject, monkeypatch, change):
    ui, store = subject
    store.apply()
    cancellation_records(store)
    if change == "wrong-credential":
        store.saved["dispatch_cancellations"][0]["evidence"]["revocations"][0]["credential_id"] = (
            "BRANCH-1"
        )
    elif change == "duplicate-execution":
        store.saved["executions"].append(deepcopy(store.saved["executions"][1]))
    elif change == "allow-denial":
        store.saved["executions"][1]["decision"] = "ALLOW"
    elif change == "dispatched-original":
        store.saved["executions"][0]["state"] = "DISPATCHED"
    elif change == "wrong-request-hash":
        store.saved["executions"][1]["request_hash"] = "c" * 64
    elif change == "wrong-audit-hash":
        store.saved["audit_events"][0]["payload_hash"] = "c" * 64
    elif change == "row-reason-mismatch":
        store.saved["dispatch_cancellations"][0]["reason_code"] = "KEY_REVOKED"
    elif change == "denial-reason-mismatch":
        store.saved["executions"][1]["reason_code"] = "KEY_REVOKED"
    elif change in {"unsupported-reason", "invalid-reason-type"}:
        store.saved["dispatch_cancellations"][0]["evidence"]["reason_code"] = (
            "CREDENTIAL_EXPIRED" if change == "unsupported-reason" else ["ANCESTOR_REVOKED"]
        )
    else:
        store.saved["audit_events"] = []
    monkeypatch.setattr(
        sidecar.httpx, "Client", Mock(side_effect=AssertionError("saved read only"))
    )
    result = revoke(ui)
    assert result["audit_status"] == "PENDING"
    if change not in {"missing-audit", "wrong-audit-hash"}:
        assert result["cancellations"] == []


@pytest.mark.parametrize("reason_code", ["ANCESTOR_REVOKED", "KEY_REVOKED"])
@pytest.mark.parametrize(
    "receipt_condition", ["missing", "wrong-execution", "wrong-reason", "duplicate"]
)
def test_real_cancellation_stays_visible_when_its_denial_receipt_is_pending(
    subject,
    monkeypatch,
    receipt_condition,
    reason_code,
):
    ui, store = subject
    identifier = "LEAF-1" if reason_code == "KEY_REVOKED" else "ROOT-1"
    store.apply(identifier)
    cancellation_records(store, credential_id=identifier, reason_code=reason_code)
    if receipt_condition == "missing":
        store.saved["receipts"] = []
    elif receipt_condition == "wrong-execution":
        store.saved["receipts"][0]["execution_id"] = "OTHER-execution"
    elif receipt_condition == "wrong-reason":
        store.saved["receipts"][0]["reason_code"] = (
            "KEY_REVOKED" if reason_code == "ANCESTOR_REVOKED" else "ANCESTOR_REVOKED"
        )
    else:
        store.saved["receipts"].append(deepcopy(store.saved["receipts"][0]))
    monkeypatch.setattr(
        sidecar.httpx, "Client", Mock(side_effect=AssertionError("saved read only"))
    )
    result = revoke(ui, identifier)
    assert len(result["cancellations"]) == 1
    assert result["cancellations"][0]["denied_receipt_id"] is None
    assert result["cancellations"][0]["denied_execution_id"] == "EXEC-denied"


@pytest.mark.parametrize(
    "hash_condition",
    [
        "matching",
        "wrong-task",
        "wrong-reason",
        "wrong-reference",
        "duplicate-event",
        "invalid-binding",
    ],
)
def test_credential_audit_link_requires_the_exact_saved_revocation_payload(
    subject,
    monkeypatch,
    hash_condition,
):
    ui, store = subject
    store.apply()
    evidence = {
        "schema_version": "1.0",
        "record_type": "CREDENTIAL_REVOKED_V1",
        "task_id": TASK,
        "credential_id": "ROOT-1",
        "credential_type": "ROOT",
        "parent_credential_id": None,
        "revoked_at": CURRENT,
        "revoked_by": OPERATOR,
        "reason": "Stop this task",
    }
    if hash_condition == "wrong-task":
        evidence["task_id"] = "OTHER-task"
    elif hash_condition == "wrong-reason":
        evidence["reason"] = "Different reason"
    event = {
        "schema_version": "4.0",
        "event_id": "AUDIT-revocation",
        "execution_id": None,
        "event_type": "CREDENTIAL_REVOKED",
        "evidence_reference": "ROOT-1",
        "payload_hash": sm3_hex(canonicalize(evidence)),
    }
    if hash_condition == "wrong-reference":
        event["evidence_reference"] = "BRANCH-1"
    elif hash_condition == "invalid-binding":
        event["evidence_binding_valid"] = False
    store.saved["audit_events"] = (
        [event, deepcopy(event)] if hash_condition == "duplicate-event" else [event]
    )
    monkeypatch.setattr(
        sidecar.httpx, "Client", Mock(side_effect=AssertionError("saved read only"))
    )
    result = revoke(ui)
    assert result["audit_event_ids"] == (
        ["AUDIT-revocation"] if hash_condition == "matching" else []
    )
    assert result["audit_status"] == ("RECORDED" if hash_condition == "matching" else "PENDING")


def route_client(ui: UiService) -> TestClient:
    app = FastAPI()
    app.router.route_class = StrictJsonRoute
    app.add_middleware(OperatorSessionGuard, required=True, secret=SECRET)

    @app.exception_handler(UiApiError)
    async def error_handler(_request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={"reason_code": exc.reason_code, "message": str(exc)},
        )

    @app.post(
        "/api/tasks/{task_id}/credentials/{credential_id}/revoke",
        response_model=UiRevocationResponse,
    )
    def revoke_route(
        task_id: str, credential_id: str, body: UiRevokeCredentialRequest, request: Request
    ):
        operator = sidecar.authenticated_operator(request, ui.settings, operator_id=OPERATOR)
        return sidecar.revoke_credential(
            ui, task_id, credential_id, body, operator_id=operator, revocation_url=URL
        )

    return TestClient(app, base_url="http://127.0.0.1:8088")


def test_http_route_authenticates_operator_and_forbids_browser_attribution(subject, monkeypatch):
    ui, store = subject
    requests = mock_authority(monkeypatch, lambda _request: httpx.Response(200, json=store.apply()))
    with route_client(ui) as client:
        path = f"/api/tasks/{TASK}/credentials/ROOT-1/revoke"
        assert (
            client.post(path, json={"confirmed": True, "reason": "Stop this task"}).status_code
            == 401
        )
        cookie = OperatorSessionGuard(None, required=True, secret=SECRET).signed_cookie(CURRENT)
        client.cookies.set(COOKIE_NAME, cookie)
        assert (
            client.post(
                path,
                json={"confirmed": True, "reason": "Stop this task", "revoked_by": "browser-user"},
            ).status_code
            == 422
        )
        response = client.post(path, json={"confirmed": True, "reason": "Stop this task"})
    assert response.status_code == 200 and response.json()["revoked_by"] == OPERATOR
    assert len(requests) == 1


@pytest.mark.parametrize(
    "condition",
    [
        "disabled",
        "no-cookie",
        "forged-cookie",
        "expired",
        "future",
        "cross-origin",
        "cross-site",
        "foreign-host",
    ],
)
def test_operator_dependency_fails_closed_independently_of_route_middleware(subject, condition):
    ui, _ = subject
    guard = OperatorSessionGuard(None, required=True, secret=SECRET)
    time = (
        CURRENT - 28801
        if condition == "expired"
        else CURRENT + 1
        if condition == "future"
        else CURRENT
    )
    cookie = guard.signed_cookie(time)
    headers = [(b"host", b"127.0.0.1:8088"), (b"cookie", f"{COOKIE_NAME}={cookie}".encode())]
    if condition == "disabled":
        ui.settings.operator_auth_required = False
    elif condition == "no-cookie":
        headers.pop()
    elif condition == "forged-cookie":
        headers[-1] = (b"cookie", f"{COOKIE_NAME}={CURRENT}.{'0' * 64}".encode())
    elif condition == "cross-origin":
        headers.append((b"origin", b"https://evil.invalid"))
    elif condition == "cross-site":
        headers.append((b"sec-fetch-site", b"cross-site"))
    elif condition == "foreign-host":
        headers[0] = (b"host", b"evil.invalid")
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": "/api/tasks/x/credentials/y/revoke",
            "query_string": b"",
            "headers": headers,
            "server": ("127.0.0.1", 8088),
        }
    )
    with pytest.raises(UiApiError) as caught:
        sidecar.authenticated_operator(request, ui.settings, operator_id=OPERATOR)
    assert caught.value.status_code in {401, 403}


def test_operator_identity_is_server_configured_not_forwarded_from_request_headers(subject):
    ui, _ = subject
    cookie = OperatorSessionGuard(None, required=True, secret=SECRET).signed_cookie(CURRENT)
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": "/api/tasks/x/credentials/y/revoke",
            "query_string": b"",
            "headers": [
                (b"host", b"127.0.0.1:8088"),
                (b"cookie", f"{COOKIE_NAME}={cookie}".encode()),
                (b"x-operator-id", b"browser-user"),
            ],
            "server": ("127.0.0.1", 8088),
        }
    )
    assert sidecar.authenticated_operator(request, ui.settings, operator_id=OPERATOR) == OPERATOR
