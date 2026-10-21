"""BFF boundary tests with structural fixtures, never real approval signatures."""

from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

import backend.crypto.sm as sm_module
import backend.ui_api.service as service_module
from backend.authorization.policy import build_root_capabilities
from backend.coauthorization.contracts import (
    MAX_BUNDLE_BYTES,
    ApprovalPayload,
    ChallengeResponse,
    CoauthorizationBundle,
    CoauthorizationHistoryEntry,
    CoauthorizationResponse,
    CoauthorizationTaskReview,
)
from backend.coauthorization.verifier import approval_payload_hash, build_approval_statement
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.ui_api.app import make_app
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore

NOW = 1_800_000_120
TASK_ID = "TASK-APPROVAL-01"
AUTHORITY_PATH = f"/extensions/coauthorization/v1/tasks/{TASK_ID}"
BFF_PATH = f"/api{AUTHORITY_PATH}"
MAX_RESPONSE_BYTES = 2_097_152
REDACTION_MARKER = "FORBIDDEN_TEST_DATA"
CHALLENGE_REQUEST = {
    "holder_agent_id": "agent-coordinator", "holder_key_id": "agent-coordinator-key-01",
    "delegation_depth": 2,
}


def _raw(document: dict) -> bytes:
    return json.dumps(document, indent=2, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"


def _signature(key_id: str, signed_at: int) -> dict:
    # A zero signature is a valid encoding fixture, not a verified SM2 signature.
    return {
        "algorithm": "SM2", "key_id": key_id, "key_purpose": "AUTHORIZATION_ROOT_SIGNING",
        "encoding": "SM2_RS_HEX_128_LOWERCASE", "value": "0" * 128, "signed_at": signed_at,
    }


@pytest.fixture
def case() -> dict:
    capabilities = build_root_capabilities(ticket_id="T10086", customer_id="C9527", refund_total_fen=7_000)
    payload = ApprovalPayload.model_validate({
        "schema_version": "1.0", "payload_type": "COAUTHORIZATION_TASK_APPROVAL",
        "approval_purpose": "TASK_COAUTHORIZATION_APPROVAL_V1",
        "verifier_audience": "agentguard-root-authorization",
        "tenant_id": "tenant-A", "task_id": TASK_ID, "ticket_id": "T10086", "customer_id": "C9527",
        "capabilities_hash": sm3_hex(canonicalize({"capabilities": capabilities})),
        "quotas": {"refund_total_fen": 7_000, "max_tool_calls": 4},
        "holder": {"agent_id": "agent-coordinator", "key_id": "agent-coordinator-key-01"},
        "not_before": NOW - 100, "expires_at": NOW + 1_800, "delegation_depth": 2,
        "policy_revision": "refund-approval-policy-v1",
        "required_signers": {
            "enterprise_approver": {"subject_id": "enterprise-approver", "key_id": "enterprise-key-01"},
            "finance_approver": {"subject_id": "finance-approver", "key_id": "finance-key-01"},
        },
        "challenge_id": "challenge-01", "approval_not_before": NOW - 60, "approval_expires_at": NOW + 120,
    })
    approvals = []
    for index, role in enumerate(("ENTERPRISE_APPROVER", "FINANCE_APPROVER")):
        statement = build_approval_statement(
            payload=payload, role=role, approved_at=NOW - 20 + index,
        ).model_dump(mode="json")
        approvals.append({"statement": statement, "signature": _signature(statement["key_id"], statement["approved_at"])})
    bundle = CoauthorizationBundle.model_validate({
        "payload": payload.model_dump(mode="json"), "approvals": approvals,
    }).model_dump(mode="json")
    challenge = ChallengeResponse.model_validate({
        "payload": payload.model_dump(mode="json"), "approval_payload_hash": approval_payload_hash(payload),
        "task_capabilities": capabilities,
    }).model_dump(mode="json")
    # All required fields of the frozen ROOT schema, with no claim of issuance.
    credential = {
        "payload": {
            "schema_version": "1.0", "credential_id": "root-01", "credential_type": "ROOT",
            "issuer": {"subject_id": "authority", "key_id": "authority-key-01"},
            "holder": payload.holder.model_dump(mode="json"), "tenant_id": payload.tenant_id,
            "task_id": payload.task_id, "verifier_audience": "secure-tool-gateway",
            "capabilities": deepcopy(capabilities), "quotas": payload.quotas.model_dump(mode="json"),
            "not_before": payload.not_before, "expires_at": payload.expires_at,
            "delegation_depth": payload.delegation_depth, "parent_credential_id": None,
            "parent_credential_hash": None, "issued_at": NOW - 10,
        },
        "signature": _signature("authority-key-01", NOW - 10),
    }
    authorization = CoauthorizationResponse.model_validate({
        "challenge_id": payload.challenge_id, "approval_payload_hash": approval_payload_hash(payload),
        "bundle_hash": sm3_hex(canonicalize(bundle)), "root_credential_id": "root-01",
        "root_credential_hash": signed_object_hash(credential), "reused": False, "credential": credential,
    }).model_dump(mode="json")
    return {
        "payload": payload, "capabilities": capabilities, "bundle": bundle, "raw": _raw(bundle),
        "challenge": challenge, "authorization": authorization,
    }


def _history(case, *, offset=0, consumed=False) -> dict:
    payload = case["payload"]
    entry = CoauthorizationHistoryEntry.model_validate({
        "challenge_id": payload.challenge_id, "challenge_status": "CONSUMED" if consumed else "PENDING",
        "window_state": "OPEN", "issued_at": payload.approval_not_before, "expires_at": payload.approval_expires_at,
        "consumed_at": NOW - 10 if consumed else None, "revoked_at": None,
        "payload": payload.model_dump(mode="json"), "approval_payload_hash": approval_payload_hash(payload),
        "task_capabilities": case["capabilities"],
        "bundle_hash": case["authorization"]["bundle_hash"] if consumed else None,
        "signed_bundle": case["bundle"] if consumed else None,
        "root_credential_id": "root-01" if consumed else None,
        "root_credential_hash": case["authorization"]["root_credential_hash"] if consumed else None,
    })
    return CoauthorizationTaskReview(
        task_id=TASK_ID, task_status="AUTHORIZED" if consumed else "PENDING_AUTHORIZATION",
        observed_at=NOW, offset=offset, has_more=False, items=[entry],
    ).model_dump(mode="json")


@pytest.fixture
def subject() -> UiService:
    return UiService(
        SimpleNamespace(
            authority_url="https://authority.invalid", ui_request_timeout_seconds=3.25,
            internal_auth_required=False, internal_auth_service_id="", internal_auth_keys="{}",
            operator_auth_required=False, operator_session_secret="",
        ),
        Mock(spec=UiReadStore),
    )


@pytest.fixture(autouse=True)
def no_store_or_signature_access(subject, monkeypatch):
    guards = []
    for name in ("sign_payload", "verify_payload"):
        guard = Mock(side_effect=AssertionError("BFF must not sign or verify approval signatures"))
        monkeypatch.setattr(sm_module, name, guard)
        guards.append(guard)
    yield
    assert subject.store.mock_calls == []
    for guard in guards:
        guard.assert_not_called()


def _client(subject) -> TestClient:
    return TestClient(make_app(settings=subject.settings, service=subject))


def _set_path(document, path, value) -> None:
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = deepcopy(value)


def _invalid_bundle(case, kind) -> bytes:
    bundle = deepcopy(case["bundle"])
    if kind == "duplicate":
        return b'{"payload":{},' + _raw(bundle)[1:]
    if kind == "nested-duplicate":
        return _raw(bundle).replace(b'"refund_total_fen": 7000', b'"refund_total_fen":7000,"refund_total_fen":8000')
    if kind == "oversize":
        return case["raw"] + b" " * (MAX_BUNDLE_BYTES + 1 - len(case["raw"]))
    if kind == "empty":
        return b""
    if kind == "scientific":
        return _raw(bundle).replace(b'"refund_total_fen": 7000', b'"refund_total_fen":7e3')
    if kind == "float":
        bundle["payload"]["quotas"]["refund_total_fen"] = 7_000.0
    elif kind == "boolean":
        bundle["payload"]["quotas"]["max_tool_calls"] = True
    elif kind == "unsafe-integer":
        bundle["payload"]["quotas"]["max_tool_calls"] = 9_007_199_254_740_992
    elif kind == "extra":
        bundle["current_valid"] = REDACTION_MARKER
    elif kind == "private-payload":
        bundle["payload"]["private_key"] = REDACTION_MARKER
    elif kind == "private-holder":
        bundle["payload"]["holder"]["private_key"] = REDACTION_MARKER
    elif kind == "private-signature":
        bundle["approvals"][0]["signature"]["private_key"] = REDACTION_MARKER
    elif kind == "cross-task":
        bundle["payload"]["task_id"] = "another-task"
    else:
        raise AssertionError(f"unknown fixture mutation: {kind}")
    return _raw(bundle)


@pytest.mark.parametrize("kind", [
    "duplicate", "nested-duplicate", "oversize", "empty", "scientific", "float", "boolean",
    "unsafe-integer", "extra", "private-payload", "private-holder", "private-signature", "cross-task",
])
def test_bff_rejects_invalid_raw_bundle_before_upstream_and_redacts_input(subject, case, monkeypatch, kind) -> None:
    upstream = Mock(side_effect=AssertionError("invalid bundle must not reach Authority"))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).post(
        f"{BFF_PATH}/authorize", content=_invalid_bundle(case, kind),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert set(response.json()) == {"reason_code", "message"}
    assert response.json()["reason_code"] == "COAUTH_INVALID_BUNDLE"
    assert REDACTION_MARKER not in response.text
    assert "enterprise-key-01" not in response.text
    assert "another-task" not in response.text
    upstream.assert_not_called()


@pytest.mark.parametrize("raw", [None, {}, bytearray(b"{}"), "{}"])
def test_bff_service_requires_bytes_without_calling_upstream(subject, monkeypatch, raw) -> None:
    upstream = Mock(side_effect=AssertionError("nonbytes must not reach Authority"))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    with pytest.raises(UiApiError) as caught:
        subject.authorize_coauthorization_task(TASK_ID, raw)
    assert caught.value.reason_code == "COAUTH_INVALID_BUNDLE"
    assert caught.value.status_code == 400
    upstream.assert_not_called()


def test_authorization_service_passes_matching_raw_bytes_without_reserialization(subject, case, monkeypatch) -> None:
    upstream = Mock(return_value=deepcopy(case["authorization"]))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    result = subject.authorize_coauthorization_task(TASK_ID, case["raw"])
    assert result == case["authorization"]
    upstream.assert_called_once_with("POST", f"{AUTHORITY_PATH}/authorize", raw_body=case["raw"])
    assert upstream.call_args.kwargs["raw_body"] is case["raw"]
    assert case["raw"] != canonicalize(case["bundle"])


@pytest.mark.parametrize("size", [MAX_BUNDLE_BYTES - 1, MAX_BUNDLE_BYTES, MAX_BUNDLE_BYTES + 1])
def test_bff_api_bundle_byte_limit_is_inclusive(subject, case, monkeypatch, size) -> None:
    raw = case["raw"] + b" " * (size - len(case["raw"]))
    upstream = Mock(return_value=deepcopy(case["authorization"]))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).post(
        f"{BFF_PATH}/authorize", content=raw, headers={"content-type": "Application/JSON; charset=utf-8"},
    )
    if size > MAX_BUNDLE_BYTES:
        assert response.status_code == 400
        assert response.json()["reason_code"] == "COAUTH_INVALID_BUNDLE"
        upstream.assert_not_called()
    else:
        assert response.status_code == 200
        assert response.json() == case["authorization"]
        upstream.assert_called_once_with("POST", f"{AUTHORITY_PATH}/authorize", raw_body=raw)


@pytest.mark.parametrize("content_type", ["", "text/plain", "application/octet-stream", "application/jsonx"])
def test_bff_api_requires_json_content_type_before_upstream(subject, case, monkeypatch, content_type) -> None:
    upstream = Mock(side_effect=AssertionError("bad content type must not reach Authority"))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).post(
        f"{BFF_PATH}/authorize", content=case["raw"], headers={"content-type": content_type},
    )
    assert response.status_code == 400
    assert response.json()["reason_code"] == "COAUTH_INVALID_BUNDLE"
    upstream.assert_not_called()


@pytest.mark.parametrize("raw", [
    b'{"holder_agent_id":"agent","holder_agent_id":"other","holder_key_id":"key","delegation_depth":2}',
    b'{"holder_agent_id":"agent","holder_key_id":"key","delegation_depth":2.0}',
    b'{"holder_agent_id":"agent","holder_key_id":"key","delegation_depth":true}',
    b'{"holder_agent_id":"agent","holder_key_id":"key","delegation_depth":2,"private_key":"FORBIDDEN_TEST_DATA"}',
    b'{"holder_agent_id":"agent","holder_key_id":"key","delegation_depth":2,"policy_revision":"FORBIDDEN_TEST_DATA"}',
    b'{"holder_agent_id":"agent","holder_key_id":"key","delegation_depth":2,"public_key_hex":"FORBIDDEN_TEST_DATA"}',
])
def test_challenge_api_rejects_ambiguous_or_client_selected_policy_material(subject, monkeypatch, raw) -> None:
    upstream = Mock(side_effect=AssertionError("invalid challenge must not reach Authority"))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).post(
        f"{BFF_PATH}/challenges", content=raw, headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert set(response.json()) == {"reason_code", "message"}
    assert response.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"
    assert REDACTION_MARKER not in response.text
    upstream.assert_not_called()


def test_bff_challenge_validates_authority_scope_and_only_forwards_public_request(subject, case, monkeypatch) -> None:
    upstream = Mock(return_value=deepcopy(case["challenge"]))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).post(f"{BFF_PATH}/challenges", json=CHALLENGE_REQUEST)
    assert response.status_code == 200
    assert response.json() == case["challenge"]
    upstream.assert_called_once_with("POST", f"{AUTHORITY_PATH}/challenges", body=CHALLENGE_REQUEST)


@pytest.mark.parametrize("path,value", [
    (("payload", "task_id"), "another-task"), (("approval_payload_hash",), "0" * 64),
    (("payload", "holder", "agent_id"), "another-holder"),
    (("payload", "holder", "key_id"), "another-holder-key"),
    (("payload", "delegation_depth"), 1),
    (("task_capabilities", 0, "resources", "ticket_ids"), ["another-ticket"]),
    (("task_capabilities", 2, "constraints", "single_max_fen"), 6_999),
    (("challenge_status",), "CONSUMED"), (("current_valid",), REDACTION_MARKER),
])
def test_bff_invalid_challenge_result_is_an_error_not_success(subject, case, monkeypatch, path, value) -> None:
    document = deepcopy(case["challenge"])
    _set_path(document, path, value)
    if path[0] == "payload":
        document["approval_payload_hash"] = approval_payload_hash(ApprovalPayload.model_validate(document["payload"]))
    upstream = Mock(return_value=document)
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).post(f"{BFF_PATH}/challenges", json=CHALLENGE_REQUEST)
    assert response.status_code == 502
    assert response.json()["reason_code"] == "CONTROLLED_RESULT_INVALID"
    assert set(response.json()) == {"reason_code", "message"}
    assert REDACTION_MARKER not in response.text
    upstream.assert_called_once_with("POST", f"{AUTHORITY_PATH}/challenges", body=CHALLENGE_REQUEST)


@pytest.mark.parametrize("consumed", [False, True])
@pytest.mark.parametrize("offset", [0, 20, 1_000_000])
def test_bff_history_preserves_stored_observation_and_matching_offset(subject, case, monkeypatch, consumed, offset) -> None:
    document = _history(case, offset=offset, consumed=consumed)
    upstream = Mock(return_value=document)
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).get(BFF_PATH, params={"offset": offset})
    assert response.status_code == 200
    assert response.json() == document
    assert response.json()["observation_kind"] == "STORED_EVIDENCE_NOT_REVALIDATED"
    assert "current_valid" not in response.json()
    upstream.assert_called_once_with("GET", AUTHORITY_PATH, params={"offset": offset})


@pytest.mark.parametrize("consumed,path,value", [
    (False, ("task_id",), "another-task"), (False, ("offset",), 1),
    (False, ("items", 0, "payload", "task_id"), "another-task"),
    (False, ("items", 0, "approval_payload_hash"), "0" * 64),
    (False, ("items", 0, "task_capabilities", 2, "constraints", "single_max_fen"), 6_999),
    (False, ("items", 0, "window_state"), "EXPIRED"),
    (False, ("items", 0, "root_credential_id"), "root-01"),
    (False, ("items", 0, "challenge_status"), "CONSUMED"),
    (False, ("items", 0, "revoked_at"), NOW - 5),
    (False, ("observation_kind",), "CURRENT_SIGNATURES_VALID"),
    (False, ("current_valid",), REDACTION_MARKER),
    (True, ("items", 0, "bundle_hash"), "0" * 64),
])
def test_bff_rejects_cross_task_hash_state_or_fresh_validity_history(subject, case, monkeypatch, consumed, path, value) -> None:
    document = _history(case, consumed=consumed)
    _set_path(document, path, value)
    upstream = Mock(return_value=document)
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).get(BFF_PATH)
    assert response.status_code == 502
    assert set(response.json()) == {"reason_code", "message"}
    assert response.json()["reason_code"] == "CONTROLLED_RESULT_INVALID"
    assert REDACTION_MARKER not in response.text
    upstream.assert_called_once_with("GET", AUTHORITY_PATH, params={"offset": 0})


def test_bff_rejects_duplicate_history_entries(subject, case, monkeypatch) -> None:
    document = _history(case)
    document["items"].append(deepcopy(document["items"][0]))
    monkeypatch.setattr(subject, "_coauthorization_request", Mock(return_value=document))
    response = _client(subject).get(BFF_PATH)
    assert response.status_code == 502
    assert response.json()["reason_code"] == "CONTROLLED_RESULT_INVALID"
    assert "items" not in response.json()


@pytest.mark.parametrize("error", [
    UiApiError("UPSTREAM_UNAVAILABLE", "Authority unavailable", status_code=503),
    UiApiError("COAUTH_STORED_EVIDENCE_INVALID", "stored evidence invalid", status_code=503),
])
def test_bff_history_failure_is_not_empty_history(subject, monkeypatch, error) -> None:
    upstream = Mock(side_effect=error)
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).get(BFF_PATH)
    assert response.status_code == 503
    assert set(response.json()) == {"reason_code", "message"}
    assert response.json()["reason_code"] == error.reason_code
    upstream.assert_called_once_with("GET", AUTHORITY_PATH, params={"offset": 0})


@pytest.mark.parametrize("path,value", [
    (("challenge_id",), "another-challenge"), (("approval_payload_hash",), "0" * 64),
    (("bundle_hash",), "0" * 64), (("root_credential_id",), "another-root"),
    (("root_credential_hash",), "0" * 64), (("reused",), "true"),
    (("current_valid",), REDACTION_MARKER),
    (("credential", "payload", "task_id"), "another-task"),
    (("credential", "payload", "credential_id"), "another-root"),
    (("credential", "payload", "credential_type"), "DELEGATED"),
    (("credential", "payload", "tenant_id"), "another-tenant"),
    (("credential", "payload", "holder", "agent_id"), "another-holder"),
    (("credential", "payload", "holder", "key_id"), "another-holder-key"),
    (("credential", "payload", "quotas", "refund_total_fen"), 6_999),
    (("credential", "payload", "quotas", "max_tool_calls"), 5),
    (("credential", "payload", "not_before"), NOW - 99),
    (("credential", "payload", "expires_at"), NOW + 1_799),
    (("credential", "payload", "delegation_depth"), 1),
    (("credential", "payload", "capabilities", 0, "resources", "ticket_ids"), ["another-ticket"]),
    (("credential", "payload", "capabilities", 2, "constraints", "single_max_fen"), 6_999),
    (("credential", "payload", "capabilities", 3, "constraints", "template_ids"), ["another-template"]),
    (("credential", "signature", "key_id"), "another-authority-key"),
    (("credential", "signature", "key_purpose"), "AGENT_HOLDER_SIGNING"),
    (("credential", "signature", "signed_at"), NOW - 9),
    (("credential", "signature", "private_key"), REDACTION_MARKER),
])
def test_invalid_authorization_result_is_unconfirmed_and_does_not_echo_submission(
    subject, case, monkeypatch, path, value,
) -> None:
    document = deepcopy(case["authorization"])
    _set_path(document, path, value)
    if path[0] == "credential":
        # A matching recomputed root digest must not hide a mismatched task scope.
        document["root_credential_hash"] = signed_object_hash(document["credential"])
    upstream = Mock(return_value=document)
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).post(
        f"{BFF_PATH}/authorize", content=case["raw"], headers={"content-type": "application/json"},
    )
    assert response.status_code == 502
    assert set(response.json()) == {"reason_code", "message"}
    assert response.json()["reason_code"] == "COAUTH_RESULT_UNCONFIRMED"
    assert REDACTION_MARKER not in response.text
    assert "enterprise-key-01" not in response.text
    assert "another-task" not in response.text
    upstream.assert_called_once_with("POST", f"{AUTHORITY_PATH}/authorize", raw_body=case["raw"])


@pytest.mark.parametrize("document", [{}, [], None])
def test_missing_authorization_result_stays_unknown(subject, case, monkeypatch, document) -> None:
    upstream = Mock(return_value=document)
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).post(
        f"{BFF_PATH}/authorize", content=case["raw"], headers={"content-type": "application/json"},
    )
    assert response.status_code == 502
    assert response.json()["reason_code"] == "COAUTH_RESULT_UNCONFIRMED"
    assert set(response.json()) == {"reason_code", "message"}
    upstream.assert_called_once_with("POST", f"{AUTHORITY_PATH}/authorize", raw_body=case["raw"])


@pytest.mark.parametrize("suffix,method", [("", "GET"), ("/challenges", "POST"), ("/authorize", "POST")])
@pytest.mark.parametrize("task_id", ["invalid!id", "a" * 129])
def test_bff_path_identifier_rejected_before_upstream(subject, case, monkeypatch, suffix, method, task_id) -> None:
    upstream = Mock(side_effect=AssertionError("invalid path must not reach Authority"))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    client = _client(subject)
    path = f"/api/extensions/coauthorization/v1/tasks/{task_id}{suffix}"
    if method == "GET":
        response = client.get(path)
    elif suffix == "/challenges":
        response = client.post(path, json=CHALLENGE_REQUEST)
    else:
        response = client.post(path, content=case["raw"], headers={"content-type": "application/json"})
    assert response.status_code == 400
    assert response.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"
    upstream.assert_not_called()


@pytest.mark.parametrize("offset", ["-1", "1000001", "1.5", "not-an-integer"])
def test_bff_query_offset_rejected_before_upstream(subject, monkeypatch, offset) -> None:
    upstream = Mock(side_effect=AssertionError("invalid offset must not reach Authority"))
    monkeypatch.setattr(subject, "_coauthorization_request", upstream)
    response = _client(subject).get(BFF_PATH, params={"offset": offset})
    assert response.status_code == 400
    assert response.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"
    upstream.assert_not_called()


def test_bff_generated_openapi_describes_raw_bundle_and_history_boundaries(subject) -> None:
    app = make_app(settings=subject.settings, service=subject)
    document = app.openapi()
    operation = document["paths"]["/api/extensions/coauthorization/v1/tasks/{task_id}/authorize"]["post"]
    body = operation["requestBody"]
    assert body["required"] is True
    assert "32768" in body["description"]
    assert set(body["content"]) == {"application/json"}
    assert body["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/UiCoauthV1Bundle"}
    bundle = document["components"]["schemas"]["UiCoauthV1Bundle"]
    assert bundle["additionalProperties"] is False
    assert set(bundle["required"]) == {"payload", "approvals"}
    assert bundle["properties"]["payload"]["$ref"] == "#/components/schemas/UiCoauthV1ApprovalPayload"
    assert bundle["properties"]["approvals"]["minItems"] == 2
    assert bundle["properties"]["approvals"]["maxItems"] == 2
    route = next(route for route in app.routes if route.path == "/api/extensions/coauthorization/v1/tasks/{task_id}/authorize")
    assert route.body_field is None
    parameters = document["paths"]["/api/extensions/coauthorization/v1/tasks/{task_id}"]["get"]["parameters"]
    offset = next(item["schema"] for item in parameters if item["name"] == "offset")
    assert offset["default"] == 0
    assert offset["minimum"] == 0
    assert offset["maximum"] == 1_000_000


def _install_transport(monkeypatch, handler):
    # Save the actual constructor before patching the shared httpx module.
    original_client = httpx.Client
    requests = []

    def record(request):
        request.read()
        requests.append(request)
        return handler(request)

    transport = httpx.MockTransport(record)

    def create_client(*args, **options):
        return original_client(*args, transport=transport, **options)

    factory = Mock(side_effect=create_client)
    monkeypatch.setattr(service_module.httpx, "Client", factory)
    return requests, factory


def _assert_one_client(subject, requests, factory) -> None:
    assert len(requests) == 1, "a failed or unconfirmed authorization must not be retried"
    factory.assert_called_once_with(
        base_url=subject.settings.authority_url, timeout=subject.settings.ui_request_timeout_seconds,
        trust_env=False,
    )


def _transport_request(subject, case, mode):
    if mode == "history":
        return subject._coauthorization_request("GET", AUTHORITY_PATH, params={"offset": 20})
    if mode == "challenge":
        return subject._coauthorization_request("POST", f"{AUTHORITY_PATH}/challenges", body=CHALLENGE_REQUEST)
    assert mode == "authorize"
    return subject._coauthorization_request("POST", f"{AUTHORITY_PATH}/authorize", raw_body=case["raw"])


class _Chunks(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    def close(self) -> None:
        self.closed = True


def test_real_mock_transport_receives_authorization_bytes_exactly_once(subject, case, monkeypatch) -> None:
    requests, factory = _install_transport(
        monkeypatch, lambda _request: httpx.Response(200, json=case["authorization"]),
    )
    response = _client(subject).post(
        f"{BFF_PATH}/authorize", content=case["raw"], headers={"content-type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json() == case["authorization"]
    _assert_one_client(subject, requests, factory)
    assert requests[0].method == "POST"
    assert str(requests[0].url) == f"https://authority.invalid{AUTHORITY_PATH}/authorize"
    assert requests[0].headers["content-type"] == "application/json"
    assert requests[0].content == case["raw"]


@pytest.mark.parametrize("mode", ["history", "challenge"])
def test_real_mock_transport_receives_history_offset_or_public_challenge_body(subject, case, monkeypatch, mode) -> None:
    document = _history(case, offset=20) if mode == "history" else case["challenge"]
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(200, json=document))
    if mode == "history":
        response = _client(subject).get(BFF_PATH, params={"offset": 20})
    else:
        response = _client(subject).post(f"{BFF_PATH}/challenges", json=CHALLENGE_REQUEST)
    assert response.status_code == 200
    assert response.json() == document
    _assert_one_client(subject, requests, factory)
    if mode == "history":
        assert requests[0].method == "GET"
        assert str(requests[0].url) == f"https://authority.invalid{AUTHORITY_PATH}?offset=20"
        assert requests[0].content == b""
    else:
        assert requests[0].method == "POST"
        assert str(requests[0].url) == f"https://authority.invalid{AUTHORITY_PATH}/challenges"
        assert json.loads(requests[0].content) == CHALLENGE_REQUEST
        assert requests[0].headers["content-type"] == "application/json"


@pytest.mark.parametrize("mode", ["history", "challenge", "authorize"])
@pytest.mark.parametrize("oversize", [False, True])
def test_transport_enforces_two_mib_on_actual_stream_bytes(subject, case, monkeypatch, mode, oversize) -> None:
    prefix = b'{"ok":true}'
    chunks = [prefix + b" " * (MAX_RESPONSE_BYTES - len(prefix))]
    if oversize:
        chunks.extend([b" ", REDACTION_MARKER.encode("ascii")])
    stream = _Chunks(chunks)
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(
        200, headers={"content-type": "application/json", "content-length": "1"}, stream=stream,
    ))
    if oversize:
        with pytest.raises(UiApiError) as caught:
            _transport_request(subject, case, mode)
        expected = "COAUTH_RESULT_UNCONFIRMED" if mode == "authorize" else "CONTROLLED_RESULT_INVALID"
        assert caught.value.reason_code == expected
        assert caught.value.status_code == 502
        assert REDACTION_MARKER not in str(caught.value)
        assert stream.yielded == 2, "stop at the overflowing chunk, without reading the remainder"
    else:
        assert _transport_request(subject, case, mode) == {"ok": True}
        assert stream.yielded == 1
    assert stream.closed is True
    _assert_one_client(subject, requests, factory)


@pytest.mark.parametrize("mode", ["history", "challenge", "authorize"])
@pytest.mark.parametrize("status,raw_response", [
    (200, b'{"enabled":true,"enabled":false}'),
    (403, b'{"reason_code":"COAUTH_KEY_NOT_ACTIVE","reason_code":"COAUTH_INVALID_BUNDLE","message":"FORBIDDEN_TEST_DATA"}'),
    (200, b'{"quota":1.0}'), (200, b'{"quota":9007199254740992}'),
    (200, b"[]"), (200, b"null"), (200, b""), (200, b"\xff"),
])
def test_transport_rejects_ambiguous_or_nonobject_strict_json_response(
    subject, case, monkeypatch, mode, status, raw_response,
) -> None:
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(status, content=raw_response))
    with pytest.raises(UiApiError) as caught:
        _transport_request(subject, case, mode)
    expected = "COAUTH_RESULT_UNCONFIRMED" if mode == "authorize" else "CONTROLLED_RESULT_INVALID"
    assert caught.value.reason_code == expected
    assert caught.value.status_code == 502
    assert REDACTION_MARKER not in str(caught.value)
    _assert_one_client(subject, requests, factory)


@pytest.mark.parametrize("mode", ["history", "challenge", "authorize"])
@pytest.mark.parametrize("status,code", [
    (400, "COAUTH_INVALID_BUNDLE"), (400, "REQUEST_SCHEMA_INVALID"),
    (403, "COAUTH_KEY_NOT_ACTIVE"), (403, "COAUTH_INVALID_TRUSTED_CONTEXT"),
    (404, "COAUTH_DISABLED"), (409, "COAUTH_CHALLENGE_CONFLICT"),
    (409, "COAUTH_IDEMPOTENCY_CONFLICT"), (409, "COAUTH_TASK_NOT_AUTHORIZABLE"),
])
def test_exact_known_four_xx_error_is_deterministic_and_message_is_redacted(
    subject, case, monkeypatch, mode, status, code,
) -> None:
    document = {"reason_code": code, "message": REDACTION_MARKER}
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(status, json=document))
    with pytest.raises(UiApiError) as caught:
        _transport_request(subject, case, mode)
    assert caught.value.reason_code == code
    assert caught.value.status_code == status
    assert REDACTION_MARKER not in str(caught.value)
    _assert_one_client(subject, requests, factory)


@pytest.mark.parametrize("mode", ["history", "challenge", "authorize"])
@pytest.mark.parametrize("status,document", [
    (400, {}), (400, {"message": REDACTION_MARKER}),
    (400, {"reason_code": "COAUTH_INVALID_BUNDLE"}),
    (400, {"reason_code": "COAUTH_INVALID_BUNDLE", "message": None}),
    (400, {"reason_code": "COAUTH_INVALID_BUNDLE", "message": 17}),
    (400, {"reason_code": "UNKNOWN_UPSTREAM_REASON", "message": REDACTION_MARKER}),
    (400, {"reason_code": True, "message": REDACTION_MARKER}),
    (400, {"reason_code": "COAUTH_INVALID_BUNDLE", "message": REDACTION_MARKER, "submitted_bundle": REDACTION_MARKER}),
    (403, {"reason_code": "COAUTH_INVALID_BUNDLE", "message": REDACTION_MARKER}),
    (400, {"reason_code": "COAUTH_KEY_NOT_ACTIVE", "message": REDACTION_MARKER}),
    (404, {"reason_code": "COAUTH_TASK_NOT_AUTHORIZABLE", "message": REDACTION_MARKER}),
    (409, {"reason_code": "COAUTH_DISABLED", "message": REDACTION_MARKER}),
])
def test_malformed_unknown_or_wrong_http_error_is_not_a_deterministic_rejection(
    subject, case, monkeypatch, mode, status, document,
) -> None:
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(status, json=document))
    with pytest.raises(UiApiError) as caught:
        _transport_request(subject, case, mode)
    expected = "COAUTH_RESULT_UNCONFIRMED" if mode == "authorize" else "CONTROLLED_RESULT_INVALID"
    assert caught.value.reason_code == expected
    assert caught.value.status_code == 502
    assert REDACTION_MARKER not in str(caught.value)
    assert "UNKNOWN_UPSTREAM_REASON" not in str(caught.value)
    _assert_one_client(subject, requests, factory)


@pytest.mark.parametrize("status,expected_status", [
    (201, 502), (302, 502), (401, 502), (422, 502), (429, 502),
    (500, 502), (502, 502), (503, 503),
])
def test_authorization_nondeterministic_http_result_is_unconfirmed_without_retry(
    subject, case, monkeypatch, status, expected_status,
) -> None:
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(
        status, json={"reason_code": "COAUTH_REGISTRY_UNAVAILABLE", "message": REDACTION_MARKER},
    ))
    response = _client(subject).post(
        f"{BFF_PATH}/authorize", content=case["raw"], headers={"content-type": "application/json"},
    )
    assert response.status_code == expected_status
    assert set(response.json()) == {"reason_code", "message"}
    assert response.json()["reason_code"] == "COAUTH_RESULT_UNCONFIRMED"
    assert REDACTION_MARKER not in response.text
    assert "enterprise-key-01" not in response.text
    _assert_one_client(subject, requests, factory)
    assert requests[0].content == case["raw"]


@pytest.mark.parametrize("mode", ["history", "challenge"])
@pytest.mark.parametrize("code", ["COAUTH_REGISTRY_UNAVAILABLE", "COAUTH_STORED_EVIDENCE_INVALID"])
def test_read_and_challenge_preserve_exact_known_storage_failure(subject, case, monkeypatch, mode, code) -> None:
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(
        503, json={"reason_code": code, "message": REDACTION_MARKER},
    ))
    with pytest.raises(UiApiError) as caught:
        _transport_request(subject, case, mode)
    assert caught.value.reason_code == code
    assert caught.value.status_code == 503
    assert REDACTION_MARKER not in str(caught.value)
    _assert_one_client(subject, requests, factory)


@pytest.mark.parametrize("mode", ["history", "challenge", "authorize"])
@pytest.mark.parametrize("error_type", [httpx.ReadTimeout, httpx.ConnectTimeout, httpx.ConnectError, httpx.RemoteProtocolError])
def test_http_error_has_unknown_authorization_result_and_no_automatic_retry(subject, case, monkeypatch, mode, error_type) -> None:
    def fail(request):
        raise error_type(REDACTION_MARKER, request=request)

    requests, factory = _install_transport(monkeypatch, fail)
    with pytest.raises(UiApiError) as caught:
        _transport_request(subject, case, mode)
    expected = "COAUTH_RESULT_UNCONFIRMED" if mode == "authorize" else "UPSTREAM_UNAVAILABLE"
    assert caught.value.reason_code == expected
    assert caught.value.status_code == 503
    assert REDACTION_MARKER not in str(caught.value)
    _assert_one_client(subject, requests, factory)


def test_unconfigured_authority_fails_before_creating_http_client(subject, monkeypatch) -> None:
    subject.settings.authority_url = ""
    factory = Mock(side_effect=AssertionError("an unconfigured Authority cannot receive a request"))
    monkeypatch.setattr(service_module.httpx, "Client", factory)
    with pytest.raises(UiApiError) as caught:
        subject._coauthorization_request("GET", AUTHORITY_PATH)
    assert caught.value.reason_code == "UPSTREAM_UNAVAILABLE"
    assert caught.value.status_code == 503
    factory.assert_not_called()


def _status(enabled=True) -> dict:
    return {
        "schema_version": "1.0", "enabled": enabled,
        "policy_source": "SERVER_REGISTERED_PUBLIC_KEYS", "signing": "EXTERNAL_APPROVERS_ONLY",
    }


@pytest.mark.parametrize("enabled", [False, True])
def test_status_endpoint_uses_the_bounded_strict_transport(subject, monkeypatch, enabled) -> None:
    document = _status(enabled)
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(200, json=document))
    response = _client(subject).get("/api/extensions/coauthorization/v1/status")
    assert response.status_code == 200
    assert response.json() == document
    _assert_one_client(subject, requests, factory)
    assert requests[0].method == "GET"
    assert str(requests[0].url) == "https://authority.invalid/extensions/coauthorization/v1/status"
    assert requests[0].content == b""


@pytest.mark.parametrize("kind", ["duplicate-enabled", "oversize", "nonboolean-enabled", "wrong-http-code"])
def test_status_response_ambiguity_or_oversize_never_becomes_disabled_status(subject, monkeypatch, kind) -> None:
    document = _status()
    status = 200
    if kind == "duplicate-enabled":
        raw = _raw(document).replace(b'"enabled": true', b'"enabled":true,"enabled":false')
    elif kind == "oversize":
        raw = _raw(document)
        raw += b" " * (MAX_RESPONSE_BYTES + 1 - len(raw))
    elif kind == "nonboolean-enabled":
        document["enabled"] = "true"
        raw = _raw(document)
    else:
        status = 403
        raw = _raw({"reason_code": "COAUTH_INVALID_BUNDLE", "message": REDACTION_MARKER})
    requests, factory = _install_transport(monkeypatch, lambda _request: httpx.Response(
        status, content=raw, headers={"content-type": "application/json", "content-length": "1"},
    ))
    response = _client(subject).get("/api/extensions/coauthorization/v1/status")
    assert response.status_code == 502
    assert set(response.json()) == {"reason_code", "message"}
    assert response.json()["reason_code"] == "CONTROLLED_RESULT_INVALID"
    assert "enabled" not in response.json()
    assert REDACTION_MARKER not in response.text
    _assert_one_client(subject, requests, factory)
