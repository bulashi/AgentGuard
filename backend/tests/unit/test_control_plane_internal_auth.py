from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

import backend.common.internal_auth as auth_module
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.authorization.app import make_app as make_authority_app
from backend.authorization.policy import build_root_capabilities
from backend.authorization.service import RootAuthorizationService
from backend.coauthorization.service import CoauthorizationService
from backend.coauthorization.verifier import CoauthorizationError, CoauthorizationReason
from backend.common.internal_auth import CALLER_HEADER, PROOF_HEADER
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.delegation.app import make_app as make_delegation_app
from backend.delegation.contracts import DelegateCredentialRequest
from backend.delegation.service import DelegationService
from backend.revocation.app import make_app as make_revocation_app
from backend.revocation.service import RevocationService
from backend.tests.unit.test_internal_auth import authenticator
from backend.ui_api.service import UiApiError, UiService

CONTROL_KEYS = {
    "ui-api->authorization-authority": "55" * 32,
    "agent-coordinator->coordinator-delegation-agent": "66" * 32,
    "agent-case->case-delegation-agent": "77" * 32,
    "agent-refund->refund-delegation-agent": "88" * 32,
    "revocation-controller->revocation-authority": "99" * 32,
}
CREATE_BODY = {
    "tenant_id": "tenant-A", "ticket_id": "T10086", "customer_id": "C9527",
    "refund_total_fen": 7000, "max_tool_calls": 4, "expires_in_seconds": 1800,
}
AUTHORIZE_BODY = {
    "confirmed": True, "confirmer_id": "user-admin-01",
    "holder_agent_id": "agent-coordinator", "holder_key_id": "agent-coordinator-key-01",
    "delegation_depth": 2,
}
CHALLENGE_BODY = {
    "holder_agent_id": "agent-coordinator", "holder_key_id": "agent-coordinator-key-01",
    "delegation_depth": 2,
}


def control_auth(tmp_path: Path, service_id: str, *, keys: dict[str, str] | None = None):
    return authenticator(tmp_path, service_id, keys=CONTROL_KEYS if keys is None else keys)


def post_control(client: TestClient, sender, recipient: str, path: str, document: dict):
    body = canonicalize(document)
    headers = sender.request_headers(recipient=recipient, method="POST", path=path, body=body)
    return client.post(path, content=body, headers=headers)


def authority_client(tmp_path: Path):
    root = Mock(spec=RootAuthorizationService)
    root.create_task.return_value = {"task_id": "TASK-001", "status": "PENDING_AUTHORIZATION"}
    root.authorize_task.return_value = {"guard_test": "not_a_signature_result"}
    coauth = Mock(spec=CoauthorizationService)
    coauth.authorize_task.side_effect = CoauthorizationError(
        CoauthorizationReason.INVALID_BUNDLE, "unsigned unit bundle rejected by business verifier",
    )
    client = TestClient(make_authority_app(
        settings=Settings(coauthorization_required=True), service=root,
        coauthorization_service=coauth,
        internal_auth=control_auth(tmp_path, "authorization-authority"),
    ))
    return client, root, coauth


@pytest.mark.parametrize(("path", "body"), [
    ("/tasks", CREATE_BODY), ("/tasks/TASK-001/authorize", AUTHORIZE_BODY),
    ("/extensions/coauthorization/v1/tasks/TASK-001/challenges", CHALLENGE_BODY),
    ("/extensions/coauthorization/v1/tasks/TASK-001/authorize", {}),
])
@pytest.mark.parametrize("headers", [{}, {CALLER_HEADER: "ui-api"}])
def test_authority_write_routes_require_proof_not_confirmer_text(
    tmp_path: Path, path: str, body: dict, headers: dict,
) -> None:
    client, root, coauth = authority_client(tmp_path)
    response = client.post(path, json=body, headers=headers)
    assert response.status_code == 403
    root.create_task.assert_not_called()
    root.authorize_task.assert_not_called()
    coauth.create_challenge.assert_not_called()
    coauth.authorize_task.assert_not_called()


def test_control_proof_allows_task_creation_without_changing_frozen_body(tmp_path: Path) -> None:
    client, root, _ = authority_client(tmp_path)
    response = post_control(
        client, control_auth(tmp_path, "ui-api"), "authorization-authority", "/tasks", CREATE_BODY,
    )
    assert response.status_code == 201
    assert root.create_task.call_args.args[0].model_dump(mode="json") == CREATE_BODY


def test_control_proof_does_not_bypass_independent_joint_approval_requirement(
    tmp_path: Path,
) -> None:
    client, root, coauth = authority_client(tmp_path)
    response = post_control(
        client, control_auth(tmp_path, "ui-api"), "authorization-authority",
        "/tasks/TASK-001/authorize", AUTHORIZE_BODY,
    )
    assert response.status_code == 403
    assert response.json()["reason_code"] == "COAUTH_REQUIRED"
    root.authorize_task.assert_not_called()
    coauth.authorize_task.assert_not_called()


def test_authenticated_joint_bundle_retains_exact_raw_bytes_and_business_verification(
    tmp_path: Path,
) -> None:
    client, root, coauth = authority_client(tmp_path)
    body = b'{ "invalid_bundle": true }'
    path = "/extensions/coauthorization/v1/tasks/TASK-001/authorize"
    headers = control_auth(tmp_path, "ui-api").request_headers(
        recipient="authorization-authority", method="POST", path=path, body=body,
    )
    response = client.post(path, content=body, headers=headers)
    assert response.status_code == 400
    assert response.json()["reason_code"] == "COAUTH_INVALID_BUNDLE"
    coauth.authorize_task.assert_called_once_with("TASK-001", body)
    root.authorize_task.assert_not_called()


def test_agent_cannot_issue_a_root_even_if_its_mac_edge_is_configured(tmp_path: Path) -> None:
    keys = {**CONTROL_KEYS, "agent-refund->authorization-authority": "aa" * 32}
    root = Mock(spec=RootAuthorizationService)
    client = TestClient(make_authority_app(
        settings=Settings(), service=root,
        internal_auth=control_auth(tmp_path, "authorization-authority", keys=keys),
    ))
    response = post_control(
        client, control_auth(tmp_path, "agent-refund", keys=keys), "authorization-authority",
        "/tasks/TASK-001/authorize", AUTHORIZE_BODY,
    )
    assert response.status_code == 403
    root.authorize_task.assert_not_called()


def delegate_body() -> dict:
    return {
        "holder_agent_id": "agent-refund", "holder_key_id": "agent-refund-key-01",
        "capabilities": build_root_capabilities(
            ticket_id="T10086", customer_id="C9527", refund_total_fen=7000,
        )[2:3],
        "quotas": {"refund_total_fen": 7000, "max_tool_calls": 1},
        "not_before": 1000, "expires_at": 1500,
    }


@pytest.mark.parametrize("role", ["coordinator", "case", "refund"])
def test_delegation_service_requires_the_corresponding_agent(tmp_path: Path, role: str) -> None:
    service = Mock(spec=DelegationService)
    service.delegate.return_value = {"guard_test": "not_a_signature_result"}
    recipient = f"{role}-delegation-agent"
    client = TestClient(make_delegation_app(
        settings=Settings(delegation_agent_id=f"agent-{role}"), service=service,
        internal_auth=control_auth(tmp_path, recipient),
    ))
    path = "/credentials/CRED-001/delegate"
    document = delegate_body()
    assert client.post(path, json=document).status_code == 403
    response = post_control(
        client, control_auth(tmp_path, f"agent-{role}"), recipient, path, document,
    )
    assert response.status_code == 201
    service.delegate.assert_called_once()
    assert service.delegate.call_args.args[0] == "CRED-001"
    expected = DelegateCredentialRequest.model_validate(document).model_dump(mode="json")
    assert service.delegate.call_args.args[1].model_dump(mode="json") == expected


def test_another_agent_cannot_use_case_delegation_signer(tmp_path: Path) -> None:
    keys = {**CONTROL_KEYS, "agent-refund->case-delegation-agent": "aa" * 32}
    service = Mock(spec=DelegationService)
    client = TestClient(make_delegation_app(
        settings=Settings(delegation_agent_id="agent-case"), service=service,
        internal_auth=control_auth(tmp_path, "case-delegation-agent", keys=keys),
    ))
    response = post_control(
        client, control_auth(tmp_path, "agent-refund", keys=keys), "case-delegation-agent",
        "/credentials/CRED-001/delegate", delegate_body(),
    )
    assert response.status_code == 403
    service.delegate.assert_not_called()


def test_revocation_requires_control_identity_not_constant_header(tmp_path: Path) -> None:
    service = Mock(spec=RevocationService)
    service.revoke.return_value = {
        "credential_id": "CRED-001", "revoked_at": 1000, "revocation_reason": "user request",
        "revoked_by": "user-admin-01", "status": "REVOKED",
    }
    client = TestClient(make_revocation_app(
        settings=Settings(), service=service,
        internal_auth=control_auth(tmp_path, "revocation-authority"),
    ))
    path = "/credentials/CRED-001/revoke"
    document = {"reason": "user request", "revoked_by": "user-admin-01"}
    response = client.post(path, json=document, headers={CALLER_HEADER: "revocation-authority"})
    assert response.status_code == 403
    service.revoke.assert_not_called()
    response = post_control(
        client, control_auth(tmp_path, "revocation-controller"), "revocation-authority", path,
        document,
    )
    assert response.status_code == 200
    service.revoke.assert_called_once()


def test_ui_authority_client_signs_the_exact_sent_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(auth_module, "now_unix", lambda: 1000)
    receiver = control_auth(tmp_path, "authorization-authority")
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={"ui-api"},
        )
        assert json.loads(request.content) == CREATE_BODY
        return httpx.Response(201, json={"task_id": "TASK-001", "status": "PENDING_AUTHORIZATION"})

    real_client = httpx.Client
    monkeypatch.setattr(
        "backend.ui_api.service.httpx.Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    subject = UiService(Settings(
        internal_auth_required=True, internal_auth_service_id="ui-api",
        internal_auth_keys=json.dumps(CONTROL_KEYS), authority_url="http://authority.invalid",
    ), Mock())
    for _ in range(2):
        result = subject._post(
            "http://authority.invalid", "/tasks", CREATE_BODY, expected_status=201,
        )
        assert result["task_id"] == "TASK-001"
    assert len(requests) == 2
    assert requests[0].headers[PROOF_HEADER] != requests[1].headers[PROOF_HEADER]


@pytest.mark.parametrize("raw_bundle", [False, True])
def test_joint_approval_client_signs_canonical_challenge_or_exact_bundle_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw_bundle: bool,
) -> None:
    monkeypatch.setattr(auth_module, "now_unix", lambda: 1000)
    receiver = control_auth(tmp_path, "authorization-authority")
    requests = []
    raw = b'{ "guard_test": "not_a_signature_bundle" }'
    path = "/extensions/coauthorization/v1/tasks/TASK-001/" + (
        "authorize" if raw_bundle else "challenges"
    )

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={"ui-api"},
        )
        assert request.content == (raw if raw_bundle else canonicalize(CHALLENGE_BODY))
        return httpx.Response(200, json={"guard_test": "not_an_approval_result"})

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: real_client(
            transport=httpx.MockTransport(handle), **kwargs,
        ),
    )
    subject = UiService(Settings(
        internal_auth_required=True, internal_auth_service_id="ui-api",
        internal_auth_keys=json.dumps(CONTROL_KEYS), authority_url="http://authority.invalid",
    ), Mock())
    options = {"raw_body": raw} if raw_bundle else {"body": CHALLENGE_BODY}
    for _ in range(2):
        assert subject._coauthorization_request("POST", path, **options) == {
            "guard_test": "not_an_approval_result",
        }
    assert len(requests) == 2
    assert requests[0].headers[PROOF_HEADER] != requests[1].headers[PROOF_HEADER]


def test_joint_approval_client_does_not_send_unsigned_bundle_when_key_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_factory = Mock(side_effect=AssertionError("must not send unsigned bundle"))
    monkeypatch.setattr(httpx, "Client", client_factory)
    subject = UiService(Settings(
        internal_auth_required=True, internal_auth_service_id="ui-api",
        internal_auth_keys="{}", authority_url="http://authority.invalid",
    ), Mock())
    with pytest.raises(UiApiError) as raised:
        subject._coauthorization_request(
            "POST", "/extensions/coauthorization/v1/tasks/TASK-001/authorize", raw_body=b"{}",
        )
    assert raised.value.reason_code == "INTERNAL_AUTH_UNAVAILABLE"
    client_factory.assert_not_called()


@pytest.mark.parametrize("role", ["coordinator", "case", "refund"])
def test_agent_delegation_client_binds_identity_and_retains_other_headers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str,
) -> None:
    monkeypatch.setattr(auth_module, "now_unix", lambda: 1000)
    receiver = control_auth(tmp_path, f"{role}-delegation-agent")
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["X-Workflow-Token"] == "unit-only-observation-token"
        receiver.verify_headers(
            headers=request.headers, method=request.method, path=request.url.path,
            body=request.content, allowed_callers={f"agent-{role}"},
        )
        assert json.loads(request.content) == delegate_body()
        return httpx.Response(201, json={"guard_test": "not_a_signature_result"})

    real_client = httpx.Client
    monkeypatch.setattr(
        "backend.agent_runtime.service.httpx.Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    subject = AgentRuntimeService.__new__(AgentRuntimeService)
    subject.role = role
    subject.agent_id = f"agent-{role}"
    subject.settings = Settings(
        internal_auth_required=True, internal_auth_service_id=subject.agent_id,
        internal_auth_keys=json.dumps(CONTROL_KEYS), agent_delegation_url="http://delegation.invalid",
    )
    subject._post_json(
        "http://delegation.invalid", "/credentials/CRED-001/delegate", delegate_body(),
        expected_status=201, headers={"X-Workflow-Token": "unit-only-observation-token"},
    )
    assert len(requests) == 1


@pytest.mark.parametrize("kind", ["ui", "agent"])
def test_missing_control_key_has_no_unsigned_network_fallback(
    monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    def forbid_http(**_kwargs):
        raise AssertionError("missing authentication keys must fail before HTTP")

    monkeypatch.setattr(httpx, "Client", forbid_http)
    if kind == "ui":
        subject = UiService(Settings(
            internal_auth_required=True, internal_auth_service_id="ui-api",
            internal_auth_keys="{}", authority_url="http://authority.invalid",
        ), Mock())
        with pytest.raises(UiApiError, match="authentication is unavailable"):
            subject._post("http://authority.invalid", "/tasks", CREATE_BODY)
    else:
        subject = AgentRuntimeService.__new__(AgentRuntimeService)
        subject.role = "case"
        subject.agent_id = "agent-case"
        subject.settings = Settings(
            internal_auth_required=True, internal_auth_service_id="agent-case",
            internal_auth_keys="{}", agent_delegation_url="http://delegation.invalid",
        )
        with pytest.raises(AgentRuntimeError, match="authentication is unavailable"):
            subject._post_json(
                "http://delegation.invalid", "/credentials/CRED-001/delegate", delegate_body(),
            )
