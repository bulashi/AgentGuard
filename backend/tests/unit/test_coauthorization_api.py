from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from psycopg import OperationalError, errors

from backend.authorization.app import make_app
from backend.authorization.contracts import AuthorizeTaskRequest
from backend.authorization.service import AuthorizationError, RootAuthorizationService
from backend.coauthorization.contracts import MAX_BUNDLE_BYTES, CreateChallengeRequest
from backend.coauthorization.service import CoauthorizationService
from backend.coauthorization.verifier import CoauthorizationError, CoauthorizationReason
from backend.config.settings import Settings
from scripts.native_config import service_specs


class RejectingApprovalService:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls: list[tuple] = []

    def create_challenge(self, task_id: str, request: CreateChallengeRequest):
        self.calls.append((task_id, request))
        raise self.error

    def authorize_task(self, task_id: str, raw: bytes):
        self.calls.append((task_id, raw))
        raise self.error


def _client(service, *, enabled: bool = True) -> TestClient:
    return TestClient(make_app(
        settings=Settings(coauthorization_required=enabled), coauthorization_service=service,
    ))


def test_extension_default_disabled_without_constructing_database_service() -> None:
    service = RejectingApprovalService(AssertionError("disabled service must not be called"))
    client = _client(service, enabled=False)
    assert client.get("/extensions/coauthorization/v1/status").json() == {
        "schema_version": "1.0", "enabled": False,
        "policy_source": "SERVER_REGISTERED_PUBLIC_KEYS", "signing": "EXTERNAL_APPROVERS_ONLY",
    }
    response = client.post("/extensions/coauthorization/v1/tasks/task-01/authorize", json={})
    assert response.status_code == 404
    assert response.json()["reason_code"] == "COAUTH_DISABLED"
    assert service.calls == []


def test_generated_openapi_documents_the_raw_bundle_without_pydantic_body_decoding() -> None:
    service = RejectingApprovalService(AssertionError("schema generation must not access storage"))
    document = _client(service).get("/openapi.json").json()
    operation = document["paths"]["/extensions/coauthorization/v1/tasks/{task_id}/authorize"]["post"]
    assert operation["requestBody"]["required"] is True
    assert operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/CoauthV1Bundle"
    }
    bundle = document["components"]["schemas"]["CoauthV1Bundle"]
    assert set(bundle["required"]) == {"payload", "approvals"}
    assert bundle["additionalProperties"] is False
    assert bundle["properties"]["payload"]["$ref"] == "#/components/schemas/CoauthV1ApprovalPayload"
    assert "CoauthV1ApprovalPayload" in document["components"]["schemas"]
    assert service.calls == []


def test_enabled_extension_blocks_legacy_http_root_authorization() -> None:
    service = RejectingApprovalService(AssertionError("legacy route must not call the extension"))
    response = _client(service).post("/tasks/task-01/authorize", json={
        "confirmed": True, "confirmer_id": "policy-refund-v1",
        "holder_agent_id": "agent-coordinator", "holder_key_id": "agent-coordinator-key-01",
        "delegation_depth": 2,
    })
    assert response.status_code == 403
    assert response.json()["reason_code"] == "COAUTH_REQUIRED"
    assert service.calls == []


def test_required_guard_precedes_any_database_or_key_access(tmp_path: Path) -> None:
    root = RootAuthorizationService(
        database_url="intentionally-invalid-never-connect", private_key_root=str(tmp_path),
        authority_subject_id="authority", authority_key_id="authority-key",
        trusted_confirmers={"policy": "POLICY"}, coauthorization_required=True,
    )
    request = AuthorizeTaskRequest(
        confirmed=True, confirmer_id="policy", holder_agent_id="agent", holder_key_id="agent-key",
        delegation_depth=2,
    )
    with pytest.raises(AuthorizationError) as caught:
        root.authorize_task("task", request, current_time=1)
    assert caught.value.status_code == 403
    assert "coauthorization is required" in str(caught.value)


@pytest.mark.parametrize("content_type", ["text/plain", "application/octet-stream", ""])
def test_raw_bundle_requires_json_content_type(content_type: str) -> None:
    service = RejectingApprovalService(AssertionError("body must be rejected first"))
    response = _client(service).post(
        "/extensions/coauthorization/v1/tasks/task-01/authorize",
        content=b"{}", headers={"content-type": content_type},
    )
    assert response.status_code == 400
    assert service.calls == []


def test_raw_bundle_limit_precedes_database_service_call() -> None:
    service = RejectingApprovalService(AssertionError("oversized body must be rejected first"))
    response = _client(service).post(
        "/extensions/coauthorization/v1/tasks/task-01/authorize",
        content=b" " * (MAX_BUNDLE_BYTES + 1), headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["reason_code"] == "COAUTH_INVALID_BUNDLE"
    assert service.calls == []


@pytest.mark.parametrize("error,expected_status,reason", [
    (CoauthorizationError(CoauthorizationReason.INVALID_BUNDLE, "invalid bundle"), 400, "COAUTH_INVALID_BUNDLE"),
    (CoauthorizationError(CoauthorizationReason.KEY_NOT_ACTIVE, "key inactive"), 403, "COAUTH_KEY_NOT_ACTIVE"),
    (CoauthorizationError(CoauthorizationReason.IDEMPOTENCY_CONFLICT, "evidence conflict"), 409, "COAUTH_IDEMPOTENCY_CONFLICT"),
    (OperationalError("secret connection details"), 503, "COAUTH_REGISTRY_UNAVAILABLE"),
    (errors.UndefinedTable("secret schema details"), 503, "COAUTH_REGISTRY_UNAVAILABLE"),
])
def test_extension_error_statuses_and_storage_error_redaction(error, expected_status, reason) -> None:
    service = RejectingApprovalService(error)
    response = _client(service).post(
        "/extensions/coauthorization/v1/tasks/task-01/authorize", json={},
    )
    assert response.status_code == expected_status
    assert response.json()["reason_code"] == reason
    assert "secret" not in response.text
    assert service.calls == [("task-01", b"{}")]


def test_challenge_rejects_client_policy_key_material_and_unknown_fields() -> None:
    service = RejectingApprovalService(AssertionError("schema must reject before service"))
    response = _client(service).post("/extensions/coauthorization/v1/tasks/task-01/challenges", json={
        "holder_agent_id": "agent", "holder_key_id": "agent-key", "delegation_depth": 2,
        "public_key_hex": "a" * 128, "policy_revision": "client-selected-policy",
    })
    assert response.status_code == 400
    assert service.calls == []


def test_challenge_duplicate_keys_rejected_before_pydantic_decoding() -> None:
    service = RejectingApprovalService(AssertionError("duplicate body must not be decoded"))
    response = _client(service).post(
        "/extensions/coauthorization/v1/tasks/task-01/challenges",
        content=b'{"holder_agent_id":"agent","holder_agent_id":"other","holder_key_id":"key","delegation_depth":2}',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert service.calls == []


@pytest.mark.parametrize("task_id", ["a" * 129, "invalid!id"])
def test_extension_task_path_identifier_is_bounded(task_id: str) -> None:
    service = RejectingApprovalService(AssertionError("invalid path must not reach service"))
    response = _client(service).post(
        f"/extensions/coauthorization/v1/tasks/{task_id}/authorize", json={},
    )
    assert response.status_code == 400
    assert service.calls == []


def test_service_rejects_raw_duplicate_keys_without_database_access(tmp_path: Path) -> None:
    root = RootAuthorizationService(
        database_url="invalid-never-connect", private_key_root=str(tmp_path),
        authority_subject_id="authority", authority_key_id="authority-key",
        trusted_confirmers={"policy": "POLICY"}, coauthorization_required=True,
    )
    with pytest.raises(CoauthorizationError) as caught:
        CoauthorizationService(root_service=root).authorize_task("task", b'{"payload":{},"payload":{}}')
    assert caught.value.reason_code is CoauthorizationReason.INVALID_BUNDLE


def test_native_coauthorization_opt_in_is_forwarded_only_to_authority_and_bff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("AGENTGUARD_COAUTHORIZATION_REQUIRED", "true")
    monkeypatch.setenv("AGENTGUARD_COAUTHORIZATION_CHALLENGE_TTL_SECONDS", "120")
    services = [item for group in service_specs("m", "a", "u", tmp_path, with_llm=False) for item in group]
    authority = next(item for item in services if item.name == "authorization-authority")
    assert authority.environment["AGENTGUARD_COAUTHORIZATION_REQUIRED"] == "true"
    assert authority.environment["AGENTGUARD_COAUTHORIZATION_CHALLENGE_TTL_SECONDS"] == "120"
    ui = next(item for item in services if item.name == "ui-api")
    assert ui.environment["AGENTGUARD_COAUTHORIZATION_REQUIRED"] == "true"
    assert "AGENTGUARD_COAUTHORIZATION_CHALLENGE_TTL_SECONDS" not in ui.environment
    assert not any("PRIVATE_KEY" in key for key in ui.environment)
    assert all("AGENTGUARD_COAUTHORIZATION_REQUIRED" not in item.environment
               for item in services if item not in (authority, ui))


def test_native_does_not_silently_treat_unknown_boolean_as_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("AGENTGUARD_COAUTHORIZATION_REQUIRED", "misconfigured")
    with pytest.raises(ValueError, match="explicit boolean"):
        service_specs("m", "a", "u", tmp_path, with_llm=False)
