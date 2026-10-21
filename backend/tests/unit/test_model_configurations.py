from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.agent_runtime.model_client import ResolvedModel, completion, resolve_model
from backend.config.model_profiles import (
    ModelConfigurationError,
    ModelProfileStore,
    ProfileInput,
    WindowsCredentialCipher,
    normalized_endpoint,
    require_public_resolution,
)
from backend.config.settings import Settings
from backend.ui_api.app import make_app

TEST_KEY = "TEST_ONLY_PROFILE_CREDENTIAL_NOT_REAL"


class Cipher:
    def encrypt(self, value: str) -> str:
        return "encrypted:" + value[::-1]

    def decrypt(self, value: str) -> str:
        return value.removeprefix("encrypted:")[::-1]


def profile(**overrides) -> ProfileInput:
    return ProfileInput(
        **{
            "name": "云端智能体",
            "provider_id": "example",
            "base_url": "https://api.example.com/v1",
            "model": "example-chat",
            "api_key": TEST_KEY,
            **overrides,
        }
    )


@pytest.fixture
def profiles(tmp_path):
    return ModelProfileStore(tmp_path / "models.json", cipher=Cipher())


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://api.example.com",
        "https://127.0.0.1",
        "https://10.2.3.4",
        "https://[::1]",
        "https://169.254.169.254",
        "https://localhost",
        "https://api.local",
        "https://api.internal",
        "https://user:pass@api.example.com",
        "https://api.example.com?key=secret",
        "https://api.example.com#key",
        "https://api.example.com/../v1",
        "https://api.example.com/%2e%2e",
        "https://api.example.com\\private",
        "https://api.example.com:99999",
        "https://api.example.com/white space",
        "https://api.example.com\n",
        "https://api",
        "https://2130706433",
        "ftp://api.example.com",
        "",
    ],
)
def test_non_public_or_ambiguous_endpoints_are_rejected(endpoint):
    with pytest.raises(ModelConfigurationError):
        normalized_endpoint(endpoint)


@pytest.mark.parametrize(
    "overrides",
    [
        {"timeout_seconds": True},
        {"timeout_seconds": "30"},
        {"timeout_seconds": 0},
        {"timeout_seconds": 301},
        {"enabled": "true"},
        {"provider_id": "含空格 id"},
        {"model": "model\nnew"},
        {"name": "   "},
        {"api_key": "has whitespace"},
        {"api_key": "中文密钥"},
        {"api_mode": "responses"},
        {"extra": 1},
    ],
)
def test_strict_configuration_fields(overrides):
    with pytest.raises(ValidationError):
        profile(**overrides)


def test_profile_public_projection_and_files_do_not_expose_plaintext(profiles):
    saved = profiles.save("primary", profile())
    assert saved["has_key"] and saved["is_default"]
    assert TEST_KEY not in repr(profile())
    assert TEST_KEY not in json.dumps(profiles.public())
    assert TEST_KEY not in profiles.path.read_text(encoding="utf-8")
    assert "credential" not in saved
    public, key = profiles.configured()
    assert public["id"] == "primary" and key == TEST_KEY


def test_blank_key_preserves_encryption_but_new_endpoint_requires_confirmation(profiles):
    profiles.save("primary", profile())
    previous = profiles.path.read_bytes()
    profiles.save("primary", profile(api_key="", name="重命名"))
    assert profiles.configured()[1] == TEST_KEY
    with pytest.raises(ModelConfigurationError) as error:
        profiles.save("primary", profile(api_key=None, base_url="https://new.example.com/v1"))
    assert error.value.reason_code == "MODEL_CREDENTIAL_CONFIRMATION_REQUIRED"
    assert profiles.configured()[0]["base_url"] == "https://api.example.com/v1"
    assert profiles.path.read_bytes() != previous
    profiles.save("primary", profile(base_url="https://new.example.com/v1", api_key="NEW_TEST_KEY"))
    assert profiles.configured()[1] == "NEW_TEST_KEY"


def test_default_selection_disabled_delete_and_busy_state(profiles):
    profiles.save("primary", profile())
    profiles.save("secondary", profile(name="备用模型"))
    before = profiles.path.read_bytes()
    for operation in (
        lambda: profiles.save("third", profile(), idle=lambda: False),
        lambda: profiles.select("secondary", idle=lambda: False),
        lambda: profiles.delete("secondary", idle=lambda: False),
    ):
        with pytest.raises(ModelConfigurationError) as error:
            operation()
        assert error.value.reason_code == "MODEL_CONFIGURATION_BUSY"
        assert profiles.path.read_bytes() == before
    with pytest.raises(ModelConfigurationError):
        profiles.delete("primary")
    profiles.select("secondary")
    profiles.delete("primary")
    profiles.save("off", profile(api_key=None, enabled=False))
    with pytest.raises(ModelConfigurationError):
        profiles.select("off")
    with pytest.raises(ModelConfigurationError):
        profiles.select("missing")
    with pytest.raises(ModelConfigurationError):
        profiles.delete("missing")


def test_configuration_limits_and_invalid_ids(profiles):
    for index in range(32):
        profiles.save(f"profile-{index}", profile())
    with pytest.raises(ModelConfigurationError) as error:
        profiles.save("too-many", profile())
    assert error.value.reason_code == "MODEL_CONFIGURATION_LIMIT"
    for identifier in ("../escape", "a/b", "", "x" * 65):
        with pytest.raises(ModelConfigurationError):
            profiles.save(identifier, profile())


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b'{"items":{},"items":{}}',
        b"[]",
        b"not-json",
        b'{"schema_version":"model-profiles-v1","items":{},"default_id":"absent"}',
        b" " * 131_073,
    ],
    ids=["empty", "duplicate", "array", "malformed", "missing-default", "oversized"],
)
def test_corrupt_store_is_not_silently_reset(profiles, raw):
    profiles.path.write_bytes(raw)
    with pytest.raises(ModelConfigurationError):
        profiles.public()
    assert profiles.path.read_bytes() == raw


def test_concurrent_writers_do_not_lose_configurations(profiles):
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda index: profiles.save(f"p-{index}", profile()), range(12)))
    assert len(results) == len(profiles.public()["items"]) == 12
    assert profiles.public()["default_id"] in {f"p-{index}" for index in range(12)}


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI acceptance")
def test_windows_dpapi_actual_roundtrip_and_no_plaintext():
    cipher = WindowsCredentialCipher()
    encrypted = cipher.encrypt(TEST_KEY)
    assert TEST_KEY not in encrypted
    assert cipher.decrypt(encrypted) == TEST_KEY
    with pytest.raises(ModelConfigurationError):
        cipher.decrypt("not a DPAPI value")


def test_dns_mixed_public_private_resolution_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "backend.config.model_profiles.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(ModelConfigurationError) as error:
        require_public_resolution("https://api.example.com")
    assert error.value.reason_code == "MODEL_ENDPOINT_UNREACHABLE"


def test_dns_public_resolution_chooses_the_checked_address(monkeypatch):
    monkeypatch.setattr(
        "backend.config.model_profiles.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("8.8.8.8", 443)),
        ],
    )
    assert require_public_resolution("https://api.example.com") == "8.8.8.8"


def test_generic_chat_profile_does_not_add_vendor_specific_parameters():
    model = ResolvedModel("example", "https://api.example.com/v1", "example-chat", 10, TEST_KEY)

    def handler(request):
        payload = json.loads(request.content)
        assert str(request.url) == "https://api.example.com/v1/chat/completions"
        assert payload["model"] == "example-chat" and "thinking" not in payload
        assert request.headers["authorization"] == f"Bearer {TEST_KEY}"
        return httpx.Response(200, json={"choices": [], "usage": {"cost": 0.125}})

    result, evidence = completion(
        model, [{"role": "user", "content": "JSON"}], transport=httpx.MockTransport(handler)
    )
    assert result["usage"]["cost"] == 0.125 and evidence["http_status"] == 200
    assert TEST_KEY not in json.dumps(evidence)


@pytest.mark.parametrize(
    "body,status",
    [
        (b'{"x":1,"x":2}', 200),
        (b'{"value":NaN}', 200),
        (b"[]", 200),
        (b"not-json", 200),
        (b" " * 131_073, 200),
        (TEST_KEY.encode(), 200),
        (b"{}", 301),
        (b"{}", 401),
        (b"{}", 429),
        (b"{}", 500),
    ],
    ids=[
        "duplicate",
        "nan",
        "array",
        "malformed",
        "oversized",
        "reflected-key",
        "redirect",
        "unauthorized",
        "rate-limit",
        "server-error",
    ],
)
def test_bad_upstream_never_exposes_raw_response_or_falls_back(body, status):
    model = ResolvedModel("example", "https://api.example.com", "example-chat", 10, TEST_KEY)
    with pytest.raises(ModelConfigurationError) as error:
        completion(
            model,
            [],
            transport=httpx.MockTransport(lambda request: httpx.Response(status, content=body)),
        )
    assert TEST_KEY not in str(error.value) and TEST_KEY not in json.dumps(error.value.evidence)


@pytest.fixture
def client(tmp_path):
    settings = Settings(model_configurations_path=str(tmp_path / "models.json"))
    store = SimpleNamespace(has_pending_workflows=lambda: False)
    with TestClient(
        make_app(settings=settings, service=SimpleNamespace(store=store)),
        base_url="http://127.0.0.1:8088",
    ) as result:
        yield result, settings, store


def test_configuration_api_local_guard_and_redaction(client, monkeypatch):
    browser, settings, _ = client
    body = profile().model_dump() | {"api_key": TEST_KEY}
    headers = {"X-AgentGuard-Configuration": "1", "Origin": "http://127.0.0.1:8088"}
    assert browser.put("/api/model-configurations/primary", json=body).status_code == 403
    assert (
        browser.put(
            "/api/model-configurations/primary",
            json=body,
            headers=headers | {"Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert (
        browser.put(
            "/api/model-configurations/primary",
            json=body,
            headers=headers | {"Host": "evil.example"},
        ).status_code
        == 403
    )
    response = browser.put("/api/model-configurations/primary", json=body, headers=headers)
    assert response.status_code == 200 and response.json()["has_key"]
    assert TEST_KEY not in browser.get("/api/model-configurations").text
    response = browser.put(
        "/api/model-configurations/primary", json=body | {"timeout_seconds": "bad"}, headers=headers
    )
    assert response.status_code == 422 and TEST_KEY not in response.text
    response = browser.put(
        "/api/model-configurations/primary",
        content='{"name":"a","name":"b","api_key":"' + TEST_KEY + '"}',
        headers=headers | {"Content-Type": "application/json"},
    )
    assert response.status_code == 422 and TEST_KEY not in response.text
    assert (
        browser.put(
            "/api/model-configurations/primary",
            content="x" * 16_385,
            headers=headers | {"Content-Type": "application/json"},
        ).status_code
        == 413
    )
    assert (
        browser.put("/api/model-configurations/primary", content="x", headers=headers).status_code
        == 415
    )
    assert (
        browser.post(
            "/api/model-configurations/primary/test",
            json={"confirm_cloud_call": False},
            headers=headers,
        ).status_code
        == 400
    )
    monkeypatch.setattr(
        "backend.ui_api.model_api.test_configuration",
        lambda *args: {"status": "PASS", "duration_ms": 1},
    )
    assert (
        browser.post(
            "/api/model-configurations/primary/test",
            json={"confirm_cloud_call": True},
            headers=headers,
        ).json()["status"]
        == "PASS"
    )
    assert resolve_model(settings).configuration_id == "primary"


def test_configuration_api_rejects_switch_while_workflow_active(client):
    browser, _, store = client
    body = profile().model_dump() | {"api_key": TEST_KEY}
    headers = {"X-AgentGuard-Configuration": "1"}
    assert (
        browser.put("/api/model-configurations/primary", json=body, headers=headers).status_code
        == 200
    )
    assert (
        browser.put("/api/model-configurations/secondary", json=body, headers=headers).status_code
        == 200
    )
    store.has_pending_workflows = lambda: True
    for method, path, payload in (
        ("put", "/api/model-configurations/primary", body),
        ("patch", "/api/model-configurations/default", {"id": "secondary"}),
        ("delete", "/api/model-configurations/secondary", None),
    ):
        kwargs = {"headers": headers}
        if payload is not None:
            kwargs["json"] = payload
        assert getattr(browser, method)(path, **kwargs).status_code == 409
