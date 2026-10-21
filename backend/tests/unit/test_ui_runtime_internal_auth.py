"""Verify actual UI-to-Agent request bytes and HMAC on both submission paths.

Only HTTP transport is substituted. Authenticator, canonical JSON and replay
checks are real. Keys and identifiers below are explicit test material.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from backend.common.internal_auth import PROOF_HEADER, InternalAuthenticator, SqliteNonceStore
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore

TEST_KEYS = json.dumps(
    {
        "ui-api->agent-coordinator": "ab" * 32,
        "ui-api->agent-refund": "cd" * 32,
    }
)


@pytest.mark.parametrize(
    "path,recipient",
    [
        ("/agents/workflows", "agent-coordinator"),
        ("/agents/run", "agent-coordinator"),
        ("/agents/run", "agent-refund"),
    ],
)
def test_runtime_submission_has_a_real_bound_internal_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    path: str,
    recipient: str,
) -> None:
    observed = []
    verifier = InternalAuthenticator(
        service_id=recipient,
        keys_json=TEST_KEYS,
        nonce_store=SqliteNonceStore(tmp_path / "recipient-nonces.sqlite3"),
    )
    real_client = httpx.Client
    body = {"credential_chain": [{"test": "public-only"}], "context": {"ticket_id": "T-中文"}}

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == path
        assert request.content == canonicalize(body)
        assert PROOF_HEADER in request.headers
        observed.append(
            verifier.verify_headers(
                headers=request.headers,
                method=request.method,
                path=request.url.path,
                body=request.content,
                allowed_callers={"ui-api"},
            )
        )
        return httpx.Response(202 if path == "/agents/workflows" else 200, json={"test_ack": True})

    def client(*args: Any, **kwargs: Any) -> httpx.Client:
        assert kwargs["trust_env"] is False
        return real_client(*args, **kwargs, transport=httpx.MockTransport(handle))

    monkeypatch.setattr("backend.ui_api.service.httpx.Client", client)
    subject = UiService(
        Settings(
            coordinator_agent_url="http://coordinator.test",
            refund_agent_url="http://refund.test",
            internal_auth_required=True,
            internal_auth_keys=TEST_KEYS,
            internal_auth_nonce_root=str(tmp_path),
        ),
        cast(UiReadStore, object()),
    )
    if path == "/agents/workflows":
        result = subject._workflow_request(body)
    else:
        base_url = (
            subject.settings.coordinator_agent_url
            if recipient == "agent-coordinator"
            else subject.settings.refund_agent_url
        )
        result = subject._post(base_url, path, body)
    assert result == {"test_ack": True}
    assert observed == ["ui-api"]


def test_missing_runtime_edge_key_rejects_before_http(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def forbidden_client(*args: Any, **kwargs: Any) -> None:
        pytest.fail("missing authentication key must not send an unsigned runtime request")

    monkeypatch.setattr("backend.ui_api.service.httpx.Client", forbidden_client)
    subject = UiService(
        Settings(
            coordinator_agent_url="http://coordinator.test",
            internal_auth_required=True,
            internal_auth_keys="{}",
            internal_auth_nonce_root=str(tmp_path),
        ),
        cast(UiReadStore, object()),
    )
    with pytest.raises(UiApiError) as caught:
        subject._workflow_request({"test": "body"})
    assert caught.value.reason_code == "INTERNAL_AUTH_UNAVAILABLE"
    assert caught.value.status_code == 503
