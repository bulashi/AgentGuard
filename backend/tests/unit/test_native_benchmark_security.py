from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from backend.benchmark.runner import NativeBenchmarkRunner
from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import (
    InternalAuthenticator,
    InternalAuthError,
    SqliteNonceStore,
)
from backend.crypto.canonical_json import canonicalize
from scripts.native_security import EDGES

from .test_native_benchmark_config import native_config


def test_benchmark_client_sends_bound_canonical_body_and_fresh_durable_proof(
    tmp_path: Path,
) -> None:
    config = native_config(tmp_path)
    runner = NativeBenchmarkRunner(config)
    captured: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(201, json={"task_id": "test-task"})

    runner.agentguard._clients[config.authority_url] = httpx.Client(
        base_url=config.authority_url,
        transport=httpx.MockTransport(handle),
        trust_env=False,
    )
    sender = runner.agentguard._internal_senders["ui-api"]
    sender._clock = lambda: 1000
    receiver = InternalAuthenticator(
        service_id="authorization-authority",
        required=True,
        keys_json=config.internal_auth_keys,
        nonce_store=SqliteNonceStore(tmp_path / "nonce.sqlite3"),
        clock=lambda: 1000,
    )
    body = {"tenant_id": "\u4f01\u4e1a", "amount_fen": 7000, "confirmed": True}
    try:
        for _ in range(2):
            observation = runner.agentguard._request(
                config.authority_url,
                "POST",
                "/tasks",
                json_body=body,
                internal_caller="ui-api",
                internal_recipient="authorization-authority",
            )
            assert observation.status_code == 201
        for request in captured:
            assert request.content == canonicalize(body)
            assert (
                receiver.verify_headers(
                    headers=request.headers,
                    method="POST",
                    path="/tasks",
                    body=request.content,
                    allowed_callers={"ui-api"},
                )
                == "ui-api"
            )
        assert captured[0].headers != captured[1].headers
        restarted = InternalAuthenticator(
            service_id="authorization-authority",
            required=True,
            keys_json=config.internal_auth_keys,
            nonce_store=SqliteNonceStore(tmp_path / "nonce.sqlite3"),
            clock=lambda: 1000,
        )
        with pytest.raises(InternalAuthError) as replay:
            restarted.verify_headers(
                headers=captured[0].headers,
                method="POST",
                path="/tasks",
                body=captured[0].content,
                allowed_callers={"ui-api"},
            )
        assert replay.value.reason_code is ReasonCode.REPLAY_DETECTED
    finally:
        runner.close()


@pytest.mark.parametrize("tamper", ["body", "method", "path", "caller", "recipient", "stale"])
def test_benchmark_client_proof_rejects_tampering_and_stale_request(
    tmp_path: Path,
    tamper: str,
) -> None:
    config = native_config(tmp_path)
    runner = NativeBenchmarkRunner(config)
    captured: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(201, json={"task_id": "test-task"})

    runner.agentguard._clients[config.authority_url] = httpx.Client(
        base_url=config.authority_url,
        transport=httpx.MockTransport(handle),
        trust_env=False,
    )
    runner.agentguard._internal_senders["ui-api"]._clock = lambda: 1000
    try:
        runner.agentguard._request(
            config.authority_url,
            "POST",
            "/tasks",
            json_body={"amount_fen": 7000},
            internal_caller="ui-api",
            internal_recipient="authorization-authority",
        )
        request = captured[0]
        headers = dict(request.headers)
        if tamper == "caller":
            headers["x-agentguard-internal"] = "agent-refund"
        receiver = InternalAuthenticator(
            service_id="business-action-registry"
            if tamper == "recipient"
            else "authorization-authority",
            required=True,
            keys_json=config.internal_auth_keys,
            nonce_store=SqliteNonceStore(tmp_path / "nonce.sqlite3"),
            clock=lambda: 1200 if tamper == "stale" else 1000,
        )
        with pytest.raises(InternalAuthError):
            receiver.verify_headers(
                headers=headers,
                method="GET" if tamper == "method" else "POST",
                path="/authorize" if tamper == "path" else "/tasks",
                body=canonicalize({"amount_fen": 999999}) if tamper == "body" else request.content,
                allowed_callers={"ui-api"},
            )
    finally:
        runner.close()


def test_benchmark_client_rejects_incomplete_identity_and_missing_edge(tmp_path: Path) -> None:
    config = native_config(tmp_path)
    runner = NativeBenchmarkRunner(config)
    try:
        with pytest.raises(ValueError, match="both internal"):
            runner.agentguard._request(
                config.authority_url,
                "POST",
                "/tasks",
                json_body={},
                internal_caller="ui-api",
            )
        with pytest.raises(InternalAuthError) as missing:
            runner.agentguard._request(
                config.authority_url,
                "POST",
                "/tasks",
                json_body={},
                internal_caller="agent-refund",
                internal_recipient="authorization-authority",
            )
        assert missing.value.reason_code is ReasonCode.TOOL_NOT_ALLOWED
        keys = json.loads(config.internal_auth_keys)
        assert set(keys) == {"->".join(edge) for edge in EDGES}
        assert len(set(keys.values())) == len(EDGES)
    finally:
        runner.close()


@pytest.mark.parametrize(
    "caller,recipient,route",
    [
        ("agent-coordinator", "coordinator-delegation-agent", "coordinator_delegation_url"),
        ("agent-case", "case-delegation-agent", "case_delegation_url"),
    ],
)
def test_delegation_proof_reads_the_nested_protocol_holder(
    tmp_path: Path, caller: str, recipient: str, route: str
) -> None:
    config = native_config(tmp_path)
    runner = NativeBenchmarkRunner(config)
    base_url = getattr(config, route)
    captured: list[httpx.Request] = []
    parent = {
        "payload": {
            "credential_id": "credential-parent",
            "holder": {"agent_id": caller, "key_id": "key-1"},
            "capabilities": [],
            "not_before": 1000,
            "expires_at": 2000,
        }
    }

    def handle(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(201, json={"payload": {"credential_id": "credential-child"}})

    runner.agentguard._clients[base_url] = httpx.Client(
        base_url=base_url,
        transport=httpx.MockTransport(handle),
        trust_env=False,
    )
    runner.agentguard._internal_senders[caller]._clock = lambda: 1000
    receiver = InternalAuthenticator(
        service_id=recipient,
        required=True,
        keys_json=config.internal_auth_keys,
        nonce_store=SqliteNonceStore(tmp_path / "delegate-nonce.sqlite3"),
        clock=lambda: 1000,
    )
    try:
        result = runner.agentguard._delegate(
            base_url,
            parent,
            holder_agent_id="agent-refund",
            holder_key_id="agent-refund-key-01",
            refund_total_fen=7000,
            max_tool_calls=4,
        )
        assert result["payload"]["credential_id"] == "credential-child"
        assert len(captured) == 1
        request = captured[0]
        assert (
            receiver.verify_headers(
                headers=request.headers,
                method="POST",
                path="/credentials/credential-parent/delegate",
                body=request.content,
                allowed_callers={caller},
            )
            == caller
        )
        body = json.loads(request.content)
        assert body["expires_at"] == 1940
        assert body["capabilities"] == parent["payload"]["capabilities"]
    finally:
        runner.close()


@pytest.mark.parametrize("route", ["coordinator_delegation_url", "case_delegation_url"])
def test_benchmark_cannot_delegate_as_an_unrelated_parent_holder(
    tmp_path: Path, route: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = native_config(tmp_path)
    runner = NativeBenchmarkRunner(config)
    parent = {"payload": {"holder": {"agent_id": "agent-knowledge"}}}
    monkeypatch.setattr(
        runner.agentguard,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("unrelated holder must not send an HTTP request"),
    )
    try:
        with pytest.raises(ValueError, match="does not own"):
            runner.agentguard._delegate(
                getattr(config, route),
                parent,
                holder_agent_id="agent-refund",
                holder_key_id="agent-refund-key-01",
                refund_total_fen=7000,
                max_tool_calls=4,
            )
    finally:
        runner.close()
