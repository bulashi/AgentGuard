from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.config.settings import Settings
from backend.ui_api.app import make_app
from backend.ui_api.operator_session import COOKIE_NAME, SESSION_TTL_SECONDS

SECRET = "1" * 64


def client(secret=SECRET):
    store = SimpleNamespace(list_tasks=lambda **kwargs: [])
    service = SimpleNamespace(store=store, create_task=lambda request: {"task_id": "test-only"})
    return TestClient(
        make_app(
            settings=Settings(operator_auth_required=True, operator_session_secret=secret),
            service=service,
        ),
        base_url="http://127.0.0.1:8088",
    )


def test_unauthenticated_operator_cannot_read_or_mint_task():
    with client() as browser:
        assert browser.get("/api/tasks").status_code == 401
        assert browser.post("/api/tasks", json={}).status_code == 401
        assert browser.put("/api/model-configurations/x", json={}).status_code == 401


def test_launch_token_is_consumed_without_echo_and_cookie_is_http_only():
    with client() as browser:
        response = browser.post("/api/operator-session", json={"launch_token": SECRET})
        assert response.status_code == 200 and response.json() == {"authenticated": True}
        assert SECRET not in response.text and SECRET not in response.headers["set-cookie"]
        cookie = response.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie and "path=/api" in cookie
        assert browser.get("/api/tasks").status_code == 200
        browser.cookies.clear()
        assert browser.get("/api/tasks").status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"launch_token": "wrong"},
        {"launch_token": SECRET, "extra": True},
        {"launch_token": 123},
        [],
    ],
)
def test_invalid_launch_requests_are_denied_without_input_echo(body):
    with client() as browser:
        response = browser.post("/api/operator-session", json=body)
        assert response.status_code == 401 and SECRET not in response.text
        assert browser.get("/api/tasks").status_code == 401


def test_duplicate_and_oversized_bootstrap_are_denied():
    with client() as browser:
        headers = {"Content-Type": "application/json"}
        assert (
            browser.post(
                "/api/operator-session",
                content='{"launch_token":"x","launch_token":"y"}',
                headers=headers,
            ).status_code
            == 401
        )
        assert (
            browser.post(
                "/api/operator-session",
                content=json.dumps({"launch_token": "x" * 1024}),
                headers=headers,
            ).status_code
            == 413
        )
        assert browser.post("/api/operator-session", content="invalid").status_code == 415


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Host": "evil.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Origin": "https://127.0.0.1:8088"},
    ],
)
def test_cross_origin_or_dns_rebinding_requests_are_denied(headers):
    with client() as browser:
        assert (
            browser.post(
                "/api/operator-session", json={"launch_token": SECRET}, headers=headers
            ).status_code
            == 403
        )


def test_session_from_previous_start_does_not_authorize_new_runtime():
    with client() as old:
        old.post("/api/operator-session", json={"launch_token": SECRET})
        cookie = old.cookies[COOKIE_NAME]
    with client("2" * 64) as current:
        assert (
            current.get("/api/tasks", headers={"Cookie": COOKIE_NAME + "=" + cookie}).status_code
            == 401
        )


def test_missing_native_operator_secret_fails_closed_at_startup():
    with pytest.raises(ValueError, match="requires a random session secret"):
        with client(""):
            pass


def test_expired_raw_cookie_is_rejected_even_if_client_ignores_max_age(monkeypatch):
    clock = [1_800_000_000]
    monkeypatch.setattr("backend.ui_api.operator_session.time.time", lambda: clock[0])
    with client() as browser:
        response = browser.post("/api/operator-session", json={"launch_token": SECRET})
        cookie = response.cookies[COOKIE_NAME]
        browser.cookies.clear()
        clock[0] += SESSION_TTL_SECONDS + 1
        assert (
            browser.get("/api/tasks", headers={"Cookie": f"{COOKIE_NAME}={cookie}"}).status_code
            == 401
        )


def test_timestamp_tampering_cannot_extend_cookie_lifetime():
    with client() as browser:
        response = browser.post("/api/operator-session", json={"launch_token": SECRET})
        issued_at, signature = response.cookies[COOKIE_NAME].split(".")
        browser.cookies.clear()
        cookie = f"{int(issued_at) + SESSION_TTL_SECONDS}.{signature}"
        assert (
            browser.get("/api/tasks", headers={"Cookie": f"{COOKIE_NAME}={cookie}"}).status_code
            == 401
        )


def test_clock_rollback_rejects_session_and_bootstrap(monkeypatch):
    clock = [1_800_000_000]
    monkeypatch.setattr("backend.ui_api.operator_session.time.time", lambda: clock[0])
    with client() as browser:
        browser.post("/api/operator-session", json={"launch_token": SECRET})
        clock[0] -= 1
        assert browser.get("/api/tasks").status_code == 401
        assert (
            browser.post("/api/operator-session", json={"launch_token": SECRET}).status_code == 401
        )
