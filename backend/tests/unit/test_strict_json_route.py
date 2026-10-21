from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.common.strict_json_route import StrictJsonRoute


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b'{"amount_fen":1,"amount_fen":2}', "DUPLICATE_FIELD"),
        (b'{"payload":{"amount_fen":1,"amount_fen":2},"ok":true}', "DUPLICATE_FIELD"),
        (b'{"amount_fen":1.0}', "REQUEST_SCHEMA_INVALID"),
        (b'{"amount_fen":1e3}', "REQUEST_SCHEMA_INVALID"),
        (b'{"amount_fen":9007199254740992}', "REQUEST_SCHEMA_INVALID"),
        (b'{"amount_fen":' + b"9" * 5_000 + b"}", "REQUEST_SCHEMA_INVALID"),
        (b"[" * 2_000 + b"0" + b"]" * 2_000, "REQUEST_SCHEMA_INVALID"),
        (b'{"amount_fen":NaN}', "REQUEST_SCHEMA_INVALID"),
        (b'{"payload":"\xff"}', "INVALID_UTF8"),
        (b'{', "MALFORMED_JSON"),
    ],
)
def test_strict_route_rejects_before_endpoint(raw: bytes, reason: str) -> None:
    app = FastAPI()
    app.router.route_class = StrictJsonRoute
    calls: list[dict[str, Any]] = []

    @app.post("/protocol")
    def receive(payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(payload)
        return payload

    with TestClient(app) as client:
        response = client.post("/protocol", content=raw, headers={"content-type": "application/json"})
    assert response.status_code == 422
    assert response.json()["detail"][0]["ctx"]["reason_code"] == reason
    assert calls == []


def test_strict_route_preserves_valid_integer_json() -> None:
    app = FastAPI()
    app.router.route_class = StrictJsonRoute

    @app.post("/protocol")
    def receive(payload: dict[str, Any]) -> dict[str, Any]:
        return payload

    with TestClient(app) as client:
        response = client.post("/protocol", json={"amount_fen": 7000, "confirmed": True})
    assert response.status_code == 200
    assert response.json() == {"amount_fen": 7000, "confirmed": True}
