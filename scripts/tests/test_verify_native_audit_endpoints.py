from __future__ import annotations

from types import SimpleNamespace
from typing import ClassVar

from scripts import verify_native


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, *_args):
        if "audit_outbox" in statement:
            value = 0
        elif "audit_chain_head" in statement:
            value = 1
        elif "credential_budget_state" in statement:
            value = 0
        else:
            raise AssertionError(f"unexpected database statement: {statement}")
        return SimpleNamespace(fetchone=lambda: (value,))


class _HttpClient:
    calls: ClassVar[list[tuple[str, str]]] = []

    def __init__(self, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, url):
        self.calls.append(("GET", url))
        checkpoint = {
            "payload": {"latest_event_sequence": 1, "checkpoint_sequence": 3},
            "signature": {"key_id": "checkpoint-key"},
        }
        return SimpleNamespace(status_code=200, json=lambda: {"checkpoint": checkpoint})

    def post(self, url, **_kwargs):
        self.calls.append(("POST", url))
        return SimpleNamespace(
            status_code=200,
            json=lambda: {"valid": True, "rollback_detected": False},
        )


def test_audit_check_uses_injected_isolated_audit_endpoints(monkeypatch):
    _HttpClient.calls = []
    monkeypatch.setattr(verify_native.httpx, "Client", _HttpClient)
    monkeypatch.setattr(verify_native, "connect", lambda _url: _Connection())
    monkeypatch.setattr(
        verify_native,
        "PostgresKeyRegistry",
        lambda _url: SimpleNamespace(
            get=lambda _key_id: SimpleNamespace(
                key_id="checkpoint-key", public_key_hex="public-key"
            )
        ),
    )
    monkeypatch.setattr(verify_native, "verify_payload", lambda *_args, **_kwargs: True)

    result = verify_native.audit_check(
        {
            "main": "postgresql://local/test",
            "checkpoint_service_url": "http://127.0.0.1:28008",
            "audit_service_url": "http://127.0.0.1:28007",
        }
    )

    assert result["verification"] == {"valid": True, "rollback_detected": False}
    assert _HttpClient.calls == [
        ("GET", "http://127.0.0.1:28008/checkpoints/latest"),
        (
            "POST",
            "http://127.0.0.1:28007/audit/verify",
        ),
    ]
