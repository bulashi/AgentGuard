from __future__ import annotations

from typing import Any

import pytest

from backend.crypto.sm import signed_object_hash
from backend.ui_api.store import UiReadStore


@pytest.mark.parametrize("malformed", [False, True])
def test_projection_limits_resources_and_constraints_to_public_typed_fields(
    monkeypatch: pytest.MonkeyPatch, malformed: bool,
) -> None:
    capability: dict[str, Any] = {
        "tool": "refund.create", "service": "refund-service", "version": "v1",
        "resources": {"ticket_ids": ["T10086"], "customer_ids": ["C9527"], "private_key": "test-only-secret"},
        "constraints": {"single_max_fen": 0, "api_key": "test-only-secret"},
    }
    if malformed:
        capability["resources"] = "invalid-resources"
        capability["constraints"] = {"single_max_fen": True, "template_ids": [None]}
    signed = {"payload": {"capabilities": [capability]}, "signature": {}}
    row = ("ROOT-test", "ROOT", None, None, signed_object_hash(signed), signed,
           "authority-test", "auth-key-test", "agent-coordinator", "holder-key-test",
           10, 100, 2, 10, None, None, 10, "tenant-test", "task-test", "secure-tool-gateway")
    monkeypatch.setattr(UiReadStore, "_verify_signed", staticmethod(lambda *_args, **_kwargs: False))
    projected = UiReadStore("unused-test-only")._credential_projection(None, row)
    value = projected["capabilities"][0]
    assert value["resources"] == ({} if malformed else {"ticket_ids": ["T10086"], "customer_ids": ["C9527"]})
    assert value["constraints"] == ({} if malformed else {"single_max_fen": 0})
    assert projected["signature"]["valid"] is False
    assert "test-only-secret" not in str(projected)
