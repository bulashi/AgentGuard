from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from backend.config.settings import Settings
from backend.ui_api.app import make_app
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore


def _service(tmp_path: Path) -> UiService:
    return UiService(Settings(), Mock(spec=UiReadStore), artifact_root=tmp_path)


def _status(enabled: bool) -> dict:
    return {
        "schema_version": "1.0", "enabled": enabled,
        "policy_source": "SERVER_REGISTERED_PUBLIC_KEYS", "signing": "EXTERNAL_APPROVERS_ONLY",
    }


@pytest.mark.parametrize("enabled", [True, False])
def test_bff_only_reads_and_validates_authority_configuration(tmp_path, monkeypatch, enabled) -> None:
    subject = _service(tmp_path)
    read = Mock(return_value=_status(enabled))
    monkeypatch.setattr(subject, "_coauthorization_request", read)
    result = TestClient(make_app(settings=Settings(), service=subject)).get(
        "/api/extensions/coauthorization/v1/status"
    )
    assert result.status_code == 200
    assert result.json() == _status(enabled)
    read.assert_called_once_with("GET", "/extensions/coauthorization/v1/status")
    assert subject.store.mock_calls == []


@pytest.mark.parametrize("changes", [
    {"enabled": "true"}, {"enabled": 1}, {"schema_version": "2.0"},
    {"policy_source": "CLIENT_PUBLIC_KEYS"}, {"signing": "SERVER_SIGNS_BOTH_ROLES"},
    {"approval_status": "APPROVED"}, {"private_key": "forbidden"},
])
def test_bff_rejects_untrusted_or_extra_status_fields(tmp_path, monkeypatch, changes) -> None:
    subject = _service(tmp_path)
    monkeypatch.setattr(subject, "_coauthorization_request", Mock(return_value=_status(True) | changes))
    result = TestClient(make_app(settings=Settings(), service=subject)).get(
        "/api/extensions/coauthorization/v1/status"
    )
    assert result.status_code == 502
    assert result.json()["reason_code"] == "CONTROLLED_RESULT_INVALID"
    assert "forbidden" not in result.text


def test_bff_failure_does_not_fall_back_to_disabled_configuration(tmp_path, monkeypatch) -> None:
    subject = _service(tmp_path)
    monkeypatch.setattr(subject, "_coauthorization_request", Mock(side_effect=UiApiError("UPSTREAM_UNAVAILABLE", "unavailable", status_code=503)))
    result = TestClient(make_app(settings=Settings(), service=subject)).get(
        "/api/extensions/coauthorization/v1/status"
    )
    assert result.status_code == 503
    assert "enabled" not in result.json()
