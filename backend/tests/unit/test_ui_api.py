from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

import backend.ui_api.store as store_module
from backend.config.settings import Settings
from backend.ui_api.app import make_app
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore
from scripts.native_config import service_specs

PROJECT_ROOT = Path(__file__).parents[3]


class FakeStore:
    def __init__(self) -> None:
        self.schema_probed = False

    def probe_schema(self) -> None:
        self.schema_probed = True

    def overview(self) -> dict[str, Any]:
        return {}


class ProbeConnection:
    def __init__(self) -> None:
        self.query = ""

    def __enter__(self) -> ProbeConnection:
        return self

    def __exit__(self, *args: object) -> bool:
        del args
        return False

    def execute(self, query: str) -> ProbeConnection:
        self.query = query
        return self


def service(tmp_path: Path) -> UiService:
    return UiService(
        Settings(),
        cast(UiReadStore, FakeStore()),
        protocol_root=PROJECT_ROOT / "protocol",
        artifact_root=tmp_path,
    )


def test_optional_artifact_setting_preserves_minimal_service_configuration() -> None:
    ui = UiService(cast(Settings, SimpleNamespace()), cast(UiReadStore, FakeStore()))
    assert ui.artifact_root == Path("artifacts")


@pytest.mark.parametrize("explicit_override", [False, True])
def test_artifact_setting_and_explicit_override_remain_isolated(
    tmp_path: Path, explicit_override: bool,
) -> None:
    configured = tmp_path / "configured"
    explicit = tmp_path / "explicit"
    ui = UiService(
        cast(Settings, SimpleNamespace(ui_artifact_root=str(configured))),
        cast(UiReadStore, FakeStore()),
        artifact_root=explicit if explicit_override else None,
    )
    assert ui.artifact_root == (explicit if explicit_override else configured)


def test_checkpoint_projection_never_exposes_signature_value(tmp_path: Path) -> None:
    projected = service(tmp_path)._checkpoint_projection(
        {
            "status": "AVAILABLE",
            "checkpoint": {
                "payload": {
                    "checkpoint_sequence": 7,
                    "latest_event_sequence": 42,
                    "latest_event_hash": "a" * 64,
                    "timestamp": 1_790_000_000,
                },
                "signature": {
                    "algorithm": "SM2",
                    "key_id": "audit-key-01",
                    "value": "b" * 128,
                },
            },
        }
    )
    signature = projected["checkpoint"]["signature"]
    assert signature["algorithm"] == "SM2"
    assert signature["key_id"] == "audit-key-01"
    assert len(signature["fingerprint_sm3"]) == 24
    assert "value" not in signature


def test_ui_schema_probe_tracks_revocation_migration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = ProbeConnection()
    monkeypatch.setattr(
        store_module,
        "connect",
        lambda _database_url: connection,
    )

    UiReadStore("postgresql://read-only").probe_schema()

    assert "r.revocation_reason" in connection.query
    assert "r.reason" not in connection.query


def test_trace_projection_drops_model_content_and_authority_material(tmp_path: Path) -> None:
    projected = service(tmp_path)._sanitize_trace_step(
        {
            "sequence": 1,
            "agent_id": "agent-refund",
            "action": "plan",
            "status": "COMPLETED",
            "details": {
                "planner": "llm",
                "response_sm3": "a" * 64,
                "response_content": "raw model output",
                "credential_chain": [{"signature": "secret"}],
                "private_key": "secret",
                "intents": [{"name": "refund.create"}],
            },
        }
    )
    details = projected["details"]
    assert details["planner"] == "llm"
    assert details["response_sm3"] == "a" * 64
    assert details["intents"] == [{"name": "refund.create"}]
    assert "response_content" not in details
    assert "credential_chain" not in details
    assert "private_key" not in details


def test_security_matrix_and_benchmark_evidence_boundary(tmp_path: Path) -> None:
    subject = service(tmp_path)
    matrix = subject.security_matrix()
    assert matrix["scenario_count"] == 36
    assert matrix["success_invariant"] == "unauthorized_side_effects == 0"
    assert subject.benchmark_summary() == {
        "status": "PENDING_CURRENT_ACCEPTANCE",
        "message": (
            "The current Windows-native cloud acceptance has not published verified metrics."
        ),
    }


def test_benchmark_summary_requires_verified_acceptance(tmp_path: Path) -> None:
    benchmark_dir = tmp_path / "benchmarks"
    benchmark_dir.mkdir()
    path = benchmark_dir / "current-cloud-summary.json"
    path.write_text(
        '{"status":"VERIFIED","run_id":"formal-01",'
        '"acceptance_target":"native_windows_cloud_20261004",'
        '"environment":{"deployment":"native_windows"},'
        '"acceptance":{"passed":true}}',
        encoding="utf-8",
    )

    assert service(tmp_path).benchmark_summary()["run_id"] == "formal-01"

    path.write_text(
        '{"status":"FAILED","acceptance":{"passed":false}}',
        encoding="utf-8",
    )
    with pytest.raises(UiApiError, match="did not pass"):
        service(tmp_path).benchmark_summary()


def test_old_benchmark_is_not_current_acceptance(tmp_path: Path) -> None:
    benchmark_dir = tmp_path / "benchmarks"
    benchmark_dir.mkdir()
    (benchmark_dir / "summary.json").write_text(
        '{"status":"VERIFIED","acceptance":{"passed":true}}', encoding="utf-8"
    )
    assert service(tmp_path).benchmark_summary()["status"] == "PENDING_CURRENT_ACCEPTANCE"


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"acceptance_target": "native_windows_cloud_20261004"},
        {"environment": {"deployment": "native_windows"}},
    ],
)
def test_current_benchmark_requires_current_deployment(tmp_path: Path, extra: dict) -> None:
    benchmark_dir = tmp_path / "benchmarks"
    benchmark_dir.mkdir()
    (benchmark_dir / "current-cloud-summary.json").write_text(
        json.dumps({"status": "VERIFIED", "acceptance": {"passed": True}, **extra}),
        encoding="utf-8",
    )
    with pytest.raises(UiApiError, match="did not pass"):
        service(tmp_path).benchmark_summary()


def test_health_checks_database_schema_and_static_security_evidence(
    tmp_path: Path,
) -> None:
    subject = service(tmp_path)
    response = TestClient(make_app(settings=Settings(), service=subject)).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "ui-api"}
    assert cast(FakeStore, subject.store).schema_probed is True


def test_browser_api_has_no_naked_result_or_receipt_endpoint() -> None:
    app = make_app(settings=Settings(), service=cast(Any, object()))
    paths = set(app.openapi()["paths"])
    assert "/api/tasks/{task_id}" in paths
    assert not any("result" in path.lower() for path in paths)
    assert not any("receipt" in path.lower() for path in paths)


def test_history_pagination_search_and_bounds() -> None:
    class HistoryStore:
        def __init__(self) -> None:
            self.arguments: dict[str, Any] = {}

        def list_tasks(self, **kwargs: Any) -> list[dict[str, str]]:
            self.arguments = kwargs
            return [{"task_id": f"TASK-{index}"} for index in range(3)]

    history = HistoryStore()
    subject = cast(Any, type("Subject", (), {"store": history})())
    client = TestClient(make_app(settings=Settings(), service=subject))
    response = client.get("/api/tasks?limit=2&offset=40&search=T10086&status=AUTHORIZED")
    assert response.status_code == 200
    assert response.json() == {
        "items": [{"task_id": "TASK-0"}, {"task_id": "TASK-1"}], "has_more": True
    }
    assert history.arguments == {
        "limit": 3, "offset": 40, "search": "T10086", "status": "AUTHORIZED"
    }
    assert client.get("/api/tasks?offset=-1").status_code == 422
    assert client.get("/api/tasks?limit=101").status_code == 422
    assert client.get("/api/tasks?search=" + "x" * 201).status_code == 422


def test_history_query_is_parameterized_and_select_only(monkeypatch: pytest.MonkeyPatch) -> None:
    class HistoryConnection(ProbeConnection):
        arguments: tuple[Any, ...] = ()

        def execute(self, query: str, params: tuple[Any, ...] = ()) -> HistoryConnection:
            self.query = query
            self.arguments = params
            return self

        def fetchall(self) -> list[Any]:
            return []

    connection = HistoryConnection()
    monkeypatch.setattr(store_module, "connect", lambda _url: connection)
    result = UiReadStore("postgresql://read-only").list_tasks(
        limit=500, offset=40, search="T_100%", status="AUTHORIZED"
    )
    assert result == []
    assert connection.query.lstrip().startswith("SELECT")
    assert "T_100%" not in connection.query
    assert connection.arguments[1] == "%T\\_100\\%%"
    assert connection.arguments[-2:] == (101, 40)


def test_history_projection_includes_workflow_reason_code(monkeypatch: pytest.MonkeyPatch) -> None:
    class HistoryConnection(ProbeConnection):
        def execute(self, query: str, params: tuple[Any, ...] = ()) -> HistoryConnection:
            del params
            self.query = query
            return self

        def fetchall(self) -> list[Any]:
            return [[
                "TASK-denied", "tenant-A", "T10086", "C9527", 7000, 4, 1_900_000_000,
                "AUTHORIZED", 1_790_000_000, 1_790_000_100, 4, 2,
                "DENIED", "cloud", "deepseek-flash", 1_900_000_000,
                "PLANNER_DECLINED", "REJECTED", "VERIFIED", 0, 0,
            ]]

    connection = HistoryConnection()
    monkeypatch.setattr(store_module, "connect", lambda _url: connection)
    projection = UiReadStore("postgresql://read-only").list_tasks()

    assert projection[0]["workflow_state"] == "DENIED"
    assert projection[0]["workflow_reason_code"] == "PLANNER_DECLINED"
    assert projection[0]["business_verification_status"] == "REJECTED"
    assert projection[0]["refund_count"] == 0
    assert "w.reason_code" in connection.query


def test_native_ui_environment_has_no_core_database_signing_key_or_model_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_CLOUD_LLM_ENABLED", "false")
    services = [service for group in service_specs(
        "main-secret", "audit-secret", "ui-readonly", tmp_path, with_llm=False,
    ) for service in group]
    ui_api = next(service for service in services if service.name == "ui-api")
    assert ui_api.port == 8090
    assert ui_api.environment["AGENTGUARD_UI_DATABASE_URL"] == "ui-readonly"
    assert "AGENTGUARD_DATABASE_URL" not in ui_api.environment
    assert "AGENTGUARD_AUDIT_DATABASE_URL" not in ui_api.environment
    assert not any("PRIVATE_KEY" in key or "API_KEY" in key for key in ui_api.environment)
    assert not any(service.name == "ollama" for service in services)
