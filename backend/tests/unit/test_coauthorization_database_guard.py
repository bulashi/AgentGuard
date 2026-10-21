from __future__ import annotations

import pytest
from psycopg.conninfo import conninfo_to_dict

from backend.tests.integration.test_coauthorization_postgres import _validated_database_url


@pytest.fixture(autouse=True)
def no_database_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PGSERVICE", raising=False)
    monkeypatch.delenv("PGSERVICEFILE", raising=False)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]", "postgres"])
def test_explicit_local_target_is_preserved(host: str) -> None:
    conninfo, name = _validated_database_url(
        f"postgresql://tester:test-password@{host}:25432/agentguard_coauth_test_guard"
    )
    parameters = conninfo_to_dict(conninfo)
    assert name == "agentguard_coauth_test_guard"
    assert parameters["host"] == host.strip("[]")
    assert parameters["port"] == "25432"
    assert parameters["dbname"] == name
    assert parameters["user"] == "tester"
    assert parameters["password"] == "test-password"
    assert "service" not in parameters
    assert "hostaddr" not in parameters


@pytest.mark.parametrize(
    "candidate",
    [
        "postgresql://tester:x@127.0.0.1:25432/agentguard_coauth_test_guard?host=external.invalid",
        "postgresql://tester:x@127.0.0.1:25432/agentguard_coauth_test_guard?hostaddr=203.0.113.1",
        "postgresql://tester:x@127.0.0.1:25432/agentguard_coauth_test_guard?service=production",
        "postgresql://tester:x@127.0.0.1:25432/agentguard_coauth_test_guard?dbname=production",
        "postgresql://tester:x@127.0.0.1:25432/agentguard_coauth_test_guard#fragment",
        "postgresql://tester:x@external.invalid:25432/agentguard_coauth_test_guard",
        "postgresql://tester:x@/agentguard_coauth_test_guard",
        "postgresql://tester:x@127.0.0.1/agentguard_coauth_test_guard",
        "postgresql://tester:x@127.0.0.1:0/agentguard_coauth_test_guard",
        "postgresql://tester@127.0.0.1:25432/agentguard_coauth_test_guard",
        "postgresql://tester:x@127.0.0.1:25432/agentguard",
        "postgresql://tester:x@127.0.0.1,external.invalid:25432/agentguard_coauth_test_guard",
    ],
)
def test_unsafe_target_is_rejected_before_connecting(candidate: str) -> None:
    with pytest.raises(pytest.fail.Exception):
        _validated_database_url(candidate)


@pytest.mark.parametrize("variable", ["PGSERVICE", "PGSERVICEFILE"])
def test_environment_service_is_rejected(
    variable: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(variable, "untrusted-service")
    with pytest.raises(pytest.fail.Exception):
        _validated_database_url(
            "postgresql://tester:x@127.0.0.1:25432/agentguard_coauth_test_guard"
        )
