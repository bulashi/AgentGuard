from __future__ import annotations

import os
import re
from collections.abc import Iterator
from urllib.parse import urlsplit

import pytest

from backend.tests import business_fixtures

BUSINESS_FIXTURE_MODULES = {
    "test_admission_postgres.py",
    "test_business_action_postgres.py",
    "test_delegation_postgres.py",
    "test_dispatch_postgres.py",
    "test_dispatch_revocation_postgres.py",
    "test_gateway_postgres.py",
    "test_multi_agent_postgres.py",
    "test_notification_binding_locking_postgres.py",
    "test_receipt_audit_postgres.py",
    "test_recovery_postgres.py",
    "test_recovery_singleflight_postgres.py",
    "test_result_retrieval_postgres.py",
    "test_revocation_postgres.py",
    "test_root_authorization_postgres.py",
    "test_tool_postgres.py",
    "test_deterministic_security.py",
    "test_native_tool_boundary.py",
}


@pytest.fixture(autouse=True)
def independently_verified_business(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    if request.node.path.name not in BUSINESS_FIXTURE_MODULES:
        yield
        return
    database_url = os.getenv("AGENTGUARD_DATABASE_URL")
    if not database_url:
        yield
        return
    target = urlsplit(database_url)
    if target.hostname not in {"localhost", "127.0.0.1", "::1"} or not re.fullmatch(
        r"/agentguard_test_backend_[a-f0-9]+", target.path
    ):
        pytest.fail("business fixtures require a parent-owned disposable PostgreSQL database")
    case = business_fixtures.verified_postgres_case(database_url)
    monkeypatch.setattr(business_fixtures, "POSTGRES_BUSINESS_TEST_CASE", case)
    yield
