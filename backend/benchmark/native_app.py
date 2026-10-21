"""Run the production app factories with isolated, durable replay state."""

from __future__ import annotations

import importlib
import os
from pathlib import Path

from fastapi import FastAPI

from backend.common.internal_auth import InternalAuthenticator, SqliteNonceStore
from backend.config.settings import get_settings

ISOLATED_APP = "backend.benchmark.native_app:create_app"
TARGET_ENV = "AGENTGUARD_BENCHMARK_TARGET_APP"
NONCE_ROOT_ENV = "AGENTGUARD_BENCHMARK_NONCE_ROOT"
INSTANCE_ENV = "AGENTGUARD_BENCHMARK_SERVICE_INSTANCE"
TARGET_IDENTITIES = {
    "backend.authorization.app:app": {"authorization-authority"},
    "backend.delegation.app:app": {
        "coordinator-delegation-agent",
        "case-delegation-agent",
        "refund-delegation-agent",
    },
    "backend.business_action.app:app": {"business-action-registry"},
    "backend.revocation.app:app": {"revocation-authority"},
    "backend.receipt.app:app": {"receipt-service"},
    "backend.audit.app:app": {"audit-append-authority"},
    "backend.checkpoint.app:app": {"checkpoint-service"},
    "backend.recovery.app:app": {"recovery-worker"},
    "backend.tools.app:app": {
        "ticket-service",
        "knowledge-service",
        "refund-service",
        "notification-service",
    },
}


def create_app() -> FastAPI:
    target = os.environ.get(TARGET_ENV, "")
    root = Path(os.environ.get(NONCE_ROOT_ENV, "")).resolve()
    instance = os.environ.get(INSTANCE_ENV, "")
    project = Path(__file__).resolve().parents[2]
    settings = get_settings()
    if (
        target not in TARGET_IDENTITIES
        or settings.internal_auth_required is not True
        or settings.internal_auth_service_id not in TARGET_IDENTITIES[target]
        or not root.is_relative_to(project / "artifacts")
        or not any(parent.name == "native-benchmark-runtime" for parent in root.parents)
        or not instance
        or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in instance)
    ):
        raise ValueError("isolated benchmark app requires strict run-local authentication")
    auth = InternalAuthenticator(
        service_id=settings.internal_auth_service_id,
        required=True,
        keys_json=settings.internal_auth_keys,
        freshness_window_seconds=settings.freshness_window_seconds,
        allowed_clock_skew_seconds=settings.allowed_clock_skew_seconds,
        nonce_store=SqliteNonceStore(root / instance / "nonces.sqlite3"),
    )
    module = importlib.import_module(target.split(":", 1)[0])
    return module.make_app(settings=settings, internal_auth=auth)
