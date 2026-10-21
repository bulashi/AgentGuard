from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from backend.common.internal_auth import InternalAuthenticator
from backend.config.settings import Settings, get_settings
from backend.crypto.canonical_json import canonicalize

LOGGER = logging.getLogger(__name__)


class AuditAppendWorker:
    def __init__(
        self, service_url: str, *, interval_seconds: int, internal_auth: InternalAuthenticator,
    ) -> None:
        if not service_url or interval_seconds <= 0:
            raise ValueError("audit worker requires a URL and positive interval")
        self.service_url = service_url.rstrip("/")
        self.interval_seconds = interval_seconds
        self.internal_auth = internal_auth
        self.last_error: str | None = None
        self.last_appended_count = 0
        self.cycles = 0

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                body = canonicalize({"max_events": 1000})
                headers = self.internal_auth.request_headers(
                    recipient="audit-append-authority", method="POST",
                    path="/internal/audit/append",
                    body=body,
                )
                async with httpx.AsyncClient(
                    base_url=self.service_url, timeout=10, trust_env=False
                ) as client:
                    response = await client.post(
                        "/internal/audit/append",
                        headers=headers, content=body,
                    )
                    response.raise_for_status()
                    body = response.json()
                self.last_appended_count = int(body["appended_count"])
                self.last_error = None
                self.cycles += 1
            except Exception as exc:
                self.last_error = type(exc).__name__
                LOGGER.exception("audit append cycle failed")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.interval_seconds)
            except TimeoutError:
                continue


def make_app(*, settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    stop_event = asyncio.Event()
    worker: AuditAppendWorker | None = None
    task: asyncio.Task[None] | None = None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        nonlocal task, worker
        worker = AuditAppendWorker(
            resolved.audit_service_url,
            interval_seconds=resolved.audit_worker_interval_seconds,
            internal_auth=InternalAuthenticator.from_settings(resolved, service_id="audit-worker"),
        )
        task = asyncio.create_task(worker.run(stop_event))
        yield
        stop_event.set()
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    app = FastAPI(title="AgentGuard Audit Outbox Worker", version="1.0.0", lifespan=lifespan)

    @app.get("/health")
    def health() -> dict[str, object]:
        if worker is None:
            return {
                "status": "starting", "service": "audit-worker", "cycles": 0,
                "last_appended_count": 0, "last_error": None,
            }
        return {
            "status": "ok" if worker.last_error is None else "degraded",
            "service": "audit-worker",
            "cycles": worker.cycles,
            "last_appended_count": worker.last_appended_count,
            "last_error": worker.last_error,
        }

    return app


app = make_app()
