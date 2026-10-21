from __future__ import annotations

import asyncio
import logging

from backend.recovery.service import RecoveryService

LOGGER = logging.getLogger(__name__)


class RecoveryWorker:
    """Periodic scanner for existing executions and pending recovery decisions."""

    def __init__(self, service: RecoveryService, *, interval_seconds: int = 5) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.service = service
        self.interval_seconds = interval_seconds

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.interval_seconds)
            except TimeoutError:
                if stop_event.is_set():
                    break
                try:
                    await asyncio.to_thread(self.service.scan_once)
                except Exception:
                    LOGGER.exception("recovery scan failed")
