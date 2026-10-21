from __future__ import annotations

from typing import Any

import httpx

from backend.common.internal_auth import InternalAuthenticator, InternalAuthError
from backend.crypto.canonical_json import canonicalize


class ReceiptClient:
    def __init__(
        self, base_url: str, *, internal_auth: InternalAuthenticator,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.internal_auth = internal_auth

    def issue(
        self, execution_id: str, *, current_time: int | None = None
    ) -> dict[str, Any] | None:
        # Legacy callers may pass their entry time; the receipt service owns its clock.
        del current_time
        if not self.base_url:
            return None
        try:
            body = canonicalize({"execution_id": execution_id})
            headers = self.internal_auth.request_headers(
                recipient="receipt-service", method="POST", path="/internal/receipts/issue",
                body=body,
            )
            with httpx.Client(timeout=self.timeout_seconds, trust_env=False) as client:
                response = client.post(
                    f"{self.base_url}/internal/receipts/issue",
                    headers=headers, content=body,
                )
            if response.status_code != 200:
                return None
            value = response.json()
            if not isinstance(value, dict) or not isinstance(value.get("receipt"), dict):
                return None
            return value["receipt"]
        except (httpx.HTTPError, ValueError, InternalAuthError):
            return None
