from __future__ import annotations

from typing import Any

import httpx

from backend.common.internal_auth import InternalAuthenticator, InternalAuthError
from backend.crypto.canonical_json import canonicalize


class AuditClient:
    def __init__(
        self, base_url: str, *, internal_auth: InternalAuthenticator,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.internal_auth = internal_auth

    def enqueue_rejected(self, event: dict[str, Any]) -> bool:
        if not self.base_url:
            return False
        try:
            body = canonicalize(event)
            headers = self.internal_auth.request_headers(
                recipient="audit-append-authority", method="POST", path="/internal/audit/rejected",
                body=body,
            )
            with httpx.Client(timeout=self.timeout_seconds, trust_env=False) as client:
                response = client.post(
                    f"{self.base_url}/internal/audit/rejected",
                    headers=headers, content=body,
                )
            return response.status_code == 200
        except (httpx.HTTPError, ValueError, InternalAuthError):
            return False
