"""Authenticate local acceptance clients through the same native operator gate as the UI."""

from __future__ import annotations

from pathlib import Path

import httpx

from backend.config.model_profiles import WindowsCredentialCipher

ROOT = Path(__file__).resolve().parents[1]


def authenticate(client: httpx.Client, *, root: Path = ROOT) -> None:
    path = root / ".native/operator-session.dpapi"
    secret = WindowsCredentialCipher().decrypt(path.read_text(encoding="ascii"))
    response = client.post("/api/operator-session", json={"launch_token": secret})
    if response.status_code != 200 or response.json() != {"authenticated": True}:
        raise RuntimeError("native operator authentication failed; no bypass used")
