from __future__ import annotations

import json
import os
from pathlib import Path

import httpx


def pytest_sessionstart(session):
    destination = Path(os.environ["AGENTGUARD_BACKEND_RESPONSE_LOG"])
    evidence = Path(os.environ["AGENTGUARD_BACKEND_EVIDENCE_ROOT"])
    if destination.parent.resolve() != evidence.resolve() or not destination.name.startswith("backend-"):
        raise RuntimeError("diagnostic output must stay in the evidence directory")
    original = httpx.Client.post

    def observed(client, url, *args, **kwargs):
        response = original(client, url, *args, **kwargs)
        if response.url.path == "/gateway/admit":
            body = response.json()
            request = kwargs.get("json", {})
            entry = {
                "request_id": request.get("request_id"),
                "http_status": response.status_code,
                "response_keys": sorted(body) if isinstance(body, dict) else None,
                "status": body.get("status"),
                "state": body.get("state"),
                "decision": body.get("decision"),
                "reason_code": body.get("reason_code"),
                "receipt_present": isinstance(body.get("receipt"), dict),
            }
            with destination.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=True) + "\n")
        return response

    httpx.Client.post = observed
