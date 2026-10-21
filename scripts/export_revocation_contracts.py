"""Deterministic exports of the bounded revocation UI contracts; no runtime calls."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.config.settings import Settings
from backend.ui_api.app import make_app
from backend.ui_api.revocation_contracts import UiRevocationResponse, UiRevokeCredentialRequest
from backend.ui_api.revocation_verification import (
    RevocationVerificationResponse,
    VerifyRevokedRequest,
)

DESTINATION = ROOT / "protocol/extensions/dispatch-revocation/v1"
PATHS = (
    "/api/tasks/{task_id}/credentials/{credential_id}/revoke",
    "/api/tasks/{task_id}/credentials/{credential_id}/verify-revoked",
)
MODELS = {
    "ui-revoke-credential.schema.json": UiRevokeCredentialRequest,
    "ui-revocation-response.schema.json": UiRevocationResponse,
    "verify-revoked-request.schema.json": VerifyRevokedRequest,
    "verify-revoked-response.schema.json": RevocationVerificationResponse,
}


def schema_references(value):
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            yield ref.removeprefix("#/components/schemas/")
        for item in value.values():
            yield from schema_references(item)
    elif isinstance(value, list):
        for item in value:
            yield from schema_references(item)


def exports() -> dict[str, dict]:
    documents = {
        filename: model.model_json_schema()
        | {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://agentguard.local/extensions/dispatch-revocation/v1/" + filename,
        }
        for filename, model in MODELS.items()
    }
    document = make_app(settings=Settings()).openapi()
    paths = {path: document["paths"][path] for path in PATHS}
    included = {}
    pending = set(schema_references(paths))
    while pending:
        name = pending.pop()
        included[name] = document["components"]["schemas"][name]
        pending.update(set(schema_references(included[name])) - included.keys())
    documents["openapi.json"] = {
        "openapi": "3.1.0",
        "info": {
            "title": "AgentGuard Credential Revocation UI Extension",
            "version": "1.0.0",
            "description": "Task-scoped operator control. No browser keys, new grants or LLM calls.",
        },
        "paths": paths,
        "security": [{"OperatorSession": []}],
        "components": {
            "schemas": included,
            "securitySchemes": {
                "OperatorSession": {"type": "apiKey", "in": "cookie", "name": "agentguard_operator"}
            },
        },
    }
    return documents


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    documents = exports()
    if args.check:
        mismatches = [
            name for name, value in documents.items()
            if not (DESTINATION / name).is_file()
            or json.loads((DESTINATION / name).read_text("utf-8")) != value
        ]
        print(json.dumps({"status": "FAIL" if mismatches else "PASS", "mismatches": mismatches}))
        return int(bool(mismatches))
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for name, value in documents.items():
        (DESTINATION / name).write_text(
            json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps({"exported": sorted(documents)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
