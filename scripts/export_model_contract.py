"""Export the additive model-configuration contract, not the frozen signed protocol."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.config.settings import Settings
from backend.ui_api.app import make_app

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "protocol/extensions/model-configurations-v1/openapi.json"


def document() -> dict:
    api = make_app(settings=Settings()).openapi()
    paths = {
        key: value
        for key, value in api["paths"].items()
        if key.startswith("/api/model-configurations") or key == "/api/operator-session"
    }
    dependencies = set()
    pending = [paths]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            reference = value.get("$ref", "")
            if reference.startswith("#/components/schemas/"):
                name = reference.rsplit("/", 1)[-1]
                if name not in dependencies:
                    dependencies.add(name)
                    pending.append(api["components"]["schemas"][name])
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "AgentGuard Local Model Configuration Extension",
            "version": "1.0.0",
            "description": "Local same-origin configuration. Credentials are write-only. "
            "The frozen signed capability and execution schemas are unchanged.",
        },
        "paths": paths,
        "components": {
            "schemas": {name: api["components"]["schemas"][name] for name in sorted(dependencies)}
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    current = document()
    if args.check:
        if json.loads(DESTINATION.read_text(encoding="utf-8")) != current:
            raise SystemExit("MODEL_EXTENSION_CONTRACT=FAIL drift")
    else:
        DESTINATION.parent.mkdir(parents=True, exist_ok=True)
        DESTINATION.write_text(
            json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print("MODEL_EXTENSION_CONTRACT=PASS")


if __name__ == "__main__":
    main()
