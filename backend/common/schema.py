from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "protocol" / "schemas"


class SchemaStore:
    def __init__(self, root: Path = SCHEMA_ROOT) -> None:
        self.root = root
        self.documents: dict[str, dict[str, Any]] = {}
        resources: list[tuple[str, Resource[Any]]] = []
        for path in sorted(root.glob("*.schema.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            schema_id = document["$id"]
            self.documents[path.name] = document
            resources.append((schema_id, Resource.from_contents(document)))
        self.registry = Registry().with_resources(resources)

    def validator(self, schema_name: str) -> Draft202012Validator:
        return Draft202012Validator(self.documents[schema_name], registry=self.registry)

    def validate(self, schema_name: str, instance: Any) -> None:
        self.validator(schema_name).validate(instance)
