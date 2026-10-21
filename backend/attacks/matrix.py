from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = PROJECT_ROOT / "attacks" / "deterministic_scenarios" / "scenarios.json"


def load_matrix() -> dict[str, Any]:
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def scenario_map() -> dict[str, dict[str, Any]]:
    matrix = load_matrix()
    scenarios = matrix.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("deterministic scenario matrix is empty")
    result: dict[str, dict[str, Any]] = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ValueError("scenario entry must be an object")
        identifier = scenario.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("scenario id must be a non-empty string")
        if identifier in result:
            raise ValueError(f"duplicate scenario id: {identifier}")
        required = {
            "category",
            "attacker_capability",
            "target_invariant",
            "expected_decision",
            "expected_reason_codes",
            "expected_business_effects",
            "evidence",
        }
        missing = required - scenario.keys()
        if missing:
            raise ValueError(f"scenario {identifier} is missing {sorted(missing)}")
        if not isinstance(scenario["expected_reason_codes"], list):
            raise ValueError(f"scenario {identifier} reason codes must be a list")
        if not isinstance(scenario["evidence"], list) or not scenario["evidence"]:
            raise ValueError(f"scenario {identifier} must list evidence")
        result[identifier] = scenario
    return result

