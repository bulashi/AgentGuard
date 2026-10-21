from __future__ import annotations

from backend.attacks.matrix import load_matrix, scenario_map


def test_deterministic_matrix_is_explicit_and_llm_free() -> None:
    matrix = load_matrix()
    scenarios = scenario_map()
    assert matrix["schema_version"] == "1.0"
    assert matrix["llm_required"] is False
    assert matrix["success_invariant"] == "unauthorized_side_effects == 0"
    assert len(scenarios) >= 30
    assert {item["category"] for item in scenarios.values()} >= {
        "raw_parse",
        "authorization",
        "delegation",
        "budget",
        "concurrency",
        "recovery",
        "retrieval",
    }

