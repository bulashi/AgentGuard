from __future__ import annotations

import json

from backend.coauthorization.verifier import EXTENSION_SCHEMA_ROOT, CoauthorizationReason


def test_versioned_error_manifest_matches_the_actual_enum() -> None:
    document = json.loads((EXTENSION_SCHEMA_ROOT / "error-codes.json").read_text(encoding="utf-8"))
    assert {item["code"] for item in document["codes"]} == {reason.value for reason in CoauthorizationReason}
    assert len(document["codes"]) == len(CoauthorizationReason)
    expected_overrides = {
        "COAUTH_DISABLED": 404, "COAUTH_INVALID_BUNDLE": 400,
        "COAUTH_CHALLENGE_CONFLICT": 409, "COAUTH_IDEMPOTENCY_CONFLICT": 409,
        "COAUTH_TASK_NOT_AUTHORIZABLE": 409, "COAUTH_REGISTRY_UNAVAILABLE": 503,
        "COAUTH_STORED_EVIDENCE_INVALID": 503,
    }
    for item in document["codes"]:
        assert item["http_status"] == expected_overrides.get(item["code"], 403)


def test_challenge_machine_cannot_transition_out_of_a_terminal_state() -> None:
    document = json.loads((EXTENSION_SCHEMA_ROOT / "state-machines.json").read_text(encoding="utf-8"))
    challenge = document["challenge"]
    assert challenge["initial"] == "PENDING"
    assert set(challenge["terminal"]) == {"CONSUMED", "REVOKED"}
    assert all(item["from"] == "PENDING" for item in challenge["transitions"])
    assert challenge["maximum_pending_per_task"] == 1
    retry = challenge["replay_after_consumption"]
    assert retry["new_root_or_budget_writes"] is False
    assert retry["root_lock"] == "FOR SHARE NOWAIT"
    assert document["configuration"]["default"] is False
