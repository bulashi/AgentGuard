from __future__ import annotations

import json
from dataclasses import replace

import pytest

from backend.formal.budget_effect_model import (
    INVARIANTS,
    MAX_STATES,
    BudgetCounter,
    BudgetLimit,
    ExecutionSpec,
    ModelConfig,
    ModelState,
    Observation,
    Phase,
    compare_barriers,
    explore,
    initial_state,
    invariant_violations,
    main,
    successors,
)


def _step(config: ModelConfig, state: ModelState, action: str) -> ModelState:
    following = dict(successors(config, state))
    assert action in following, f"disabled model action: {action}"
    return following[action]


def _walk(config: ModelConfig, *actions: str) -> ModelState:
    state = initial_state(config)
    for action in actions:
        state = _step(config, state, action)
    return state


def _single(**changes: object) -> ModelConfig:
    return replace(ModelConfig(executions=(ExecutionSpec(0),)), **changes)


@pytest.mark.parametrize(
    ("root", "intermediate", "same_leaf"),
    [
        (BudgetLimit(1, 2), BudgetLimit(1, 2), False),
        (BudgetLimit(2, 1), BudgetLimit(2, 1), False),
        (BudgetLimit(2, 2), BudgetLimit(1, 2), False),
        (BudgetLimit(2, 2), BudgetLimit(2, 1), False),
        (BudgetLimit(2, 2), BudgetLimit(2, 2), True),
    ],
)
def test_admission_checks_every_shared_budget_atomically(
    root: BudgetLimit, intermediate: BudgetLimit, same_leaf: bool
) -> None:
    config = ModelConfig(
        executions=(ExecutionSpec(0), ExecutionSpec(0 if same_leaf else 1)),
        limits=(root, intermediate, BudgetLimit(1, 1), BudgetLimit(1, 1)),
    )
    admitted = _walk(config, "e0:admit")
    denied = _step(config, admitted, "e1:deny_budget")
    assert denied.budgets == admitted.budgets
    assert denied.executions[1].phase == Phase.DENIED
    assert all(admitted.budgets[c] == BudgetCounter(1, 1) for c in (0, 1, 2))
    assert admitted.budgets[3] == BudgetCounter()
    assert not invariant_violations(config, denied)


def test_zero_refund_cost_still_consumes_call_budget() -> None:
    config = ModelConfig(
        executions=(ExecutionSpec(0, 0),),
        limits=tuple(BudgetLimit(1, 0) for _ in range(4)),
    )
    committed = _walk(config, "e0:admit", "e0:dispatch", "e0:tool_effect",
                      "e0:dispatch_commit")
    assert committed.budgets[0] == BudgetCounter(0, 0, 1, 0)
    assert not invariant_violations(config, committed)


def test_normal_commit_moves_all_three_reservations_once() -> None:
    config = _single()
    committed = _walk(config, "e0:admit", "e0:dispatch", "e0:tool_effect",
                      "e0:dispatch_commit")
    assert committed.executions[0].effect_count == 1
    assert all(committed.budgets[c] == BudgetCounter(0, 0, 1, 1) for c in (0, 1, 2))
    actions = dict(successors(config, committed))
    assert "e0:tool_effect" not in actions
    assert "e0:dispatch_commit" not in actions
    assert not invariant_violations(config, committed)


def test_lost_response_recovers_existing_effect_without_redispatch() -> None:
    config = _single()
    unknown = _walk(config, "e0:admit", "e0:dispatch", "e0:tool_effect",
                    "e0:dispatch_timeout")
    assert unknown.budgets[0] == BudgetCounter(1, 1)
    committed = unknown
    for action in ("e0:recovery_prepare", "e0:query_effect", "e0:recovery_commit"):
        assert "e0:dispatch" not in dict(successors(config, committed))
        committed = _step(config, committed, action)
    assert committed.executions[0].phase == Phase.COMMITTED
    assert committed.executions[0].effect_count == 1
    assert committed.budgets[0] == BudgetCounter(0, 0, 1, 1)
    assert not invariant_violations(config, committed)


def test_admitted_timeout_releases_without_ever_dispatching() -> None:
    config = _single()
    released = _walk(config, "e0:admit", "e0:admitted_timeout_release")
    assert released.executions[0].phase == Phase.RELEASED
    assert not released.executions[0].pending_envelope
    assert all(budget == BudgetCounter() for budget in released.budgets)
    assert not invariant_violations(config, released)


def test_no_effect_observation_releases_but_blocks_late_first_execution() -> None:
    config = _single()
    state = _walk(config, "e0:admit", "e0:dispatch", "e0:dispatch_timeout")
    for action in ("e0:recovery_prepare", "e0:query_no_effect", "e0:recovery_release"):
        assert "e0:tool_effect" not in dict(successors(config, state))
        state = _step(config, state, action)
    assert state.executions[0].pending_envelope and state.executions[0].envelope_valid
    assert state.executions[0].phase == Phase.RELEASED
    assert "e0:tool_effect" not in dict(successors(config, state))
    assert all(budget == BudgetCounter() for budget in state.budgets)
    assert not invariant_violations(config, state)


def test_stale_dispatched_recovery_takes_over_before_query() -> None:
    config = _single()
    reconciling = _walk(config, "e0:admit", "e0:dispatch", "e0:stale_dispatch_recovery")
    assert reconciling.executions[0].phase == Phase.RECONCILING
    assert reconciling.executions[0].query_pending
    assert reconciling.executions[0].recovery_attempts == 1
    assert "e0:tool_effect" not in dict(successors(config, reconciling))
    assert not invariant_violations(config, reconciling)


@pytest.mark.parametrize("has_effect", [False, True])
def test_unknown_recovery_exhaustion_keeps_reservations(has_effect: bool) -> None:
    config = _single(max_recovery_attempts=2)
    actions = ["e0:admit", "e0:dispatch"]
    if has_effect:
        actions.append("e0:tool_effect")
    state = _walk(config, *actions, "e0:dispatch_timeout")
    for action in (
        "e0:recovery_prepare", "e0:query_unavailable", "e0:recovery_retry",
        "e0:recovery_prepare", "e0:query_unavailable", "e0:recovery_final",
    ):
        state = _step(config, state, action)
    execution = state.executions[0]
    assert execution.phase == Phase.RECOVERY_FAILED_FINAL
    assert execution.recovery_attempts == 2
    assert execution.effect_count == int(has_effect)
    assert state.budgets[0] == BudgetCounter(1, 1)
    assert "e0:recovery_release" not in dict(successors(config, state))
    assert not invariant_violations(config, state)


def test_deadline_does_not_release_an_unknown_execution() -> None:
    config = _single()
    state = _walk(config, "e0:admit", "e0:dispatch", "e0:dispatch_timeout",
                  "e0:recovery_deadline_expire", "e0:recovery_final")
    assert state.executions[0].phase == Phase.RECOVERY_FAILED_FINAL
    assert state.budgets[0] == BudgetCounter(1, 1)
    assert not invariant_violations(config, state)


def test_effect_observation_can_commit_after_recovery_deadline() -> None:
    config = _single()
    state = _walk(config, "e0:admit", "e0:dispatch", "e0:tool_effect",
                  "e0:dispatch_timeout", "e0:recovery_prepare", "e0:query_effect",
                  "e0:recovery_deadline_expire", "e0:recovery_commit")
    assert state.executions[0].phase == Phase.COMMITTED
    assert not invariant_violations(config, state)


@pytest.mark.parametrize("credential", ["root", "intermediate", "leaf-0"])
def test_revocation_blocks_new_admission_on_the_applicable_chain(credential: str) -> None:
    config = _single()
    state = _walk(config, f"revoke:{credential}", "e0:deny_revoked")
    assert state.executions[0].denial_reason == "REVOKED"
    assert all(budget == BudgetCounter() for budget in state.budgets)
    assert not invariant_violations(config, state)


def test_other_leaf_revocation_does_not_block_an_unrelated_path() -> None:
    config = ModelConfig()
    state = _walk(config, "revoke:leaf-1", "e0:admit", "e1:deny_revoked")
    assert state.executions[0].admission_revocations == 8
    assert state.executions[0].phase == Phase.ADMITTED
    assert not invariant_violations(config, state)


@pytest.mark.parametrize("credential", ["root", "intermediate", "leaf-0"])
def test_undispatched_admission_is_cancelled_after_chain_revocation(credential: str) -> None:
    config = _single()
    state = _walk(config, "e0:admit", f"revoke:{credential}", "e0:dispatch_revoked_release")
    assert "e0:dispatch" not in dict(successors(config, state))
    assert state.executions[0].admission_revocations == 0
    assert state.executions[0].phase == Phase.RELEASED
    assert state.executions[0].effect_count == 0
    assert state.executions[0].denial_reason == "REVOKED_AT_DISPATCH"
    assert all(budget == BudgetCounter() for budget in state.budgets)
    assert not invariant_violations(config, state)


def test_revocation_after_dispatch_cannot_recall_existing_effect() -> None:
    config = _single()
    state = _walk(config, "e0:admit", "e0:dispatch", "revoke:root",
                  "e0:tool_effect", "e0:dispatch_commit")
    assert state.executions[0].admission_revocations == 0
    assert state.executions[0].phase == Phase.COMMITTED
    assert not invariant_violations(config, state)


def test_explicit_old_admission_boundary_is_not_the_current_dispatch_guarantee() -> None:
    config = _single(dispatch_revocation_gate=False)
    state = _walk(config, "e0:admit", "revoke:root", "e0:dispatch")
    assert "dispatch_precedes_chain_revocation" in invariant_violations(config, state)


def test_expired_envelope_cannot_produce_effect_even_in_model_ablation() -> None:
    config = _single(late_dispatch_barrier=False)
    expired = _walk(config, "e0:admit", "e0:dispatch", "e0:envelope_expire")
    assert "e0:tool_effect" not in dict(successors(config, expired))


def test_isolated_no_barrier_model_exposes_the_query_settlement_race() -> None:
    config = _single(late_dispatch_barrier=False)
    state = _walk(config, "e0:admit", "e0:dispatch", "e0:dispatch_timeout",
                  "e0:recovery_prepare", "e0:query_no_effect", "e0:tool_effect")
    assert state.executions[0].observed == Observation.NO_EFFECT
    assert state.executions[0].effect_count == 1
    released = _step(config, state, "e0:recovery_release")
    violations = invariant_violations(config, released)
    assert "released_has_no_effect" in violations
    assert "effect_cost_is_budget_covered" in violations
    assert "first_effect_requires_active_dispatch" in violations


def test_isolated_no_barrier_model_exposes_release_then_late_effect() -> None:
    config = _single(late_dispatch_barrier=False)
    state = _walk(config, "e0:admit", "e0:dispatch", "e0:dispatch_timeout",
                  "e0:recovery_prepare", "e0:query_no_effect", "e0:recovery_release",
                  "e0:tool_effect")
    assert state.executions[0].phase == Phase.RELEASED
    assert "released_has_no_effect" in invariant_violations(config, state)


def test_independent_budget_counters_are_not_derived_tautologically() -> None:
    config = _single()
    state = _walk(config, "e0:admit")
    bad = replace(state, budgets=(BudgetCounter(), *state.budgets[1:]))
    assert "reservation_ledger_matches_execution_states" in invariant_violations(config, bad)


def test_single_execution_bound_is_complete_and_has_no_barrier_counterexample() -> None:
    result = explore(_single(max_states=MAX_STATES))
    assert result.complete
    assert not result.counterexamples
    assert result.expanded_states == len(result.states)
    assert all(not invariant_violations(result.config, state) for state in result.states)


def test_no_effect_or_commit_coverage_is_explicitly_vacuous_not_a_workflow_pass() -> None:
    config = _single(limits=tuple(BudgetLimit(0, 0) for _ in range(4)))
    output = explore(config).to_dict()
    assert output["complete"]
    assert output["coverage"]["phase_states"]["COMMITTED"] == 0
    assert output["coverage"]["antecedent_states"]["committed_has_effect"] == 0
    assert output["invariants"]["committed_has_effect"] == "vacuous_within_complete_bound"
    assert output["invariants"]["effect_cost_is_budget_covered"] == (
        "vacuous_within_complete_bound"
    )


def test_comparison_changes_only_the_model_barrier_and_replays_counterexamples() -> None:
    guarded, ablation = compare_barriers(_single(max_states=MAX_STATES))
    assert guarded.complete and ablation.complete
    assert not guarded.counterexamples
    assert replace(guarded.config, late_dispatch_barrier=False) == ablation.config
    assert "released_has_no_effect" in {item.invariant for item in ablation.counterexamples}
    for example in ablation.counterexamples:
        assert example.trace[0].action == "initial"
        assert example.trace[0].state == initial_state(ablation.config)
        for previous, following in zip(example.trace, example.trace[1:], strict=False):
            assert _step(ablation.config, previous.state, following.action) == following.state
        assert example.invariant in invariant_violations(ablation.config, example.trace[-1].state)


def test_three_execution_model_respects_the_discovery_cap_without_claiming_a_pass() -> None:
    config = ModelConfig(
        executions=(ExecutionSpec(0), ExecutionSpec(1), ExecutionSpec(0)), max_states=20
    )
    result = explore(config)
    assert len(result.states) == 20
    assert not result.complete
    output = result.to_dict(include_states=True)
    assert output["stop_reason"] == "STATE_LIMIT"
    assert set(output["invariants"]) == set(INVARIANTS)
    assert set(output["invariants"].values()) == {"not_violated_in_explored_prefix"}
    assert len(output["states"]) == 20
    assert json.loads(json.dumps(output))["reachable_states"] == 20


@pytest.mark.parametrize("value", [-1, 7, True, 1.5])
def test_budget_resource_guardrails_reject_out_of_range_or_ambiguous_units(value: int) -> None:
    with pytest.raises(ValueError):
        BudgetLimit(calls=value)
    with pytest.raises(ValueError):
        BudgetLimit(refund_fen=value)
    with pytest.raises(ValueError):
        ExecutionSpec(refund_fen=value)


@pytest.mark.parametrize("changes", [
    {"executions": ()},
    {"executions": (ExecutionSpec(),) * 4},
    {"executions": [ExecutionSpec()]},
    {"limits": (BudgetLimit(),)},
    {"limits": (BudgetLimit(1, 1), BudgetLimit(2, 2), BudgetLimit(1, 1), BudgetLimit(1, 1))},
    {"max_states": 0},
    {"max_states": MAX_STATES + 1},
    {"max_states": True},
    {"max_recovery_attempts": 0},
    {"max_recovery_attempts": 4},
    {"late_dispatch_barrier": 1},
])
def test_model_guardrails_cannot_be_disabled(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        replace(ModelConfig(), **changes)


def test_cli_reports_truncation_as_json_without_writing_files(capsys: pytest.CaptureFixture) -> None:
    assert main(["--executions", "1", "--max-states", "1"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["scope"] == "offline_finite_model"
    result = output["results"][0]
    assert result["reachable_states"] == 1
    assert not result["complete"]
    assert result["stop_reason"] == "STATE_LIMIT"
