"""Bounded budget/effect/recovery enumeration; not a production formal proof."""

from __future__ import annotations

import argparse
import json
from collections import deque
from collections.abc import Iterator
from dataclasses import asdict, dataclass, replace
from enum import Enum

MAX_EXECUTIONS = 3
MAX_RESOURCE_UNITS = 6
MAX_RECOVERY_ATTEMPTS = 3
MAX_STATES = 50_000
CREDENTIALS = ("root", "intermediate", "leaf-0", "leaf-1")


def _bounded_integer(name: str, value: int, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")


@dataclass(frozen=True, slots=True)
class BudgetLimit:
    calls: int = 2
    refund_fen: int = 2

    def __post_init__(self) -> None:
        _bounded_integer("calls", self.calls, 0, MAX_RESOURCE_UNITS)
        _bounded_integer("refund_fen", self.refund_fen, 0, MAX_RESOURCE_UNITS)


@dataclass(frozen=True, slots=True)
class ExecutionSpec:
    leaf: int = 0
    refund_fen: int = 1

    def __post_init__(self) -> None:
        _bounded_integer("leaf", self.leaf, 0, 1)
        _bounded_integer("refund_fen", self.refund_fen, 0, MAX_RESOURCE_UNITS)

    @property
    def path(self) -> tuple[int, int, int]:
        return (0, 1, 2 + self.leaf)

    @property
    def path_mask(self) -> int:
        return sum(1 << credential for credential in self.path)


@dataclass(frozen=True, slots=True)
class ModelConfig:
    executions: tuple[ExecutionSpec, ...] = (ExecutionSpec(0), ExecutionSpec(1))
    limits: tuple[BudgetLimit, ...] = (
        BudgetLimit(),
        BudgetLimit(),
        BudgetLimit(1, 1),
        BudgetLimit(1, 1),
    )
    max_recovery_attempts: int = 2
    max_states: int = 20_000
    late_dispatch_barrier: bool = True
    dispatch_revocation_gate: bool = True

    def __post_init__(self) -> None:
        if type(self.executions) is not tuple or not 1 <= len(self.executions) <= MAX_EXECUTIONS:
            raise ValueError("executions must be a tuple of one to three execution specs")
        if not all(isinstance(item, ExecutionSpec) for item in self.executions):
            raise ValueError("executions must contain ExecutionSpec values")
        if type(self.limits) is not tuple or len(self.limits) != len(CREDENTIALS):
            raise ValueError("limits must contain root, intermediate, and two leaf budgets")
        if not all(isinstance(item, BudgetLimit) for item in self.limits):
            raise ValueError("limits must contain BudgetLimit values")
        for parent, child in ((0, 1), (1, 2), (1, 3)):
            if self.limits[child].calls > self.limits[parent].calls or (
                self.limits[child].refund_fen > self.limits[parent].refund_fen
            ):
                raise ValueError("child budget limits must not exceed their parent's limits")
        _bounded_integer(
            "max_recovery_attempts", self.max_recovery_attempts, 1, MAX_RECOVERY_ATTEMPTS
        )
        _bounded_integer("max_states", self.max_states, 1, MAX_STATES)
        if type(self.late_dispatch_barrier) is not bool:
            raise ValueError("late_dispatch_barrier must be a boolean")
        if type(self.dispatch_revocation_gate) is not bool:
            raise ValueError("dispatch_revocation_gate must be a boolean")


class Phase(str, Enum):
    NEW = "NEW"
    DENIED = "DENIED"
    ADMITTED = "ADMITTED"
    DISPATCHED = "DISPATCHED"
    UNKNOWN = "UNKNOWN"
    RECONCILING = "RECONCILING"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"
    RECOVERY_FAILED_FINAL = "RECOVERY_FAILED_FINAL"


class Observation(str, Enum):
    NONE = "NONE"
    EFFECT = "ALREADY_EXECUTED"
    NO_EFFECT = "NOT_EXECUTED"
    UNKNOWN = "UNKNOWN"


RESERVING = frozenset({
    Phase.ADMITTED,
    Phase.DISPATCHED,
    Phase.UNKNOWN,
    Phase.RECONCILING,
    Phase.RECOVERY_FAILED_FINAL,
})
RECOVERABLE = frozenset({Phase.DISPATCHED, Phase.UNKNOWN, Phase.RECONCILING})
INVARIANTS = (
    "budget_within_limits",
    "reservation_ledger_matches_execution_states",
    "released_has_no_effect",
    "effect_cost_is_budget_covered",
    "committed_has_effect",
    "at_most_one_effect_per_execution",
    "admission_precedes_chain_revocation",
    "dispatch_precedes_chain_revocation",
    "first_effect_requires_active_dispatch",
    "non_admitted_has_no_effect",
)


@dataclass(frozen=True, slots=True)
class BudgetCounter:
    reserved_calls: int = 0
    reserved_fen: int = 0
    committed_calls: int = 0
    committed_fen: int = 0


@dataclass(frozen=True, slots=True)
class Execution:
    phase: Phase = Phase.NEW
    pending_envelope: bool = False
    envelope_valid: bool = False
    effect_count: int = 0
    effect_started_phase: Phase | None = None
    admission_revocations: int | None = None
    dispatch_revocations: int | None = None
    recovery_attempts: int = 0
    deadline_expired: bool = False
    query_pending: bool = False
    observed: Observation = Observation.NONE
    denial_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ModelState:
    budgets: tuple[BudgetCounter, ...]
    executions: tuple[Execution, ...]
    revoked_mask: int = 0


def initial_state(config: ModelConfig) -> ModelState:
    return ModelState(
        budgets=tuple(BudgetCounter() for _ in CREDENTIALS),
        executions=tuple(Execution() for _ in config.executions),
    )


def _execution(state: ModelState, index: int, **changes: object) -> ModelState:
    executions = list(state.executions)
    executions[index] = replace(executions[index], **changes)
    return replace(state, executions=tuple(executions))


def _budget_change(
    config: ModelConfig, state: ModelState, index: int, reserved: int, committed: int = 0
) -> ModelState:
    spec = config.executions[index]
    budgets = list(state.budgets)
    for credential in spec.path:
        old = budgets[credential]
        budgets[credential] = BudgetCounter(
            old.reserved_calls + reserved,
            old.reserved_fen + reserved * spec.refund_fen,
            old.committed_calls + committed,
            old.committed_fen + committed * spec.refund_fen,
        )
    return replace(state, budgets=tuple(budgets))


def _can_reserve(config: ModelConfig, state: ModelState, index: int) -> bool:
    spec = config.executions[index]
    return all(
        state.budgets[c].reserved_calls + state.budgets[c].committed_calls + 1
        <= config.limits[c].calls
        and state.budgets[c].reserved_fen + state.budgets[c].committed_fen + spec.refund_fen
        <= config.limits[c].refund_fen
        for c in spec.path
    )


def _settle(config: ModelConfig, state: ModelState, index: int, phase: Phase) -> ModelState:
    settled = _budget_change(config, state, index, -1, int(phase == Phase.COMMITTED))
    return _execution(
        settled, index, phase=phase, query_pending=False, observed=Observation.NONE
    )


def successors(config: ModelConfig, state: ModelState) -> Iterator[tuple[str, ModelState]]:
    for credential, name in enumerate(CREDENTIALS):
        bit = 1 << credential
        if not state.revoked_mask & bit:
            yield f"revoke:{name}", replace(state, revoked_mask=state.revoked_mask | bit)

    for index, execution in enumerate(state.executions):
        prefix = f"e{index}:"
        phase = execution.phase
        if phase == Phase.NEW:
            if state.revoked_mask & config.executions[index].path_mask:
                yield prefix + "deny_revoked", _execution(
                    state, index, phase=Phase.DENIED, denial_reason="REVOKED"
                )
            elif not _can_reserve(config, state, index):
                yield prefix + "deny_budget", _execution(
                    state, index, phase=Phase.DENIED, denial_reason="BUDGET_EXCEEDED"
                )
            else:
                admitted = _budget_change(config, state, index, 1)
                yield prefix + "admit", _execution(
                    admitted, index, phase=Phase.ADMITTED,
                    admission_revocations=state.revoked_mask,
                )
        if phase == Phase.ADMITTED:
            if config.dispatch_revocation_gate and state.revoked_mask & config.executions[index].path_mask:
                cancelled = _settle(config, state, index, Phase.RELEASED)
                yield prefix + "dispatch_revoked_release", _execution(
                    cancelled, index, denial_reason="REVOKED_AT_DISPATCH",
                )
            else:
                yield prefix + "dispatch", _execution(
                    state, index, phase=Phase.DISPATCHED,
                    pending_envelope=True, envelope_valid=True,
                    dispatch_revocations=state.revoked_mask,
                )
            yield prefix + "admitted_timeout_release", _settle(
                config, state, index, Phase.RELEASED
            )
        if execution.pending_envelope and execution.envelope_valid:
            yield prefix + "envelope_expire", _execution(state, index, envelope_valid=False)
            if execution.effect_count == 0 and (
                not config.late_dispatch_barrier or phase == Phase.DISPATCHED
            ):
                yield prefix + "tool_effect", _execution(
                    state, index, pending_envelope=False, envelope_valid=False,
                    effect_count=execution.effect_count + 1, effect_started_phase=phase,
                )
        if phase == Phase.DISPATCHED:
            yield prefix + "dispatch_timeout", _execution(state, index, phase=Phase.UNKNOWN)
            if execution.effect_count:
                yield prefix + "dispatch_commit", _settle(config, state, index, Phase.COMMITTED)
        if phase in {Phase.UNKNOWN, Phase.RECONCILING} and not execution.deadline_expired:
            yield prefix + "recovery_deadline_expire", _execution(
                state, index, deadline_expired=True
            )
        if phase in RECOVERABLE and not execution.query_pending and (
            execution.observed == Observation.NONE
        ):
            if execution.deadline_expired or execution.recovery_attempts >= (
                config.max_recovery_attempts
            ):
                yield prefix + "recovery_final", _execution(
                    state, index, phase=Phase.RECOVERY_FAILED_FINAL
                )
            else:
                action = (
                    "stale_dispatch_recovery" if phase == Phase.DISPATCHED else "recovery_prepare"
                )
                yield prefix + action, _execution(
                    state, index, phase=Phase.RECONCILING,
                    recovery_attempts=execution.recovery_attempts + 1, query_pending=True,
                )
        if phase == Phase.RECONCILING and execution.query_pending:
            observed = Observation.EFFECT if execution.effect_count else Observation.NO_EFFECT
            action = "query_effect" if execution.effect_count else "query_no_effect"
            yield prefix + action, _execution(
                state, index, query_pending=False, observed=observed
            )
            yield prefix + "query_unavailable", _execution(
                state, index, query_pending=False, observed=Observation.UNKNOWN
            )
        if phase == Phase.RECONCILING and not execution.query_pending:
            if execution.observed == Observation.EFFECT:
                yield prefix + "recovery_commit", _settle(config, state, index, Phase.COMMITTED)
            elif execution.observed == Observation.NO_EFFECT:
                # Use the prior tool observation, not an omniscient side-effect guard.
                yield prefix + "recovery_release", _settle(config, state, index, Phase.RELEASED)
            elif execution.observed == Observation.UNKNOWN:
                final = execution.deadline_expired or execution.recovery_attempts >= (
                    config.max_recovery_attempts
                )
                yield prefix + ("recovery_final" if final else "recovery_retry"), _execution(
                    state, index, phase=Phase.RECOVERY_FAILED_FINAL if final else phase,
                    observed=Observation.NONE,
                )


def invariant_violations(config: ModelConfig, state: ModelState) -> tuple[str, ...]:
    violated: set[str] = set()
    for credential, (budget, limit) in enumerate(zip(state.budgets, config.limits, strict=True)):
        values = (
            budget.reserved_calls, budget.reserved_fen, budget.committed_calls, budget.committed_fen
        )
        if min(values) < 0 or budget.reserved_calls + budget.committed_calls > limit.calls or (
            budget.reserved_fen + budget.committed_fen > limit.refund_fen
        ):
            violated.add("budget_within_limits")
        reserved_calls = reserved_fen = committed_calls = committed_fen = 0
        effect_calls = effect_fen = 0
        for spec, execution in zip(config.executions, state.executions, strict=True):
            if credential not in spec.path:
                continue
            if execution.phase in RESERVING:
                reserved_calls += 1
                reserved_fen += spec.refund_fen
            elif execution.phase == Phase.COMMITTED:
                committed_calls += 1
                committed_fen += spec.refund_fen
            effect_calls += execution.effect_count
            effect_fen += execution.effect_count * spec.refund_fen
        if budget != BudgetCounter(reserved_calls, reserved_fen, committed_calls, committed_fen):
            violated.add("reservation_ledger_matches_execution_states")
        if effect_calls > budget.reserved_calls + budget.committed_calls or (
            effect_fen > budget.reserved_fen + budget.committed_fen
        ):
            violated.add("effect_cost_is_budget_covered")
    for spec, execution in zip(config.executions, state.executions, strict=True):
        if execution.phase == Phase.RELEASED and execution.effect_count:
            violated.add("released_has_no_effect")
        if execution.phase == Phase.COMMITTED and execution.effect_count != 1:
            violated.add("committed_has_effect")
        if execution.effect_count not in (0, 1):
            violated.add("at_most_one_effect_per_execution")
        if execution.phase not in {Phase.NEW, Phase.DENIED} and (
            execution.admission_revocations is None
            or execution.admission_revocations & spec.path_mask
        ):
            violated.add("admission_precedes_chain_revocation")
        if execution.effect_count and execution.effect_started_phase != Phase.DISPATCHED:
            violated.add("first_effect_requires_active_dispatch")
        if execution.pending_envelope or execution.effect_count:
            if execution.dispatch_revocations is None or execution.dispatch_revocations & spec.path_mask:
                violated.add("dispatch_precedes_chain_revocation")
        if execution.phase in {Phase.NEW, Phase.DENIED} and (
            execution.effect_count or execution.pending_envelope
        ):
            violated.add("non_admitted_has_no_effect")
    return tuple(name for name in INVARIANTS if name in violated)


def _state_dict(state: ModelState) -> dict[str, object]:
    return {
        "revoked_credentials": [
            name for c, name in enumerate(CREDENTIALS) if state.revoked_mask & (1 << c)
        ],
        "budgets": {
            name: asdict(budget)
            for name, budget in zip(CREDENTIALS, state.budgets, strict=True)
        },
        "executions": [asdict(execution) for execution in state.executions],
    }


def _antecedents(state: ModelState) -> dict[str, bool]:
    executions = state.executions
    has_effect = any(execution.effect_count != 0 for execution in executions)
    return {
        "budget_within_limits": True,
        "reservation_ledger_matches_execution_states": True,
        "released_has_no_effect": any(execution.phase == Phase.RELEASED for execution in executions),
        "effect_cost_is_budget_covered": has_effect,
        "committed_has_effect": any(execution.phase == Phase.COMMITTED for execution in executions),
        "at_most_one_effect_per_execution": has_effect,
        "admission_precedes_chain_revocation": any(
            execution.phase not in {Phase.NEW, Phase.DENIED} for execution in executions
        ),
        "dispatch_precedes_chain_revocation": any(
            execution.pending_envelope or execution.effect_count for execution in executions
        ),
        "first_effect_requires_active_dispatch": has_effect,
        "non_admitted_has_no_effect": any(
            execution.phase in {Phase.NEW, Phase.DENIED} for execution in executions
        ),
    }


@dataclass(frozen=True, slots=True)
class TraceStep:
    action: str
    state: ModelState


@dataclass(frozen=True, slots=True)
class Counterexample:
    invariant: str
    trace: tuple[TraceStep, ...]


@dataclass(frozen=True, slots=True)
class ExplorationResult:
    config: ModelConfig
    states: tuple[ModelState, ...]
    expanded_states: int
    transitions: int
    complete: bool
    counterexamples: tuple[Counterexample, ...]

    def to_dict(self, *, include_states: bool = False) -> dict[str, object]:
        violated = {example.invariant for example in self.counterexamples}
        antecedent_states = dict.fromkeys(INVARIANTS, 0)
        phase_states = dict.fromkeys((phase.value for phase in Phase), 0)
        for state in self.states:
            for name, applicable in _antecedents(state).items():
                antecedent_states[name] += int(applicable)
            for phase in {execution.phase for execution in state.executions}:
                phase_states[phase.value] += 1
        statuses = {}
        for name in INVARIANTS:
            if name in violated:
                statuses[name] = "violated"
            elif not self.complete:
                statuses[name] = "not_violated_in_explored_prefix"
            elif antecedent_states[name] == 0:
                statuses[name] = "vacuous_within_complete_bound"
            else:
                statuses[name] = "holds_within_complete_bound"
        output: dict[str, object] = {
            "scope": "offline_finite_model_not_production_proof",
            "mechanism_variant": (
                "isolated_no_dispatch_revocation_gate" if not self.config.dispatch_revocation_gate
                else "production_barrier_abstraction" if self.config.late_dispatch_barrier
                else "isolated_no_barrier_ablation"
            ),
            "config": asdict(self.config),
            "reachable_states": len(self.states),
            "expanded_states": self.expanded_states,
            "transitions": self.transitions,
            "complete": self.complete,
            "stop_reason": None if self.complete else "STATE_LIMIT",
            "invariants": statuses,
            "coverage": {"antecedent_states": antecedent_states, "phase_states": phase_states},
            "counterexamples": [{
                "invariant": example.invariant,
                "trace": [{"action": step.action, "state": _state_dict(step.state)}
                          for step in example.trace],
            } for example in self.counterexamples],
        }
        if include_states:
            output["states"] = [_state_dict(state) for state in self.states]
        return output


def _trace(
    states: list[ModelState], parents: list[tuple[int | None, str]], index: int
) -> tuple[TraceStep, ...]:
    steps: list[TraceStep] = []
    current: int | None = index
    while current is not None:
        parent, action = parents[current]
        steps.append(TraceStep(action, states[current]))
        current = parent
    return tuple(reversed(steps))


def explore(config: ModelConfig = ModelConfig()) -> ExplorationResult:
    first = initial_state(config)
    states = [first]
    seen = {first: 0}
    parents: list[tuple[int | None, str]] = [(None, "initial")]
    pending = deque([0])
    counterexamples: dict[str, Counterexample] = {}
    for name in invariant_violations(config, first):
        counterexamples[name] = Counterexample(name, (TraceStep("initial", first),))
    expanded = transitions = 0
    complete = True
    while pending:
        index = pending.popleft()
        for action, following in successors(config, states[index]):
            transitions += 1
            if following in seen:
                continue
            if len(states) >= config.max_states:
                complete = False
                break
            next_index = len(states)
            seen[following] = next_index
            states.append(following)
            parents.append((index, action))
            pending.append(next_index)
            for name in invariant_violations(config, following):
                if name not in counterexamples:
                    counterexamples[name] = Counterexample(
                        name, _trace(states, parents, next_index)
                    )
        if not complete:
            break
        expanded += 1
    return ExplorationResult(
        config, tuple(states), expanded, transitions, complete,
        tuple(counterexamples[name] for name in INVARIANTS if name in counterexamples),
    )


def compare_barriers(
    config: ModelConfig = ModelConfig(),
) -> tuple[ExplorationResult, ExplorationResult]:
    return (
        explore(replace(config, late_dispatch_barrier=True)),
        explore(replace(config, late_dispatch_barrier=False)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executions", type=int, choices=(1, 2, 3), default=2)
    parser.add_argument("--max-states", type=int, default=20_000)
    parser.add_argument("--barrier", choices=("on", "off"), default="on")
    parser.add_argument("--dispatch-revocation-gate", choices=("on", "off"), default="on")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--include-states", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = ModelConfig(
            executions=tuple(ExecutionSpec(index % 2) for index in range(args.executions)),
            max_states=args.max_states, late_dispatch_barrier=args.barrier == "on",
            dispatch_revocation_gate=args.dispatch_revocation_gate == "on",
        )
    except ValueError as exc:
        parser.error(str(exc))
    results = compare_barriers(config) if args.compare else (explore(config),)
    output = {
        "scope": "isolated_model_ablation" if args.compare else "offline_finite_model",
        "results": [result.to_dict(include_states=args.include_states) for result in results],
    }
    print(json.dumps(output, ensure_ascii=True, indent=2))
    if any(result.counterexamples for result in results):
        return 1
    return 0 if all(result.complete for result in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
