from __future__ import annotations

from typing import Any

from backend.common.error_codes import ReasonCode


class AttenuationError(RuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.reason_code = ReasonCode.DELEGATION_ESCALATION


def _require_equal(parent: dict[str, Any], child: dict[str, Any], field: str) -> None:
    if child.get(field) != parent.get(field):
        raise AttenuationError(f"{field} must equal the parent value")


def _set_subset(child: dict[str, Any], parent: dict[str, Any], field: str) -> None:
    if field not in child:
        return
    if field not in parent or not set(child[field]).issubset(set(parent[field])):
        raise AttenuationError(f"{field} is not a subset of the parent")


def _capability_is_attenuated(
    parent_capability: dict[str, Any], child_capability: dict[str, Any]
) -> bool:
    if child_capability["version"] != parent_capability["version"]:
        return False
    parent_resources = parent_capability["resources"]
    child_resources = child_capability["resources"]
    for field in ("ticket_ids", "customer_ids", "document_ids"):
        if field in parent_resources and field not in child_resources:
            return False
        if field in child_resources:
            if field not in parent_resources:
                return False
            if not set(child_resources[field]).issubset(set(parent_resources[field])):
                return False

    parent_constraints = parent_capability["constraints"]
    child_constraints = child_capability["constraints"]
    if any(field not in child_constraints for field in parent_constraints):
        return False
    if "template_ids" in child_constraints:
        if "template_ids" not in parent_constraints:
            return False
        if not set(child_constraints["template_ids"]).issubset(
            set(parent_constraints["template_ids"])
        ):
            return False
    if "single_max_fen" in child_constraints:
        if "single_max_fen" not in parent_constraints:
            return False
        if child_constraints["single_max_fen"] > parent_constraints["single_max_fen"]:
            return False
    return True


def assert_monotonic_attenuation(
    parent_payload: dict[str, Any], child_payload: dict[str, Any]
) -> None:
    for field in ("tenant_id", "task_id", "verifier_audience"):
        _require_equal(parent_payload, child_payload, field)

    parent_capabilities = parent_payload["capabilities"]
    for child_capability in child_payload["capabilities"]:
        matching = [
            candidate
            for candidate in parent_capabilities
            if candidate["service"] == child_capability["service"]
            and candidate["tool"] == child_capability["tool"]
        ]
        if not any(
            _capability_is_attenuated(candidate, child_capability)
            for candidate in matching
        ):
            raise AttenuationError(
                "child capability is absent from or broader than the parent"
            )

    parent_quotas = parent_payload["quotas"]
    child_quotas = child_payload["quotas"]
    for field in ("refund_total_fen", "max_tool_calls"):
        if child_quotas[field] > parent_quotas[field]:
            raise AttenuationError(f"{field} exceeds the parent quota")

    if child_payload["not_before"] < parent_payload["not_before"]:
        raise AttenuationError("not_before widens the parent interval")
    if child_payload["expires_at"] > parent_payload["expires_at"]:
        raise AttenuationError("expires_at widens the parent interval")
    expected_depth = parent_payload["delegation_depth"] - 1
    if expected_depth < 0 or child_payload["delegation_depth"] != expected_depth:
        raise AttenuationError("delegation_depth must equal parent depth minus one")
