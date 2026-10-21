"""Finite security probes. A signed probe is not an LLM-generated proposal."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from backend.agent_runtime.contracts import StrictContract, ToolIntent
from backend.authorization.contracts import IDENTIFIER_PATTERN

ProofKind = Literal["wrong_customer", "over_amount"]


class SecurityProofRequest(StrictContract):
    kind: ProofKind
    confirmed: Literal[True]

    @field_validator("confirmed", mode="before")
    @classmethod
    def require_explicit_boolean_confirmation(cls, value: Any) -> Any:
        if value is not True:
            raise ValueError("confirmation must be the JSON Boolean true")
        return value


class ProofChainRequest(StrictContract):
    credential_chain: list[dict[str, Any]] = Field(min_length=1, max_length=3)


class ProofCandidateRequest(ProofChainRequest):
    kind: Literal["wrong_customer", "over_amount", "legal_control"]
    business_action_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN,
    )

    @model_validator(mode="after")
    def persisted_action_only_for_revocation_control(self) -> ProofCandidateRequest:
        if self.business_action_id is not None and self.kind != "legal_control":
            raise ValueError("persisted action is only allowed for a legal revocation probe")
        return self


def prepare_chain(runtime: Any, request: ProofChainRequest) -> dict[str, Any]:
    from backend.agent_runtime.service import AgentRuntimeError

    chain = deepcopy(request.credential_chain)
    runtime._require_chain_for_this_agent(chain)
    expected_length = {"coordinator": 1, "case": 2}.get(runtime.role)
    if len(chain) != expected_length:
        raise AgentRuntimeError("WRONG_HOLDER", "security proof requires the coordinator/case path")
    child_role = "case" if runtime.role == "coordinator" else "refund"
    child = runtime._delegate(
        chain,
        child_role=child_role,
        tools=("refund.create",),
        refund_total_fen=int(chain[-1]["payload"]["quotas"]["refund_total_fen"]),
        max_tool_calls=1,
    )
    chain.append(child)
    if runtime.role == "coordinator":
        return runtime._post_json(
            runtime.settings.case_agent_url,
            "/agents/security-proof/prepare",
            {"credential_chain": chain},
        )
    return {"credential_chain": chain}


def signed_candidate(runtime: Any, request: ProofCandidateRequest) -> dict[str, Any]:
    from backend.agent_runtime.service import AgentRuntimeError

    chain = deepcopy(request.credential_chain)
    runtime._require_chain_for_this_agent(chain)
    holders = [item.get("payload", {}).get("holder", {}).get("agent_id") for item in chain]
    if runtime.role != "refund" or holders != ["agent-coordinator", "agent-case", "agent-refund"]:
        raise AgentRuntimeError("WRONG_HOLDER", "security proof requires two real delegations")
    capability = next(
        (
            item
            for item in chain[-1]["payload"]["capabilities"]
            if item.get("tool") == "refund.create"
        ),
        None,
    )
    if not isinstance(capability, dict):
        raise AgentRuntimeError("TOOL_NOT_ALLOWED", "refund capability is required")
    resources = capability["resources"]
    tickets, customers = resources.get("ticket_ids", []), resources.get("customer_ids", [])
    amount = capability["constraints"].get("single_max_fen")
    if len(tickets) != 1 or len(customers) != 1 or type(amount) is not int or amount <= 0:
        raise AgentRuntimeError("REQUEST_SCHEMA_INVALID", "proof requires a single bounded refund")
    parameters = {"ticket_id": tickets[0], "customer_id": customers[0], "amount_fen": amount}
    if request.kind == "wrong_customer":
        parameters["customer_id"] = "CUSTOMER-OUTSIDE-AUTHORIZATION"
        if parameters["customer_id"] in customers:
            raise AgentRuntimeError("REQUEST_SCHEMA_INVALID", "probe customer must be out of scope")
    elif request.kind == "over_amount":
        parameters["amount_fen"] = amount + 1
    action_id = request.business_action_id
    if action_id is None:
        action = runtime._post_json(
            runtime.settings.business_action_registry_url,
            "/business-actions/refund/resolve",
            {"task_id": runtime._task_id(chain)},
        )
        action_id = str(action["business_action_id"])
    envelope = runtime._tool_request(
        chain,
        ToolIntent(service="refund-service", name="refund.create", parameters=parameters),
        business_action_id=action_id,
    )
    return {"request": envelope, "candidate_origin": "deterministic_security_probe"}
