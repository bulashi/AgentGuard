from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.agent_runtime.knowledge_attacks import KnowledgeInjectionText

from backend.authorization.contracts import BusinessIdentifier

AgentRole = Literal["coordinator", "knowledge", "case", "refund"]
# Keep "local" readable for historical records; current runtime profiles reject new local runs.
RuntimeMode = Literal["deterministic", "local", "cloud"]
WorkflowScenario = Literal["normal", "policy_injection"]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AgentContext(StrictContract):
    ticket_id: str = Field(min_length=1, max_length=128)
    customer_id: BusinessIdentifier
    refund_amount_fen: int = Field(ge=0, le=9_007_199_254_740_991)
    prompt_text: str = Field(default="", max_length=16_384)
    runtime_mode: RuntimeMode | None = None
    scenario: WorkflowScenario = "normal"
    cloud_data_confirmed: bool = False
    custom_injection_text: KnowledgeInjectionText | None = None
    knowledge_context: dict[str, Any] = Field(default_factory=dict)
    ticket_context: dict[str, Any] = Field(default_factory=dict)
    refund_context: dict[str, Any] = Field(default_factory=dict)
    authorization_context: dict[str, Any] = Field(default_factory=dict)
    workflow_run_id: str = Field(default="", max_length=128)
    workflow_token: str = Field(default="", max_length=128, repr=False)

    @model_validator(mode="after")
    def validate_injection_scenario(self) -> AgentContext:
        if self.custom_injection_text is not None and self.scenario != "policy_injection":
            raise ValueError("custom injection requires policy_injection scenario")
        return self


class ToolIntent(StrictContract):
    service: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9-]*$")
    name: str = Field(
        min_length=3,
        max_length=96,
        pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$",
    )
    version: Literal["v1"] = "v1"
    parameters: dict[str, Any]


class PlanDecision(StrictContract):
    planner: Literal["deterministic", "llm"]
    intents: tuple[ToolIntent, ...]
    evidence: dict[str, Any] = Field(default_factory=dict)


class AgentRunRequest(StrictContract):
    credential_chain: list[dict[str, Any]] = Field(min_length=1, max_length=17)
    context: AgentContext


class AgentStep(StrictContract):
    sequence: int = Field(ge=1)
    agent_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=64)
    status: Literal["RUNNING", "COMPLETED", "DENIED", "FAILED"]
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp_ms: int = Field(default_factory=lambda: int(time.time() * 1000), ge=0)


class AgentRunResponse(StrictContract):
    schema_version: Literal["1.0"] = "1.0"
    planner: Literal["deterministic", "llm"] = "deterministic"
    root_task_id: str
    status: Literal["COMPLETED", "DENIED", "FAILED"]
    result: dict[str, Any]
    trace: list[AgentStep]
