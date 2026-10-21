from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from backend.agent_runtime.contracts import RuntimeMode, WorkflowScenario
from backend.agent_runtime.knowledge_attacks import KnowledgeInjectionText, forged_approval_addendum
from backend.authorization.contracts import IDENTIFIER_PATTERN, StrictContract


class RunTaskRequest(StrictContract):
    prompt_text: str = Field(default="", max_length=16_384)


class StartWorkflowRequest(StrictContract):
    runtime_mode: RuntimeMode = "deterministic"
    scenario: WorkflowScenario = "normal"
    cloud_data_confirmed: bool = False
    custom_injection_text: KnowledgeInjectionText | None = None

    @model_validator(mode="after")
    def validate_injection_scenario(self) -> StartWorkflowRequest:
        if self.custom_injection_text is not None and self.scenario != "policy_injection":
            raise ValueError("custom injection requires policy_injection scenario")
        return self


class QueuedWorkflowResponse(StrictContract):
    run_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    state: Literal["QUEUED"]
    runtime_mode: RuntimeMode


class WorkflowErrorResponse(StrictContract):
    reason_code: str
    message: str


class PromptInjectionDemoRequest(StrictContract):
    prompt_text: str = Field(
        default=forged_approval_addendum("T10086", "C9527", 7000),
        min_length=1,
        max_length=16_384,
    )
