from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal, cast

import httpx
from jsonschema import ValidationError
from psycopg.errors import ForeignKeyViolation, UniqueViolation

from backend.agent_runtime.contracts import (
    AgentContext,
    AgentRole,
    AgentRunRequest,
    AgentRunResponse,
    AgentStep,
    PlanDecision,
    ToolIntent,
)
from backend.agent_runtime.planner import (
    DeterministicPlanner,
    Planner,
    PlannerError,
)
from backend.agent_runtime.workflow_planner import (
    WorkflowPlanner,
    has_business_facts,
    planning_input,
    runtime_profiles,
)
from backend.agent_runtime.workflow_store import WorkflowStore, WorkflowStoreError, safe_observation
from backend.business_action.contracts import BusinessFactEvaluationResponse
from backend.common.enums import KeyPurpose
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.config.model_profiles import ModelConfigurationError, ModelProfileStore
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import EXECUTION_RECEIPT, HOLDER_PROOF
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex, verify_payload

ROLE_IDENTITIES: dict[AgentRole, tuple[str, str]] = {
    "coordinator": ("agent-coordinator", "agent-coordinator-key-01"),
    "knowledge": ("agent-knowledge", "agent-knowledge-key-01"),
    "case": ("agent-case", "agent-case-key-01"),
    "refund": ("agent-refund", "agent-refund-key-01"),
}


def public_credential_scope(chain: list[dict[str, Any]]) -> dict[str, Any]:
    """Expose signed scope claims, never keys or a live remaining-budget assertion."""
    fields = (
        "tenant_id", "task_id", "holder", "capabilities", "quotas",
        "not_before", "expires_at", "delegation_depth", "verifier_audience",
    )
    return {
        "source": "credential_claims_gateway_verifies_before_execution",
        "root": {key: deepcopy(chain[0]["payload"][key]) for key in fields
                 if key in chain[0]["payload"]},
        "current_branch": {key: deepcopy(chain[-1]["payload"][key]) for key in fields
                           if key in chain[-1]["payload"]},
        "chain_length": len(chain),
        "budget_semantics": "limits_not_live_remaining_budget_atomic_gateway_is_authoritative",
    }


class RecordedTrace(list[AgentStep]):
    def __init__(self, recorder: Callable[[AgentStep], None]) -> None:
        super().__init__()
        self.recorder = recorder


class AgentRuntimeError(RuntimeError):
    def __init__(self, reason_code: str, message: str, *, status_code: int = 403) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code
        self.execution_id: str | None = None
        self.admission_outcome: str | None = None


class AgentRuntimeService:
    def __init__(self, settings: Settings, planner: Planner | None = None) -> None:
        if settings.agent_role not in ROLE_IDENTITIES:
            raise ValueError(f"unsupported agent role: {settings.agent_role}")
        self.settings = settings
        self.role = cast(AgentRole, settings.agent_role)
        expected_agent, expected_key = ROLE_IDENTITIES[self.role]
        if (settings.agent_id, settings.agent_key_id) != (expected_agent, expected_key):
            raise ValueError("configured agent identity does not match its role")
        self.agent_id = expected_agent
        self.key_id = expected_key
        self.private_key = Path(settings.agent_private_key_file).read_text(encoding="ascii").strip()
        self.public_key = derive_public_key(self.private_key)
        if planner is not None:
            self.planner = planner
        elif settings.llm_mode == "deterministic":
            self.planner = DeterministicPlanner()
        else:
            raise ValueError(f"unsupported planner mode: {settings.llm_mode}")
        self.planner_name = cast(Literal["deterministic", "llm"], self.planner.name)

    def run(self, request: AgentRunRequest) -> AgentRunResponse:
        chain = deepcopy(request.credential_chain)
        task_id = self._require_chain_for_this_agent(chain)
        self._authorize_run(chain, request.context)
        request = request.model_copy(update={
            "context": request.context.model_copy(update={
                "authorization_context": public_credential_scope(chain),
            }),
        })
        trace: list[AgentStep] = []
        planner_name = (
            "llm" if request.context.runtime_mode in {"local", "cloud"} else self.planner_name
        )
        if request.context.runtime_mode == "deterministic":
            planner_name = "deterministic"
        if request.context.workflow_run_id:
            trace = RecordedTrace(lambda event: self.observe(request.context, event))
            self._step(
                trace,
                "agent_started",
                {"role": self.role, "runtime_mode": request.context.runtime_mode},
                status="RUNNING",
            )
        try:
            if self.role == "coordinator":
                result = self._run_coordinator(chain, request.context, trace)
            elif self.role == "knowledge":
                result = self._run_knowledge(chain, request.context, trace)
            elif self.role == "case":
                result = self._run_case(chain, request.context, trace)
            else:
                result = self._run_refund(chain, request.context, trace)
        except AgentRuntimeError as exc:
            if (
                planner_name != "llm" and not request.context.workflow_run_id
            ) or exc.status_code not in {403, 409}:
                if request.context.workflow_run_id:
                    self._step(
                        trace,
                        "agent_finished",
                        {"reason_code": exc.reason_code, "message": str(exc)},
                        status="FAILED",
                    )
                raise
            self._step(
                trace,
                "agent_finished" if request.context.workflow_run_id else "gateway_decision",
                {"reason_code": exc.reason_code, "message": str(exc)},
                status="DENIED",
            )
            return AgentRunResponse(
                planner=cast(Any, planner_name),
                root_task_id=task_id,
                status="DENIED",
                result={"reason_code": exc.reason_code, "message": str(exc)},
                trace=trace,
            )
        if request.context.workflow_run_id:
            self._step(trace, "agent_finished", {"output": safe_observation(result)})
        return AgentRunResponse(
            planner=cast(Any, planner_name),
            root_task_id=task_id,
            status="COMPLETED",
            result=result,
            trace=trace,
        )

    def prepare_workflow(self, request: AgentRunRequest) -> tuple[dict[str, Any], AgentRunRequest]:
        context = request.context
        if (
            self.role != "coordinator"
            or context.runtime_mode is None
            or context.workflow_run_id
            or context.workflow_token
        ):
            raise AgentRuntimeError(
                "REQUEST_SCHEMA_INVALID",
                "workflow starts require a coordinator and a public mode",
                status_code=400,
            )
        if context.runtime_mode == "cloud" and not context.cloud_data_confirmed:
            raise AgentRuntimeError(
                "CLOUD_CONFIRMATION_REQUIRED",
                "cloud execution requires explicit business-data confirmation",
                status_code=400,
            )
        task_id = self._require_chain_for_this_agent(request.credential_chain)
        self._authorize_run(request.credential_chain, context)
        try:
            configuration_lock = (
                ModelProfileStore(Path(self.settings.model_configurations_path)).lock()
                if self.settings.model_configurations_path else nullcontext()
            )
            # Default-model changes and workflow admission use the same cross-process lock.
            with configuration_lock:
                profile = next((item for item in runtime_profiles(self.settings)["items"]
                                if item["mode"] == context.runtime_mode), None)
                if profile is None:
                    raise AgentRuntimeError("MODEL_MODE_UNAVAILABLE", "该运行模式已停用；请选择智能体审查或确定性规则", status_code=503)
                if not profile["available"]:
                    raise AgentRuntimeError("MODEL_MODE_UNAVAILABLE", profile["message"], status_code=503)
                run_id, token = WorkflowStore(self.settings.workflow_database_url).create(
                    task_id=task_id, mode=context.runtime_mode, scenario=context.scenario,
                    model=profile["model"], timeout_seconds=self.settings.workflow_timeout_seconds,
                )
        except ModelConfigurationError as exc:
            raise AgentRuntimeError(exc.reason_code, str(exc), status_code=exc.status_code) from exc
        except UniqueViolation as exc:
            raise AgentRuntimeError(
                "WORKFLOW_ALREADY_EXISTS",
                "this task already has a persistent workflow",
                status_code=409,
            ) from exc
        except ForeignKeyViolation as exc:
            raise AgentRuntimeError(
                "CROSS_TASK", "workflow task does not exist", status_code=404
            ) from exc
        except WorkflowStoreError as exc:
            raise AgentRuntimeError(
                "OBSERVATION_STORE_UNAVAILABLE", str(exc), status_code=503
            ) from exc
        internal = request.model_copy(
            update={
                "context": context.model_copy(
                    update={
                        "workflow_run_id": run_id,
                        "workflow_token": token,
                    }
                )
            }
        )
        return {
            "run_id": run_id,
            "task_id": task_id,
            "state": "QUEUED",
            "runtime_mode": context.runtime_mode,
        }, internal

    def execute_workflow(self, request: AgentRunRequest) -> None:
        store = WorkflowStore(self.settings.workflow_database_url)
        store.state(request.context.workflow_run_id, "RUNNING")
        try:
            response = self.run(request)
            store.state(
                request.context.workflow_run_id, response.status, response.result.get("reason_code")
            )
        except Exception as exc:
            reason = (
                exc.reason_code if isinstance(exc, AgentRuntimeError) else "WORKFLOW_RUNTIME_FAILED"
            )
            store.state(request.context.workflow_run_id, "FAILED", reason)

    def observe(self, context: AgentContext, event: AgentStep) -> None:
        try:
            if self.role == "coordinator":
                WorkflowStore(self.settings.workflow_database_url).append(
                    context.workflow_run_id, context.workflow_token, event
                )
            else:
                self._post_json(
                    self.settings.coordinator_agent_url,
                    f"/agents/workflows/{context.workflow_run_id}/observe",
                    event.model_dump(mode="json"),
                    headers={"X-Workflow-Token": context.workflow_token},
                )
        except WorkflowStoreError as exc:
            raise AgentRuntimeError(
                "OBSERVATION_STORE_UNAVAILABLE", str(exc), status_code=503
            ) from exc

    def _run_coordinator(
        self,
        chain: list[dict[str, Any]],
        context: AgentContext,
        trace: list[AgentStep],
    ) -> dict[str, Any]:
        self._plan(
            "coordinator", context, trace, expected_tools=(), stage="coordinate", chain=chain,
        )
        knowledge = self._delegate(
            chain,
            child_role="knowledge",
            tools=("knowledge.read_associated",),
            refund_total_fen=0,
            max_tool_calls=1,
        )
        knowledge_chain = [*chain, knowledge]
        self._step(
            trace,
            "delegate",
            {"child_agent_id": "agent-knowledge", "credential_id": self._credential_id(knowledge)},
        )
        knowledge_result = self._run_child(
            self.settings.knowledge_agent_url, knowledge_chain, context, trace
        )

        case = self._delegate(
            chain,
            child_role="case",
            tools=("ticket.read", "refund.create", "notification.send_template"),
            refund_total_fen=context.refund_amount_fen,
            max_tool_calls=3,
        )
        case_chain = [*chain, case]
        self._step(
            trace,
            "delegate",
            {"child_agent_id": "agent-case", "credential_id": self._credential_id(case)},
        )
        case_context = (
            context.model_copy(update={"knowledge_context": knowledge_result})
            if context.runtime_mode
            else context
        )
        case_result = self._run_child(self.settings.case_agent_url, case_chain, case_context, trace)
        return {"knowledge": knowledge_result, "case": case_result}

    def _run_knowledge(
        self,
        chain: list[dict[str, Any]],
        context: AgentContext,
        trace: list[AgentStep],
    ) -> dict[str, Any]:
        intent = self._plan(
            "knowledge",
            context,
            trace,
            expected_tools=("knowledge.read_associated",),
            stage="knowledge_read",
            chain=chain,
        ).intents[0]
        result = self._call_tool(chain, intent, trace=trace)
        self._step(
            trace,
            "call_tool",
            {
                "tool": intent.name,
                "execution_id": result["execution_id"],
                "output": safe_observation(result["result"]),
            },
        )
        if context.runtime_mode:
            knowledge = deepcopy(result["result"])
            if not isinstance(knowledge, dict) or not isinstance(knowledge.get("documents"), list):
                raise AgentRuntimeError(
                    "CONTROLLED_RESULT_INVALID", "knowledge result is malformed", status_code=502
                )
            original_hash = sm3_hex(canonicalize(knowledge))
            if context.scenario == "policy_injection":
                if not knowledge["documents"]:
                    raise AgentRuntimeError(
                        "CONTROLLED_RESULT_INVALID",
                        "knowledge injection requires an actual associated document",
                        status_code=502,
                    )
                from backend.agent_runtime.knowledge_attacks import inject_knowledge_copy

                knowledge = inject_knowledge_copy(
                    knowledge, context.ticket_id, context.customer_id, context.refund_amount_fen,
                    context.custom_injection_text,
                )
            self._step(
                trace,
                "knowledge_result",
                {
                    "output": knowledge,
                    "execution_id": result["execution_id"],
                    "injection_applied": context.scenario == "policy_injection",
                    "original_result_sm3": original_hash,
                },
            )
            summary = self._plan(
                "knowledge",
                context.model_copy(update={"knowledge_context": knowledge}),
                trace,
                expected_tools=(),
                stage="knowledge_summary",
                chain=chain,
            )
            return {
                "documents": knowledge["documents"],
                "summary": summary.evidence["summary"],
                "demo_injection": knowledge.get("demo_injection"),
                "execution_id": result["execution_id"],
            }
        return {"knowledge": result["result"]}

    def _run_case(
        self,
        chain: list[dict[str, Any]],
        context: AgentContext,
        trace: list[AgentStep],
    ) -> dict[str, Any]:
        decision = self._plan(
            "case",
            context,
            trace,
            expected_tools=("ticket.read",)
            if context.runtime_mode
            else ("ticket.read", "notification.send_template"),
            stage="case_read",
            chain=chain,
        )
        ticket_intent = decision.intents[0]
        notification_intent = decision.intents[1] if not context.runtime_mode else None
        ticket = self._call_tool(chain, ticket_intent, trace=trace)
        self._step(
            trace,
            "call_tool",
            {
                "tool": ticket_intent.name,
                "execution_id": ticket["execution_id"],
                "output": safe_observation(ticket["result"]),
            },
        )
        ticket_row = ticket["result"]
        expected_tenant = self._payload(chain[0]).get("tenant_id")
        if (
            not isinstance(ticket_row, dict)
            or ticket_row.get("ticket_id") != context.ticket_id
            or ticket_row.get("customer_id") != context.customer_id
            or ("tenant_id" in ticket_row and ticket_row["tenant_id"] != expected_tenant)
        ):
            raise AgentRuntimeError(
                "BUSINESS_CONTEXT_MISMATCH",
                "ticket result does not match the authorized task; no refund is delegated",
                status_code=502,
            )
        business_context = (
            context.model_copy(update={"ticket_context": ticket_row})
            if context.runtime_mode or isinstance(ticket_row.get("business_facts"), dict)
            else context
        )

        if ticket_row.get("status") not in {"OPEN", "IN_PROGRESS"}:
            raise AgentRuntimeError(
                "BUSINESS_PRECONDITION_FAILED",
                "ticket is not eligible for refund processing; no refund is delegated",
                status_code=409,
            )

        refund_credential = self._delegate(
            chain,
            child_role="refund",
            tools=("refund.create",),
            refund_total_fen=context.refund_amount_fen,
            max_tool_calls=1,
        )
        refund_chain = [*chain, refund_credential]
        self._step(
            trace,
            "delegate",
            {
                "child_agent_id": "agent-refund",
                "credential_id": self._credential_id(refund_credential),
            },
        )
        refund = self._run_child(
            self.settings.refund_agent_url, refund_chain, business_context, trace
        )
        refund_row = refund.get("refund")
        self._validate_refund_result(chain, business_context, refund_row)
        related_effect_id = str(refund_row["refund_id"])
        if context.runtime_mode or has_business_facts(business_context):
            notification_intent = self._plan(
                "case",
                business_context.model_copy(update={"refund_context": refund_row}),
                trace,
                expected_tools=("notification.send_template",),
                stage="case_notify",
                chain=chain,
            ).intents[0]
        assert notification_intent is not None
        action = self._post_json(
            self.settings.business_action_registry_url,
            "/business-actions/notification/resolve",
            {
                "task_id": self._task_id(chain),
                "template_id": "REFUND_SUCCESS",
                "related_business_effect_id": related_effect_id,
            },
        )
        notification_parameters = dict(notification_intent.parameters)
        notification_parameters["related_business_effect_id"] = related_effect_id
        notification = self._call_tool(
            chain,
            ToolIntent(
                service=notification_intent.service,
                name=notification_intent.name,
                version=notification_intent.version,
                parameters=notification_parameters,
            ),
            business_action_id=str(action["business_action_id"]),
            trace=trace,
        )
        self._step(
            trace,
            "call_tool",
            {
                "tool": notification_intent.name,
                "execution_id": notification["execution_id"],
                "output": safe_observation(notification["result"]),
            },
        )
        notification_row = notification["result"]
        if (
            not isinstance(notification_row, dict)
            or not isinstance(notification_row.get("notification_id"), str)
            or not notification_row["notification_id"]
            or notification_row.get("status") != "SENT"
            or notification_row.get("template_id") != "REFUND_SUCCESS"
            or (
                "related_business_effect_id" in notification_row
                and notification_row["related_business_effect_id"] != related_effect_id
            )
            or (
                "customer_id" in notification_row
                and notification_row["customer_id"] != context.customer_id
            )
            or (
                "tenant_id" in notification_row and notification_row["tenant_id"] != expected_tenant
            )
            or (
                "task_id" in notification_row
                and notification_row["task_id"] != self._task_id(chain)
            )
        ):
            raise AgentRuntimeError(
                "BUSINESS_RESULT_MISMATCH",
                "notification result does not confirm delivery for the committed refund",
                status_code=502,
            )
        return {
            "ticket": ticket_row,
            "refund": refund_row,
            "notification": notification_row,
        }

    def _run_refund(
        self,
        chain: list[dict[str, Any]],
        context: AgentContext,
        trace: list[AgentStep],
    ) -> dict[str, Any]:
        try:
            decision = self._plan(
                "refund", context, trace, expected_tools=("refund.create",),
                stage="refund", chain=chain,
            )
        except AgentRuntimeError as exc:
            if has_business_facts(context) and exc.reason_code == "PLANNER_DECLINED":
                # A model stopping is distinct from the independent business verdict.
                evaluation = self._evaluate_refund_facts(chain, context, trace)
                self._require_verified_facts(evaluation)
            raise
        intent = decision.intents[0]
        evaluation = self._evaluate_refund_facts(chain, context, trace) if has_business_facts(context) else None
        if evaluation is not None:
            self._require_verified_facts(evaluation)
        expected_amount = evaluation["refundable_amount_fen"] if evaluation else context.refund_amount_fen
        if (
            type(intent.parameters.get("amount_fen")) is not int
            or intent.parameters.get("amount_fen") != expected_amount
            or not 0 < expected_amount <= context.refund_amount_fen
            or intent.parameters.get("customer_id") != context.customer_id
            or intent.parameters.get("ticket_id") != context.ticket_id
        ):
            raise AgentRuntimeError(
                "BUSINESS_RESULT_MISMATCH",
                "退款建议的客户、工单或金额与原始支付事实及授权上限不一致，未提交退款",
                status_code=502,
            )
        action = self._post_json(
            self.settings.business_action_registry_url,
            "/business-actions/refund/resolve",
            {"task_id": self._task_id(chain)},
        )
        result = self._call_tool(
            chain,
            intent,
            business_action_id=str(action["business_action_id"]),
            trace=trace,
        )
        self._step(
            trace,
            "call_tool",
            {
                "tool": intent.name,
                "execution_id": result["execution_id"],
                "output": safe_observation(result["result"]),
            },
        )
        refund = result["result"]
        self._validate_refund_result(chain, context, refund, verification=evaluation)
        return {"refund": refund, **({"business_verification": evaluation} if evaluation else {})}

    def _evaluate_refund_facts(
        self,
        chain: list[dict[str, Any]],
        context: AgentContext,
        trace: list[AgentStep] | None = None,
    ) -> dict[str, Any]:
        body = self._post_json(
            self.settings.business_action_registry_url,
            "/business-actions/refund/evaluate",
            {"task_id": self._task_id(chain)},
        )
        try:
            evaluation = BusinessFactEvaluationResponse.model_validate(body).model_dump(
                mode="json"
            )
            if (
                evaluation["task_id"] != self._task_id(chain)
                or evaluation["ticket_id"] != context.ticket_id
            ):
                raise ValueError("fact evaluation task binding mismatch")
            if (
                context.ticket_context is None
                or evaluation["facts_hash"] != context.ticket_context.get("facts_hash")
            ):
                raise ValueError("fact evaluation source binding mismatch")
        except ValueError as exc:
            raise AgentRuntimeError(
                "BUSINESS_CONTEXT_MISMATCH",
                "独立核验记录无法与本任务的原始支付资料核对",
                status_code=502,
            ) from exc
        if trace is not None:
            self._step(
                trace,
                "business_verification",
                {**evaluation, "stage": "refund"},
                status="COMPLETED" if evaluation["status"] == "VERIFIED" else "DENIED",
            )
        return evaluation

    @staticmethod
    def _require_verified_facts(evaluation: dict[str, Any]) -> None:
        if evaluation["status"] != "VERIFIED":
            raise AgentRuntimeError(
                "BUSINESS_VERIFICATION_REJECTED"
                if evaluation["status"] == "REJECTED"
                else "BUSINESS_VERIFICATION_PENDING",
                evaluation["reason"],
                status_code=409,
            )

    def _validate_refund_result(
        self, chain: list[dict[str, Any]], context: AgentContext, refund: Any,
        *, verification: dict[str, Any] | None = None,
    ) -> None:
        # The parent rechecks the child result before planning a success notification.
        expected_scope = {
            "customer_id": context.customer_id,
            "ticket_id": context.ticket_id,
            "task_id": self._task_id(chain),
        }
        if chain:
            expected_scope["tenant_id"] = self._payload(chain[0]).get("tenant_id")
        if has_business_facts(context):
            verification = verification or self._evaluate_refund_facts(chain, context)
            self._require_verified_facts(verification)
        expected_amount = verification["refundable_amount_fen"] if verification else context.refund_amount_fen
        if (
            not isinstance(refund, dict)
            or type(refund.get("amount_fen")) is not int
            or refund.get("amount_fen") != expected_amount
            or not 0 < expected_amount <= context.refund_amount_fen
            or not isinstance(refund.get("refund_id"), str)
            or not refund.get("refund_id")
            or refund.get("status") != "COMMITTED"
            or any(
                field in refund and refund[field] != expected
                for field, expected in expected_scope.items()
            )
        ):
            raise AgentRuntimeError(
                "BUSINESS_RESULT_MISMATCH",
                "committed refund does not fulfill the requested business task; "
                "no notification is planned",
                status_code=502,
            )

    def _delegate(
        self,
        chain: list[dict[str, Any]],
        *,
        child_role: AgentRole,
        tools: tuple[str, ...],
        refund_total_fen: int,
        max_tool_calls: int,
    ) -> dict[str, Any]:
        if not self.settings.agent_delegation_url:
            raise AgentRuntimeError(
                "RUNTIME_CONFIGURATION_INVALID",
                "delegating agent has no delegation service URL",
                status_code=500,
            )
        parent = chain[-1]
        payload = self._payload(parent)
        capabilities = []
        for tool in tools:
            capability = next(
                (item for item in payload["capabilities"] if item.get("tool") == tool),
                None,
            )
            if capability is None:
                raise AgentRuntimeError(
                    "DELEGATION_ESCALATION",
                    f"parent credential lacks required capability {tool}",
                )
            capabilities.append(deepcopy(capability))
        child_agent_id, child_key_id = ROLE_IDENTITIES[child_role]
        return self._post_json(
            self.settings.agent_delegation_url,
            f"/credentials/{payload['credential_id']}/delegate",
            {
                "holder_agent_id": child_agent_id,
                "holder_key_id": child_key_id,
                "capabilities": capabilities,
                "quotas": {
                    "refund_total_fen": refund_total_fen,
                    "max_tool_calls": max_tool_calls,
                },
                "not_before": int(payload["not_before"]),
                "expires_at": int(payload["expires_at"]),
            },
            expected_status=201,
        )

    def _run_child(
        self,
        base_url: str,
        chain: list[dict[str, Any]],
        context: AgentContext,
        trace: list[AgentStep],
    ) -> dict[str, Any]:
        body = self._post_json(
            base_url,
            "/agents/run",
            {
                "credential_chain": chain,
                "context": context.model_dump(mode="json"),
            },
            timeout_seconds=self.settings.workflow_timeout_seconds
            if context.runtime_mode
            else None,
        )
        child_trace = body.get("trace")
        if not isinstance(child_trace, list):
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                "child agent response omitted its trace",
                status_code=502,
            )
        for item in child_trace:
            if not isinstance(item, dict):
                continue
            trace.append(
                AgentStep(
                    sequence=len(trace) + 1,
                    agent_id=str(item.get("agent_id", "unknown")),
                    action=str(item.get("action", "unknown")),
                    status=cast(Any, item.get("status", "FAILED")),
                    details=cast(dict[str, Any], item.get("details") or {}),
                    **(
                        {"timestamp_ms": item["timestamp_ms"]}
                        if isinstance(item.get("timestamp_ms"), int)
                        else {}
                    ),
                )
            )
        result = body.get("result")
        if context.runtime_mode and body.get("status") == "DENIED" and isinstance(result, dict):
            raise AgentRuntimeError(
                str(result.get("reason_code", "GATEWAY_DENIED")),
                str(result.get("message", "child workflow was denied")),
            )
        if not isinstance(result, dict) or body.get("status") != "COMPLETED":
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                "child agent did not complete successfully",
                status_code=502,
            )
        return result

    def _tool_request(
        self,
        chain: list[dict[str, Any]],
        intent: ToolIntent,
        *,
        business_action_id: str | None = None,
    ) -> dict[str, Any]:
        task_id = self._task_id(chain)
        issued_at = now_unix()
        request_id = new_id("REQ")
        parameter_hash = sm3_hex(canonicalize(intent.parameters))
        holder_payload = {
            "schema_version": "1.0",
            "credential_chain_hash": sm3_hex(canonicalize(chain)),
            "task_id": task_id,
            "tool_service": intent.service,
            "tool_name": intent.name,
            "tool_version": intent.version,
            "canonical_parameter_hash": parameter_hash,
            "request_id": request_id,
            "issued_at": issued_at,
            "business_action_id": business_action_id,
        }
        envelope = {
            "schema_version": "1.0",
            "credential_chain": chain,
            "task_id": task_id,
            "tool_service": intent.service,
            "tool_name": intent.name,
            "tool_version": intent.version,
            "canonical_parameters": intent.parameters,
            "request_id": request_id,
            "issued_at": issued_at,
            "holder_key_id": self.key_id,
            "business_action_id": business_action_id,
            "holder_proof": {
                "payload": holder_payload,
                "signature": self._sign(holder_payload, issued_at=issued_at),
            },
        }
        return envelope

    def _call_tool(
        self,
        chain: list[dict[str, Any]],
        intent: ToolIntent,
        *,
        business_action_id: str | None = None,
        trace: list[AgentStep] | None = None,
    ) -> dict[str, Any]:
        envelope = self._tool_request(chain, intent, business_action_id=business_action_id)
        task_id = envelope["task_id"]
        request_id = envelope["request_id"]
        issued_at = envelope["issued_at"]
        parameter_hash = envelope["holder_proof"]["payload"]["canonical_parameter_hash"]
        holder_payload = envelope["holder_proof"]["payload"]
        if isinstance(trace, RecordedTrace):
            self._step(
                trace,
                "gateway_request",
                {
                    "tool": intent.name,
                    "tool_service": intent.service,
                    "tool_version": intent.version,
                    "task_id": task_id,
                    "parameters": intent.parameters,
                    "parameter_hash": parameter_hash,
                    "request_hash": sm3_hex(canonicalize(envelope)),
                    "credential_chain_hash": holder_payload["credential_chain_hash"],
                    "request_id": request_id,
                    "issued_at": issued_at,
                    "holder_key_id": self.key_id,
                    "business_action_id": business_action_id,
                    "credential_ids": [self._credential_id(item) for item in chain],
                },
                status="RUNNING",
            )
        try:
            body = self._post_json(self.settings.gateway_url, "/gateway/dispatch", envelope)
        except AgentRuntimeError as exc:
            if exc.reason_code == "TOOL_EXECUTION_UNKNOWN" and exc.execution_id:
                # Recovery queries the existing effect; this request is never dispatched twice.
                body = {
                    "execution_id": exc.execution_id,
                    "decision": "ALLOW",
                    "state": "UNKNOWN",
                    "admission_outcome": exc.admission_outcome,
                    "receipt": None,
                }
            else:
                if isinstance(trace, RecordedTrace):
                    self._step(
                        trace,
                        "gateway_decision",
                        {
                            "tool": intent.name,
                            "request_id": request_id,
                            "request_hash": sm3_hex(canonicalize(envelope)),
                            "reason_code": exc.reason_code,
                            "message": str(exc),
                            "execution_id": exc.execution_id,
                            "decision": "DENY" if exc.status_code in {403, 409} else None,
                        },
                        status="DENIED" if exc.status_code in {403, 409} else "FAILED",
                    )
                raise
        if body.get("decision") != "ALLOW" or body.get("state") not in {
            "COMMITTED", "DISPATCHED", "UNKNOWN", "RECONCILING",
        }:
            raise AgentRuntimeError(
                str(body.get("reason_code", "GATEWAY_DENIED")),
                "gateway did not commit the controlled tool execution",
                status_code=403,
            )
        execution_id = body.get("execution_id")
        receipt = body.get("receipt")
        if not isinstance(execution_id, str) or not execution_id.startswith("EXEC-"):
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                "gateway response omitted execution evidence",
                status_code=502,
            )
        if body.get("state") != "COMMITTED" or receipt is None:
            retrieved, receipt = self._wait_for_execution(
                chain, execution_id=execution_id, trace=trace, tool_name=intent.name,
            )
        else:
            retrieved = self._retrieve_result(chain, execution_id=execution_id)
        self._validate_execution_receipt(
            envelope, execution_id=execution_id, result=retrieved.get("result"), receipt=receipt,
            original_request=body.get("admission_outcome") not in {
                "IDEMPOTENT_RETURN", "EXISTING_EXECUTION",
            },
        )
        if isinstance(trace, RecordedTrace):
            self._step(
                trace,
                "gateway_decision",
                {
                    "tool": intent.name,
                    "request_id": request_id,
                    "request_hash": sm3_hex(canonicalize(envelope)),
                    "execution_id": execution_id,
                    "decision": body["decision"],
                    "state": "COMMITTED",
                    "receipt_id": receipt["payload"].get("receipt_id"),
                },
            )
        return {
            "execution_id": execution_id,
            "receipt": receipt,
            "result": retrieved.get("result"),
        }

    def _wait_for_execution(
        self, chain: list[dict[str, Any]], *, execution_id: str,
        trace: list[AgentStep] | None, tool_name: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        wait_seconds = min(
            self.settings.recovery_deadline_seconds,
            self.settings.workflow_timeout_seconds if isinstance(trace, RecordedTrace)
            else self.settings.agent_request_timeout_seconds,
        )
        deadline = time.monotonic() + wait_seconds
        if isinstance(trace, RecordedTrace):
            self._step(
                trace, "gateway_recovery_wait",
                {"tool": tool_name, "execution_id": execution_id,
                 "timeout_seconds": wait_seconds}, status="RUNNING",
            )
        retrieved: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            try:
                if retrieved is None:
                    retrieved = self._retrieve_result(
                        chain, execution_id=execution_id,
                        timeout_seconds=min(
                            self.settings.agent_request_timeout_seconds,
                            max(0.001, deadline - time.monotonic()),
                        ),
                    )
                if time.monotonic() >= deadline:
                    break
                receipt = self._post_json(
                    self.settings.gateway_url, "/gateway/receipts/retrieve",
                    self._retrieval_request(chain, execution_id=execution_id),
                    timeout_seconds=min(
                        self.settings.agent_request_timeout_seconds,
                        max(0.001, deadline - time.monotonic()),
                    ),
                )
                if time.monotonic() >= deadline:
                    break
                return retrieved, receipt
            except AgentRuntimeError as exc:
                if exc.reason_code not in {
                    "RESULT_ACCESS_DENIED", "UPSTREAM_UNAVAILABLE", "TOOL_EXECUTION_UNKNOWN",
                }:
                    raise
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(self.settings.recovery_interval_seconds, remaining, 5))
        error = AgentRuntimeError(
            "WORKFLOW_RECOVERY_TIMEOUT",
            "existing tool execution or signed receipt did not become available in time; "
            "no tool request is resubmitted",
            status_code=502,
        )
        error.execution_id = execution_id
        raise error

    def _validate_execution_receipt(
        self, envelope: dict[str, Any], *, execution_id: str, result: Any, receipt: Any,
        original_request: bool,
    ) -> None:
        try:
            SchemaStore().validate("execution-receipt.schema.json", receipt)
            payload, signature = receipt["payload"], receipt["signature"]
            expected = {
                "execution_id": execution_id,
                "task_id": envelope["task_id"],
                "tenant_id": self._payload(envelope["credential_chain"][0])["tenant_id"],
                "credential_chain_hash": (
                    envelope["holder_proof"]["payload"]["credential_chain_hash"]
                ),
                "tool_service": envelope["tool_service"],
                "tool_name": envelope["tool_name"],
                "tool_version": envelope["tool_version"],
                "parameter_hash": envelope["holder_proof"]["payload"]["canonical_parameter_hash"],
                "business_action_id": envelope["business_action_id"],
                "business_result_hash": sm3_hex(canonicalize(result)),
                "decision": "ALLOW",
                "reason_code": "ALLOWED",
                "receipt_signing_key_id": self.settings.receipt_key_id,
            }
            if original_request:
                expected.update(
                    request_id=envelope["request_id"], request_hash=sm3_hex(canonicalize(envelope)),
                )
            public_key = Path(self.settings.receipt_public_key_file).read_text(
                encoding="ascii",
            ).strip()
            valid = all(payload[field] == value for field, value in expected.items()) and (
                signature["signed_at"] == payload["receipt_issued_at"]
                and verify_payload(
                    payload, signature, domain_separator=EXECUTION_RECEIPT,
                    expected_key_id=self.settings.receipt_key_id,
                    expected_key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
                    public_key_hex=public_key,
                )
            )
        except (KeyError, TypeError, ValueError, OSError, ValidationError):
            valid = False
        if not valid:
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                "signed receipt does not verify the committed execution, parameters and result",
                status_code=502,
            )

    def _retrieval_request(
        self, chain: list[dict[str, Any]], *, execution_id: str,
    ) -> dict[str, Any]:
        task_id = self._task_id(chain)
        issued_at = now_unix()
        request_id = new_id("RETRIEVE")
        target = {"execution_id": execution_id, "receipt_id": None}
        holder_payload = {
            "schema_version": "1.0",
            "credential_chain_hash": sm3_hex(canonicalize(chain)),
            "task_id": task_id,
            "tool_service": "secure-tool-gateway",
            "tool_name": "gateway.result_retrieve",
            "tool_version": "v1",
            "canonical_parameter_hash": sm3_hex(canonicalize(target)),
            "request_id": request_id,
            "issued_at": issued_at,
            "business_action_id": None,
        }
        return {
            "schema_version": "1.0",
            "credential_chain": chain,
            "holder_proof": {
                "payload": holder_payload,
                "signature": self._sign(holder_payload, issued_at=issued_at),
            },
            "task_id": task_id,
            "execution_id": execution_id,
            "receipt_id": None,
            "request_id": request_id,
            "issued_at": issued_at,
        }

    def _retrieve_result(
        self, chain: list[dict[str, Any]], *, execution_id: str,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        body = self._post_json(
            self.settings.gateway_url,
            "/gateway/results/retrieve",
            self._retrieval_request(chain, execution_id=execution_id),
            timeout_seconds=timeout_seconds,
        )
        if body.get("state") != "COMMITTED" or body.get("execution_id") != execution_id:
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                "controlled result retrieval did not bind to the committed execution",
                status_code=502,
            )
        return body

    def _plan(
        self,
        role: AgentRole,
        context: AgentContext,
        trace: list[AgentStep],
        *,
        expected_tools: tuple[str, ...],
        stage: str = "",
        chain: list[dict[str, Any]] | None = None,
    ) -> PlanDecision:
        if has_business_facts(context) and context.runtime_mode is None:
            context = context.model_copy(update={"runtime_mode": "deterministic"})
        if context.runtime_mode in {"local", "cloud"}:
            if chain is None:
                raise AgentRuntimeError(
                    "RUNTIME_CONFIGURATION_INVALID",
                    "model planning requires its current credential chain",
                    status_code=500,
                )
            self._authorize_run(chain, context)
        try:
            if context.runtime_mode:
                self._step(
                    trace,
                    "plan_started",
                    {"stage": stage, "input": planning_input(context, role, stage)},
                    status="RUNNING",
                )
                decision = WorkflowPlanner(self.settings).plan(role, context, stage=stage)
            else:
                decision = self.planner.plan(role, context)
        except PlannerError as exc:
            if context.runtime_mode:
                self._step(
                    trace,
                    "plan",
                    {
                        **exc.evidence,
                        "stage": stage,
                        "reason_code": exc.reason_code,
                        "message": str(exc),
                    },
                    status="DENIED" if exc.reason_code == "PLANNER_DECLINED" else "FAILED",
                )
            raise AgentRuntimeError(exc.reason_code, str(exc), status_code=exc.status_code) from exc
        details = dict(decision.evidence)
        details["planner"] = decision.planner
        details["intents"] = [item.model_dump(mode="json") for item in decision.intents]
        actual_tools = tuple(item.name for item in decision.intents)
        if actual_tools != expected_tools:
            details["expected_tools"] = list(expected_tools)
            details["actual_tools"] = list(actual_tools)
            self._step(trace, "plan", details, status="FAILED")
            raise AgentRuntimeError(
                "PLANNER_OUTPUT_INVALID",
                f"planner returned an invalid tool sequence for role {role}",
                status_code=502,
            )
        self._step(trace, "plan", details)
        return decision

    def _sign(self, payload: dict[str, Any], *, issued_at: int) -> dict[str, Any]:
        return sign_payload(
            payload,
            domain_separator=HOLDER_PROOF,
            key_id=self.key_id,
            key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            private_key_hex=self.private_key,
            public_key_hex=self.public_key,
            signed_at=issued_at,
        )

    def _post_json(
        self,
        base_url: str,
        path: str,
        body: dict[str, Any],
        *,
        expected_status: int = 200,
        timeout_seconds: float | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        options: dict[str, Any] = {"json": body, "headers": headers}
        recipient: str | None = None
        if (
            self.settings.agent_delegation_url
            and base_url.rstrip("/") == self.settings.agent_delegation_url.rstrip("/")
            and path.startswith("/credentials/") and path.endswith("/delegate")
        ):
            recipient = f"{self.role}-delegation-agent"
        elif (
            self.settings.business_action_registry_url
            and base_url.rstrip("/") == self.settings.business_action_registry_url.rstrip("/")
            and path in {
                "/business-actions/refund/resolve", "/business-actions/notification/resolve",
                "/business-actions/refund/evaluate",
            }
        ):
            recipient = "business-action-registry"
        elif (
            path == "/agents/security-proof/prepare"
            and self.role == "coordinator"
            and base_url.rstrip("/") == self.settings.case_agent_url.rstrip("/")
        ):
            recipient = "agent-case"
        elif path == "/agents/run":
            if self.role == "coordinator":
                if base_url.rstrip("/") == self.settings.knowledge_agent_url.rstrip("/"):
                    recipient = "agent-knowledge"
                elif base_url.rstrip("/") == self.settings.case_agent_url.rstrip("/"):
                    recipient = "agent-case"
            elif (
                self.role == "case"
                and base_url.rstrip("/") == self.settings.refund_agent_url.rstrip("/")
            ):
                recipient = "agent-refund"
        elif (
            path == "/gateway/runtime/authorize"
            and base_url.rstrip("/") == self.settings.gateway_url.rstrip("/")
        ):
            recipient = "secure-gateway"
        if recipient is not None and (
            self.settings.internal_auth_required or path == "/gateway/runtime/authorize"
        ):
            from backend.common.internal_auth import InternalAuthenticator, InternalAuthError

            try:
                request_body = canonicalize(body)
                auth = InternalAuthenticator.from_settings(self.settings, service_id=self.agent_id)
                options = {
                    "content": request_body,
                    "headers": {
                        **(headers or {}),
                        **auth.request_headers(
                            recipient=recipient, method="POST", path=path,
                            body=request_body,
                        ),
                    },
                }
            except (InternalAuthError, ValueError):
                raise AgentRuntimeError(
                    "INTERNAL_AUTH_UNAVAILABLE", "internal service authentication is unavailable",
                    status_code=503,
                ) from None
        try:
            with httpx.Client(
                base_url=base_url,
                timeout=timeout_seconds or self.settings.agent_request_timeout_seconds,
                trust_env=False,
            ) as client:
                response = client.post(path, **options)
        except httpx.HTTPError as exc:
            raise AgentRuntimeError(
                "UPSTREAM_UNAVAILABLE",
                f"controlled runtime dependency failed: {path}",
                status_code=502,
            ) from exc
        if response.status_code != expected_status:
            try:
                response_body = response.json()
            except ValueError:
                response_body = {}
            response_body = response_body if isinstance(response_body, dict) else {}
            error = AgentRuntimeError(
                str(response_body.get("reason_code", "UPSTREAM_REJECTED")),
                str(response_body.get("message", f"upstream rejected {path}")),
                status_code=response.status_code,
            )
            execution_id = response_body.get("execution_id")
            if isinstance(execution_id, str) and execution_id.startswith("EXEC-"):
                error.execution_id = execution_id
            outcome = response_body.get("admission_outcome")
            if isinstance(outcome, str):
                error.admission_outcome = outcome
            raise error
        try:
            parsed = response.json()
        except ValueError as exc:
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                f"upstream returned non-JSON data for {path}",
                status_code=502,
            ) from exc
        if not isinstance(parsed, dict):
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                f"upstream returned a non-object for {path}",
                status_code=502,
            )
        return cast(dict[str, Any], parsed)

    def _authorize_run(self, chain: list[dict[str, Any]], context: AgentContext) -> None:
        # Agents never receive the authority database. Validate at the gateway before planning.
        body = self._post_json(
            self.settings.gateway_url,
            "/gateway/runtime/authorize",
            {
                "credential_chain": chain,
                "context": {
                    "ticket_id": context.ticket_id,
                    "customer_id": context.customer_id,
                    "refund_amount_fen": context.refund_amount_fen,
                    "runtime_mode": context.runtime_mode,
                    "scenario": context.scenario,
                    "cloud_data_confirmed": context.cloud_data_confirmed,
                },
            },
        )
        if (
            body.get("authorized") is not True
            or body.get("task_id") != self._task_id(chain)
            or body.get("agent_id") != self.agent_id
            or body.get("credential_chain_hash") != sm3_hex(canonicalize(chain))
        ):
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                "runtime authorization response does not bind to this agent and task",
                status_code=502,
            )

    def _require_chain_for_this_agent(self, chain: list[dict[str, Any]]) -> str:
        task_id = self._task_id(chain)
        for credential in chain:
            if self._payload(credential).get("task_id") != task_id:
                raise AgentRuntimeError("CROSS_TASK", "credential chain crosses task scope")
        holder = self._payload(chain[-1]).get("holder")
        if holder != {"agent_id": self.agent_id, "key_id": self.key_id}:
            raise AgentRuntimeError(
                "WRONG_HOLDER",
                "agent runtime does not hold the leaf credential",
            )
        return task_id

    @staticmethod
    def _payload(credential: dict[str, Any]) -> dict[str, Any]:
        payload = credential.get("payload")
        if not isinstance(payload, dict):
            raise AgentRuntimeError(
                "REQUEST_SCHEMA_INVALID",
                "credential lacks a payload object",
                status_code=400,
            )
        return cast(dict[str, Any], payload)

    def _task_id(self, chain: list[dict[str, Any]]) -> str:
        if not chain:
            raise AgentRuntimeError(
                "REQUEST_SCHEMA_INVALID", "credential chain is empty", status_code=400
            )
        task_id = self._payload(chain[0]).get("task_id")
        if not isinstance(task_id, str):
            raise AgentRuntimeError(
                "REQUEST_SCHEMA_INVALID",
                "root credential lacks task_id",
                status_code=400,
            )
        return task_id

    def _credential_id(self, credential: dict[str, Any]) -> str:
        value = self._payload(credential).get("credential_id")
        if not isinstance(value, str):
            raise AgentRuntimeError(
                "CONTROLLED_RESULT_INVALID",
                "delegation response lacks credential_id",
                status_code=502,
            )
        return value

    def _step(
        self,
        trace: list[AgentStep],
        action: str,
        details: dict[str, Any],
        *,
        status: Literal["RUNNING", "COMPLETED", "DENIED", "FAILED"] = "COMPLETED",
    ) -> None:
        trace.append(
            AgentStep(
                sequence=len(trace) + 1,
                agent_id=self.agent_id,
                action=action,
                status=status,
                details=details,
            )
        )
        if isinstance(trace, RecordedTrace):
            trace.recorder(trace[-1])
