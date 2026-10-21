from __future__ import annotations

import json
from functools import cached_property
from pathlib import Path
from typing import Any

import httpx
from jsonschema import ValidationError as SchemaValidationError
from referencing import Resource

from backend.audit.prefix_contracts import AuditPrefixRequest, AuditPrefixResponse
from backend.authorization.contracts import AuthorizeTaskRequest, CreateTaskRequest
from backend.business_action.contracts import CreateBusinessCaseRequest, CreateBusinessCaseResponse
from backend.coauthorization.contracts import (
    MAX_BUNDLE_BYTES,
    ApprovalPayload,
    ChallengeResponse,
    CoauthorizationBundle,
    CoauthorizationResponse,
    CoauthorizationTaskReview,
    CreateChallengeRequest,
    RootCapability,
    TrustedTask,
)
from backend.coauthorization.verifier import (
    EXTENSION_SCHEMA_ROOT,
    CoauthorizationReason,
    approval_payload_hash,
    capabilities_hash,
)
from backend.common.error_codes import ReasonCode
from backend.common.schema import SchemaStore
from backend.common.time import now_unix
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.crypto.strict_json import StrictJsonError, parse_strict_json
from backend.ui_api.contracts import QueuedWorkflowResponse, StartWorkflowRequest
from backend.ui_api.store import UiReadStore


class UiApiError(RuntimeError):
    def __init__(self, reason_code: str, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


class UiService:
    def __init__(
        self,
        settings: Settings,
        store: UiReadStore,
        *,
        protocol_root: Path | None = None,
        artifact_root: Path | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.protocol_root = protocol_root or Path("protocol")
        self.artifact_root = artifact_root or Path(getattr(settings, "ui_artifact_root", "artifacts"))

    def create_task(self, request: CreateTaskRequest) -> dict[str, Any]:
        try:
            return self._post(
                self.settings.authority_url,
                "/tasks",
                request.model_dump(mode="json"),
                expected_status=201,
            )
        except UiApiError as exc:
            if exc.reason_code == "RESOURCE_NOT_ALLOWED":
                raise UiApiError(
                    exc.reason_code, "工单不存在，或租户、客户与工单记录不一致；请选择已有工单", status_code=exc.status_code,
                ) from exc
            raise

    def create_business_case(self, request: CreateBusinessCaseRequest) -> dict[str, Any]:
        body = self._post(
            self.settings.business_action_registry_url, "/business-cases",
            request.model_dump(mode="json"), expected_status=201,
        )
        try:
            result = CreateBusinessCaseResponse.model_validate(body)
            if any(getattr(result, field) != getattr(request, field) for field in (
                "ticket_id", "tenant_id", "customer_id", "cloud_shareable",
            )) or result.business_facts.model_dump() != request.raw_facts() or result.facts_hash != sm3_hex(canonicalize(request.raw_facts())):
                raise ValueError("business case response binding mismatch")
        except ValueError as exc:
            raise UiApiError("CONTROLLED_RESULT_INVALID", "新工单保存结果无法与提交的业务事实核对") from exc
        return result.model_dump(mode="json")

    def authorize_task(self, task_id: str, request: AuthorizeTaskRequest) -> dict[str, Any]:
        self._require_single_sign_mode()
        signed = self._post(
            self.settings.authority_url,
            f"/tasks/{task_id}/authorize",
            request.model_dump(mode="json"),
            expected_status=201,
        )
        payload = signed.get("payload")
        signature = signed.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            raise UiApiError("CONTROLLED_RESULT_INVALID", "authority omitted signed credential")
        return {
            "task_id": task_id,
            "status": "AUTHORIZED",
            "credential_id": payload.get("credential_id"),
            "holder": payload.get("holder"),
            "delegation_depth": payload.get("delegation_depth"),
            "signature": {
                "algorithm": signature.get("algorithm"),
                "key_id": signature.get("key_id"),
            },
        }

    def run_task(self, task_id: str, *, prompt_text: str = "") -> dict[str, Any]:
        if not prompt_text:
            queued = self.start_authorized_workflow(task_id, StartWorkflowRequest())
            return {
                "demo_kind": "NORMAL_MULTI_AGENT", "task_id": task_id,
                "planner": "deterministic", "status": queued["state"],
                "reason_code": None, "trace": [], "run_id": queued["run_id"],
            }
        root = self.store.root_credential(task_id)
        if root is None:
            raise UiApiError(
                "CROSS_TASK", "authorized root credential was not found", status_code=404
            )
        payload = root.get("payload")
        holder = payload.get("holder") if isinstance(payload, dict) else None
        expected_holder = {
            "agent_id": "agent-coordinator",
            "key_id": "agent-coordinator-key-01",
        }
        if holder != expected_holder:
            raise UiApiError(
                "WRONG_HOLDER",
                "Task Center execution requires a coordinator-held root credential",
                status_code=409,
            )
        snapshot = self.store.task_snapshot(task_id)
        if snapshot is None:
            raise UiApiError("CROSS_TASK", "task does not exist", status_code=404)
        task = snapshot["task"]
        body = self._post(
            self.settings.coordinator_agent_url,
            "/agents/run",
            {
                "credential_chain": [root],
                "context": {
                    "ticket_id": task["ticket_id"],
                    "customer_id": task["customer_id"],
                    "refund_amount_fen": task["refund_total_fen"],
                    "prompt_text": prompt_text,
                },
            },
        )
        return self._demo_projection(body, task_id=task_id, demo_kind="NORMAL_MULTI_AGENT")

    def run_normal_demo(self) -> dict[str, Any]:
        self._require_single_sign_mode()
        business = self._default_workflow_case()
        created = self.create_task(
            CreateTaskRequest(
                tenant_id=business["tenant_id"],
                ticket_id=business["ticket_id"],
                customer_id=business["customer_id"],
                refund_total_fen=7_000,
                max_tool_calls=4,
                expires_in_seconds=1_800,
            )
        )
        task_id = str(created["task_id"])
        self.authorize_task(
            task_id,
            AuthorizeTaskRequest(
                confirmed=True,
                confirmer_id="policy-refund-v1",
                holder_agent_id="agent-coordinator",
                holder_key_id="agent-coordinator-key-01",
                delegation_depth=2,
            ),
        )
        return self.run_task(task_id)

    def start_authorized_workflow(self, task_id: str, request: StartWorkflowRequest) -> dict[str, Any]:
        snapshot = self.store.task_snapshot(task_id)
        if snapshot is None:
            raise UiApiError("CROSS_TASK", "当前任务不存在", status_code=404)
        task = snapshot.get("task")
        if not isinstance(task, dict) or task.get("task_id") != task_id:
            raise UiApiError("CROSS_TASK", "任务读取结果与请求不一致", status_code=409)
        if task.get("status") != "AUTHORIZED":
            raise UiApiError("TASK_NOT_EXECUTABLE", "当前任务尚未签发可执行的根授权", status_code=409)
        if snapshot.get("workflow_runs"):
            raise UiApiError("WORKFLOW_ALREADY_EXISTS", "当前任务已有协作运行，请查看运行档案", status_code=409)
        effects = snapshot.get("business_effects", {})
        if snapshot.get("executions") or effects.get("refunds") or effects.get("notifications"):
            raise UiApiError("TASK_ALREADY_STARTED", "当前任务已有执行或业务效果，不作为新协作再次启动", status_code=409)
        roots = [item for item in snapshot.get("credentials", []) if item.get("credential_type") == "ROOT"]
        root = self.store.root_credential(task_id)
        if root is None or len(roots) != 1:
            raise UiApiError("TASK_NOT_EXECUTABLE", "当前任务必须有唯一且可核对的根授权", status_code=409)
        credential = roots[0]
        try:
            self.workflow_schemas.validate("capability-credential.schema.json", root)
            payload = root["payload"]
            if payload["task_id"] != task_id or payload["tenant_id"] != task["tenant_id"]:
                raise UiApiError("CROSS_TASK", "根授权与当前任务或租户不一致", status_code=409)
            if payload["quotas"] != {
                "refund_total_fen": task["refund_total_fen"], "max_tool_calls": task["max_tool_calls"],
            } or payload["expires_at"] != task["expires_at"]:
                raise UiApiError("TASK_NOT_EXECUTABLE", "根授权范围与保存的任务额度或有效期不一致", status_code=409)
            if (
                payload["credential_id"] != credential.get("credential_id")
                or signed_object_hash(root) != credential.get("signed_object_hash")
                or credential.get("stored_hash_valid") is not True
                or not isinstance(credential.get("signature"), dict)
                or credential["signature"].get("valid") is not True
                or any(payload[name] != credential.get(name) for name in (
                    "not_before", "expires_at", "delegation_depth", "issued_at",
                ))
                or payload["holder"] != {
                    "agent_id": credential.get("holder_agent_id"), "key_id": credential.get("holder_key_id"),
                }
                or payload["issuer"] != {
                    "subject_id": credential.get("issuer_subject_id"), "key_id": credential.get("issuer_key_id"),
                }
                or root["signature"]["key_id"] != payload["issuer"]["key_id"]
                or root["signature"]["key_purpose"] != "AUTHORIZATION_ROOT_SIGNING"
                or root["signature"]["signed_at"] != payload["issued_at"]
                or credential["signature"].get("key_id") != root["signature"]["key_id"]
                or credential["signature"].get("algorithm") != "SM2"
            ):
                raise ValueError("stored root projection mismatch")
        except (ValueError, TypeError, KeyError, SchemaValidationError) as exc:
            raise UiApiError("INVALID_SIGNATURE", "根授权结构、签名投影或存储摘要无法核对", status_code=409) from exc
        if credential.get("revoked_at") is not None:
            raise UiApiError("ANCESTOR_REVOKED", "当前根授权已撤销，不能启动新协作", status_code=409)
        current_time = now_unix()
        if not payload["not_before"] <= current_time < payload["expires_at"] or current_time >= task["expires_at"]:
            raise UiApiError("CREDENTIAL_EXPIRED", "根授权尚未生效或已过期", status_code=409)
        if payload["holder"] != {"agent_id": "agent-coordinator", "key_id": "agent-coordinator-key-01"}:
            raise UiApiError("WRONG_HOLDER", "当前根授权不属于协调智能体，不能启动四角色协作", status_code=409)
        if payload["delegation_depth"] < 2:
            raise UiApiError("DELEGATION_ESCALATION", "当前根授权不足以支持两级委托", status_code=409)
        if request.runtime_mode == "cloud":
            business = self.store.business_ticket(str(task["ticket_id"]))
            if business is None or business.get("cloud_shareable") is not True or any(
                business.get(field) != task.get(field) for field in ("tenant_id", "ticket_id", "customer_id")
            ):
                raise UiApiError(
                    "CLOUD_TASK_SCOPE_DENIED", "当前工单未获准发送云端；可选择确定性规则", status_code=403,
                )
        self._require_workflow_mode(request)
        # This read-side preflight is not admission; delegation and Gateway recheck authorization.
        return self._queue_workflow(root, task, request)

    @cached_property
    def workflow_schemas(self) -> SchemaStore:
        return SchemaStore(self.protocol_root / "schemas")

    def _require_single_sign_mode(self) -> None:
        if self.settings.coauthorization_required or self.coauthorization_status()["enabled"]:
            raise UiApiError(
                "COAUTH_REQUIRED", "共同授权已启用，请在授权与预算中完成企业与财务双签；不会创建单签任务",
                status_code=403,
            )

    def _require_workflow_mode(self, request: StartWorkflowRequest) -> None:
        if request.runtime_mode not in {"deterministic", "cloud"}:
            raise UiApiError(
                "MODEL_MODE_UNAVAILABLE", "该运行模式已停用；请选择智能体审查或确定性规则", status_code=503,
            )
        profiles = self.runtime_profiles()
        profile = next(
            (item for item in profiles.get("items", []) if item.get("mode") == request.runtime_mode), None,
        )
        if profiles.get("workflow_enabled") is not True or profile is None or profile.get("available") is not True:
            raise UiApiError(
                "MODEL_MODE_UNAVAILABLE", str(profile.get("message")) if profile else "运行层尚未配置", status_code=503,
            )
        if request.runtime_mode == "cloud" and not request.cloud_data_confirmed:
            raise UiApiError(
                "CLOUD_CONFIRMATION_REQUIRED", "须确认发送当前工单与关联业务资料，并允许本次云端调用", status_code=400,
            )

    def _queue_workflow(self, root: dict[str, Any], task: dict[str, Any], request: StartWorkflowRequest) -> dict[str, Any]:
        if not self.settings.coordinator_agent_url:
            raise UiApiError("MODEL_MODE_UNAVAILABLE", "协调智能体地址未配置", status_code=503)
        try:
            document = self._workflow_request({
                "credential_chain": [root],
                "context": {
                    "ticket_id": task["ticket_id"],
                    "customer_id": task["customer_id"],
                    "refund_amount_fen": task["refund_total_fen"],
                    "runtime_mode": request.runtime_mode,
                    "scenario": request.scenario,
                    "cloud_data_confirmed": request.cloud_data_confirmed,
                    **({"custom_injection_text": request.custom_injection_text}
                       if request.custom_injection_text is not None else {}),
                },
            })
        except UiApiError as exc:
            if exc.status_code >= 500 or exc.reason_code == "CONTROLLED_RESULT_INVALID":
                raise UiApiError(
                    "WORKFLOW_RESULT_UNCONFIRMED", "启动结果未确认，请查看当前任务及运行档案；不要重复启动",
                    status_code=503 if exc.status_code == 503 else 502,
                ) from exc
            raise
        try:
            response = QueuedWorkflowResponse.model_validate(document)
            if response.task_id != task["task_id"] or response.runtime_mode != request.runtime_mode:
                raise ValueError("queued workflow request binding mismatch")
        except (ValueError, TypeError) as exc:
            raise UiApiError(
                "WORKFLOW_RESULT_UNCONFIRMED", "启动响应与本任务无法核对，请查看运行档案；不要重复启动",
            ) from exc
        return response.model_dump(mode="json")

    def _workflow_request(self, body: dict[str, Any]) -> dict[str, Any]:
        if not self.settings.coordinator_agent_url:
            raise UiApiError("MODEL_MODE_UNAVAILABLE", "协调智能体地址未配置", status_code=503)
        options = self._internal_post_options(
            body, recipient="agent-coordinator", path="/agents/workflows",
        )
        try:
            with httpx.Client(
                base_url=self.settings.coordinator_agent_url, timeout=self.settings.ui_request_timeout_seconds,
                trust_env=False,
            ) as client, client.stream("POST", "/agents/workflows", **options) as response:
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > 65_536:
                        raise UiApiError("WORKFLOW_RESULT_UNCONFIRMED", "启动响应超过允许大小，请查看运行档案")
                    raw.extend(chunk)
                response_status = response.status_code
        except httpx.HTTPError as exc:
            raise UiApiError(
                "WORKFLOW_RESULT_UNCONFIRMED", "启动结果未知，请查看运行档案；不要重复启动", status_code=503,
            ) from exc
        try:
            document = parse_strict_json(bytes(raw))
            if not isinstance(document, dict):
                raise ValueError("response is not an object")
        except (ValueError, TypeError, RecursionError, StrictJsonError) as exc:
            raise UiApiError("WORKFLOW_RESULT_UNCONFIRMED", "启动响应无法核对，请查看运行档案") from exc
        if response_status == 202:
            return document
        allowed = {
            400: {"REQUEST_SCHEMA_INVALID", "CLOUD_CONFIRMATION_REQUIRED"},
            403: {
                "WRONG_HOLDER", "CROSS_TASK", "CROSS_TENANT", "INVALID_SIGNATURE",
                "UNKNOWN_KEY", "KEY_REVOKED", "KEY_COMPROMISED", "KEY_RETIRED_FOR_SIGNING",
                "ANCESTOR_REVOKED", "CREDENTIAL_EXPIRED", "WRONG_AUDIENCE",
                "TOOL_NOT_ALLOWED", "RESOURCE_NOT_ALLOWED", "PARAMETER_CONSTRAINT_VIOLATION",
                "BUDGET_EXCEEDED", "DELEGATION_ESCALATION",
            },
            404: {"CROSS_TASK"},
            409: {"WORKFLOW_ALREADY_EXISTS"},
        }
        code = document.get("reason_code")
        if (
            set(document) == {"reason_code", "message"} and isinstance(document.get("message"), str)
            and isinstance(code, str) and code in allowed.get(response_status, set())
        ):
            raise UiApiError(code, "协调智能体拒绝协作启动，请核对当前任务及运行档案", status_code=response_status)
        raise UiApiError(
            "WORKFLOW_RESULT_UNCONFIRMED", "启动结果未确认，请查看运行档案；不要重复启动",
            status_code=503 if response_status == 503 else 502,
        )

    def runtime_profiles(self) -> dict[str, Any]:
        return self._get(self.settings.coordinator_agent_url, "/agents/runtime-profiles")

    def coauthorization_status(self) -> dict[str, Any]:
        document = self._coauthorization_request("GET", "/extensions/coauthorization/v1/status")
        if (
            set(document) != {"schema_version", "enabled", "policy_source", "signing"}
            or document.get("schema_version") != "1.0"
            or type(document.get("enabled")) is not bool
            or document.get("policy_source") != "SERVER_REGISTERED_PUBLIC_KEYS"
            or document.get("signing") != "EXTERNAL_APPROVERS_ONLY"
        ):
            raise UiApiError("CONTROLLED_RESULT_INVALID", "invalid Authority approval configuration response")
        return document

    @cached_property
    def coauthorization_schemas(self) -> SchemaStore:
        schemas = SchemaStore(EXTENSION_SCHEMA_ROOT)
        schemas.registry = schemas.registry.with_resources(
            (document["$id"], Resource.from_contents(document))
            for document in SchemaStore().documents.values()
        )
        return schemas

    def create_coauthorization_challenge(self, task_id: str, request: CreateChallengeRequest) -> dict[str, Any]:
        document = self._coauthorization_request(
            "POST", f"/extensions/coauthorization/v1/tasks/{task_id}/challenges",
            body=request.model_dump(mode="json"),
        )
        try:
            self.coauthorization_schemas.validate("challenge-response.schema.json", document)
            response = ChallengeResponse.model_validate(document)
            self._check_approval_scope(response.payload, response.task_capabilities, task_id)
            if (
                approval_payload_hash(response.payload) != response.approval_payload_hash
                or response.payload.holder.agent_id != request.holder_agent_id
                or response.payload.holder.key_id != request.holder_key_id
                or response.payload.delegation_depth != request.delegation_depth
            ):
                raise ValueError("approval payload hash mismatch")
        except (ValueError, TypeError, KeyError, RecursionError, SchemaValidationError) as exc:
            raise UiApiError("CONTROLLED_RESULT_INVALID", "Authority 返回的审批挑战无效") from exc
        return response.model_dump(mode="json")

    def coauthorization_task(self, task_id: str, *, offset: int = 0) -> dict[str, Any]:
        document = self._coauthorization_request(
            "GET", f"/extensions/coauthorization/v1/tasks/{task_id}", params={"offset": offset},
        )
        try:
            self.coauthorization_schemas.validate("task-review-response.schema.json", document)
            response = CoauthorizationTaskReview.model_validate(document)
            if response.task_id != task_id or response.offset != offset:
                raise ValueError("history request binding mismatch")
            for entry in response.items:
                self._check_approval_scope(entry.payload, entry.task_capabilities, task_id)
                if approval_payload_hash(entry.payload) != entry.approval_payload_hash:
                    raise ValueError("stored payload hash mismatch")
                if entry.signed_bundle is not None and sm3_hex(canonicalize(
                    entry.signed_bundle.model_dump(mode="json")
                )) != entry.bundle_hash:
                    raise ValueError("stored bundle hash mismatch")
        except (ValueError, TypeError, KeyError, RecursionError, SchemaValidationError) as exc:
            raise UiApiError("CONTROLLED_RESULT_INVALID", "Authority 返回的审批历史无效") from exc
        return response.model_dump(mode="json")

    def authorize_coauthorization_task(self, task_id: str, raw_bundle: bytes) -> dict[str, Any]:
        try:
            if not isinstance(raw_bundle, bytes) or not 0 < len(raw_bundle) <= MAX_BUNDLE_BYTES:
                raise ValueError("invalid bundle size")
            submitted = parse_strict_json(raw_bundle)
            self.coauthorization_schemas.validate("coauthorization-bundle.schema.json", submitted)
            bundle = CoauthorizationBundle.model_validate(submitted)
            if bundle.payload.task_id != task_id:
                raise ValueError("approval task binding mismatch")
        except (ValueError, TypeError, KeyError, RecursionError, SchemaValidationError, StrictJsonError) as exc:
            raise UiApiError("COAUTH_INVALID_BUNDLE", "审批签名包不符合严格 JSON 契约", status_code=400) from exc
        document = self._coauthorization_request(
            "POST", f"/extensions/coauthorization/v1/tasks/{task_id}/authorize", raw_body=raw_bundle,
        )
        try:
            self.coauthorization_schemas.validate("coauthorization-response.schema.json", document)
            response = CoauthorizationResponse.model_validate(document)
            root_payload = response.credential["payload"]
            root_signature = response.credential["signature"]
            if (
                response.challenge_id != bundle.payload.challenge_id
                or response.approval_payload_hash != approval_payload_hash(bundle.payload)
                or response.bundle_hash != sm3_hex(canonicalize(submitted))
                or root_payload["task_id"] != task_id
                or response.root_credential_id != root_payload["credential_id"]
                or response.root_credential_hash != signed_object_hash(response.credential)
                or root_signature["key_id"] != root_payload["issuer"]["key_id"]
                or root_signature["key_purpose"] != "AUTHORIZATION_ROOT_SIGNING"
                or root_signature["signed_at"] != root_payload["issued_at"]
                or any(root_payload.get(name) != value for name, value in (
                    ("tenant_id", bundle.payload.tenant_id),
                    ("holder", bundle.payload.holder.model_dump(mode="json")),
                    ("quotas", bundle.payload.quotas.model_dump(mode="json")),
                    ("not_before", bundle.payload.not_before), ("expires_at", bundle.payload.expires_at),
                    ("delegation_depth", bundle.payload.delegation_depth),
                ))
                or sm3_hex(canonicalize({"capabilities": root_payload["capabilities"]})) != bundle.payload.capabilities_hash
            ):
                raise ValueError("authorization response binding mismatch")
        except (ValueError, TypeError, KeyError, RecursionError, SchemaValidationError) as exc:
            raise UiApiError(
                "COAUTH_RESULT_UNCONFIRMED", "授权响应无法确认，请刷新审批历史；不要更换签名包重试",
            ) from exc
        return response.model_dump(mode="json")

    @staticmethod
    def _check_approval_scope(payload: ApprovalPayload, capabilities: list[RootCapability], task_id: str) -> None:
        task = TrustedTask(
            tenant_id=payload.tenant_id, task_id=payload.task_id, ticket_id=payload.ticket_id,
            customer_id=payload.customer_id, holder=payload.holder, capabilities=capabilities,
            quotas=payload.quotas, not_before=payload.not_before, expires_at=payload.expires_at,
            delegation_depth=payload.delegation_depth, status="PENDING_AUTHORIZATION",
        )
        if task.task_id != task_id or capabilities_hash(task) != payload.capabilities_hash:
            raise ValueError("approval scope binding mismatch")

    def _coauthorization_request(
        self, method: str, path: str, *, body: dict[str, Any] | None = None,
        raw_body: bytes | None = None, params: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        if not self.settings.authority_url:
            raise UiApiError("UPSTREAM_UNAVAILABLE", "Authority 地址未配置", status_code=503)
        options: dict[str, Any] = {"params": params}
        if raw_body is not None:
            options.update(content=raw_body, headers={"Content-Type": "application/json"})
        elif body is not None:
            options["json"] = body
        if self.settings.internal_auth_required and method.upper() == "POST":
            from backend.common.internal_auth import InternalAuthenticator, InternalAuthError

            try:
                request_body = raw_body if raw_body is not None else (
                    canonicalize(body) if body is not None else b""
                )
                auth = InternalAuthenticator.from_settings(self.settings, service_id="ui-api")
                options.pop("json", None)
                options.update(
                    content=request_body,
                    headers=auth.request_headers(
                        recipient="authorization-authority", method=method, path=path,
                        body=request_body,
                    ),
                )
            except (InternalAuthError, ValueError):
                raise UiApiError(
                    "INTERNAL_AUTH_UNAVAILABLE", "Authority 服务认证配置不可用", status_code=503,
                ) from None
        try:
            with httpx.Client(
                base_url=self.settings.authority_url, timeout=self.settings.ui_request_timeout_seconds,
                trust_env=False,
            ) as client, client.stream(method, path, **options) as response:
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > 2_097_152:
                        code = "COAUTH_RESULT_UNCONFIRMED" if raw_body is not None else "CONTROLLED_RESULT_INVALID"
                        raise UiApiError(code, "Authority 响应超过允许大小，请刷新审批历史")
                    raw.extend(chunk)
                response_status = response.status_code
        except httpx.HTTPError as exc:
            if raw_body is not None:
                raise UiApiError(
                    "COAUTH_RESULT_UNCONFIRMED", "授权结果未知，请刷新审批历史；不要更换签名包重试", status_code=503,
                ) from exc
            raise UiApiError("UPSTREAM_UNAVAILABLE", "Authority 请求失败", status_code=503) from exc
        try:
            document = parse_strict_json(bytes(raw))
            if not isinstance(document, dict):
                raise ValueError("response is not an object")
        except (ValueError, TypeError, RecursionError, StrictJsonError) as exc:
            code = "COAUTH_RESULT_UNCONFIRMED" if raw_body is not None else "CONTROLLED_RESULT_INVALID"
            raise UiApiError(code, "Authority 响应无法确认，请刷新审批历史") from exc
        if response_status != 200:
            if raw_body is not None and response_status not in {400, 403, 404, 409}:
                raise UiApiError(
                    "COAUTH_RESULT_UNCONFIRMED", "授权结果未确认，请刷新审批历史；不要更换签名包重试",
                    status_code=503 if response_status == 503 else 502,
                )
            known = {item.value for item in CoauthorizationReason} | {item.value for item in ReasonCode}
            submitted_code = document.get("reason_code")
            overrides = {
                "COAUTH_DISABLED": 404, "COAUTH_INVALID_BUNDLE": 400,
                "REQUEST_SCHEMA_INVALID": 400, "COAUTH_CHALLENGE_CONFLICT": 409,
                "COAUTH_IDEMPOTENCY_CONFLICT": 409, "COAUTH_TASK_NOT_AUTHORIZABLE": 409,
                "COAUTH_REGISTRY_UNAVAILABLE": 503, "COAUTH_STORED_EVIDENCE_INVALID": 503,
            }
            if (
                set(document) != {"reason_code", "message"} or not isinstance(document.get("message"), str)
                or not isinstance(submitted_code, str) or submitted_code not in known
                or response_status != overrides.get(submitted_code, 403)
            ):
                code = "COAUTH_RESULT_UNCONFIRMED" if raw_body is not None else "CONTROLLED_RESULT_INVALID"
                raise UiApiError(code, "Authority 错误响应无法确认，请刷新审批历史")
            raise UiApiError(
                submitted_code, "Authority 拒绝共同授权请求", status_code=response_status,
            )
        return document

    def start_workflow(self, request: StartWorkflowRequest) -> dict[str, Any]:
        self._require_single_sign_mode()
        self._require_workflow_mode(request)
        business = self._default_workflow_case(cloud=request.runtime_mode == "cloud")
        created = self.create_task(
            CreateTaskRequest(
                tenant_id=business["tenant_id"],
                ticket_id=business["ticket_id"],
                customer_id=business["customer_id"],
                refund_total_fen=7000,
                max_tool_calls=4,
                expires_in_seconds=1800,
            )
        )
        task_id = str(created["task_id"])
        root = self._post(
            self.settings.authority_url,
            f"/tasks/{task_id}/authorize",
            AuthorizeTaskRequest(
                confirmed=True,
                confirmer_id="policy-refund-v1",
                holder_agent_id="agent-coordinator",
                holder_key_id="agent-coordinator-key-01",
                delegation_depth=2,
            ).model_dump(mode="json"),
            expected_status=201,
        )
        return self._queue_workflow(root, {
            "task_id": task_id, "ticket_id": business["ticket_id"],
            "customer_id": business["customer_id"], "refund_total_fen": 7000,
        }, request)

    def _default_workflow_case(self, *, cloud: bool = False) -> dict[str, Any]:
        candidates = [item for item in self.store.list_business_tickets()
                      if item.get("can_refund") is True
                      and min(item.get("refundable_amount_fen", 0), item.get("transaction_remaining_fen", 0)) >= 7000
                      and (not cloud or item.get("cloud_shareable") is True)]
        if not candidates:
            raise UiApiError(
                "BUSINESS_CASE_UNAVAILABLE", "没有可办理的新工单；请在任务中心选择其他工单。已办理业务不会因新建任务重办", status_code=409,
            )
        return candidates[0]

    def run_prompt_injection_demo(self, prompt_text: str) -> dict[str, Any]:
        if not self.settings.live_refund_agent_url:
            raise UiApiError(
                "UPSTREAM_UNAVAILABLE",
                "This legacy demo is unavailable; use the cloud workflow with policy_injection",
                status_code=503,
            )
        self._require_single_sign_mode()
        created = self.create_task(
            CreateTaskRequest(
                tenant_id="tenant-A",
                ticket_id="T10086",
                customer_id="C9527",
                refund_total_fen=7_000,
                max_tool_calls=1,
                expires_in_seconds=1_800,
            )
        )
        task_id = str(created["task_id"])
        signed = self._post(
            self.settings.authority_url,
            f"/tasks/{task_id}/authorize",
            AuthorizeTaskRequest(
                confirmed=True,
                confirmer_id="policy-refund-v1",
                holder_agent_id="agent-refund",
                holder_key_id="agent-refund-key-01",
                delegation_depth=0,
            ).model_dump(mode="json"),
            expected_status=201,
        )
        body = self._post(
            self.settings.live_refund_agent_url,
            "/agents/run",
            {
                "credential_chain": [signed],
                "context": {
                    "ticket_id": "T10086",
                    "customer_id": "C9527",
                    "refund_amount_fen": 7_000,
                    "prompt_text": prompt_text,
                },
            },
        )
        return self._demo_projection(body, task_id=task_id, demo_kind="LIVE_LLM_INJECTION")

    def overview(self) -> dict[str, Any]:
        projection = self.store.overview()
        projection["audit"]["verification"] = self._post(
            self.settings.audit_service_url,
            "/audit/verify",
            {"from_sequence": 1, "include_independent_checkpoint": True},
        )
        checkpoint_response = self._get(self.settings.checkpoint_service_url, "/checkpoints/latest")
        projection["audit"]["checkpoint"] = self._checkpoint_projection(checkpoint_response)
        return projection

    def audit_prefix(self, task_id: str, request: AuditPrefixRequest) -> dict[str, Any]:
        if request.task_id != task_id:
            raise UiApiError("CROSS_TASK", "审计核验请求与当前任务不一致", status_code=403)
        snapshot = self.store.task_snapshot(task_id)
        if snapshot is None:
            raise UiApiError("CROSS_TASK", "任务不存在", status_code=404)
        identities = {(event["event_sequence"], event["event_id"]) for event in snapshot["audit_events"]}
        if any((event["event_sequence"], event["event_id"]) not in identities for event in request.events):
            raise UiApiError("CROSS_TASK", "事件标识不在当前任务记录中，请刷新后重试", status_code=403)
        result = self._post(
            self.settings.audit_service_url,
            "/extensions/audit-prefix-binding/v1/verify-events",
            request.model_dump(mode="json"),
        )
        try:
            report = AuditPrefixResponse.model_validate(result)
            report.require_request_binding(request)
        except ValueError as exc:
            raise UiApiError(
                "CONTROLLED_RESULT_INVALID", "审计服务报告与所请求的完整事件批次不一致", status_code=502,
            ) from exc
        return report.model_dump(mode="json")

    @staticmethod
    def _checkpoint_projection(response: dict[str, Any]) -> dict[str, Any]:
        signed = response.get("checkpoint")
        if not isinstance(signed, dict):
            return {"status": str(response.get("status", "EMPTY")), "checkpoint": None}
        payload = signed.get("payload")
        signature = signed.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            raise UiApiError(
                "CONTROLLED_RESULT_INVALID",
                "checkpoint response is malformed",
                status_code=502,
            )
        value = signature.get("value")
        fingerprint = (
            sm3_hex(value.encode("ascii"))[:24]
            if isinstance(value, str) and value.isascii()
            else None
        )
        return {
            "status": str(response.get("status", "AVAILABLE")),
            "checkpoint": {
                "payload": payload,
                "signature": {
                    "algorithm": signature.get("algorithm"),
                    "key_id": signature.get("key_id"),
                    "fingerprint_sm3": fingerprint,
                },
            },
        }

    def security_matrix(self) -> dict[str, Any]:
        from backend.ui_api.security_ledger import current_ledger

        matrix = self._load_json(
            self.protocol_root.parent / "attacks" / "deterministic_scenarios" / "scenarios.json"
        )
        error_codes = self._load_json(self.protocol_root / "error-codes.json")
        scenarios = matrix.get("scenarios") if isinstance(matrix, dict) else None
        if not isinstance(scenarios, list):
            raise UiApiError(
                "RUNTIME_CONFIGURATION_INVALID",
                "security matrix is malformed",
                status_code=500,
            )
        categories: dict[str, int] = {}
        for scenario in scenarios:
            if isinstance(scenario, dict):
                category = str(scenario.get("category", "unknown"))
                categories[category] = categories.get(category, 0) + 1
        ledger = current_ledger(self.protocol_root.parent, self.artifact_root, scenarios)
        results = {item["scenario_id"]: item for item in ledger.pop("records")}
        return {
            "suite": matrix.get("suite"),
            "llm_required": matrix.get("llm_required"),
            "success_invariant": matrix.get("success_invariant"),
            "scenario_count": len(scenarios),
            "categories": categories,
            "scenarios": [dict(item, latest_result=results.get(item["id"])) for item in scenarios],
            "latest_batch": ledger,
            "error_codes": error_codes,
        }

    def benchmark_summary(self) -> dict[str, Any]:
        from backend.benchmark.provenance import source_provenance

        path = self.artifact_root / "benchmarks" / "current-cloud-summary.json"
        if not path.is_file():
            return {
                "status": "PENDING_CURRENT_ACCEPTANCE",
                "message": (
                    "The current Windows-native cloud acceptance has not published verified metrics."
                ),
            }
        summary = self._load_json(path)
        if not isinstance(summary, dict):
            raise UiApiError(
                "RUNTIME_CONFIGURATION_INVALID",
                "benchmark summary is malformed",
                status_code=500,
            )
        acceptance = summary.get("acceptance")
        environment = summary.get("environment")
        if (
            summary.get("status") != "VERIFIED"
            or not isinstance(acceptance, dict)
            or acceptance.get("passed") is not True
            or summary.get("acceptance_target") != "native_windows_cloud_20261004"
            or not isinstance(environment, dict)
            or environment.get("deployment") != "native_windows"
        ):
            raise UiApiError(
                "RUNTIME_CONFIGURATION_INVALID",
                "benchmark summary did not pass the current native cloud acceptance gate",
                status_code=500,
            )
        return {
            **summary,
            "source_provenance": source_provenance(summary, self.protocol_root.parent),
        }

    def _demo_projection(
        self, body: dict[str, Any], *, task_id: str, demo_kind: str
    ) -> dict[str, Any]:
        trace = body.get("trace")
        result = body.get("result")
        reason_code = result.get("reason_code") if isinstance(result, dict) else None
        return {
            "demo_kind": demo_kind,
            "task_id": task_id,
            "planner": body.get("planner"),
            "status": body.get("status"),
            "reason_code": reason_code,
            "trace": [self._sanitize_trace_step(item) for item in trace]
            if isinstance(trace, list)
            else [],
        }

    @staticmethod
    def _sanitize_trace_step(item: Any) -> dict[str, Any]:
        if not isinstance(item, dict):
            return {
                "sequence": 0,
                "agent_id": "unknown",
                "action": "unknown",
                "status": "FAILED",
                "details": {},
            }
        details = item.get("details")
        details = details if isinstance(details, dict) else {}
        allowed = {
            "child_agent_id",
            "credential_id",
            "tool",
            "execution_id",
            "planner",
            "source",
            "prompt_text_consumed",
            "provider",
            "model_requested",
            "model_returned",
            "seed",
            "temperature",
            "prompt_source",
            "response_sm3",
            "total_duration_ns",
            "load_duration_ns",
            "prompt_eval_count",
            "eval_count",
            "intents",
            "reason_code",
            "message",
            "input",
            "output",
            "summary",
            "stage",
            "duration_ms",
            "http_status",
            "request_length_bytes",
            "response_length_bytes",
            "response_sha256",
            "failure_type",
            "decision",
            "prompt_profile",
            "prompt_messages_sm3",
            "system_prompt",
            "user_prompt",
            "output_schema",
        }
        return {
            "sequence": item.get("sequence"),
            "agent_id": item.get("agent_id"),
            "action": item.get("action"),
            "status": item.get("status"),
            "timestamp_ms": item.get("timestamp_ms"),
            "details": {key: details[key] for key in allowed if key in details},
        }

    def _post(
        self,
        base_url: str,
        path: str,
        body: dict[str, Any],
        *,
        expected_status: int = 200,
    ) -> dict[str, Any]:
        if not base_url:
            raise UiApiError(
                "UPSTREAM_UNAVAILABLE", f"service URL is missing for {path}", status_code=503
            )
        recipient = None
        if base_url.rstrip("/") == self.settings.authority_url.rstrip("/"):
            recipient = "authorization-authority"
        elif (
            self.settings.business_action_registry_url
            and base_url.rstrip("/") == self.settings.business_action_registry_url.rstrip("/")
            and path == "/business-cases"
        ):
            recipient = "business-action-registry"
        elif base_url.rstrip("/") == self.settings.revocation_url.rstrip("/"):
            recipient = "revocation-authority"
        elif (
            path in {"/agents/security-proof/prepare", "/agents/run", "/agents/workflows"}
            and base_url.rstrip("/") == self.settings.coordinator_agent_url.rstrip("/")
        ):
            recipient = "agent-coordinator"
        elif (
            path in {"/agents/security-proof/request", "/agents/run"}
            and base_url.rstrip("/") == self.settings.refund_agent_url.rstrip("/")
        ):
            recipient = "agent-refund"
        options = self._internal_post_options(body, recipient=recipient, path=path)
        try:
            with httpx.Client(
                base_url=base_url,
                timeout=self.settings.ui_request_timeout_seconds,
                trust_env=False,
            ) as client:
                response = client.post(path, **options)
        except httpx.HTTPError as exc:
            raise UiApiError(
                "UPSTREAM_UNAVAILABLE", f"upstream failed: {path}", status_code=503
            ) from exc
        if response.status_code != expected_status:
            try:
                error = response.json()
            except ValueError:
                error = {}
            detail = error.get("detail") if isinstance(error, dict) else None
            source = detail if isinstance(detail, dict) else error
            reason_code = (
                str(source.get("reason_code", "UPSTREAM_REJECTED"))
                if isinstance(source, dict)
                else "UPSTREAM_REJECTED"
            )
            message = (
                str(source.get("message", f"upstream rejected {path}"))
                if isinstance(source, dict)
                else f"upstream rejected {path}"
            )
            raise UiApiError(reason_code, message, status_code=response.status_code)
        try:
            parsed = response.json()
        except ValueError as exc:
            raise UiApiError(
                "CONTROLLED_RESULT_INVALID", f"upstream returned non-JSON for {path}"
            ) from exc
        if not isinstance(parsed, dict):
            raise UiApiError(
                "CONTROLLED_RESULT_INVALID", f"upstream returned non-object for {path}"
            )
        return parsed

    def _internal_post_options(
        self, body: dict[str, Any], *, recipient: str | None, path: str,
    ) -> dict[str, Any]:
        if self.settings.internal_auth_required and recipient:
            from backend.common.internal_auth import InternalAuthenticator, InternalAuthError

            try:
                request_body = canonicalize(body)
                auth = InternalAuthenticator.from_settings(self.settings, service_id="ui-api")
                return {
                    "content": request_body,
                    "headers": auth.request_headers(
                        recipient=recipient, method="POST", path=path,
                        body=request_body,
                    ),
                }
            except (InternalAuthError, ValueError):
                raise UiApiError(
                    "INTERNAL_AUTH_UNAVAILABLE", "control service authentication is unavailable",
                    status_code=503,
                ) from None
        return {"json": body}

    def _get(self, base_url: str, path: str) -> dict[str, Any]:
        try:
            with httpx.Client(
                base_url=base_url,
                timeout=self.settings.ui_request_timeout_seconds,
                trust_env=False,
            ) as client:
                response = client.get(path)
                response.raise_for_status()
                parsed = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise UiApiError(
                "UPSTREAM_UNAVAILABLE", f"upstream failed: {path}", status_code=503
            ) from exc
        if not isinstance(parsed, dict):
            raise UiApiError(
                "CONTROLLED_RESULT_INVALID", f"upstream returned non-object for {path}"
            )
        return parsed

    @staticmethod
    def _load_json(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise UiApiError(
                "RUNTIME_CONFIGURATION_INVALID",
                f"cannot load {path}",
                status_code=500,
            ) from exc
