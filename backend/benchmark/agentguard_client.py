from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter_ns
from typing import Any

import httpx

from backend.benchmark.business_cases import BenchmarkBusinessCase
from backend.benchmark.internal_security import validate_keys
from backend.common.enums import KeyPurpose
from backend.common.ids import new_id
from backend.common.internal_auth import InternalAuthenticator
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex


class BenchmarkClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


@dataclass(frozen=True)
class HttpObservation:
    status_code: int
    body: dict[str, Any]
    elapsed_ms: float


@dataclass(frozen=True)
class AgentGuardChain:
    task_id: str
    credential_chain: list[dict[str, Any]]
    credential_ids: list[str]
    holder_agent_id: str
    holder_key_id: str
    holder_private_key: str = field(repr=False)
    holder_public_key: str
    tenant_id: str = "tenant-A"
    ticket_id: str = "T10086"
    customer_id: str = "C9527"


class AgentGuardBenchmarkClient:
    def __init__(
        self,
        *,
        authority_url: str,
        coordinator_delegation_url: str,
        case_delegation_url: str,
        gateway_url: str,
        registry_url: str,
        revocation_url: str,
        coordinator_agent_url: str,
        live_refund_agent_url: str,
        private_key_root: str | Path,
        timeout_seconds: float = 60.0,
        internal_auth_required: bool = False,
        internal_auth_keys: str = "{}",
    ) -> None:
        self.authority_url = authority_url
        self.coordinator_delegation_url = coordinator_delegation_url
        self.case_delegation_url = case_delegation_url
        self.gateway_url = gateway_url
        self.registry_url = registry_url
        self.revocation_url = revocation_url
        self.coordinator_agent_url = coordinator_agent_url
        self.live_refund_agent_url = live_refund_agent_url
        self.private_key_root = Path(private_key_root)
        self.timeout_seconds = timeout_seconds
        self.internal_auth_required = internal_auth_required
        keys = validate_keys(internal_auth_keys) if internal_auth_required else {}
        self._internal_senders = {
            caller: InternalAuthenticator(
                service_id=caller,
                required=internal_auth_required,
                keys_json=json.dumps(
                    {edge: key for edge, key in keys.items() if edge.startswith(caller + "->")}
                ),
            )
            for caller in (
                "ui-api",
                "agent-coordinator",
                "agent-case",
                "agent-refund",
                "revocation-controller",
            )
        }
        self._task_cases: dict[str, BenchmarkBusinessCase] = {}
        self._clients: dict[str, httpx.Client] = {}

    def close(self) -> None:
        for client in self._clients.values():
            client.close()
        self._clients.clear()

    def __enter__(self) -> AgentGuardBenchmarkClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def health(self, base_url: str) -> HttpObservation:
        return self._request(base_url, "GET", "/health")

    def create_chain(
        self,
        chain_length: int,
        *,
        refund_total_fen: int,
        max_tool_calls: int,
        expires_in_seconds: int = 1_800,
        business_case: BenchmarkBusinessCase | None = None,
    ) -> AgentGuardChain:
        if chain_length not in {1, 2, 3}:
            raise ValueError("chain_length must be 1, 2, or 3")
        if chain_length == 1:
            root_holder = ("agent-refund", "agent-refund-key-01")
        elif chain_length == 2:
            root_holder = ("agent-case", "agent-case-key-01")
        else:
            root_holder = ("agent-coordinator", "agent-coordinator-key-01")
        root = self._create_root(
            holder_agent_id=root_holder[0],
            holder_key_id=root_holder[1],
            delegation_depth=chain_length - 1,
            refund_total_fen=refund_total_fen,
            max_tool_calls=max_tool_calls,
            expires_in_seconds=expires_in_seconds,
            business_case=business_case,
        )
        chain = [root]
        if chain_length == 3:
            chain.append(
                self._delegate(
                    self.coordinator_delegation_url,
                    chain[-1],
                    holder_agent_id="agent-case",
                    holder_key_id="agent-case-key-01",
                    refund_total_fen=refund_total_fen,
                    max_tool_calls=max_tool_calls,
                )
            )
        if chain_length >= 2:
            chain.append(
                self._delegate(
                    self.case_delegation_url,
                    chain[-1],
                    holder_agent_id="agent-refund",
                    holder_key_id="agent-refund-key-01",
                    refund_total_fen=refund_total_fen,
                    max_tool_calls=max_tool_calls,
                )
            )
        private_key = self._private_key("agent-refund")
        return AgentGuardChain(
            task_id=str(self._payload(root)["task_id"]),
            credential_chain=chain,
            credential_ids=[str(self._payload(item)["credential_id"]) for item in chain],
            holder_agent_id="agent-refund",
            holder_key_id="agent-refund-key-01",
            holder_private_key=private_key,
            holder_public_key=derive_public_key(private_key),
            **(business_case.binding() if business_case is not None else {}),
        )

    def create_coordinator_root(
        self,
        *,
        refund_total_fen: int,
        max_tool_calls: int,
        expires_in_seconds: int = 1_800,
        business_case: BenchmarkBusinessCase | None = None,
    ) -> dict[str, Any]:
        return self._create_root(
            holder_agent_id="agent-coordinator",
            holder_key_id="agent-coordinator-key-01",
            delegation_depth=2,
            refund_total_fen=refund_total_fen,
            max_tool_calls=max_tool_calls,
            expires_in_seconds=expires_in_seconds,
            business_case=business_case,
        )

    def run_normal_task(
        self,
        root: dict[str, Any],
        *,
        refund_amount_fen: int,
        prompt_text: str,
    ) -> HttpObservation:
        case = self._task_cases.get(str(self._payload(root)["task_id"]))
        return self._request(
            self.coordinator_agent_url,
            "POST",
            "/agents/run",
            json_body={
                "credential_chain": [root],
                "context": {
                    "ticket_id": case.ticket_id if case is not None else "T10086",
                    "customer_id": case.customer_id if case is not None else "C9527",
                    "refund_amount_fen": refund_amount_fen,
                    "prompt_text": prompt_text,
                },
            },
        )

    def run_live_refund_task(
        self,
        root: dict[str, Any],
        *,
        refund_amount_fen: int,
        prompt_text: str,
    ) -> HttpObservation:
        case = self._task_cases.get(str(self._payload(root)["task_id"]))
        return self._request(
            self.live_refund_agent_url,
            "POST",
            "/agents/run",
            json_body={
                "credential_chain": [root],
                "context": {
                    "ticket_id": case.ticket_id if case is not None else "T10086",
                    "customer_id": case.customer_id if case is not None else "C9527",
                    "refund_amount_fen": refund_amount_fen,
                    "prompt_text": prompt_text,
                },
            },
        )

    def resolve_refund_action(self, task_id: str) -> HttpObservation:
        return self._request(
            self.registry_url,
            "POST",
            "/business-actions/refund/resolve",
            json_body={"task_id": task_id},
            internal_caller="agent-refund",
            internal_recipient="business-action-registry",
        )

    def revoke(self, credential_id: str, *, reason: str) -> HttpObservation:
        return self._request(
            self.revocation_url,
            "POST",
            f"/credentials/{credential_id}/revoke",
            json_body={"reason": reason, "revoked_by": "benchmark-runner"},
            internal_caller="revocation-controller",
            internal_recipient="revocation-authority",
        )

    def dispatch(
        self,
        chain: AgentGuardChain,
        *,
        tool_service: str,
        tool_name: str,
        parameters: dict[str, Any],
        business_action_id: str | None = None,
        request_id: str | None = None,
        issued_at: int | None = None,
        holder_private_key: str | None = None,
    ) -> HttpObservation:
        request = self.build_request(
            chain,
            tool_service=tool_service,
            tool_name=tool_name,
            parameters=parameters,
            business_action_id=business_action_id,
            request_id=request_id,
            issued_at=issued_at,
            holder_private_key=holder_private_key,
        )
        return self._request(
            self.gateway_url,
            "POST",
            "/gateway/dispatch",
            json_body=request,
        )

    def build_request(
        self,
        chain: AgentGuardChain,
        *,
        tool_service: str,
        tool_name: str,
        parameters: dict[str, Any],
        business_action_id: str | None = None,
        request_id: str | None = None,
        issued_at: int | None = None,
        holder_private_key: str | None = None,
    ) -> dict[str, Any]:
        timestamp = now_unix() if issued_at is None else issued_at
        resolved_request_id = request_id or new_id("BENCHREQ")
        parameter_hash = sm3_hex(canonicalize(parameters))
        holder_payload = {
            "schema_version": "1.0",
            "credential_chain_hash": sm3_hex(canonicalize(chain.credential_chain)),
            "task_id": chain.task_id,
            "tool_service": tool_service,
            "tool_name": tool_name,
            "tool_version": "v1",
            "canonical_parameter_hash": parameter_hash,
            "request_id": resolved_request_id,
            "issued_at": timestamp,
            "business_action_id": business_action_id,
        }
        private_key = holder_private_key or chain.holder_private_key
        public_key = derive_public_key(private_key)
        return {
            "schema_version": "1.0",
            "credential_chain": deepcopy(chain.credential_chain),
            "task_id": chain.task_id,
            "tool_service": tool_service,
            "tool_name": tool_name,
            "tool_version": "v1",
            "canonical_parameters": deepcopy(parameters),
            "request_id": resolved_request_id,
            "issued_at": timestamp,
            "holder_key_id": chain.holder_key_id,
            "business_action_id": business_action_id,
            "holder_proof": {
                "payload": holder_payload,
                "signature": sign_payload(
                    holder_payload,
                    domain_separator=HOLDER_PROOF,
                    key_id=chain.holder_key_id,
                    key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
                    private_key_hex=private_key,
                    public_key_hex=public_key,
                    signed_at=timestamp,
                ),
            },
        }

    def _create_root(
        self,
        *,
        holder_agent_id: str,
        holder_key_id: str,
        delegation_depth: int,
        refund_total_fen: int,
        max_tool_calls: int,
        expires_in_seconds: int,
        business_case: BenchmarkBusinessCase | None = None,
    ) -> dict[str, Any]:
        if self.internal_auth_required and business_case is None:
            raise ValueError("strict benchmarks require an explicitly provisioned business case")
        created = self._request(
            self.authority_url,
            "POST",
            "/tasks",
            json_body={
                **(
                    business_case.binding()
                    if business_case is not None
                    else {"tenant_id": "tenant-A", "ticket_id": "T10086", "customer_id": "C9527"}
                ),
                "refund_total_fen": refund_total_fen,
                "max_tool_calls": max_tool_calls,
                "expires_in_seconds": expires_in_seconds,
            },
            internal_caller="ui-api",
            internal_recipient="authorization-authority",
        )
        self._require_status(created, {201}, "create AgentGuard task")
        task_id = str(created.body["task_id"])
        authorized = self._request(
            self.authority_url,
            "POST",
            f"/tasks/{task_id}/authorize",
            json_body={
                "confirmed": True,
                "confirmer_id": "policy-refund-v1",
                "holder_agent_id": holder_agent_id,
                "holder_key_id": holder_key_id,
                "delegation_depth": delegation_depth,
            },
            internal_caller="ui-api",
            internal_recipient="authorization-authority",
        )
        self._require_status(authorized, {201}, "authorize AgentGuard task")
        if business_case is not None:
            self._task_cases[task_id] = business_case
        return authorized.body

    def _delegate(
        self,
        base_url: str,
        parent: dict[str, Any],
        *,
        holder_agent_id: str,
        holder_key_id: str,
        refund_total_fen: int,
        max_tool_calls: int,
    ) -> dict[str, Any]:
        payload = self._payload(parent)
        caller = str(payload["holder"]["agent_id"])
        routes = {
            self.coordinator_delegation_url: ("agent-coordinator", "coordinator-delegation-agent"),
            self.case_delegation_url: ("agent-case", "case-delegation-agent"),
        }
        expected_caller, recipient = routes[base_url]
        if caller != expected_caller:
            raise ValueError("benchmark delegation caller does not own the parent credential")
        capabilities = deepcopy(payload["capabilities"])
        delegated = self._request(
            base_url,
            "POST",
            f"/credentials/{payload['credential_id']}/delegate",
            json_body={
                "holder_agent_id": holder_agent_id,
                "holder_key_id": holder_key_id,
                "capabilities": capabilities,
                "quotas": {
                    "refund_total_fen": refund_total_fen,
                    "max_tool_calls": max_tool_calls,
                },
                "not_before": int(payload["not_before"]),
                "expires_at": int(payload["expires_at"]) - 60,
            },
            internal_caller=caller,
            internal_recipient=recipient,
        )
        self._require_status(delegated, {201}, "delegate AgentGuard credential")
        return delegated.body

    def _request(
        self,
        base_url: str,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        internal_caller: str | None = None,
        internal_recipient: str | None = None,
    ) -> HttpObservation:
        if (internal_caller is None) != (internal_recipient is None):
            raise ValueError("both internal benchmark request identities are required")
        client = self._clients.get(base_url)
        if client is None:
            client = httpx.Client(
                base_url=base_url,
                timeout=self.timeout_seconds,
                trust_env=False,
            )
            self._clients[base_url] = client
        started = perf_counter_ns()
        raw = canonicalize(json_body) if json_body is not None else b""
        request_headers = dict(headers or {})
        if internal_caller is not None and internal_recipient is not None:
            request_headers.update(
                self._internal_senders[internal_caller].request_headers(
                    recipient=internal_recipient,
                    method=method,
                    path=path,
                    body=raw,
                )
            )
        elif json_body is not None:
            request_headers.setdefault("Content-Type", "application/json")
        try:
            response = client.request(method, path, headers=request_headers, content=raw)
        except httpx.HTTPError as exc:
            raise BenchmarkClientError(f"request failed: {method} {base_url}{path}") from exc
        elapsed_ms = (perf_counter_ns() - started) / 1_000_000
        try:
            body = response.json()
        except ValueError:
            body = {"raw_text": response.text}
        if not isinstance(body, dict):
            body = {"value": body}
        return HttpObservation(
            status_code=response.status_code,
            body=body,
            elapsed_ms=round(elapsed_ms, 6),
        )

    @staticmethod
    def _require_status(
        observation: HttpObservation,
        expected: set[int],
        operation: str,
    ) -> None:
        if observation.status_code not in expected:
            raise BenchmarkClientError(
                f"{operation} returned HTTP {observation.status_code}",
                status_code=observation.status_code,
                body=observation.body,
            )

    def _private_key(self, stem: str) -> str:
        return (self.private_key_root / f"{stem}.private").read_text(encoding="ascii").strip()

    @staticmethod
    def _payload(credential: dict[str, Any]) -> dict[str, Any]:
        payload = credential.get("payload")
        if not isinstance(payload, dict):
            raise BenchmarkClientError("credential payload is missing")
        return payload
