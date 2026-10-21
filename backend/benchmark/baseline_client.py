from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter_ns
from typing import Any, Literal

import httpx

from backend.benchmark.agentguard_client import BenchmarkClientError, HttpObservation
from backend.benchmark.contracts import BaselineMode
from backend.common.ids import new_id


@dataclass(frozen=True)
class BaselineWorkload:
    run_id: str
    workload_id: str
    task_id: str
    tenant_id: str = "tenant-A"
    ticket_id: str = "T10086"
    customer_id: str = "C9527"


class BaselineBenchmarkClient:
    """HTTP client for one isolated benchmark baseline gateway."""

    def __init__(
        self,
        *,
        mode: BaselineMode,
        base_url: str,
        admin_token: str,
        credential: str,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.mode = mode
        self.base_url = base_url
        self.admin_token = admin_token
        self.credential = credential
        self.client = httpx.Client(
            base_url=base_url,
            timeout=timeout_seconds,
            trust_env=False,
        )

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> BaselineBenchmarkClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def health(self) -> HttpObservation:
        return self._request("GET", "/health")

    def configure(self, run_id: str) -> HttpObservation:
        return self._request(
            "POST",
            "/benchmark/configure",
            headers={"X-Benchmark-Admin": self.admin_token},
            json_body={"run_id": run_id},
        )

    def setup_workload(
        self,
        run_id: str,
        *,
        refund_total_fen: int,
        max_tool_calls: int,
        tenant_id: str = "tenant-A",
        ticket_id: str = "T10086",
        customer_id: str = "C9527",
        workload_id: str | None = None,
        task_id: str | None = None,
    ) -> tuple[BaselineWorkload, HttpObservation]:
        workload = BaselineWorkload(
            run_id=run_id,
            workload_id=workload_id or new_id("BASEWORK"),
            task_id=task_id or new_id("BASETASK"),
            tenant_id=tenant_id,
            ticket_id=ticket_id,
            customer_id=customer_id,
        )
        observation = self._request(
            "POST",
            "/benchmark/workloads",
            headers={"X-Benchmark-Admin": self.admin_token},
            json_body={
                "run_id": workload.run_id,
                "workload_id": workload.workload_id,
                "task_id": workload.task_id,
                "tenant_id": workload.tenant_id,
                "ticket_id": workload.ticket_id,
                "customer_id": workload.customer_id,
                "refund_total_fen": refund_total_fen,
                "max_tool_calls": max_tool_calls,
                "expires_in_seconds": 1_800,
            },
        )
        return workload, observation

    def revoke(self, run_id: str, *, reason: str) -> HttpObservation:
        return self._request(
            "POST",
            "/benchmark/principal/revoke",
            headers={"X-Benchmark-Admin": self.admin_token},
            json_body={"run_id": run_id, "reason": reason},
        )

    def execute(
        self,
        workload: BaselineWorkload,
        *,
        tool_service: str,
        tool_name: str,
        parameters: dict[str, Any],
        trusted_action_slot: str | None = None,
        request_id: str | None = None,
        operation_id: str | None = None,
        tenant_id: str | None = None,
        credential: str | None = None,
    ) -> HttpObservation:
        return self._request(
            "POST",
            "/benchmark/execute",
            headers={"Authorization": f"Bearer {credential or self.credential}"},
            json_body={
                "run_id": workload.run_id,
                "workload_id": workload.workload_id,
                "request_id": request_id or new_id("BASEREQ"),
                "operation_id": operation_id or new_id("BASEOP"),
                "task_id": workload.task_id,
                "tenant_id": tenant_id or workload.tenant_id,
                "tool_service": tool_service,
                "tool_name": tool_name,
                "tool_version": "v1",
                "canonical_parameters": parameters,
                "trusted_action_slot": trusted_action_slot,
            },
        )

    def run_normal_task(
        self,
        workload: BaselineWorkload,
        *,
        refund_amount_fen: int,
    ) -> list[HttpObservation]:
        observations: list[HttpObservation] = []
        for service, tool in (
            ("ticket-service", "ticket.read"),
            ("knowledge-service", "knowledge.read_associated"),
        ):
            observation = self.execute(
                workload,
                tool_service=service,
                tool_name=tool,
                parameters={"ticket_id": workload.ticket_id},
            )
            observations.append(observation)
            if not self.allowed(observation):
                return observations
        observations.append(
            self.execute(
                workload,
                tool_service="refund-service",
                tool_name="refund.create",
                parameters={
                    "ticket_id": workload.ticket_id,
                    "customer_id": workload.customer_id,
                    "amount_fen": refund_amount_fen,
                },
                trusted_action_slot="primary-refund",
            )
        )
        refund_effect_id = observations[-1].body.get("business_effect_id")
        if not self.allowed(observations[-1]) or not isinstance(
            refund_effect_id, str
        ) or not refund_effect_id:
            return observations
        observations.append(
            self.execute(
                workload,
                tool_service="notification-service",
                tool_name="notification.send_template",
                parameters={
                    "customer_id": workload.customer_id,
                    "template_id": "REFUND_SUCCESS",
                    "related_business_effect_id": refund_effect_id,
                },
                trusted_action_slot="refund-success-notification",
            )
        )
        return observations

    @staticmethod
    def allowed(observation: HttpObservation) -> bool:
        return (
            observation.status_code == 200
            and observation.body.get("decision") == "ALLOW"
            and observation.body.get("state") == "COMMITTED"
        )

    def _request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> HttpObservation:
        started = perf_counter_ns()
        try:
            response = self.client.request(method, path, headers=headers, json=json_body)
        except httpx.HTTPError as exc:
            raise BenchmarkClientError(
                f"request failed: {method} {self.base_url}{path}"
            ) from exc
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
