from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from backend.agent_runtime.model_client import test_configuration
from backend.common.strict_json_route import StrictJsonRoute
from backend.config.model_profiles import ModelConfigurationError, ModelProfileStore, ProfileInput
from backend.config.settings import Settings

CONFIGURATION_PREFIX = "/api/model-configurations"
MAX_CONFIGURATION_REQUEST_BYTES = 16_384


class ModelConfigurationGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith(CONFIGURATION_PREFIX):
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        host = headers.get("host", "")
        try:
            parsed_host = urlsplit("http://" + host)
            local_host = parsed_host.hostname in {"127.0.0.1", "localhost", "::1"}
            valid_host = (
                local_host
                and not parsed_host.username
                and not parsed_host.password
                and not parsed_host.path
            )
            origin = headers.get("origin")
            parsed_origin = urlsplit(origin) if origin is not None else None
            valid_origin = parsed_origin is None or (
                parsed_origin.scheme == scope["scheme"]
                and parsed_origin.netloc.lower() == host.lower()
                and not parsed_origin.path
                and not parsed_origin.query
                and not parsed_origin.fragment
            )
        except ValueError:
            valid_host = valid_origin = False
        mutation = scope["method"] not in {"GET", "HEAD", "OPTIONS"}
        valid_origin = valid_origin and headers.get("sec-fetch-site", "none") in {
            "same-origin",
            "none",
        }
        if (
            not valid_host
            or not valid_origin
            or (mutation and headers.get("x-agentguard-configuration") != "1")
        ):
            return await JSONResponse(
                status_code=403,
                content={
                    "reason_code": "MODEL_CONFIGURATION_ORIGIN_DENIED",
                    "message": "模型配置只接受本机同源操作",
                },
            )(scope, receive, send)
        if not mutation:
            return await self.app(scope, receive, send)
        if (
            scope["method"] != "DELETE"
            and headers.get("content-type", "").split(";", 1)[0].lower() != "application/json"
        ):
            return await JSONResponse(
                status_code=415,
                content={
                    "reason_code": "REQUEST_SCHEMA_INVALID",
                    "message": "配置请求须使用 application/json",
                },
            )(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_CONFIGURATION_REQUEST_BYTES:
                return await JSONResponse(
                    status_code=413,
                    content={
                        "reason_code": "REQUEST_SCHEMA_INVALID",
                        "message": "配置请求超过大小限制",
                    },
                )(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class SelectConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class TestConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    confirm_cloud_call: bool


class PublicModelConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    name: str
    provider_id: str
    base_url: str
    api_mode: Literal["chat_completions"]
    model: str
    timeout_seconds: int
    enabled: bool
    has_key: bool
    is_default: bool


class ConfigurationList(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    items: list[PublicModelConfiguration]
    default_id: str | None
    supported_api_modes: list[Literal["chat_completions"]]


class DeletedConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    deleted: bool
    id: str


class ModelConnectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    status: Literal["PASS", "FAIL"]
    model_requested: str | None = None
    model_returned: str | None = None
    duration_ms: int
    reason_code: str | None = None
    message: str | None = None


def model_configuration_router(settings: Settings, *, idle: Callable[[], bool]) -> APIRouter:
    router = APIRouter(prefix=CONFIGURATION_PREFIX, route_class=StrictJsonRoute)

    def store() -> ModelProfileStore:
        if not settings.model_configurations_path:
            raise ModelConfigurationError(
                "MODEL_CONFIGURATION_UNAVAILABLE", "当前启动配置未启用模型配置管理", status_code=503
            )
        return ModelProfileStore(Path(settings.model_configurations_path))

    @router.get("", response_model=ConfigurationList)
    def configurations() -> dict:
        return store().public()

    @router.patch("/default", response_model=PublicModelConfiguration)
    def select(request: SelectConfiguration) -> dict:
        return store().select(request.id, idle=idle)

    @router.put("/{identifier}", response_model=PublicModelConfiguration)
    def save(identifier: str, request: ProfileInput) -> dict:
        return store().save(identifier, request, idle=idle)

    @router.delete("/{identifier}", response_model=DeletedConfiguration)
    def delete(identifier: str) -> dict:
        return store().delete(identifier, idle=idle)

    @router.post("/{identifier}/test", response_model=ModelConnectionResult)
    def test(identifier: str, request: TestConfiguration) -> dict:
        if not request.confirm_cloud_call:
            raise ModelConfigurationError(
                "CLOUD_CONFIRMATION_REQUIRED", "请先确认本次云端连接测试", status_code=400
            )
        return test_configuration(store(), identifier)

    return router
