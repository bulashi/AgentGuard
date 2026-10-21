from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from backend.config.model_profiles import (
    ModelConfigurationError,
    ModelProfileStore,
    normalized_endpoint,
    require_public_resolution,
)
from backend.config.settings import Settings
from backend.crypto.strict_json import parse_strict_json

MAX_RESPONSE_BYTES = 131_072
MAX_OUTPUT_TOKENS = 1536


def parse_upstream_response(raw: bytes) -> dict[str, Any]:
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate upstream field")
            result[key] = value
        return result

    result = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs)
    stack = [(result, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 64 or (isinstance(item, float) and not math.isfinite(item)):
            raise ValueError("invalid upstream JSON")
        if isinstance(item, dict):
            stack.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            stack.extend((value, depth + 1) for value in item)
    if not isinstance(result, dict):
        raise ValueError("non-object upstream response")
    return result


@dataclass(frozen=True)
class ResolvedModel:
    provider_id: str
    base_url: str
    model: str
    timeout_seconds: float
    api_key: str = field(repr=False)
    configuration_id: str | None = None

    @property
    def deepseek(self) -> bool:
        return urlsplit(self.base_url).hostname == "api.deepseek.com"


def resolve_model(settings: Settings) -> ResolvedModel:
    if settings.model_configurations_path:
        configured = ModelProfileStore(Path(settings.model_configurations_path)).configured()
        if configured is None:
            raise ModelConfigurationError(
                "MODEL_MODE_UNAVAILABLE", "尚未设置默认云端模型", status_code=503
            )
        profile, key = configured
        if not profile["enabled"] or not key:
            raise ModelConfigurationError(
                "MODEL_MODE_UNAVAILABLE", "默认模型未启用或密钥不可用", status_code=503
            )
        return ResolvedModel(
            profile["provider_id"],
            profile["base_url"],
            profile["model"],
            profile["timeout_seconds"],
            key,
            profile["id"],
        )
    # Legacy environment-only configuration is deliberately not an arbitrary endpoint enrolment.
    if not settings.cloud_llm_enabled or not settings.cloud_llm_api_key:
        raise ModelConfigurationError("MODEL_MODE_UNAVAILABLE", "云端模型尚未配置", status_code=503)
    if (
        settings.cloud_llm_base_url != "https://api.deepseek.com"
        or settings.cloud_llm_model != "deepseek-flash"
    ):
        raise ModelConfigurationError(
            "MODEL_CONFIGURATION_INVALID", "自定义模型须先通过配置界面明确登记", status_code=503
        )
    return ResolvedModel(
        "deepseek",
        settings.cloud_llm_base_url,
        settings.cloud_llm_model,
        settings.llm_request_timeout_seconds,
        settings.cloud_llm_api_key,
    )


def completion(
    model: ResolvedModel,
    messages: list[dict[str, str]],
    *,
    transport: httpx.BaseTransport | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    endpoint = normalized_endpoint(model.base_url)
    target = endpoint if endpoint.endswith("/chat/completions") else endpoint + "/chat/completions"
    body: dict[str, Any] = {
        "model": model.model,
        "messages": messages,
        "stream": False,
        "response_format": {"type": "json_object"},
        "temperature": 0,
        "max_tokens": MAX_OUTPUT_TOKENS,
    }
    if model.deepseek:
        body["thinking"] = {"type": "disabled"}
    evidence: dict[str, Any] = {"http_status": 0, "api_mode": "chat_completions"}
    started = time.perf_counter()
    response: httpx.Response | None = None
    try:
        with httpx.Client(
            timeout=model.timeout_seconds,
            trust_env=False,
            follow_redirects=False,
            transport=transport,
        ) as client:
            request = client.build_request(
                "POST",
                target,
                headers={
                    "Authorization": f"Bearer {model.api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            evidence["request_length_bytes"] = len(request.content)
            if transport is None:
                address = require_public_resolution(endpoint)
                host = urlsplit(endpoint).hostname
                # Pin the checked address while retaining TLS hostname verification.
                request.headers["Host"] = request.url.netloc.decode("ascii")
                request.extensions["sni_hostname"] = host
                request.url = request.url.copy_with(host=address)
            response = client.send(request, stream=True)
            evidence["http_status"] = response.status_code
            raw = bytearray()
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError("response size exceeded")
                raw.extend(chunk)
            evidence.update(
                response_length_bytes=len(raw), response_sha256=hashlib.sha256(raw).hexdigest()
            )
            if model.api_key.encode("ascii") in raw:
                raise ValueError("upstream reflected a credential")
            response.raise_for_status()
            result = parse_upstream_response(bytes(raw))
            return result, evidence
    except (httpx.HTTPError, ValueError, ModelConfigurationError) as exc:
        code = (
            exc.reason_code
            if isinstance(exc, ModelConfigurationError)
            else "LLM_UPSTREAM_UNAVAILABLE"
        )
        error = ModelConfigurationError(
            code, "模型服务未返回可用结果，未切换其他模型或规则模式", status_code=503
        )
        error.evidence = {**evidence, "failure_type": type(exc).__name__}
        raise error from None
    finally:
        evidence["duration_ms"] = max(1, round((time.perf_counter() - started) * 1000))
        if response is not None:
            response.close()


def test_configuration(store: ModelProfileStore, identifier: str) -> dict:
    configured = store.configured(identifier)
    if configured is None:
        raise ModelConfigurationError(
            "MODEL_CONFIGURATION_NOT_FOUND", "配置不存在", status_code=404
        )
    profile, key = configured
    if not key:
        raise ModelConfigurationError("MODEL_CREDENTIAL_REQUIRED", "请先保存 API 密钥")
    model = ResolvedModel(
        profile["provider_id"],
        profile["base_url"],
        profile["model"],
        profile["timeout_seconds"],
        key,
        identifier,
    )
    started = time.perf_counter()
    try:
        result, _ = completion(
            model,
            [
                {"role": "system", "content": 'Return only JSON: {"connection":"ok"}.'},
                {"role": "user", "content": "Check the configured JSON text interface."},
            ],
        )
        content = result["choices"][0]["message"]["content"]
        if not isinstance(content, str) or parse_strict_json(content.encode("utf-8")) != {
            "connection": "ok"
        }:
            raise ValueError()
        returned = result.get("model")
        if returned is not None and (not isinstance(returned, str) or len(returned) > 128):
            raise ValueError()
        return {
            "status": "PASS",
            "model_requested": profile["model"],
            "model_returned": returned,
            "duration_ms": max(1, round((time.perf_counter() - started) * 1000)),
            "message": "接口与 JSON 响应校验通过",
        }
    except (ModelConfigurationError, ValueError, KeyError, TypeError, IndexError) as exc:
        return {
            "status": "FAIL",
            "model_requested": profile["model"],
            "duration_ms": max(1, round((time.perf_counter() - started) * 1000)),
            "reason_code": exc.reason_code
            if isinstance(exc, ModelConfigurationError)
            else "LLM_OUTPUT_INVALID",
            "message": "接口测试未通过；未切换模型，未发送任何业务资料",
        }
