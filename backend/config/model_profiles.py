from __future__ import annotations

import base64
import ctypes
import ipaddress
import json
import os
import re
import socket
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import ClassVar, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.crypto.strict_json import parse_strict_json

PROFILE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
SUPPORTED_MODES = ("chat_completions",)


class ModelConfigurationError(ValueError):
    def __init__(self, reason_code: str, message: str, *, status_code: int = 400):
        super().__init__(message)
        self.reason_code, self.status_code = reason_code, status_code


def normalized_endpoint(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        port = parsed.port
        invalid = (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(ord(char) < 33 or ord(char) == 127 for char in value)
            or "\\" in value
            or "%" in parsed.path
            or ".." in parsed.path.split("/")
            or host.lower() == "localhost"
            or host.endswith((".localhost", ".local", ".internal"))
            or (port is not None and not 1 <= port <= 65535)
        )
        try:
            invalid = invalid or not ipaddress.ip_address(host).is_global
        except ValueError:
            invalid = invalid or "." not in host or not re.fullmatch(r"[A-Za-z0-9.-]+", host)
        if invalid:
            raise ValueError()
        return urlunsplit(("https", parsed.netloc.lower(), parsed.path.rstrip("/"), "", ""))
    except (ValueError, TypeError):
        raise ModelConfigurationError(
            "MODEL_ENDPOINT_INVALID",
            "云端端点须为公开 HTTPS 地址，不得包含凭据、查询参数或本机地址",
        ) from None


def require_public_resolution(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        if not addresses or any(
            not ipaddress.ip_address(item[4][0]).is_global for item in addresses
        ):
            raise ValueError()
        ordered = sorted(addresses, key=lambda item: ipaddress.ip_address(item[4][0]).version)
        return ordered[0][4][0]
    except (OSError, ValueError):
        raise ModelConfigurationError(
            "MODEL_ENDPOINT_UNREACHABLE", "云端端点未解析为公开网络地址", status_code=503
        ) from None


class ProfileInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=80)
    provider_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    base_url: str = Field(min_length=8, max_length=512)
    api_mode: Literal["chat_completions"] = "chat_completions"
    model: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    timeout_seconds: int = Field(default=120, ge=5, le=300)
    enabled: bool = True
    api_key: str | None = Field(
        default=None,
        max_length=1024,
        repr=False,
        exclude=True,
        json_schema_extra={"writeOnly": True, "format": "password"},
    )
    set_default: bool = False

    @field_validator("base_url")
    @classmethod
    def endpoint(cls, value: str) -> str:
        return normalized_endpoint(value)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        if value != value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("invalid configuration name")
        return value

    @field_validator("api_key")
    @classmethod
    def key(cls, value: str | None) -> str | None:
        if value and any(not 33 <= ord(char) <= 126 for char in value):
            raise ValueError("invalid credential encoding")
        return value or None


class WindowsCredentialCipher:
    """DPAPI current-user storage; it does not isolate sibling processes."""

    class Blob(ctypes.Structure):
        _fields_: ClassVar = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    def _convert(self, data: bytes, *, decrypt: bool) -> bytes:
        if os.name != "nt":
            raise ModelConfigurationError(
                "MODEL_CREDENTIAL_STORAGE_UNAVAILABLE", "密钥加密存储需要 Windows", status_code=503
            )
        source = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        blob = self.Blob(len(data), source)
        output = self.Blob()
        operation = (
            ctypes.windll.crypt32.CryptUnprotectData
            if decrypt
            else ctypes.windll.crypt32.CryptProtectData
        )
        operation.argtypes = [
            ctypes.POINTER(self.Blob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(self.Blob),
        ]
        operation.restype = ctypes.c_int
        if not operation(ctypes.byref(blob), None, None, None, None, 1, ctypes.byref(output)):
            raise ModelConfigurationError(
                "MODEL_CREDENTIAL_UNAVAILABLE",
                "当前 Windows 用户不能读取这份模型凭据",
                status_code=503,
            )
        try:
            return ctypes.string_at(output.data, output.size)
        finally:
            ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.LocalFree.restype = ctypes.c_void_p
            ctypes.windll.kernel32.LocalFree(output.data)

    def protect_bytes(self, value: bytes) -> str:
        if not isinstance(value, bytes) or not 0 < len(value) <= 65_536:
            raise ValueError("invalid protected record size")
        return base64.b64encode(self._convert(value, decrypt=False)).decode("ascii")

    def unprotect_bytes(self, value: str) -> bytes:
        if not isinstance(value, str) or not 0 < len(value) <= 131_072:
            raise ValueError("invalid protected record size")
        data = base64.b64decode(value, validate=True)
        result = self._convert(data, decrypt=True)
        if not 0 < len(result) <= 65_536:
            raise ValueError("invalid protected record size")
        return result

    def encrypt(self, value: str) -> str:
        return self.protect_bytes(value.encode("ascii"))

    def decrypt(self, value: str) -> str:
        try:
            result = self.unprotect_bytes(value).decode("ascii")
            if (
                not result
                or len(result) > 1024
                or any(not 33 <= ord(char) <= 126 for char in result)
            ):
                raise ValueError()
            return result
        except (ValueError, UnicodeError):
            raise ModelConfigurationError(
                "MODEL_CREDENTIAL_UNAVAILABLE", "模型凭据无效，请在本机重新配置", status_code=503
            ) from None


class ModelProfileStore:
    def __init__(self, path: Path, *, cipher: WindowsCredentialCipher | None = None):
        if any(
            component.is_symlink() or component.is_junction()
            for component in (path, *path.absolute().parents)
        ):
            raise ModelConfigurationError(
                "MODEL_CONFIGURATION_INVALID",
                "模型配置路径不能使用链接或目录联接",
                status_code=503,
            )
        self.path = path.resolve()
        self.cipher = cipher or WindowsCredentialCipher()

    @contextmanager
    def lock(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.with_suffix(".lock").open("a+b") as handle:
            handle.seek(0, 2)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            deadline = time.monotonic() + 10
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt

                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ModelConfigurationError(
                            "MODEL_CONFIGURATION_BUSY", "配置正在更新，请稍后重试", status_code=409
                        ) from None
                    time.sleep(0.02)
            try:
                yield
            finally:
                if os.name == "nt":
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle, fcntl.LOCK_UN)

    def _read(self) -> dict:
        if not self.path.exists():
            return {"schema_version": "model-profiles-v1", "default_id": None, "items": {}}
        raw = self.path.read_bytes()
        if len(raw) > 131_072:
            raise ModelConfigurationError(
                "MODEL_CONFIGURATION_INVALID", "模型配置超过大小限制", status_code=503
            )
        try:
            document = parse_strict_json(raw)
            if (
                not isinstance(document, dict)
                or document.get("schema_version") != "model-profiles-v1"
            ):
                raise ValueError()
            if set(document) != {"schema_version", "default_id", "items"}:
                raise ValueError()
            items = document["items"]
            if (
                not isinstance(items, dict)
                or len(items) > 32
                or any(not PROFILE_ID.fullmatch(key) for key in items)
            ):
                raise ValueError()
            for row in items.values():
                if set(row) != {
                    "name",
                    "provider_id",
                    "base_url",
                    "api_mode",
                    "model",
                    "timeout_seconds",
                    "enabled",
                    "credential",
                }:
                    raise ValueError()
                ProfileInput.model_validate(
                    {
                        key: row[key]
                        for key in (
                            "name",
                            "provider_id",
                            "base_url",
                            "api_mode",
                            "model",
                            "timeout_seconds",
                            "enabled",
                        )
                    }
                )
                if not isinstance(row.get("credential", ""), str):
                    raise ValueError()
            if document.get("default_id") is not None and document["default_id"] not in items:
                raise ValueError()
            return document
        except (ValueError, KeyError, TypeError):
            raise ModelConfigurationError(
                "MODEL_CONFIGURATION_INVALID", "模型配置格式无效，未改用其他模型", status_code=503
            ) from None

    def _write(self, document: dict) -> None:
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.path)

    @staticmethod
    def _public(identifier: str, row: dict, default: str | None) -> dict:
        return {
            "id": identifier,
            **{
                key: row[key]
                for key in (
                    "name",
                    "provider_id",
                    "base_url",
                    "api_mode",
                    "model",
                    "timeout_seconds",
                    "enabled",
                )
            },
            "has_key": bool(row.get("credential")),
            "is_default": identifier == default,
        }

    def public(self) -> dict:
        document = self._read()
        return {
            "items": [
                self._public(identifier, row, document["default_id"])
                for identifier, row in document["items"].items()
            ],
            "default_id": document["default_id"],
            "supported_api_modes": list(SUPPORTED_MODES),
        }

    def configured(self, identifier: str | None = None) -> tuple[dict, str] | None:
        document = self._read()
        identifier = identifier or document["default_id"]
        if not identifier or identifier not in document["items"]:
            return None
        row = document["items"][identifier]
        key = self.cipher.decrypt(row["credential"]) if row.get("credential") else ""
        return self._public(identifier, row, document["default_id"]), key

    def save(
        self, identifier: str, request: ProfileInput, *, idle: Callable[[], bool] = lambda: True
    ) -> dict:
        if not PROFILE_ID.fullmatch(identifier):
            raise ModelConfigurationError("MODEL_CONFIGURATION_INVALID", "配置编号格式无效")
        with self.lock():
            if not idle():
                raise ModelConfigurationError(
                    "MODEL_CONFIGURATION_BUSY", "尚有任务未终结，配置未修改", status_code=409
                )
            document = self._read()
            old = document["items"].get(identifier, {})
            if not old and len(document["items"]) >= 32:
                raise ModelConfigurationError("MODEL_CONFIGURATION_LIMIT", "最多保存 32 个模型配置")
            changed_endpoint = bool(
                old
                and (old["base_url"], old["provider_id"]) != (request.base_url, request.provider_id)
            )
            if changed_endpoint and old.get("credential") and not request.api_key:
                raise ModelConfigurationError(
                    "MODEL_CREDENTIAL_CONFIRMATION_REQUIRED",
                    "更换端点或供应商时须重新填写密钥，旧密钥不会转发",
                )
            credential = (
                self.cipher.encrypt(request.api_key)
                if request.api_key
                else old.get("credential", "")
            )
            if request.enabled and not credential:
                raise ModelConfigurationError(
                    "MODEL_CREDENTIAL_REQUIRED", "启用云端配置前须填写 API 密钥"
                )
            row = request.model_dump(exclude={"api_key", "set_default"}) | {
                "credential": credential
            }
            document["items"][identifier] = row
            if request.set_default or document["default_id"] is None:
                document["default_id"] = identifier
            self._write(document)
            return self._public(identifier, row, document["default_id"])

    def select(self, identifier: str, *, idle: Callable[[], bool] = lambda: True) -> dict:
        with self.lock():
            if not idle():
                raise ModelConfigurationError(
                    "MODEL_CONFIGURATION_BUSY", "尚有任务未终结，默认模型未修改", status_code=409
                )
            document = self._read()
            if identifier not in document["items"]:
                raise ModelConfigurationError(
                    "MODEL_CONFIGURATION_NOT_FOUND", "配置不存在", status_code=404
                )
            row = document["items"][identifier]
            if not row["enabled"] or not row.get("credential"):
                raise ModelConfigurationError(
                    "MODEL_MODE_UNAVAILABLE", "该配置未启用或尚未填写密钥", status_code=409
                )
            document["default_id"] = identifier
            self._write(document)
            return self._public(identifier, row, identifier)

    def delete(self, identifier: str, *, idle: Callable[[], bool] = lambda: True) -> dict:
        with self.lock():
            if not idle():
                raise ModelConfigurationError(
                    "MODEL_CONFIGURATION_BUSY", "尚有任务未终结，配置未删除", status_code=409
                )
            document = self._read()
            if identifier == document["default_id"]:
                raise ModelConfigurationError(
                    "MODEL_CONFIGURATION_IS_DEFAULT", "请先切换默认配置再删除", status_code=409
                )
            if identifier not in document["items"]:
                raise ModelConfigurationError(
                    "MODEL_CONFIGURATION_NOT_FOUND", "配置不存在", status_code=404
                )
            del document["items"][identifier]
            self._write(document)
            return {"deleted": True, "id": identifier}
