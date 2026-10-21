from __future__ import annotations

import hmac
import re
import time
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from backend.crypto.strict_json import parse_strict_json

COOKIE_NAME = "agentguard_operator"
BOOTSTRAP_PATH = "/api/operator-session"
SESSION_TTL_SECONDS = 28_800


class OperatorSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    launch_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        repr=False,
        exclude=True,
        json_schema_extra={"writeOnly": True, "format": "password"},
    )


class OperatorSessionResponse(BaseModel):
    authenticated: bool


class OperatorSessionGuard:
    """Local operator authentication, not a claim of Windows process isolation."""

    def __init__(self, app, *, required: bool, secret: str):
        self.app, self.required = app, required
        if required and not re.fullmatch(r"[0-9a-f]{64}", secret):
            raise ValueError("native operator authentication requires a random session secret")
        self.secret = secret
        self.highest_time = int(time.time())

    def signed_cookie(self, issued_at: int) -> str:
        message = f"AGENTGUARD|LOCAL_OPERATOR|V2|{issued_at}".encode("ascii")
        signature = hmac.new(self.secret.encode("ascii"), message, "sm3").hexdigest()
        return f"{issued_at}.{signature}"

    def valid_cookie(self, token: str, now: int) -> bool:
        match = re.fullmatch(r"(0|[1-9][0-9]{0,11})\.([0-9a-f]{64})", token)
        if match is None:
            return False
        issued_at = int(match[1])
        return 0 <= now - issued_at <= SESSION_TTL_SECONDS and hmac.compare_digest(
            token, self.signed_cookie(issued_at)
        )

    async def __call__(self, scope, receive, send):
        if not self.required or scope["type"] != "http" or not scope["path"].startswith("/api/"):
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        try:
            host = headers.get("host", "")
            parsed = urlsplit("http://" + host)
            origin = headers.get("origin")
            local = (
                parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                and not parsed.username
                and not parsed.password
                and not parsed.path
                and not parsed.query
                and not parsed.fragment
            )
            same_origin = origin is None or origin.lower() == scope["scheme"] + "://" + host.lower()
        except ValueError:
            local = same_origin = False
        if (
            not local
            or not same_origin
            or headers.get("sec-fetch-site", "none") not in {"same-origin", "none"}
        ):
            return await self.error(403, "OPERATOR_ORIGIN_DENIED", "控制台只接受本机同源操作")(
                scope, receive, send
            )
        now = int(time.time())
        if now < self.highest_time:
            return await self.error(
                401, "OPERATOR_SESSION_REQUIRED", "本机会话时钟异常，请重新启动控制台"
            )(scope, receive, send)
        self.highest_time = now
        if scope["path"] == BOOTSTRAP_PATH and scope["method"] == "POST":
            if headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
                return await self.error(415, "REQUEST_SCHEMA_INVALID", "会话请求格式无效")(
                    scope, receive, send
                )
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > 1024:
                    return await self.error(413, "REQUEST_SCHEMA_INVALID", "会话请求超过大小限制")(
                        scope, receive, send
                    )
                if not message.get("more_body", False):
                    break
            try:
                document = parse_strict_json(bytes(body))
                token = document.get("launch_token") if isinstance(document, dict) else None
                valid = (
                    isinstance(document, dict)
                    and set(document) == {"launch_token"}
                    and isinstance(token, str)
                    and hmac.compare_digest(token, self.secret)
                )
            except (ValueError, TypeError):
                valid = False
            if not valid:
                return await self.error(
                    401, "OPERATOR_SESSION_REQUIRED", "请从启动 AgentGuard 入口进入控制台"
                )(scope, receive, send)
            response = JSONResponse({"authenticated": True}, headers={"Cache-Control": "no-store"})
            response.set_cookie(
                COOKIE_NAME,
                self.signed_cookie(now),
                max_age=SESSION_TTL_SECONDS,
                httponly=True,
                samesite="strict",
                path="/api",
            )
            return await response(scope, receive, send)
        try:
            cookies = SimpleCookie()
            cookies.load(headers.get("cookie", ""))
            token = cookies[COOKIE_NAME].value if COOKIE_NAME in cookies else ""
            valid = self.valid_cookie(token, now)
        except (ValueError, TypeError):
            valid = False
        if not valid:
            return await self.error(
                401, "OPERATOR_SESSION_REQUIRED", "请从启动 AgentGuard 入口进入控制台"
            )(scope, receive, send)
        await self.app(scope, receive, send)

    @staticmethod
    def error(status: int, reason: str, message: str) -> JSONResponse:
        return JSONResponse(
            status_code=status,
            content={"reason_code": reason, "message": message},
            headers={"Cache-Control": "no-store"},
        )
