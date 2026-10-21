from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute

from backend.crypto.strict_json import StrictJsonError, parse_strict_json


class StrictJsonRoute(APIRoute):
    """Reject ambiguous raw JSON before FastAPI decodes a protocol request."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def strict_handler(request: Request) -> Response:
            if self.body_field is not None:
                raw = await request.body()
                if raw:
                    try:
                        parse_strict_json(raw)
                    except StrictJsonError as exc:
                        raise RequestValidationError(
                            [
                                {
                                    "type": "value_error",
                                    "loc": ("body",),
                                    "msg": "request is not strict protocol JSON",
                                    "ctx": {"reason_code": exc.reason_code.value},
                                }
                            ]
                        ) from exc
            return await handler(request)

        return strict_handler
