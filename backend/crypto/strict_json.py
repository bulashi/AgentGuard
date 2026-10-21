from __future__ import annotations

import json
from typing import Any

from backend.common.error_codes import ReasonCode

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_NESTING_DEPTH = 128


class StrictJsonError(ValueError):
    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(ReasonCode.DUPLICATE_FIELD, f"duplicate field: {key}")
        result[key] = value
    return result


def _parse_int(value: str) -> int:
    if len(value.lstrip("-")) > len(str(MAX_SAFE_INTEGER)):
        raise StrictJsonError(ReasonCode.REQUEST_SCHEMA_INVALID, "integer exceeds safe range")
    parsed = int(value, 10)
    if parsed < -MAX_SAFE_INTEGER or parsed > MAX_SAFE_INTEGER:
        raise StrictJsonError(ReasonCode.REQUEST_SCHEMA_INVALID, "integer exceeds safe range")
    return parsed


def _reject_float(value: str) -> None:
    raise StrictJsonError(
        ReasonCode.REQUEST_SCHEMA_INVALID,
        f"floating-point and scientific notation are forbidden: {value}",
    )


def _reject_constant(value: str) -> None:
    raise StrictJsonError(ReasonCode.REQUEST_SCHEMA_INVALID, f"invalid numeric constant: {value}")


def _reject_excessive_nesting(value: Any) -> None:
    """Bound parsed container depth without relying on the process recursion limit."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_NESTING_DEPTH:
            raise StrictJsonError(ReasonCode.REQUEST_SCHEMA_INVALID, "request exceeds JSON nesting limits")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def parse_strict_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJsonError(ReasonCode.INVALID_UTF8, "request is not valid UTF-8") from exc

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        _reject_excessive_nesting(value)
        return value
    except StrictJsonError:
        raise
    except json.JSONDecodeError as exc:
        raise StrictJsonError(ReasonCode.MALFORMED_JSON, "request is not valid JSON") from exc
    except (ValueError, RecursionError) as exc:
        raise StrictJsonError(
            ReasonCode.REQUEST_SCHEMA_INVALID, "request exceeds JSON parser limits"
        ) from exc
