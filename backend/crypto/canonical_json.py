from __future__ import annotations

from copy import deepcopy
from typing import Any

import rfc8785

from backend.crypto.strict_json import MAX_SAFE_INTEGER

SET_SEMANTIC_FIELDS = frozenset(
    {
        "ticket_ids",
        "customer_ids",
        "document_ids",
        "template_ids",
        "capabilities",
    }
)


class CanonicalizationError(ValueError):
    pass


def _validate_profile(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if value < -MAX_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer out of range at {path}")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"float is forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_profile(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string object key at {path}")
            _validate_profile(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"unsupported type {type(value).__name__} at {path}")


def _sort_set_values(values: list[Any]) -> list[Any]:
    normalized = [normalize_protocol_sets(item) for item in values]
    return sorted(normalized, key=rfc8785.dumps)


def normalize_protocol_sets(value: Any) -> Any:
    if isinstance(value, list):
        return [normalize_protocol_sets(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in deepcopy(value).items():
            if key in SET_SEMANTIC_FIELDS and isinstance(item, list):
                result[key] = _sort_set_values(item)
            else:
                result[key] = normalize_protocol_sets(item)
        return result
    return value


def canonicalize(value: Any, *, normalize_sets: bool = True) -> bytes:
    normalized = normalize_protocol_sets(value) if normalize_sets else value
    _validate_profile(normalized)
    try:
        return rfc8785.dumps(normalized)
    except (rfc8785.CanonicalizationError, UnicodeEncodeError) as exc:
        raise CanonicalizationError(str(exc)) from exc
