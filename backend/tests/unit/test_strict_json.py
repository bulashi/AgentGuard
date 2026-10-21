from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from backend.common.error_codes import ReasonCode
from backend.crypto.strict_json import MAX_NESTING_DEPTH, StrictJsonError, parse_strict_json

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_reject_vectors_have_exact_reason_codes() -> None:
    vectors = json.loads(
        (PROJECT_ROOT / "protocol/test-vectors/canonical-v1.json").read_text(encoding="utf-8")
    )
    for vector in vectors["reject_vectors"]:
        if "raw_utf8" in vector:
            raw = vector["raw_utf8"].encode("utf-8")
        else:
            raw = bytes.fromhex(vector["raw_hex"])
        with pytest.raises(StrictJsonError) as caught:
            parse_strict_json(raw)
        assert caught.value.reason_code == ReasonCode(vector["reason_code"]), vector["name"]


def test_preserves_absent_vs_null() -> None:
    assert parse_strict_json(b'{"value":null}') == {"value": None}
    assert parse_strict_json(b"{}") == {}
    assert parse_strict_json(b'{"value":null}') != parse_strict_json(b"{}")


@pytest.mark.parametrize(
    "raw",
    [b'{"value":' + b"9" * 5_000 + b"}", b"[" * 2_000 + b"0" + b"]" * 2_000],
)
def test_parser_limits_fail_with_protocol_reason(raw: bytes) -> None:
    with pytest.raises(StrictJsonError) as caught:
        parse_strict_json(raw)
    assert caught.value.reason_code == ReasonCode.REQUEST_SCHEMA_INVALID


def test_explicit_nesting_boundary_is_independent_of_python_recursion_limit() -> None:
    previous = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(10000)
        parse_strict_json(b"[" * MAX_NESTING_DEPTH + b"0" + b"]" * MAX_NESTING_DEPTH)
        for depth in (MAX_NESTING_DEPTH + 1, 2000):
            with pytest.raises(StrictJsonError) as caught:
                parse_strict_json(b"[" * depth + b"0" + b"]" * depth)
            assert caught.value.reason_code == ReasonCode.REQUEST_SCHEMA_INVALID
    finally:
        sys.setrecursionlimit(previous)


def test_nesting_check_does_not_treat_json_string_brackets_as_containers() -> None:
    value = {"message": "[" * 2000 + "\\\"{}" + "]" * 2000}
    assert parse_strict_json(json.dumps(value).encode("utf-8")) == value
