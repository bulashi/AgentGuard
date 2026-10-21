from __future__ import annotations

import json
import os
from typing import Any

from backend.common.internal_auth import InternalAuthenticator
from scripts.native_security import EDGES

INTERNAL_AUTH_KEYS_ENV = "AGENTGUARD_BENCHMARK_INTERNAL_AUTH_KEYS"
INTERNAL_AUTH_REQUIRED_ENV = "AGENTGUARD_BENCHMARK_INTERNAL_AUTH_REQUIRED"


def required_from_environment() -> bool:
    value = os.environ.get(INTERNAL_AUTH_REQUIRED_ENV, "true")
    if value not in {"true", "false"}:
        raise ValueError("benchmark internal authentication requires an explicit boolean")
    return value == "true"


def keys_from_environment() -> str:
    return os.environ.get(INTERNAL_AUTH_KEYS_ENV, "{}")


def validate_keys(keys_json: str) -> dict[str, str]:
    # Use the production parser, including its duplicate-field and safe-error checks.
    InternalAuthenticator(service_id="benchmark-controller", keys_json=keys_json)
    keys: dict[str, str] = json.loads(keys_json)
    expected = {f"{caller}->{recipient}" for caller, recipient in EDGES}
    if set(keys) != expected or len(set(keys.values())) != len(expected):
        raise ValueError("benchmark requires the complete distinct native edge credentials")
    if any(value == "0" * 64 for value in keys.values()):
        raise ValueError("benchmark internal credentials must not be placeholders")
    return keys


def flatten_keys(scoped_keys: dict[str, dict[str, str]]) -> str:
    flat: dict[str, str] = {}
    for caller, recipient in EDGES:
        edge = f"{caller}->{recipient}"
        outgoing = scoped_keys.get(caller, {}).get(edge)
        incoming = scoped_keys.get(recipient, {}).get(edge)
        if outgoing is None or outgoing != incoming:
            raise ValueError("native incident key distribution is incomplete or inconsistent")
        flat[edge] = outgoing
    encoded = json.dumps(flat, sort_keys=True, separators=(",", ":"))
    validate_keys(encoded)
    return encoded


def public_auth_policy() -> dict[str, Any]:
    return {
        "required": True,
        "algorithm": "HMAC-SM3",
        "edge_count": len(EDGES),
        "key_generation": "native_security.generate_keys; fresh 32-byte random key per edge",
        "key_distribution": "incident edges per service; trusted harness owns fixture controls",
        "request_binding": "caller/recipient/method/path/raw-body-SM3/time/nonce",
        "replay_state": "persistent, run-local SQLite; production nonce state is not used",
        "gateway_dispatch": "unchanged SM2 Holder Proof and signed execution envelope",
        "performance_boundary": "internal authentication and durable replay checks remain enabled",
    }
