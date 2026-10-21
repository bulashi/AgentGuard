"""Per-edge native control credentials. This is application isolation, not OS isolation."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from backend.config.model_profiles import WindowsCredentialCipher

EDGES = (
    ("ui-api", "authorization-authority"),
    ("ui-api", "agent-coordinator"),
    ("ui-api", "agent-refund"),
    ("ui-api", "business-action-registry"),
    ("agent-coordinator", "agent-case"),
    ("agent-coordinator", "agent-knowledge"),
    ("agent-case", "agent-refund"),
    ("agent-coordinator", "secure-gateway"),
    ("agent-knowledge", "secure-gateway"),
    ("agent-case", "secure-gateway"),
    ("agent-refund", "secure-gateway"),
    ("agent-coordinator", "coordinator-delegation-agent"),
    ("agent-case", "case-delegation-agent"),
    ("agent-refund", "refund-delegation-agent"),
    ("agent-refund", "business-action-registry"),
    ("agent-case", "business-action-registry"),
    ("secure-gateway", "receipt-service"),
    ("secure-gateway", "audit-append-authority"),
    ("recovery-worker", "receipt-service"),
    ("recovery-worker", "refund-service"),
    ("recovery-worker", "notification-service"),
    ("audit-worker", "audit-append-authority"),
    ("checkpoint-worker", "checkpoint-service"),
    ("revocation-controller", "revocation-authority"),
    ("ui-api", "revocation-authority"),
    ("recovery-trigger", "recovery-worker"),
)


def service_identity(name: str) -> str:
    if name in {"coordinator-agent", "knowledge-agent", "case-agent", "refund-agent"}:
        return "agent-" + name.removesuffix("-agent")
    if name in {"ticket-tool", "knowledge-tool", "refund-tool", "notification-tool"}:
        return name.removesuffix("-tool") + "-service"
    return name


def generate_keys() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for caller, recipient in EDGES:
        key = secrets.token_hex(32)
        edge = caller + "->" + recipient
        for subject in (caller, recipient):
            result.setdefault(subject, {})[edge] = key
    return result


def save_keys(path: Path, keys: dict[str, dict[str, str]]) -> None:
    value = json.dumps(keys, sort_keys=True, separators=(",", ":"))
    protected = WindowsCredentialCipher().protect_bytes(value.encode("ascii"))
    path.write_text(protected, encoding="ascii")


def load_keys(path: Path, subject: str) -> dict[str, str]:
    """Trusted maintenance tooling reads only its requested subject, never prints secrets."""
    value = WindowsCredentialCipher().unprotect_bytes(path.read_text(encoding="ascii"))
    document = json.loads(value)
    if subject not in document:
        raise ValueError("native control identity is not configured")
    return document[subject]
