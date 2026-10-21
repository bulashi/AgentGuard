from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.time import now_unix
from backend.config.settings import get_settings
from backend.identity.key_registry import KeyRecord, PostgresKeyRegistry
from backend.state.database import connect


@dataclass(frozen=True)
class DevelopmentKey:
    file_stem: str
    key_id: str
    subject_id: str
    subject_type: str
    purpose: KeyPurpose


DEVELOPMENT_KEYS = (
    DevelopmentKey(
        "authorization",
        "auth-key-01",
        "authorization-authority",
        "AUTHORITY",
        KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
    ),
    DevelopmentKey(
        "agent-coordinator",
        "agent-coordinator-key-01",
        "agent-coordinator",
        "AGENT",
        KeyPurpose.AGENT_HOLDER_SIGNING,
    ),
    DevelopmentKey(
        "agent-knowledge",
        "agent-knowledge-key-01",
        "agent-knowledge",
        "AGENT",
        KeyPurpose.AGENT_HOLDER_SIGNING,
    ),
    DevelopmentKey(
        "agent-case",
        "agent-case-key-01",
        "agent-case",
        "AGENT",
        KeyPurpose.AGENT_HOLDER_SIGNING,
    ),
    DevelopmentKey(
        "agent-refund",
        "agent-refund-key-01",
        "agent-refund",
        "AGENT",
        KeyPurpose.AGENT_HOLDER_SIGNING,
    ),
    DevelopmentKey(
        "gateway",
        "gateway-key-01",
        "secure-tool-gateway",
        "SERVICE",
        KeyPurpose.GATEWAY_EXECUTION_SIGNING,
    ),
    DevelopmentKey(
        "receipt",
        "receipt-key-01",
        "receipt-service",
        "SERVICE",
        KeyPurpose.EXECUTION_RECEIPT_SIGNING,
    ),
    DevelopmentKey(
        "audit",
        "audit-key-01",
        "audit-checkpoint-signer",
        "SERVICE",
        KeyPurpose.AUDIT_CHECKPOINT_SIGNING,
    ),
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Register development public keys")
    parser.add_argument("--public-root", default="/run/agentguard-keys/public")
    args = parser.parse_args()
    settings = get_settings()
    public_root = Path(args.public_root)
    current = now_unix()
    registry = PostgresKeyRegistry(settings.database_url)

    with connect(settings.database_url) as connection, connection.transaction():
        for definition in DEVELOPMENT_KEYS:
            if definition.subject_type != "AGENT":
                continue
            connection.execute(
                """
                INSERT INTO agent_identities (agent_id, display_name, agent_type, created_at)
                VALUES (%s, %s, 'DETERMINISTIC', %s)
                ON CONFLICT (agent_id) DO NOTHING
                """,
                (definition.subject_id, definition.subject_id, current),
            )

    for definition in DEVELOPMENT_KEYS:
        public_key = (public_root / f"{definition.file_stem}.public").read_text(
            encoding="ascii"
        ).strip()
        registry.register(
            KeyRecord(
                key_id=definition.key_id,
                subject_id=definition.subject_id,
                subject_type=definition.subject_type,
                purpose=definition.purpose,
                public_key_hex=public_key,
                status=KeyState.ACTIVE,
                material_state=KeyMaterialState.PRESENT,
                private_key_reference=f"{definition.file_stem}.private",
                activated_at=current,
                created_at=current,
            )
        )
    print("development public keys registered; private material was not read")


if __name__ == "__main__":
    main()
