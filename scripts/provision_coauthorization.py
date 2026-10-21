from __future__ import annotations

import argparse
import os
from pathlib import Path

from backend.coauthorization.contracts import MAX_BUNDLE_BYTES, PublicApprovalSetup
from backend.coauthorization.provisioning import register_public_approval_policy
from backend.common.schema import PROJECT_ROOT
from backend.crypto.strict_json import parse_strict_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Register externally governed public approval keys; never generate private keys")
    parser.add_argument("--public-file", required=True)
    parser.add_argument("--confirm-public-key-registration", action="store_true", required=True)
    arguments = parser.parse_args()
    path = Path(arguments.public_file).resolve()
    if not path.is_relative_to(PROJECT_ROOT.resolve()) or path.suffix.lower() != ".json":
        parser.error("public registration JSON must be inside the AgentGuard project")
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        parser.error("public registration JSON exceeds 32768 bytes")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BUNDLE_BYTES + 1)
    if len(raw) > MAX_BUNDLE_BYTES:
        parser.error("public registration JSON exceeds 32768 bytes")
    database_url = os.environ.get("AGENTGUARD_DATABASE_URL", "")
    if not database_url:
        parser.error("AGENTGUARD_DATABASE_URL must identify the intended administrative database role")
    setup = PublicApprovalSetup.model_validate(parse_strict_json(raw))
    register_public_approval_policy(database_url, setup)
    print("COAUTHORIZATION_PUBLIC_POLICY=REGISTERED; no private keys generated or loaded")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("COAUTHORIZATION_PUBLIC_POLICY=FAILED; check public metadata, policy state, migration 0015 and database permissions") from None
