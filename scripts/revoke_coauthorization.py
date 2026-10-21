from __future__ import annotations

import argparse
import json
import os

from backend.coauthorization.revocation import CoauthorizationRevocationError, revoke_coauthorization_source


def main() -> None:
    parser = argparse.ArgumentParser(description="Revoke a public approval source and its coauthorized roots; no private keys loaded")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--confirm-revocation", action="store_true", required=True)
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("--approval-key-id")
    targets.add_argument("--policy-revision")
    targets.add_argument("--withdraw-root-id")
    parser.add_argument("--compromised", action="store_true")
    arguments = parser.parse_args()
    if arguments.compromised and not arguments.approval_key_id:
        parser.error("--compromised requires --approval-key-id")
    database_url = os.environ.get("AGENTGUARD_DATABASE_URL", "")
    if not database_url:
        parser.error("AGENTGUARD_DATABASE_URL must identify the intended administrative database role")
    if arguments.approval_key_id:
        kind = "APPROVAL_KEY_COMPROMISED" if arguments.compromised else "APPROVAL_KEY_REVOKED"
        identifier = arguments.approval_key_id
    elif arguments.policy_revision:
        kind, identifier = "APPROVAL_POLICY_REVOKED", arguments.policy_revision
    else:
        kind, identifier = "AUTHORIZATION_WITHDRAWN", arguments.withdraw_root_id
    response = revoke_coauthorization_source(
        database_url, tenant_id=arguments.tenant_id, source_kind=kind, source_identifier=identifier,
    )
    print(json.dumps(response, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except CoauthorizationRevocationError as exc:
        raise SystemExit(f"{exc.reason_code}: {exc}") from None
    except Exception:
        raise SystemExit("COAUTH_REVOCATION_FAILED: no verified result; check migrations 0019/0020, target state and database permissions") from None
