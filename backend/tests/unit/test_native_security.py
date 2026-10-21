from __future__ import annotations

import json

from scripts.native_config import service_specs
from scripts.native_security import EDGES, generate_keys, load_keys, save_keys, service_identity


def test_security_proof_edges_do_not_grant_root_issuance_to_agents():
    assert len(EDGES) == 26
    assert {
        ("ui-api", "agent-coordinator"),
        ("ui-api", "agent-refund"),
        ("ui-api", "business-action-registry"),
        ("agent-coordinator", "agent-case"),
        ("agent-coordinator", "agent-knowledge"),
        ("agent-case", "agent-refund"),
        ("agent-knowledge", "secure-gateway"),
    } <= set(EDGES)
    assert {
        caller for caller, recipient in EDGES if recipient == "authorization-authority"
    } == {"ui-api"}
    assert {
        caller for caller, recipient in EDGES if recipient == "business-action-registry"
    } == {"ui-api", "agent-case", "agent-refund"}
    assert {recipient for caller, recipient in EDGES if caller == "agent-knowledge"} == {
        "secure-gateway",
    }


def test_edges_are_unique_random_and_limited_to_the_two_participants():
    first, second = generate_keys(), generate_keys()
    names = {"->".join(edge) for edge in EDGES}
    assert len(names) == len(EDGES)
    for caller, recipient in EDGES:
        edge = caller + "->" + recipient
        assert len(first[caller][edge]) == 64
        assert first[caller][edge] == first[recipient][edge] != second[caller][edge]
        assert {subject for subject, keys in first.items() if edge in keys} == {caller, recipient}
    assert len({first[caller][caller + "->" + recipient] for caller, recipient in EDGES}) == len(
        EDGES
    )
    assert set(first["agent-knowledge"]) == {
        "agent-coordinator->agent-knowledge", "agent-knowledge->secure-gateway",
    }


def test_full_edge_registry_dpapi_roundtrip_and_no_plaintext_keys(tmp_path):
    keys = generate_keys()
    path = tmp_path / "control-keys.dpapi"
    save_keys(path, keys)
    for subject in keys:
        assert load_keys(path, subject) == keys[subject]
        assert all(key not in path.read_text(encoding="ascii") for key in keys[subject].values())


def test_native_required_auth_maps_runtime_and_tool_identities_without_authority_edges(tmp_path):
    keys = generate_keys()
    services = [
        service
        for group in service_specs(
            "main",
            "audit",
            "ui",
            tmp_path,
            with_llm=False,
            internal_keys=keys,
            operator_session_secret="1" * 64,
        )
        for service in group
    ]
    for service in services:
        identity = service_identity(service.name)
        assert service.environment["AGENTGUARD_INTERNAL_AUTH_REQUIRED"] == "true"
        assert service.environment["AGENTGUARD_INTERNAL_AUTH_SERVICE_ID"] == identity
        assert json.loads(service.environment["AGENTGUARD_INTERNAL_AUTH_KEYS"]) == keys.get(
            identity, {}
        )
        if service.name.endswith("-agent") and not service.name.endswith("-delegation-agent"):
            assert (
                "ui-api->authorization-authority"
                not in service.environment["AGENTGUARD_INTERNAL_AUTH_KEYS"]
            )
            assert "AGENTGUARD_OPERATOR_SESSION_SECRET" not in service.environment
            assert service.environment["AGENTGUARD_RECEIPT_PUBLIC_KEY_FILE"] == str(
                tmp_path / "public" / "receipt.public"
            )
    ui = next(service for service in services if service.name == "ui-api")
    assert ui.environment["AGENTGUARD_OPERATOR_AUTH_REQUIRED"] == "true"
